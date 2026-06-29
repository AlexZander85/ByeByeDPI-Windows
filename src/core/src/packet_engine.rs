//! Packet Engine — перехват (WinDivert) и инъекция (raw socket).
//!
//! # Разделение труда
//!
//! | Задача | Механизм | Почему |
//! |--------|----------|--------|
//! | Перехват пакетов | WinDivert | Точка входа, kernel-level filter |
//! | Модификация проходящих | WinDivert modify + reinject | Нативный, низкая задержка |
//! | Дроп пакетов | WinDivert (не reinject) | Минимальная задержка |
//! | Fake SNI + TTL | Raw socket | Нет WinDivert roundtrip |
//! | IP Fragmentation | Raw socket (IP_HDRINCL) | Полный контроль IP header |
//! | SEQ Overlap | Raw socket | Custom SEQ в raw IP |
//! | QUIC дейтаграммы | Raw socket (IPPROTO_RAW) | Полный UDP header |
//!
//! # WinDivert API (0.7.0-beta.4)
//! - `WinDivert::network()` вместо `WinDivert::new()`
//! - `recv(&mut buffer)` блокирующий, принимает буфер, возвращает `WinDivertPacket`
//! - `send(&packet)` блокирующий, принимает ссылку на пакет
//! - `set_param(param, u64)` — значения теперь `u64`

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use windivert::prelude::WinDivertParam;
use windivert::prelude::*;
use windivert::WinDivert;

/// Размер буфера для WinDivert recv (максимальный MTU + заголовки).
#[allow(dead_code)]
const PACKET_BUFFER_SIZE: usize = 65535;
/// Приоритет фильтра (0 = нормальный).
const WINDIVERT_PRIORITY: i16 = 0;

/// Режим работы пакетного движка.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EngineMode {
    /// WinDivert — полный перехват и модификация пакетов
    WinDivert,
    /// WFP (Windows Filtering Platform) — альтернатива WinDivert
    /// Не требует kernel-mode driver, но имеет ограничения
    Wfp,
    /// Только API — без перехвата пакетов
    ApiOnly,
}

/// Абстракция над WinDivert + raw socket для перехвата и инъекции.
pub struct PacketEngine {
    divert: ArcSwap<Option<WinDivert<NetworkLayer>>>,
    raw_sock: Option<RawSocketTx>,
    stats: PacketStats,
    mode: EngineMode,
}

/// Статистика пакетного движка.
///
/// Использует AtomicU64 для interior mutability (все методы `&self`).
#[derive(Debug)]
pub struct PacketStats {
    pub packets_received: AtomicU64,
    pub packets_sent: AtomicU64,
    pub packets_injected: AtomicU64,
    pub packets_dropped: AtomicU64,
}

impl PacketStats {
    fn new() -> Self {
        Self {
            packets_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_injected: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
        }
    }
}

impl Default for PacketStats {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketEngine {
    /// Создаёт WinDivert handle + raw socket.
    ///
    /// `filter` — WinDivert filter string (например, `"ip && tcp.DstPort == 443"`).
    ///
    /// Автоматически устанавливает WinDivert driver если он не загружен.
    /// Требует admin elevation для установки driver.
    pub fn new(filter: &str) -> Result<Self> {
        // Проверяем/устанавливаем driver если нужно
        if !crate::infra::windivert_driver::is_driver_loaded() {
            info!("WinDivert driver not loaded, installing...");
            crate::infra::windivert_driver::install_driver()
                .context("Failed to install WinDivert driver")?;
        }

        let divert = WinDivert::network(filter, WINDIVERT_PRIORITY, WinDivertFlags::default())
            .context("Failed to open WinDivert (driver may be blocked by HVCI/EDR)")?;

        // WinDivert tuning
        divert
            .set_param(WinDivertParam::QueueLength, 65535)
            .context("Failed to set QueueLength")?;
        divert
            .set_param(WinDivertParam::QueueTime, 500)
            .context("Failed to set QueueTime")?;

        let raw_sock = match unsafe { RawSocketTx::new() } {
            Ok(sock) => {
                debug!("Raw socket created successfully");
                Some(sock)
            }
            Err(e) => {
                error!("Failed to create raw socket (need admin?): {}", e);
                None
            }
        };

        // Отключаем TSO/LSO/RSS для совместимости с desync техниками
        if let Err(e) = Self::disable_offload() {
            warn!("Failed to disable network offload: {}", e);
        }

        debug!("PacketEngine initialized with filter: {}", filter);

        Ok(Self {
            divert: ArcSwap::new(Arc::new(Some(divert))),
            raw_sock,
            stats: PacketStats::new(),
            mode: EngineMode::WinDivert,
        })
    }

    /// Создаёт движок без WinDivert (API-only режим).
    pub fn new_api_only() -> Self {
        let raw_sock = unsafe { RawSocketTx::new() }.ok();

        Self {
            divert: ArcSwap::new(Arc::new(None)),
            raw_sock,
            stats: PacketStats::new(),
            mode: EngineMode::ApiOnly,
        }
    }

    /// Возвращает текущий режим работы.
    pub fn mode(&self) -> EngineMode {
        self.mode
    }

    /// Блокирующий перехват пакета.
    pub fn recv_blocking(
        &self,
        buffer: &mut [u8],
    ) -> Result<(bytes::Bytes, WinDivertAddress<NetworkLayer>)> {
        let guard = self.divert.load();
        let Some(ref divert) = **guard else {
            anyhow::bail!("WinDivert not initialized (API-only mode)");
        };
        let packet = divert.recv(buffer).context("WinDivert recv failed")?;
        self.stats.packets_received.fetch_add(1, Ordering::Relaxed);
        Ok((bytes::Bytes::copy_from_slice(&packet.data), packet.address))
    }

    /// Блокирующая отправка модифицированного пакета.
    ///
    /// Пакет проходит через WinDivert — может быть снова перехвачен.
    /// Должен быть запущен через `spawn_blocking`.
    pub fn send_blocking(
        &self,
        packet: &[u8],
        addr: &WinDivertAddress<NetworkLayer>,
    ) -> Result<u32> {
        let guard = self.divert.load();
        let Some(ref divert) = **guard else {
            anyhow::bail!("WinDivert not initialized (API-only mode)");
        };
        // Создаём временный WinDivertPacket из предоставленных данных
        let wd_packet = WinDivertPacket {
            address: addr.clone(),
            data: std::borrow::Cow::Borrowed(packet),
        };
        let sent = divert.send(&wd_packet).context("WinDivert send failed")?;
        self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
        Ok(sent)
    }

    /// Инъекция UDP/ICMP пакета через raw socket (обходит WinDivert).
    ///
    /// **ТОЛЬКО для UDP и ICMP!** TCP пакеты через raw socket
    /// молча дропаются Windows (XP SP2+). Для TCP используйте `inject_via_divert()`.
    pub fn inject_raw_udp(&self, packet: &[u8]) -> Result<()> {
        let Some(ref sock) = self.raw_sock else {
            anyhow::bail!("Raw socket not available");
        };
        sock.send(packet)?;
        self.stats.packets_injected.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Инъекция TCP пакета через WinDivert (reinject).
    ///
    /// TCP пакеты НЕ могут быть отправлены через raw socket на Windows.
    /// Этот метод reinject'ит пакет обратно в сетевой стек через WinDivert.
    /// Пакет может быть снова перехвачен WinDivert → нужен EventTag.
    pub fn inject_via_divert(
        &self,
        packet: &[u8],
        addr: &WinDivertAddress<NetworkLayer>,
    ) -> Result<u32> {
        let guard = self.divert.load();
        let Some(ref divert) = **guard else {
            anyhow::bail!("WinDivert not initialized (API-only mode)");
        };
        let mut impostor_addr = addr.clone();
        impostor_addr.set_impostor(true);
        let wd_packet = WinDivertPacket {
            address: impostor_addr,
            data: std::borrow::Cow::Borrowed(packet),
        };
        let sent = divert.send(&wd_packet).context("WinDivert inject failed")?;
        self.stats.packets_injected.fetch_add(1, Ordering::Relaxed);
        Ok(sent)
    }

    /// Дроп пакета — просто не вызываем `send()`.
    pub fn drop_packet(&self) {
        self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Динамическое обновление WinDivert фильтра.
    ///
    /// Вызывается при изменении blacklist/whitelist.
    /// Создаёт новый WinDivert handle (старый закрывается при drop).
    pub fn update_filter(&self, filter: &str) -> Result<()> {
        let new_divert = WinDivert::network(filter, WINDIVERT_PRIORITY, WinDivertFlags::default())
            .context("Failed to update WinDivert filter")?;
        new_divert
            .set_param(WinDivertParam::QueueLength, 65535)
            .context("Failed to set QueueLength on new handle")?;
        new_divert
            .set_param(WinDivertParam::QueueTime, 500)
            .context("Failed to set QueueTime on new handle")?;
        self.divert.store(Arc::new(Some(new_divert)));
        debug!("WinDivert filter updated: {}", filter);
        Ok(())
    }

    /// Проверяет, инициализирован ли WinDivert.
    pub fn has_divert(&self) -> bool {
        self.divert.load().is_some()
    }

    /// Проверяет, доступен ли raw socket.
    pub fn has_raw_socket(&self) -> bool {
        self.raw_sock.is_some()
    }

    /// Отключает TSO/LSO (TCP Segmentation Offload / Large Send Offload)
    /// на активном сетевом интерфейсе.
    ///
    /// NIC с TSO может "починить" фрагментированные пакеты до отправки
    /// в кабель, перезаписав контрольные суммы или собрав фрагменты.
    /// Это ломает desync техники (IP fragmentation overlap, SEQ spoofing).
    ///
    /// Использует `netsh` для отключения offload на всех адаптерах.
    pub fn disable_offload() -> Result<()> {
        // Отключаем TCP Chimney Offload (включает TSO/LSO)
        let output = std::process::Command::new("netsh")
            .args(["int", "tcp", "set", "global", "chimney=disabled"])
            .output();

        match output {
            Ok(o) if o.status.success() => {
                debug!("TCP Chimney Offload disabled");
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                warn!("Failed to disable TCP Chimney: {}", stderr);
            }
            Err(e) => {
                warn!("Failed to run netsh: {}", e);
            }
        }

        // Отключаем RSS (Receive Side Scaling) — может переупорядочить пакеты
        let output = std::process::Command::new("netsh")
            .args(["int", "tcp", "set", "global", "rss=disabled"])
            .output();

        match output {
            Ok(o) if o.status.success() => {
                debug!("RSS disabled");
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                warn!("Failed to disable RSS: {}", stderr);
            }
            Err(e) => {
                warn!("Failed to run netsh for RSS: {}", e);
            }
        }

        // Отключаем ECN (Explicit Congestion Notification) — может модифицировать TCP headers
        let output = std::process::Command::new("netsh")
            .args(["int", "tcp", "set", "global", "ecn=disabled"])
            .output();

        match output {
            Ok(o) if o.status.success() => {
                debug!("ECN disabled");
            }
            _ => {
                debug!("ECN disable skipped (non-critical)");
            }
        }

        info!("Network offload disabled (TSO/LSO/RSS/ECN) for desync compatibility");
        Ok(())
    }

    /// Текущая статистика (снэпшот).
    pub fn stats_snapshot(&self) -> PacketStatsSnapshot {
        PacketStatsSnapshot {
            packets_received: self.stats.packets_received.load(Ordering::Relaxed),
            packets_sent: self.stats.packets_sent.load(Ordering::Relaxed),
            packets_injected: self.stats.packets_injected.load(Ordering::Relaxed),
            packets_dropped: self.stats.packets_dropped.load(Ordering::Relaxed),
        }
    }
}

/// Копия статистики (не-atomic, для чтения).
#[derive(Debug, Clone, Default)]
pub struct PacketStatsSnapshot {
    pub packets_received: u64,
    pub packets_sent: u64,
    pub packets_injected: u64,
    pub packets_dropped: u64,
}

/// Raw socket для инъекции пакетов с полным IP header.
///
/// Использует `WSASocketW(AF_INET, SOCK_RAW, IPPROTO_RAW)` с `IP_HDRINCL`.
/// Позволяет отправлять пакеты с произвольным IP, TCP, UDP header.
struct RawSocketTx {
    sock: std::net::UdpSocket, // используется для sendto
}

impl RawSocketTx {
    /// Создаёт raw socket.
    ///
    /// # Требования
    /// - Admin elevation (UAC или запуск от SYSTEM)
    /// - Windows 10/11
    ///
    /// # Safety
    /// Требует admin прав; создаёт raw socket с `IP_HDRINCL`.
    unsafe fn new() -> Result<Self> {
        use windows::Win32::Networking::WinSock::*;

        let sock = WSASocketW(AF_INET.0 as i32, SOCK_RAW.0, IPPROTO_RAW.0, None, 0, 0)?;

        if sock == INVALID_SOCKET {
            anyhow::bail!("WSASocketW failed: {}", WSAGetLastError().0);
        }

        // IP_HDRINCL: весь IP header включён в пакет
        let opt: u32 = 1;
        let opt_ptr = &opt as *const u32 as *const u8;
        let result = setsockopt(
            sock,
            IPPROTO_IP.0,
            IP_HDRINCL,
            Some(std::slice::from_raw_parts(
                opt_ptr,
                std::mem::size_of::<u32>(),
            )),
        );
        if result == SOCKET_ERROR {
            let _ = closesocket(sock);
            anyhow::bail!("setsockopt(IP_HDRINCL) failed: {}", WSAGetLastError().0);
        }

        // Преобразуем SOCKET в std::net::UdpSocket для sendto
        use std::os::windows::io::{FromRawSocket, OwnedSocket};
        let owned = OwnedSocket::from_raw_socket(sock.0 as u64 as std::os::windows::raw::SOCKET);
        let udp = std::net::UdpSocket::from(owned);
        Ok(Self { sock: udp })
    }

    /// Отправляет raw IP пакет.
    ///
    /// Пакет должен содержать полный IP header + payload.
    /// sendto на raw socket игнорирует адрес назначения — он берётся из IP header.
    fn send(&self, packet: &[u8]) -> Result<()> {
        let addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0);
        let sent = self.sock.send_to(packet, addr)?;
        if sent != packet.len() {
            anyhow::bail!("sendto sent {} of {} bytes", sent, packet.len());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_stats_default() {
        let stats = PacketStats::new();
        assert_eq!(stats.packets_received.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_sent.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_injected.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_packet_stats_snapshot() {
        let engine = PacketEngine::new_api_only();
        engine
            .stats
            .packets_received
            .fetch_add(1, Ordering::Relaxed);
        engine.stats.packets_sent.fetch_add(2, Ordering::Relaxed);
        engine
            .stats
            .packets_injected
            .fetch_add(3, Ordering::Relaxed);
        engine.stats.packets_dropped.fetch_add(4, Ordering::Relaxed);

        let snap = engine.stats_snapshot();
        assert_eq!(snap.packets_received, 1);
        assert_eq!(snap.packets_sent, 2);
        assert_eq!(snap.packets_injected, 3);
        assert_eq!(snap.packets_dropped, 4);
    }

    #[test]
    fn test_api_only_engine() {
        let engine = PacketEngine::new_api_only();
        assert!(!engine.has_divert());
        // recv_blocking should fail in API-only mode
        let mut buf = vec![0u8; PACKET_BUFFER_SIZE];
        assert!(engine.recv_blocking(&mut buf).is_err());
    }

    #[test]
    fn test_inject_raw_no_socket() {
        // Without admin, RawSocketTx won't be available
        // But the engine should still be usable
        let engine = PacketEngine::new_api_only();
        let result = engine.inject_raw_udp(&[0x45, 0x00, 0x00, 0x14]);
        // Might fail because raw sock is None
        // Just validate it doesn't panic
        let _ = result;
    }
}
