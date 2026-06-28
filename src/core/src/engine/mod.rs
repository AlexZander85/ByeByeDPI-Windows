//! Processing Pipeline — центральный оркестратор, объединяющий все модули.
//!
//! ## Packet Flow (outbound TLS)
//! 1. WinDivert recv → `is_injected_packet()` → skip если наш
//! 2. `Classifier::classify()` → Classification::Tls
//! 3. `FakeIpManager::lookup(dst_ip)` → domain (reverse DNS)
//! 4. `GeoRouter::resolve(domain, dst_ip)` → RouteDecision
//! 5. `HopTab::observe(packet.ttl)` → учим расстояние до сервера
//! 6. Conntrack — записываем/обновляем соединение
//! 7. DesyncGroup → fake CH / split / bad checksum
//! 8. Inject fake пакет, forward оригинал

use crate::adaptive::hop_tab::HopTab;
use crate::classifier::{Classification, ClassifiedPacket, Classifier};
use crate::conntrack::Conntrack;
use crate::desync::group::DesyncGroup;
use crate::desync::{DesyncConfig, DesyncTechnique};
use crate::dns::fakeip::FakeIpManager;
use crate::infra::event_tag;
use crate::packet_engine::PacketEngine;
use crate::routing::geo::GeoRouter;
use pnet_packet::ipv4::Ipv4Packet;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, warn};
use windivert::prelude::{NetworkLayer, WinDivertAddress};

const PACKET_BUFFER_SIZE: usize = 65535;

#[derive(Debug)]
pub enum PacketDecision {
    Forward,
    Modify(bytes::Bytes),
    Desync {
        inject: Vec<bytes::Bytes>,
        inject_protocol: InjectProtocol,
    },
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InjectProtocol {
    Tcp,
    Udp,
}

#[derive(Debug)]
pub struct ProcessingStats {
    pub total_received: AtomicU64,
    pub injected_skipped: AtomicU64,
    pub tls_outbound: AtomicU64,
    pub fake_ch_injected: AtomicU64,
    pub forwarded: AtomicU64,
    pub dropped: AtomicU64,
    pub errors: AtomicU64,
}

impl ProcessingStats {
    fn new() -> Self {
        Self {
            total_received: AtomicU64::new(0),
            injected_skipped: AtomicU64::new(0),
            tls_outbound: AtomicU64::new(0),
            fake_ch_injected: AtomicU64::new(0),
            forwarded: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> ProcessingStatsSnapshot {
        ProcessingStatsSnapshot {
            total_received: self.total_received.load(Ordering::Relaxed),
            injected_skipped: self.injected_skipped.load(Ordering::Relaxed),
            tls_outbound: self.tls_outbound.load(Ordering::Relaxed),
            fake_ch_injected: self.fake_ch_injected.load(Ordering::Relaxed),
            forwarded: self.forwarded.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProcessingStatsSnapshot {
    pub total_received: u64,
    pub injected_skipped: u64,
    pub tls_outbound: u64,
    pub fake_ch_injected: u64,
    pub forwarded: u64,
    pub dropped: u64,
    pub errors: u64,
}

#[derive(Debug, Clone)]
pub struct ProcessingConfig {
    pub seq_spoof_enabled: bool,
    pub fake_sni: String,
    pub hop_tab_enabled: bool,
    pub event_tag_enabled: bool,
    pub geo_routing_enabled: bool,
    pub desync_port: u16,
    pub only_outbound: bool,
    pub stats_print_interval: Duration,
    pub desync: DesyncConfig,
    pub techniques: Vec<DesyncTechnique>,
}

impl Default for ProcessingConfig {
    fn default() -> Self {
        Self {
            seq_spoof_enabled: true,
            fake_sni: "www.google.com".to_string(),
            hop_tab_enabled: true,
            event_tag_enabled: true,
            geo_routing_enabled: true,
            desync_port: 443,
            only_outbound: true,
            stats_print_interval: Duration::from_secs(60),
            desync: DesyncConfig::default(),
            techniques: Vec::new(),
        }
    }
}

/// Bounded SEQ tracker с TTL — предотвращает бесконечный рост DashSet.
struct InjectedSeqTracker {
    map: std::collections::HashMap<u32, Instant>,
    ttl: Duration,
    max_entries: usize,
}

impl InjectedSeqTracker {
    fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            map: std::collections::HashMap::with_capacity(max_entries),
            ttl,
            max_entries,
        }
    }

    fn insert(&mut self, seq: u32) {
        if self.map.len() >= self.max_entries {
            let now = Instant::now();
            self.map.retain(|_, t| now.duration_since(*t) < self.ttl);
        }
        self.map.insert(seq, Instant::now());
    }

    fn contains(&self, seq: u32) -> bool {
        self.map
            .get(&seq)
            .map(|t| t.elapsed() < self.ttl)
            .unwrap_or(false)
    }
}

pub struct ProcessingPipeline {
    packet_engine: Arc<PacketEngine>,
    fake_ip: Arc<FakeIpManager>,
    geo_router: Arc<GeoRouter>,
    hop_tab: Arc<HopTab>,
    conntrack: Arc<Conntrack>,
    desync_group: Arc<DesyncGroup>,
    config: ProcessingConfig,
    stats: Arc<ProcessingStats>,
    injected_seqs: std::sync::Mutex<InjectedSeqTracker>,
}

impl ProcessingPipeline {
    pub fn new(
        filter: &str,
        config: ProcessingConfig,
        geo_router: Arc<GeoRouter>,
        fake_ip: Arc<FakeIpManager>,
        hop_tab: Arc<HopTab>,
    ) -> Result<Self, anyhow::Error> {
        let packet_engine = Arc::new(PacketEngine::new(filter)?);
        let conntrack = Arc::new(Conntrack::new(Duration::from_secs(120)));
        let desync_group = Arc::new(Self::build_desync_group(&config));

        Ok(Self {
            packet_engine,
            fake_ip,
            geo_router,
            hop_tab,
            conntrack,
            desync_group,
            config,
            stats: Arc::new(ProcessingStats::new()),
            injected_seqs: std::sync::Mutex::new(InjectedSeqTracker::new(
                65536,
                Duration::from_secs(30),
            )),
        })
    }

    pub fn new_api_only(config: ProcessingConfig) -> Self {
        let packet_engine = Arc::new(PacketEngine::new_api_only());
        let desync_group = Arc::new(Self::build_desync_group(&config));

        Self {
            packet_engine,
            fake_ip: Arc::new(FakeIpManager::new(1000)),
            geo_router: Arc::new(GeoRouter::new_default()),
            hop_tab: Arc::new(HopTab::new()),
            conntrack: Arc::new(Conntrack::new(Duration::from_secs(120))),
            desync_group,
            config,
            stats: Arc::new(ProcessingStats::new()),
            injected_seqs: std::sync::Mutex::new(InjectedSeqTracker::new(
                65536,
                Duration::from_secs(30),
            )),
        }
    }

    fn build_desync_group(config: &ProcessingConfig) -> DesyncGroup {
        let mut group = DesyncGroup::new(config.desync.clone());
        if config.techniques.is_empty() {
            group.add(DesyncTechnique::FakeSni);
            group.add(DesyncTechnique::MultiSplit);
            group.add(DesyncTechnique::BadChecksum);
        } else {
            for t in &config.techniques {
                group.add(*t);
            }
        }
        group
    }

    pub async fn run(&self, shutdown: tokio::sync::broadcast::Receiver<()>) {
        debug!("ProcessingPipeline started");

        const QUEUE_SIZE: usize = 65536;
        let ring = std::sync::Arc::new(crossbeam::queue::ArrayQueue::<CapturedPacket>::new(
            QUEUE_SIZE,
        ));
        let ring_tx = ring.clone();
        let ring_rx = ring.clone();

        let engine = self.packet_engine.clone();
        let stats = self.stats.clone();
        let mut shutdown_rx = shutdown.resubscribe();
        let handle = tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; PACKET_BUFFER_SIZE];
            loop {
                if shutdown_rx.try_recv().is_ok() {
                    debug!("WinDivert recv: shutdown signal received");
                    break;
                }
                match engine.recv_blocking(&mut buf) {
                    Ok((data, addr)) => {
                        stats.total_received.fetch_add(1, Ordering::Relaxed);
                        if ring_tx.push(CapturedPacket { data, addr }).is_err() {
                            stats.dropped.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(e) => {
                        error!("WinDivert recv error: {}", e);
                        break;
                    }
                }
            }
        });

        while let Some(captured) = ring_rx.pop() {
            if self.config.event_tag_enabled && event_tag::is_injected_packet(&captured.data) {
                self.stats.injected_skipped.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            match self.process_one(&captured).await {
                Ok(PacketDecision::Forward) => {
                    self.forward_packet(&captured).await;
                }
                Ok(PacketDecision::Modify(modified)) => {
                    if let Err(e) = self.packet_engine.send_blocking(&modified, &captured.addr) {
                        error!("Failed to send modified packet: {}", e);
                        self.stats.errors.fetch_add(1, Ordering::Relaxed);
                    }
                    self.stats.forwarded.fetch_add(1, Ordering::Relaxed);
                }
                Ok(PacketDecision::Desync {
                    inject,
                    inject_protocol,
                }) => {
                    for inject_pkt in &inject {
                        match inject_protocol {
                            InjectProtocol::Tcp => {
                                let mut tagged = inject_pkt.to_vec();
                                if self.config.event_tag_enabled {
                                    event_tag::tag_injected_packet(&mut tagged);
                                }
                                if let Err(e) = self
                                    .packet_engine
                                    .inject_via_divert(&tagged, &captured.addr)
                                {
                                    warn!("Failed to inject TCP desync packet: {}", e);
                                }
                            }
                            InjectProtocol::Udp => {
                                if let Err(e) = self.packet_engine.inject_raw_udp(inject_pkt) {
                                    warn!("Failed to inject UDP desync packet: {}", e);
                                }
                            }
                        }
                        self.stats.fake_ch_injected.fetch_add(1, Ordering::Relaxed);
                    }
                    self.forward_packet(&captured).await;
                }
                Ok(PacketDecision::Drop) => {
                    self.packet_engine.drop_packet();
                    self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    debug!("Packet processing error (forwarding as fallback): {}", e);
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                    self.forward_packet(&captured).await;
                }
            }
        }

        let _ = handle.await;
        debug!("ProcessingPipeline stopped");
    }

    async fn forward_packet(&self, captured: &CapturedPacket) {
        if let Err(e) = self
            .packet_engine
            .send_blocking(&captured.data, &captured.addr)
        {
            error!("Failed to forward packet: {}", e);
            self.stats.errors.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.forwarded.fetch_add(1, Ordering::Relaxed);
        }
    }

    async fn process_one(
        &self,
        captured: &CapturedPacket,
    ) -> Result<PacketDecision, anyhow::Error> {
        let classification = Classifier::classify(&captured.data);

        match classification {
            Classification::Tls(cp) if cp.dst_port == self.config.desync_port => {
                if self.config.only_outbound && !is_outbound(&cp.src_ip) {
                    return Ok(PacketDecision::Forward);
                }
                self.process_outbound_tls(&cp, &captured.data, &captured.addr)
                    .await
            }
            Classification::Quic(cp) => {
                if self.config.only_outbound && !is_outbound(&cp.src_ip) {
                    return Ok(PacketDecision::Forward);
                }
                self.process_quic(&cp, &captured.data).await
            }
            Classification::Dns(_) => Ok(PacketDecision::Forward),
            Classification::Http(cp) => {
                if self.config.only_outbound && !is_outbound(&cp.src_ip) {
                    return Ok(PacketDecision::Forward);
                }
                self.process_http(&cp, &captured.data).await
            }
            _ => Ok(PacketDecision::Forward),
        }
    }

    async fn process_quic(
        &self,
        _cp: &ClassifiedPacket,
        original_packet: &[u8],
    ) -> Result<PacketDecision, anyhow::Error> {
        let packet = bytes::Bytes::copy_from_slice(original_packet);
        let result = self.apply_desync_async(packet).await;
        if result.inject.is_empty() && result.modified.is_none() && !result.drop {
            return Ok(PacketDecision::Forward);
        }
        if result.drop {
            return Ok(PacketDecision::Drop);
        }
        if let Some(modified) = result.modified {
            return Ok(PacketDecision::Modify(modified));
        }
        Ok(PacketDecision::Desync {
            inject: result.inject,
            inject_protocol: InjectProtocol::Udp,
        })
    }

    async fn process_http(
        &self,
        _cp: &ClassifiedPacket,
        original_packet: &[u8],
    ) -> Result<PacketDecision, anyhow::Error> {
        let packet = bytes::Bytes::copy_from_slice(original_packet);
        let result = self.apply_desync_async(packet).await;
        if result.inject.is_empty() && result.modified.is_none() && !result.drop {
            return Ok(PacketDecision::Forward);
        }
        if result.drop {
            return Ok(PacketDecision::Drop);
        }
        if let Some(modified) = result.modified {
            return Ok(PacketDecision::Modify(modified));
        }
        Ok(PacketDecision::Desync {
            inject: result.inject,
            inject_protocol: InjectProtocol::Tcp,
        })
    }

    async fn process_outbound_tls(
        &self,
        cp: &ClassifiedPacket,
        original_packet: &[u8],
        captured_addr: &windivert::prelude::WinDivertAddress<windivert::prelude::NetworkLayer>,
    ) -> Result<PacketDecision, anyhow::Error> {
        self.stats.tls_outbound.fetch_add(1, Ordering::Relaxed);

        // 0. Skip retransmits
        {
            if let Some(ip) = crate::desync::parse_ip_header(original_packet) {
                let tcp_data = &original_packet[ip.header_len..];
                if let Some(tcp) = pnet_packet::tcp::TcpPacket::new(tcp_data) {
                    if self
                        .injected_seqs
                        .lock()
                        .unwrap()
                        .contains(tcp.get_sequence())
                    {
                        return Ok(PacketDecision::Forward);
                    }
                }
            }
        }

        // 1. Reverse DNS lookup
        let domain = self.fake_ip.lookup(&cp.dst_ip);

        // 2. Geo-Routing
        if self.config.geo_routing_enabled {
            let decision = self.geo_router.resolve(
                domain.as_deref().unwrap_or("unknown"),
                Some(std::net::IpAddr::V4(cp.dst_ip)),
            );
            if decision.excluded {
                return Ok(PacketDecision::Forward);
            }
        }

        // 3. HopTab observation
        if self.config.hop_tab_enabled {
            if let Some(ip_packet) = Ipv4Packet::new(original_packet) {
                self.hop_tab
                    .observe(HopTab::ip_to_u32(&cp.dst_ip), ip_packet.get_ttl());
            }
        }

        // 4. Conntrack — create or update (не перезаписываем существующий)
        {
            use crate::conntrack::{ConnKey, ConnState, ConntrackEntry};

            let key = ConnKey::new(cp.src_ip, cp.dst_ip, cp.src_port, cp.dst_port);

            if self.conntrack.get(&key).is_none() {
                let entry = ConntrackEntry {
                    client_isn: 0,
                    server_isn: 0,
                    client_seq: 0,
                    server_seq: 0,
                    client_ack: 0,
                    server_ack: 0,
                    rtt_us: 0,
                    state: ConnState::SynSent,
                    desync_applied: false,
                    strategy_id: 0,
                    last_activity: Instant::now(),
                    dup_ack_count: 0,
                    rng: Some(crate::desync::rand::PerConnRng::new(
                        cp.dst_ip.to_bits() as u64
                    )),
                };
                self.conntrack.insert(key, entry);
            } else {
                if let Some(mut entry) = self.conntrack.get_mut(&key) {
                    entry.last_activity = Instant::now();
                }
            }
        }

        // 5. DesyncGroup
        let packet = bytes::Bytes::copy_from_slice(original_packet);
        let result = self.apply_desync_async(packet).await;

        // 5.1. Запоминаем SEQ
        if !result.inject.is_empty() {
            if let Some(ip) = crate::desync::parse_ip_header(original_packet) {
                let tcp_data = &original_packet[ip.header_len..];
                if let Some(tcp) = pnet_packet::tcp::TcpPacket::new(tcp_data) {
                    self.injected_seqs
                        .lock()
                        .unwrap()
                        .insert(tcp.get_sequence());
                }
            }
        }

        if result.inject.is_empty() && result.modified.is_none() && !result.drop {
            return Ok(PacketDecision::Forward);
        }
        if result.drop {
            return Ok(PacketDecision::Drop);
        }

        if let Some(modified) = result.modified {
            if result.inject.is_empty() {
                return Ok(PacketDecision::Modify(modified));
            }
            for inject_pkt in &result.inject {
                self.inject_tcp_packet(inject_pkt, captured_addr)?;
            }
            return Ok(PacketDecision::Modify(modified));
        }

        Ok(PacketDecision::Desync {
            inject: result.inject,
            inject_protocol: InjectProtocol::Tcp,
        })
    }

    fn inject_tcp_packet(
        &self,
        packet: &[u8],
        addr: &windivert::prelude::WinDivertAddress<windivert::prelude::NetworkLayer>,
    ) -> Result<(), anyhow::Error> {
        let mut tagged = packet.to_vec();
        if self.config.event_tag_enabled {
            event_tag::tag_injected_packet(&mut tagged);
        }
        self.packet_engine
            .inject_via_divert(&tagged, addr)
            .map_err(|e| anyhow::anyhow!("WinDivert inject failed: {}", e))?;
        self.stats.fake_ch_injected.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn has_divert(&self) -> bool {
        self.packet_engine.has_divert()
    }

    async fn apply_desync_async(&self, packet: bytes::Bytes) -> crate::desync::DesyncResult {
        let group = self.desync_group.clone();
        tokio::task::spawn_blocking(move || group.apply(&packet))
            .await
            .unwrap_or_else(|e| {
                tracing::error!("DesyncGroup spawn_blocking failed: {}", e);
                crate::desync::DesyncResult::passthrough()
            })
    }

    pub fn stats(&self) -> &ProcessingStats {
        &self.stats
    }
    pub fn stats_arc(&self) -> Arc<ProcessingStats> {
        self.stats.clone()
    }
    pub fn packet_engine(&self) -> &PacketEngine {
        &self.packet_engine
    }
    pub fn config(&self) -> &ProcessingConfig {
        &self.config
    }
}

struct CapturedPacket {
    data: bytes::Bytes,
    addr: WinDivertAddress<NetworkLayer>,
}

/// Определяет, является ли src_ip "локальным" (outbound).
fn is_outbound(src_ip: &Ipv4Addr) -> bool {
    let octets = src_ip.octets();
    match octets[0] {
        127 => true,
        10 => true,
        172 if octets[1] >= 16 && octets[1] <= 31 => true,
        192 if octets[1] == 168 => true,
        100 if octets[1] >= 64 && octets[1] <= 127 => true, // CGN 100.64.0.0/10
        _ => false,
    }
}

impl Default for ProcessingPipeline {
    fn default() -> Self {
        Self::new_api_only(ProcessingConfig::default())
    }
}
