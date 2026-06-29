//! Desync Engine — DPI-bypass техники (ядро ByeDPI).
//!
//! ## Архитектура
//!
//! ```text
//! DesyncEngine (dispatcher)
//!   ├── TCP техники (tcp.rs)     — multisplit, multidisorder, fakedsplit, ...
//!   ├── IP техники (ip.rs)       — frag_overlap, badsum, ttl_manip, ...
//!   ├── TLS техники (tls.rs)     — tls_frag, record_padding, ...
//!   └── DesyncGroup (group.rs)   — pipeline применения нескольких техник
//! ```
//!
//! ## DesyncResult
//! Каждая техника возвращает:
//! - `modified` — изменённый оригинальный пакет (для WinDivert send)
//! - `inject` — дополнительные пакеты для инъекции (raw socket)
//!
//! ## Источники
//! - [zapret](https://github.com/bol-van/zapret) — TCP desync (Z1-Z10)
//! - [byedpi](https://github.com/hufrea/byedpi) — OOB, fake SNI (03-05)
//! - [dpibreak](https://github.com/hufrea/dpibreak) — W series
//! - [sni-spoofing-rust](https://github.com/HirbodBehnam/sni-spoofing-rust) — SEQ Spoof

pub mod crypto;
pub mod group;
pub mod http;
pub mod ip;
pub mod obfs;
pub mod quic;
pub mod rand;
pub mod segment_plan;
pub mod tcp;
pub mod tls;

use pnet_packet::ip::IpNextHeaderProtocol;
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_packet::MutablePacket;
use std::net::Ipv4Addr;

/// Результат применения desync техники.
///
/// ## Zero-Copy
/// Использует `bytes::Bytes` для zero-copy semantics:
/// - `Bytes::clone()` увеличивает ref count (не копирует данные)
/// - `Bytes::slice()` создаёт sub-slice без копирования
/// - Копирование происходит ТОЛЬКО при модификации IP/TCP header
#[derive(Debug, Clone)]
pub struct DesyncResult {
    /// Модифицированный оригинальный пакет (для отправки через WinDivert).
    pub modified: Option<bytes::Bytes>,
    /// Дополнительные пакеты для инъекции.
    pub inject: Vec<bytes::Bytes>,
    /// Дропнуть пакет (не отправлять).
    pub drop: bool,
}

impl DesyncResult {
    pub fn passthrough() -> Self {
        Self {
            modified: None,
            inject: Vec::new(),
            drop: false,
        }
    }

    pub fn modified_only(modified: impl Into<bytes::Bytes>) -> Self {
        Self {
            modified: Some(modified.into()),
            inject: Vec::new(),
            drop: false,
        }
    }

    pub fn inject_only(inject: impl Into<bytes::Bytes>) -> Self {
        Self {
            modified: None,
            inject: vec![inject.into()],
            drop: false,
        }
    }

    pub fn modify_and_inject(
        modified: impl Into<bytes::Bytes>,
        inject: impl Into<bytes::Bytes>,
    ) -> Self {
        Self {
            modified: Some(modified.into()),
            inject: vec![inject.into()],
            drop: false,
        }
    }

    pub fn inject_many(inject: Vec<bytes::Bytes>) -> Self {
        Self {
            modified: None,
            inject,
            drop: false,
        }
    }

    pub fn drop_packet() -> Self {
        Self {
            modified: None,
            inject: Vec::new(),
            drop: true,
        }
    }

    /// Объединяет два результата с detection конфликтов.
    pub fn merge(&mut self, other: Self) {
        if other.modified.is_some() {
            if self.modified.is_some() {
                tracing::warn!("DesyncResult::merge: conflict — two techniques modified the packet, last writer wins");
            }
            self.modified = other.modified;
        }
        self.inject.extend(other.inject);
        if other.drop {
            self.drop = true;
        }
    }

    /// Modified как &[u8] (zero-copy через Deref).
    pub fn modified_slice(&self) -> Option<&[u8]> {
        self.modified.as_ref().map(|b| b.as_ref())
    }

    /// Inject как срез Bytes (zero-copy через Deref).
    pub fn inject_slices(&self) -> &[bytes::Bytes] {
        &self.inject
    }
}

/// Тип desync техники.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum DesyncTechnique {
    // === TCP (P0-P3) ===
    MultiSplit,
    MultiDisorder,
    HostFakeSplit,
    FakeDataSplit,
    FakeDataDisorder,
    TcpSeg,
    SynData,
    SynAckSplit,
    WinSize,
    SynHide,
    FakeSni,
    OobInjection,
    // === P3 TCP ===
    TcpPreopen,
    MssClamp,
    AckSuppress,
    PktReorder,
    RstSelective,
    SynFloodDecoy,
    WinScaleManip,
    Disorder,
    MultidisorderNew,
    Disoob,
    HostFake,
    FakeRst,
    ByteByByte,
    UnidirFrag,
    PortShuffle,
    Wclamp,
    TsMd5,
    // === IP ===
    FragOverlap,
    BadChecksum,
    TtlManipulation,
    IpFragPrimitives,
    RstDropIpId,
    TtlJitter,
    DscpRandom,
    MutualSpoof,
    // === TLS ===
    TlsRecordFrag,
    TlsRecordPad,
    SniMasking,
    SniMicrofrag,
    TlsRecordRewrap,
    TlsVersionSpoof,
    SniRecordFrag,
    // === HTTP (P4) ===
    H2SettingsFlood,
    H2RstPadding,
    H2WindowUpdateFlood,
    H2PriorityAbuse,
    H2Goaway,
    ChunkObfuscation,
    H2FrameOrdering,
    Http11Pipeline,
    ContentLengthFuzz,
    HttpUpgradeAbuse,
    HttpCaseMix,
    // === QUIC (P5) ===
    QuicBlocking,
    QuicVersionDowngrade,
    QuicRetryInject,
    QuicConnectionClose,
    QuicStreamReset,
    QuicMaxStreams,
    // === Obfs/Crypto (P6) ===
    Udp2Icmp,
    XorFirst,
    WgObfs,
    ChaCha20,
    // === Composite ===
    ReverseFragmentOrder,
}

impl DesyncTechnique {
    pub fn name(&self) -> &'static str {
        match self {
            Self::MultiSplit => "MultiSplit",
            Self::MultiDisorder => "MultiDisorder",
            Self::HostFakeSplit => "HostFakeSplit",
            Self::FakeDataSplit => "FakeDataSplit",
            Self::FakeDataDisorder => "FakeDataDisorder",
            Self::TcpSeg => "TcpSeg",
            Self::SynData => "SynData",
            Self::SynAckSplit => "SynAckSplit",
            Self::WinSize => "WinSize",
            Self::SynHide => "SynHide",
            Self::FakeSni => "FakeSni",
            Self::OobInjection => "OobInjection",
            Self::TcpPreopen => "TcpPreopen",
            Self::MssClamp => "MssClamp",
            Self::AckSuppress => "AckSuppress",
            Self::PktReorder => "PktReorder",
            Self::RstSelective => "RstSelective",
            Self::SynFloodDecoy => "SynFloodDecoy",
            Self::WinScaleManip => "WinScaleManip",
            Self::Disorder => "Disorder",
            Self::MultidisorderNew => "MultidisorderNew",
            Self::Disoob => "Disoob",
            Self::HostFake => "HostFake",
            Self::FakeRst => "FakeRst",
            Self::ByteByByte => "ByteByByte",
            Self::UnidirFrag => "UnidirFrag",
            Self::PortShuffle => "PortShuffle",
            Self::Wclamp => "Wclamp",
            Self::TsMd5 => "TsMd5",
            Self::FragOverlap => "FragOverlap",
            Self::BadChecksum => "BadChecksum",
            Self::TtlManipulation => "TtlManipulation",
            Self::IpFragPrimitives => "IpFragPrimitives",
            Self::RstDropIpId => "RstDropIpId",
            Self::TtlJitter => "TtlJitter",
            Self::DscpRandom => "DscpRandom",
            Self::MutualSpoof => "MutualSpoof",
            Self::TlsRecordFrag => "TlsRecordFrag",
            Self::TlsRecordPad => "TlsRecordPad",
            Self::SniMasking => "SniMasking",
            Self::SniMicrofrag => "SniMicrofrag",
            Self::TlsRecordRewrap => "TlsRecordRewrap",
            Self::TlsVersionSpoof => "TlsVersionSpoof",
            Self::SniRecordFrag => "SniRecordFrag",
            Self::H2SettingsFlood => "H2SettingsFlood",
            Self::H2RstPadding => "H2RstPadding",
            Self::H2WindowUpdateFlood => "H2WindowUpdateFlood",
            Self::H2PriorityAbuse => "H2PriorityAbuse",
            Self::H2Goaway => "H2Goaway",
            Self::ChunkObfuscation => "ChunkObfuscation",
            Self::H2FrameOrdering => "H2FrameOrdering",
            Self::Http11Pipeline => "Http11Pipeline",
            Self::ContentLengthFuzz => "ContentLengthFuzz",
            Self::HttpUpgradeAbuse => "HttpUpgradeAbuse",
            Self::HttpCaseMix => "HttpCaseMix",
            Self::QuicBlocking => "QuicBlocking",
            Self::QuicVersionDowngrade => "QuicVersionDowngrade",
            Self::QuicRetryInject => "QuicRetryInject",
            Self::QuicConnectionClose => "QuicConnectionClose",
            Self::QuicStreamReset => "QuicStreamReset",
            Self::QuicMaxStreams => "QuicMaxStreams",
            Self::Udp2Icmp => "Udp2Icmp",
            Self::XorFirst => "XorFirst",
            Self::WgObfs => "WgObfs",
            Self::ChaCha20 => "ChaCha20",
            Self::ReverseFragmentOrder => "ReverseFragmentOrder",
        }
    }

    pub fn source(&self) -> &'static str {
        match self {
            Self::MultiSplit => "zapret",
            Self::MultiDisorder => "zapret",
            Self::HostFakeSplit => "zapret",
            Self::FakeDataSplit => "zapret",
            Self::FakeDataDisorder => "zapret",
            Self::TcpSeg => "zapret",
            Self::SynData => "zapret",
            Self::SynAckSplit => "zapret",
            Self::WinSize => "zapret",
            Self::SynHide => "zapret",
            Self::FakeSni => "byedpi",
            Self::OobInjection => "byedpi",
            Self::TcpPreopen => "byedpi",
            Self::MssClamp => "dpibreak",
            Self::AckSuppress => "dpibreak",
            Self::PktReorder => "dpibreak",
            Self::RstSelective => "dpibreak",
            Self::SynFloodDecoy => "dpibreak",
            Self::WinScaleManip => "dpibreak",
            Self::Disorder => "RIPDPI",
            Self::MultidisorderNew => "RIPDPI",
            Self::Disoob => "RIPDPI",
            Self::HostFake => "RIPDPI",
            Self::FakeRst => "RIPDPI",
            Self::ByteByByte => "rust-no-dpi-socks",
            Self::UnidirFrag => "rust-no-dpi-socks",
            Self::PortShuffle => "CandyTunnel",
            Self::Wclamp => "RIPDPI",
            Self::TsMd5 => "RIPDPI",
            Self::FragOverlap => "dpibreak",
            Self::BadChecksum => "zapret",
            Self::TtlManipulation => "zapret",
            Self::IpFragPrimitives => "zapret",
            Self::RstDropIpId => "offveil",
            Self::TtlJitter => "CandyTunnel",
            Self::DscpRandom => "CandyTunnel",
            Self::MutualSpoof => "CandyTunnel",
            Self::TlsRecordFrag => "zapret",
            Self::TlsRecordPad => "zapret",
            Self::SniMasking => "offveil",
            Self::SniMicrofrag => "omoikane",
            Self::TlsRecordRewrap => "greentunnel",
            Self::TlsVersionSpoof => "demergi",
            Self::SniRecordFrag => "nodpi",
            Self::H2SettingsFlood => "NaiveProxy",
            Self::H2RstPadding => "NaiveProxy",
            Self::H2WindowUpdateFlood => "NaiveProxy",
            Self::H2PriorityAbuse => "NaiveProxy",
            Self::H2Goaway => "NaiveProxy",
            Self::ChunkObfuscation => "b4",
            Self::H2FrameOrdering => "RIPDPI",
            Self::Http11Pipeline => "byedpi",
            Self::ContentLengthFuzz => "byedpi",
            Self::HttpUpgradeAbuse => "byedpi",
            Self::HttpCaseMix => "demergi",
            Self::QuicBlocking => "zapret",
            Self::QuicVersionDowngrade => "zapret",
            Self::QuicRetryInject => "zapret",
            Self::QuicConnectionClose => "zapret",
            Self::QuicStreamReset => "zapret",
            Self::QuicMaxStreams => "zapret",
            Self::Udp2Icmp => "zapret",
            Self::XorFirst => "dpimyass",
            Self::WgObfs => "zapret",
            Self::ChaCha20 => "CandyTunnel",
            Self::ReverseFragmentOrder => "offveil",
        }
    }

    pub fn category(&self) -> TechniqueCategory {
        match self {
            Self::MultiSplit
            | Self::MultiDisorder
            | Self::HostFakeSplit
            | Self::FakeDataSplit
            | Self::FakeDataDisorder
            | Self::TcpSeg
            | Self::SynData
            | Self::SynAckSplit
            | Self::WinSize
            | Self::SynHide
            | Self::FakeSni
            | Self::OobInjection
            | Self::TcpPreopen
            | Self::MssClamp
            | Self::AckSuppress
            | Self::PktReorder
            | Self::RstSelective
            | Self::SynFloodDecoy
            | Self::WinScaleManip
            | Self::Disorder
            | Self::MultidisorderNew
            | Self::Disoob
            | Self::HostFake
            | Self::FakeRst
            | Self::ByteByByte
            | Self::UnidirFrag
            | Self::PortShuffle
            | Self::Wclamp
            | Self::TsMd5 => TechniqueCategory::Tcp,
            Self::FragOverlap
            | Self::BadChecksum
            | Self::TtlManipulation
            | Self::IpFragPrimitives
            | Self::RstDropIpId
            | Self::TtlJitter
            | Self::DscpRandom
            | Self::MutualSpoof
            | Self::ReverseFragmentOrder => TechniqueCategory::Ip,
            Self::TlsRecordFrag
            | Self::TlsRecordPad
            | Self::SniMasking
            | Self::SniMicrofrag
            | Self::TlsRecordRewrap
            | Self::TlsVersionSpoof
            | Self::SniRecordFrag => TechniqueCategory::Tls,
            Self::H2SettingsFlood
            | Self::H2RstPadding
            | Self::H2WindowUpdateFlood
            | Self::H2PriorityAbuse
            | Self::H2Goaway
            | Self::ChunkObfuscation
            | Self::H2FrameOrdering
            | Self::Http11Pipeline
            | Self::ContentLengthFuzz
            | Self::HttpUpgradeAbuse
            | Self::HttpCaseMix => TechniqueCategory::Http,
            Self::QuicBlocking
            | Self::QuicVersionDowngrade
            | Self::QuicRetryInject
            | Self::QuicConnectionClose
            | Self::QuicStreamReset
            | Self::QuicMaxStreams
            | Self::Udp2Icmp => TechniqueCategory::Quic,
            Self::XorFirst | Self::WgObfs => TechniqueCategory::Obfs,
            Self::ChaCha20 => TechniqueCategory::Crypto,
        }
    }
}

/// Категория desync техники.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TechniqueCategory {
    Tcp,
    Ip,
    Tls,
    Http,
    Quic,
    Obfs,
    Crypto,
}

/// Единая конфигурация Desync Engine.
#[derive(Debug, Clone)]
pub struct DesyncConfig {
    /// Fake SNI для инъекции
    pub fake_sni: String,
    /// Размер сплита (байт) — для split-техник
    pub split_size: usize,
    /// Количество сегментов для multisplit
    pub split_count: usize,
    /// Максимальный размер сегмента для TcpSeg
    pub max_seg_size: usize,
    /// Использовать bad checksum для fake пакетов
    pub bad_checksum: bool,
    /// TTL offset для fake пакетов (обычно 1 — на 1 меньше реального)
    pub fake_ttl_offset: u8,
    /// Задержка между инъекциями (мкс)
    pub inject_delay_us: u64,
    /// Количество PRNG вызовов между reseed'ами.
    /// 0 = отключено (для benchmarking).
    /// 8192 = рекомендуется для production (~10ms при 844K pps).
    pub reseed_interval: u64,
}

impl Default for DesyncConfig {
    fn default() -> Self {
        Self {
            fake_sni: "www.google.com".to_string(),
            split_size: 1,
            split_count: 3,
            max_seg_size: 10,
            bad_checksum: false,
            fake_ttl_offset: 1,
            inject_delay_us: 1000,
            reseed_interval: 8192,
        }
    }
}

/// Вспомогательная функция: вычисляет IP checksum.
/// Корректно обрабатывает IP headers любой длины (включая IP options).
pub fn ipv4_checksum(header: &[u8]) -> u16 {
    debug_assert!(header.len() >= 20);
    let ihl = (header[0] & 0x0F) as usize * 4;
    let header = &header[..ihl.min(header.len())];
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    if !header.len().is_multiple_of(2) {
        sum += (header[header.len() - 1] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Вспомогательная функция: вычисляет TCP checksum.
pub fn tcp_checksum_v4(src: Ipv4Addr, dst: Ipv4Addr, segment: &[u8]) -> u16 {
    use pnet_packet::util;
    util::ipv4_checksum(
        segment,
        8,
        &[],
        &src,
        &dst,
        pnet_packet::ip::IpNextHeaderProtocols::Tcp,
    )
}

/// Парсит IP header для извлечения полей.
pub fn parse_ip_header(packet: &[u8]) -> Option<ParsedIpHeader> {
    let ip = pnet_packet::ipv4::Ipv4Packet::new(packet)?;
    Some(ParsedIpHeader {
        src: ip.get_source(),
        dst: ip.get_destination(),
        protocol: ip.get_next_level_protocol(),
        identification: ip.get_identification(),
        ttl: ip.get_ttl(),
        header_len: (ip.get_header_length() as usize) * 4,
        total_len: ip.get_total_length() as usize,
    })
}

/// Распарсенный IP header.
#[derive(Debug, Clone)]
pub struct ParsedIpHeader {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: IpNextHeaderProtocol,
    pub identification: u16,
    pub ttl: u8,
    pub header_len: usize,
    pub total_len: usize,
}

/// Парсит TCP пакет (payload после IP header).
pub fn parse_tcp_packet(packet: &[u8]) -> Option<ParsedTcpPacket<'_>> {
    let tcp = pnet_packet::tcp::TcpPacket::new(packet)?;
    let data_offset = tcp.get_data_offset() as usize * 4;
    Some(ParsedTcpPacket {
        src_port: tcp.get_source(),
        dst_port: tcp.get_destination(),
        sequence: tcp.get_sequence(),
        acknowledgment: tcp.get_acknowledgement(),
        flags: tcp.get_flags(),
        window: tcp.get_window(),
        data_offset,
        payload: packet.get(data_offset..)?,
        urg_ptr: tcp.get_urgent_ptr(),
    })
}

/// Распарсенный TCP packet (payload без IP header).
#[derive(Debug, Clone)]
pub struct ParsedTcpPacket<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub sequence: u32,
    pub acknowledgment: u32,
    pub flags: u8,
    pub window: u16,
    pub data_offset: usize,
    pub payload: &'a [u8],
    pub urg_ptr: u16,
}

/// Строит новый IP пакет (zero-copy: возвращает Bytes).
pub fn build_ip_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: IpNextHeaderProtocol,
    ttl: u8,
    identification: u16,
    payload: &[u8],
) -> bytes::Bytes {
    let total_len = 20 + payload.len();
    let mut buf = bytes::BytesMut::with_capacity(total_len);
    buf.resize(total_len, 0);

    {
        let mut ip = MutableIpv4Packet::new(&mut buf).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(total_len as u16);
        ip.set_identification(identification);
        ip.set_flags(0);
        ip.set_fragment_offset(0);
        ip.set_ttl(ttl);
        ip.set_next_level_protocol(protocol);
        ip.set_source(src);
        ip.set_destination(dst);
        ip.payload_mut().copy_from_slice(payload);
    }

    let checksum = ipv4_checksum(&buf[..20]);
    buf[10..12].copy_from_slice(&checksum.to_be_bytes());
    buf.freeze()
}
