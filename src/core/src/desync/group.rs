//! DesyncGroup — pipeline и concurrent применение техник.
//!
//! ## Режимы
//! 1. **Pipeline** (по умолчанию): каждая техника видит modified packet предыдущей.
//! 2. **Concurrent**: каждая техника видит оригинальный пакет.

use crate::adaptive::auto_tune::TuneParams;
use crate::desync::{http, ip, obfs, quic, tcp, tls};
use crate::desync::{DesyncConfig, DesyncResult, DesyncTechnique};

/// Override параметры для одного вызова apply() — из AutoTune.
#[derive(Debug, Clone, Default)]
pub struct ConfigOverride {
    pub split_size: Option<usize>,
    pub split_count: Option<usize>,
    pub fake_ttl_offset: Option<u8>,
}

impl From<TuneParams> for ConfigOverride {
    fn from(params: TuneParams) -> Self {
        Self {
            split_size: params.split_size,
            split_count: params.split_count,
            fake_ttl_offset: params.fake_ttl_offset,
        }
    }
}

/// Стейт pipeline — передаётся между техниками.
#[derive(Debug, Clone)]
pub struct PipelineState {
    pub packet: bytes::Bytes,
    cached_payload_offset: Option<usize>,
    cached_tcp_seq: Option<u32>,
    pub injects: Vec<bytes::Bytes>,
    pub drop: bool,
}

impl PipelineState {
    pub fn from_packet(packet: bytes::Bytes) -> Self {
        Self {
            packet,
            cached_payload_offset: None,
            cached_tcp_seq: None,
            injects: Vec::new(),
            drop: false,
        }
    }

    pub fn tcp_payload_offset(&mut self) -> usize {
        *self
            .cached_payload_offset
            .get_or_insert_with(|| Self::find_tcp_payload_offset(&self.packet))
    }

    pub fn tcp_seq(&mut self) -> u32 {
        *self
            .cached_tcp_seq
            .get_or_insert_with(|| Self::extract_tcp_seq(&self.packet))
    }

    pub fn invalidate_header_cache(&mut self) {
        self.cached_payload_offset = None;
        self.cached_tcp_seq = None;
    }

    fn find_tcp_payload_offset(packet: &[u8]) -> usize {
        if packet.len() < 20 {
            return 0;
        }
        let ihl = (packet[0] & 0xF) as usize * 4;
        if packet.len() < ihl + 12 {
            return ihl;
        }
        let tcp_header_len = ((packet[ihl + 12] >> 4) & 0xF) as usize * 4;
        ihl + tcp_header_len
    }

    fn extract_tcp_seq(packet: &[u8]) -> u32 {
        if packet.len() < 20 {
            return 0;
        }
        let ihl = (packet[0] & 0xF) as usize * 4;
        if packet.len() < ihl + 16 {
            return 0;
        }
        u32::from_be_bytes([
            packet[ihl + 4],
            packet[ihl + 5],
            packet[ihl + 6],
            packet[ihl + 7],
        ])
    }

    pub fn into_result(self) -> DesyncResult {
        DesyncResult {
            modified: Some(self.packet),
            inject: self.injects,
            drop: self.drop,
        }
    }
}

pub trait DesyncOp {
    fn apply(&self, state: &mut PipelineState, config: &DesyncConfig);
    fn weight(&self) -> u8 {
        1
    }
}

#[derive(Clone)]
pub struct DesyncGroup {
    config: DesyncConfig,
    techniques: Vec<DesyncTechnique>,
    pipeline_mode: bool,
}

impl DesyncGroup {
    pub fn new(config: DesyncConfig) -> Self {
        Self {
            config,
            techniques: Vec::new(),
            pipeline_mode: true,
        }
    }

    pub fn default_set() -> Self {
        let mut group = Self::new(DesyncConfig::default());
        group.add(DesyncTechnique::FakeSni);
        group.add(DesyncTechnique::MultiSplit);
        group.add(DesyncTechnique::BadChecksum);
        group
    }

    pub fn add(&mut self, technique: DesyncTechnique) {
        self.techniques.push(technique);
    }
    pub fn clear(&mut self) {
        self.techniques.clear();
    }
    pub fn techniques(&self) -> &[DesyncTechnique] {
        &self.techniques
    }
    pub fn set_pipeline_mode(&mut self, enabled: bool) {
        self.pipeline_mode = enabled;
    }

    /// Применяет все техники.
    /// - `dscp_value` — per-connection DSCP для DscpRandom
    /// - `override_params` — переопределения параметров из AutoTune
    pub fn apply(
        &self,
        packet: &bytes::Bytes,
        dscp_value: Option<u8>,
        override_params: Option<ConfigOverride>,
    ) -> DesyncResult {
        if self.pipeline_mode {
            self.apply_pipeline(packet.clone(), dscp_value, override_params)
        } else {
            self.apply_concurrent(packet, dscp_value)
        }
    }

    fn apply_concurrent(&self, packet: &bytes::Bytes, _dscp_value: Option<u8>) -> DesyncResult {
        let mut result = DesyncResult::passthrough();
        for technique in &self.techniques {
            let r = self.apply_single_safe(technique, packet);
            result.merge(r);
        }
        result
    }

    fn apply_pipeline(
        &self,
        packet: bytes::Bytes,
        dscp_value: Option<u8>,
        override_params: Option<ConfigOverride>,
    ) -> DesyncResult {
        let mut state = PipelineState::from_packet(packet);
        for technique in &self.techniques {
            self.apply_to_state(technique, &mut state, dscp_value, override_params.as_ref());
            if state.drop {
                break;
            }
        }
        state.into_result()
    }

    fn apply_to_state(
        &self,
        technique: &DesyncTechnique,
        state: &mut PipelineState,
        dscp_value: Option<u8>,
        override_params: Option<&ConfigOverride>,
    ) {
        // Применяем override параметры если есть, иначе используем config как есть
        let config = override_params.map_or_else(
            || self.config.clone(),
            |p| {
                let mut c = self.config.clone();
                if let Some(v) = p.split_size {
                    c.split_size = v;
                }
                if let Some(v) = p.split_count {
                    c.split_count = v;
                }
                if let Some(v) = p.fake_ttl_offset {
                    c.fake_ttl_offset = v;
                }
                c
            },
        );
        let c = &config;
        match technique {
            DesyncTechnique::FakeSni => {
                let result = tcp::fake_sni(&state.packet, &c.fake_sni, c.fake_ttl_offset);
                self.merge_into_state(state, result);
            }
            DesyncTechnique::MultiSplit => {
                let result = tcp::multisplit(
                    &state.packet,
                    c.split_size,
                    c.split_count,
                    c.fake_ttl_offset,
                );
                state.invalidate_header_cache();
                self.merge_into_state(state, result);
            }
            DesyncTechnique::MultiDisorder => {
                let result = tcp::multidisorder(
                    &state.packet,
                    c.split_size,
                    c.split_count,
                    c.fake_ttl_offset,
                );
                state.invalidate_header_cache();
                self.merge_into_state(state, result);
            }
            DesyncTechnique::Disorder => {
                let result = tcp::disorder(&state.packet, c.split_size, c.fake_ttl_offset);
                state.invalidate_header_cache();
                self.merge_into_state(state, result);
            }
            DesyncTechnique::FakeDataSplit => {
                let result = tcp::fakedsplit(&state.packet, &c.fake_sni, c.fake_ttl_offset);
                state.invalidate_header_cache();
                self.merge_into_state(state, result);
            }
            DesyncTechnique::BadChecksum => {
                // BadChecksum applies ONLY to inject packets, NOT to state.packet.
                // Original packet must keep valid checksum to reach the server.
                state.injects = state
                    .injects
                    .iter()
                    .map(|pkt| {
                        ip::bad_checksum(pkt)
                            .modified
                            .unwrap_or_else(|| pkt.clone())
                    })
                    .collect();
            }
            DesyncTechnique::TtlManipulation => {
                self.merge_into_state(state, ip::ttl_manipulation(&state.packet, 64));
            }
            DesyncTechnique::TlsRecordFrag => {
                self.merge_into_state(
                    state,
                    tls::tls_record_frag(&state.packet, 5, c.fake_ttl_offset),
                );
            }
            DesyncTechnique::SniMasking => {
                tracing::warn!("SniMasking is deprecated — server cannot restore masked SNI. Use FakeSni instead.");
            }
            DesyncTechnique::TlsRecordRewrap => {
                self.merge_into_state(
                    state,
                    tls::tls_record_rewrap(&state.packet, 100, c.fake_ttl_offset),
                );
            }
            DesyncTechnique::TlsVersionSpoof => {
                self.merge_into_state(state, tls::tls_version_overwrite(&state.packet));
            }
            DesyncTechnique::SniRecordFrag => {
                self.merge_into_state(
                    state,
                    tls::sni_record_frag(&state.packet, 2, c.fake_ttl_offset),
                );
            }
            DesyncTechnique::RstDropIpId => {
                self.merge_into_state(state, ip::rst_drop_ip_id(&state.packet));
            }
            DesyncTechnique::DscpRandom => {
                let dscp =
                    dscp_value.unwrap_or_else(|| crate::desync::rand::random_range(0, 48) as u8);
                self.merge_into_state(state, ip::dscp_random(&state.packet, dscp));
            }
            DesyncTechnique::TtlJitter => {
                self.merge_into_state(state, ip::ttl_jitter(&state.packet, None));
            }
            _ => {
                self.merge_into_state(state, self.apply_single_safe(technique, &state.packet));
            }
        }
    }

    fn merge_into_state(&self, state: &mut PipelineState, result: DesyncResult) {
        if let Some(modified) = result.modified {
            state.packet = modified;
            state.invalidate_header_cache();
        }
        state.injects.extend(result.inject);
        if result.drop {
            state.drop = true;
        }
    }

    /// Безопасная обёртка над apply_single — ловит паники.
    fn apply_single_safe(
        &self,
        technique: &DesyncTechnique,
        packet: &bytes::Bytes,
    ) -> DesyncResult {
        use std::panic::AssertUnwindSafe;
        match std::panic::catch_unwind(AssertUnwindSafe(|| self.apply_single(technique, packet))) {
            Ok(result) => result,
            Err(panic) => {
                let msg = panic.downcast_ref::<&str>().unwrap_or(&"unknown panic");
                tracing::error!("Desync technique {:?} panicked: {}", technique.name(), msg);
                DesyncResult::passthrough()
            }
        }
    }

    fn apply_single(&self, technique: &DesyncTechnique, packet: &bytes::Bytes) -> DesyncResult {
        let c = &self.config;
        match technique {
            DesyncTechnique::MultiSplit => {
                tcp::multisplit(packet, c.split_size, c.split_count, c.fake_ttl_offset)
            }
            DesyncTechnique::MultiDisorder => {
                tcp::multidisorder(packet, c.split_size, c.split_count, c.fake_ttl_offset)
            }
            DesyncTechnique::FakeDataSplit => {
                tcp::fakedsplit(packet, &c.fake_sni, c.fake_ttl_offset)
            }
            DesyncTechnique::TcpSeg => tcp::tcpseg(packet, c.max_seg_size, c.fake_ttl_offset),
            DesyncTechnique::SynData => {
                tcp::syndata(packet, &c.fake_sni.as_bytes()[..4], c.fake_ttl_offset)
            }
            DesyncTechnique::WinSize => tcp::winsize(packet, 1024),
            DesyncTechnique::SynHide => tcp::synhide(packet, c.fake_ttl_offset),
            DesyncTechnique::FakeSni => tcp::fake_sni(packet, &c.fake_sni, c.fake_ttl_offset),
            DesyncTechnique::OobInjection => {
                tcp::oob_injection(packet, &c.fake_sni, c.fake_ttl_offset)
            }
            DesyncTechnique::TcpPreopen => tcp::tcp_preopen(packet, c.fake_ttl_offset),
            DesyncTechnique::MssClamp => tcp::mss_clamp(packet, 536, c.fake_ttl_offset),
            DesyncTechnique::AckSuppress => tcp::ack_suppress(packet, 2, c.fake_ttl_offset),
            DesyncTechnique::PktReorder => tcp::pkt_reorder(packet, true),
            DesyncTechnique::RstSelective => tcp::rst_selective(packet, c.fake_ttl_offset),
            DesyncTechnique::SynFloodDecoy => {
                tcp::syn_flood_decoy(packet, 5, &c.fake_sni, c.fake_ttl_offset)
            }
            DesyncTechnique::WinScaleManip => tcp::win_scale_manip(packet, 1024, c.fake_ttl_offset),
            DesyncTechnique::Disorder => tcp::disorder(packet, c.split_size, c.fake_ttl_offset),
            DesyncTechnique::MultidisorderNew => {
                tcp::multidisorder_new(packet, c.split_count, c.fake_ttl_offset)
            }
            DesyncTechnique::Disoob => tcp::disoob(packet, c.fake_ttl_offset),
            DesyncTechnique::HostFake => tcp::hostfake(packet, &c.fake_sni, c.fake_ttl_offset),
            DesyncTechnique::FakeRst => tcp::fakerst(packet, c.fake_ttl_offset),
            DesyncTechnique::ByteByByte => tcp::byte_by_byte(packet, 10, c.fake_ttl_offset),
            DesyncTechnique::UnidirFrag => {
                tcp::unidir_frag(packet, c.split_size, c.fake_ttl_offset)
            }
            DesyncTechnique::PortShuffle => tcp::port_shuffle(packet),
            DesyncTechnique::Wclamp => tcp::wclamp(packet, 1024),
            DesyncTechnique::TsMd5 => tcp::ts_md5(packet, c.fake_ttl_offset),
            DesyncTechnique::FragOverlap => {
                ip::frag_overlap(packet, &c.fake_sni, c.fake_ttl_offset)
            }
            DesyncTechnique::BadChecksum => ip::bad_checksum(packet),
            DesyncTechnique::TtlManipulation => ip::ttl_manipulation(packet, 64),
            DesyncTechnique::IpFragPrimitives => {
                ip::ip_frag_primitives(packet, c.split_size, c.fake_ttl_offset)
            }
            DesyncTechnique::RstDropIpId => ip::rst_drop_ip_id(packet),
            DesyncTechnique::TtlJitter => ip::ttl_jitter(packet, None),
            DesyncTechnique::DscpRandom => {
                let dscp = crate::desync::rand::random_range(0, 48) as u8; // stateless path — random per-packet
                ip::dscp_random(packet, dscp)
            }
            DesyncTechnique::MutualSpoof => ip::mutual_spoof(packet),
            DesyncTechnique::TlsRecordFrag => tls::tls_record_frag(packet, 5, c.fake_ttl_offset),
            DesyncTechnique::TlsRecordPad => tls::tls_record_pad(packet, 32, c.fake_ttl_offset),
            DesyncTechnique::SniMicrofrag => tls::sni_microfrag(packet, 5, c.fake_ttl_offset),
            DesyncTechnique::SniMasking => DesyncResult::passthrough(),
            DesyncTechnique::TlsRecordRewrap => {
                tls::tls_record_rewrap(packet, 100, c.fake_ttl_offset)
            }
            DesyncTechnique::TlsVersionSpoof => tls::tls_version_overwrite(packet),
            DesyncTechnique::SniRecordFrag => tls::sni_record_frag(packet, 2, c.fake_ttl_offset),
            DesyncTechnique::H2SettingsFlood => {
                http::h2_settings_flood(packet, 3, c.fake_ttl_offset)
            }
            DesyncTechnique::H2RstPadding => http::h2_rst_padding(packet, c.fake_ttl_offset),
            DesyncTechnique::H2WindowUpdateFlood => {
                http::h2_window_update_flood(packet, 2, c.fake_ttl_offset)
            }
            DesyncTechnique::H2PriorityAbuse => http::h2_priority_abuse(packet, c.fake_ttl_offset),
            DesyncTechnique::H2Goaway => http::h2_goaway_inject(packet, 1, c.fake_ttl_offset),
            DesyncTechnique::ChunkObfuscation => {
                http::chunk_obfuscation(packet, 3, c.fake_ttl_offset)
            }
            DesyncTechnique::H2FrameOrdering => http::h2_frame_ordering(packet, c.fake_ttl_offset),
            DesyncTechnique::HttpCaseMix => http::http_case_mix(packet),
            DesyncTechnique::Http11Pipeline => {
                http::http11_pipeline(packet, &c.fake_sni, c.fake_ttl_offset)
            }
            DesyncTechnique::ContentLengthFuzz => {
                let fake_len = crate::desync::rand::random_range(100_000, 2_000_000) as usize;
                http::content_length_fuzz(packet, fake_len)
            }
            DesyncTechnique::HttpUpgradeAbuse => http::http_upgrade_abuse(packet),
            DesyncTechnique::QuicBlocking => quic::quic_blocking(packet),
            DesyncTechnique::QuicVersionDowngrade => {
                quic::quic_version_downgrade(packet, 0xFF00001D, c.fake_ttl_offset)
            }
            DesyncTechnique::QuicRetryInject => quic::quic_retry_inject(packet, c.fake_ttl_offset),
            DesyncTechnique::QuicConnectionClose => {
                quic::quic_connection_close(packet, 0x01, c.fake_ttl_offset)
            }
            DesyncTechnique::QuicStreamReset => quic::quic_stream_reset(packet, c.fake_ttl_offset),
            DesyncTechnique::QuicMaxStreams => {
                quic::quic_max_streams(packet, 100, c.fake_ttl_offset)
            }
            DesyncTechnique::Udp2Icmp => obfs::udp2icmp(packet, c.fake_ttl_offset),
            DesyncTechnique::XorFirst => obfs::xor_first(packet, 4, 0xFF),
            DesyncTechnique::WgObfs => obfs::wg_obfs(packet, c.fake_ttl_offset),
            DesyncTechnique::ChaCha20 => {
                tracing::warn!("ChaCha20 with hardcoded key is disabled — broken by design for transparent proxy");
                DesyncResult::passthrough()
            }
            DesyncTechnique::ReverseFragmentOrder => {
                let r = tcp::multisplit(packet, c.split_size, c.split_count, c.fake_ttl_offset);
                tcp::reverse_fragment_order(r)
            }
            DesyncTechnique::HostFakeSplit => {
                tcp::host_fake_split(packet, &c.fake_sni, c.fake_ttl_offset)
            }
            DesyncTechnique::FakeDataDisorder => {
                tcp::fake_data_disorder(packet, c.fake_sni.as_bytes(), c.fake_ttl_offset)
            }
            DesyncTechnique::SynAckSplit => tcp::syn_ack_split(packet),
        }
    }
}

impl Default for DesyncGroup {
    fn default() -> Self {
        Self::default_set()
    }
}
