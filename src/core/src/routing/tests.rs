//! Тесты routing модуля.
//!
//! Покрытие:
//! - geo: classify, resolve, exclude, bad route, CIDR, subdomain match, cache
//! - detect: geo-block (HTTP 403/451), DPI block (RST/timeout)
//! - chain: build_attempts, bad route skip, mark_bad
//! - health: SOCKS5 handshake format (без сети)
//! - opera: proxy list format

use super::*;

// ==================== GeoRegion ====================

#[test]
fn test_geo_region_name() {
    assert_eq!(GeoRegion::Russia.name(), "Russia");
    assert_eq!(GeoRegion::Europe.name(), "Europe");
    assert_eq!(GeoRegion::UnitedStates.name(), "UnitedStates");
    assert_eq!(GeoRegion::Global.name(), "Global");
    assert_eq!(GeoRegion::Excluded.name(), "Excluded");
}

#[test]
fn test_geo_region_serde() {
    let json = serde_json::to_string(&GeoRegion::Russia).unwrap();
    assert_eq!(json, "\"Russia\"");
    let back: GeoRegion = serde_json::from_str(&json).unwrap();
    assert_eq!(back, GeoRegion::Russia);
}

#[test]
fn test_geo_region_hash() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(GeoRegion::Russia);
    set.insert(GeoRegion::Russia);
    assert_eq!(set.len(), 1);
    set.insert(GeoRegion::Europe);
    assert_eq!(set.len(), 2);
}

// ==================== Egress ====================

#[test]
fn test_egress_display() {
    assert_eq!(
        format!("{}", Egress::Direct { desync: true }),
        "Direct(desync)"
    );
    assert_eq!(
        format!("{}", Egress::Direct { desync: false }),
        "Direct(pass)"
    );
    assert_eq!(
        format!(
            "{}",
            Egress::Socks5 {
                host: "127.0.0.1".into(),
                port: 9050
            }
        ),
        "SOCKS5(127.0.0.1:9050)"
    );
    assert_eq!(format!("{}", Egress::OperaVpn), "OperaVPN");
    assert_eq!(format!("{}", Egress::UserProxy), "UserProxy");
}

#[test]
fn test_egress_serde() {
    let egress = Egress::Socks5 {
        host: "127.0.0.1".into(),
        port: 1080,
    };
    let json = serde_json::to_string(&egress).unwrap();
    assert!(json.contains("127.0.0.1"));
    let back: Egress = serde_json::from_str(&json).unwrap();
    assert_eq!(back, egress);
}

// ==================== EgressHop ====================

#[test]
fn test_egress_hop_direct() {
    let hop = EgressHop::direct();
    assert_eq!(hop.egress, Egress::Direct { desync: true });
    assert_eq!(hop.timeout.as_secs(), 5);
}

#[test]
fn test_egress_hop_socks5() {
    let hop = EgressHop::socks5("proxy.example.com", 9050);
    assert_eq!(format!("{}", hop.egress), "SOCKS5(proxy.example.com:9050)");
    assert_eq!(hop.timeout.as_secs(), 10);
}

#[test]
fn test_egress_hop_opera() {
    let hop = EgressHop::opera_vpn();
    assert_eq!(hop.egress, Egress::OperaVpn);
}

// ==================== RouteDecision ====================

#[test]
fn test_route_decision_excluded() {
    let d = RouteDecision::excluded();
    assert!(d.excluded);
    assert_eq!(d.region, GeoRegion::Excluded);
    assert!(!d.needs_desync());
}

#[test]
fn test_route_decision_fallback() {
    let d = RouteDecision::fallback();
    assert!(!d.excluded);
    assert_eq!(d.region, GeoRegion::Global);
    assert!(d.needs_desync());
}

#[test]
fn test_route_decision_needs_desync() {
    let d = RouteDecision {
        region: GeoRegion::Russia,
        egress_chain: vec![EgressHop::direct(), EgressHop::socks5("127.0.0.1", 9050)],
        excluded: false,
    };
    assert!(d.needs_desync());

    let d_pass = RouteDecision {
        region: GeoRegion::Excluded,
        egress_chain: vec![EgressHop {
            egress: Egress::Direct { desync: false },
            timeout: Default::default(),
        }],
        excluded: true,
    };
    assert!(!d_pass.needs_desync());
}

// ==================== GeoRouter ====================

#[test]
fn test_geo_router_classify_russia_by_domain() {
    let router = geo::GeoRouter::new_default();
    assert_eq!(router.classify("yandex.ru", None), GeoRegion::Russia);
    assert_eq!(router.classify("vk.com", None), GeoRegion::Russia);
}

#[test]
fn test_geo_router_classify_europe_by_domain() {
    let router = geo::GeoRouter::new_default();
    assert_eq!(router.classify("netflix.com", None), GeoRegion::Europe);
    assert_eq!(router.classify("openai.com", None), GeoRegion::Europe);
}

#[test]
fn test_geo_router_classify_us_by_domain() {
    let router = geo::GeoRouter::new_default();
    assert_eq!(router.classify("google.com", None), GeoRegion::UnitedStates);
    assert_eq!(
        router.classify("facebook.com", None),
        GeoRegion::UnitedStates
    );
}

#[test]
fn test_geo_router_classify_global() {
    let router = geo::GeoRouter::new_default();
    // Домен, которого нет ни в одном списке
    assert_eq!(
        router.classify("example-unknown.com", None),
        GeoRegion::Global
    );
}

#[test]
fn test_geo_router_classify_by_cidr() {
    let mut router = geo::GeoRouter::new_default();
    router.add_ru_cidr("77.88.0.0/18"); // Yandex IP range
    let ip: std::net::IpAddr = "77.88.55.66".parse().unwrap();
    // yandex.ru уже в RU по домену, но проверяем CIDR для неизвестного домена
    assert_eq!(
        router.classify("unknown-yandex-ip.ru", Some(ip)),
        GeoRegion::Russia
    );
}

#[test]
fn test_geo_router_exclude_domain() {
    let router = geo::GeoRouter::new_default();
    let decision = router.resolve("online.sberbank.ru", None);
    assert!(decision.excluded);
    assert_eq!(decision.region, GeoRegion::Excluded);
}

#[test]
fn test_geo_router_resolve_caching() {
    let router = geo::GeoRouter::new_default();
    // Первый resolve — не кэширован
    let d1 = router.resolve("yandex.ru", None);
    assert_eq!(d1.region, GeoRegion::Russia);
    // Второй раз должен быть из кэша
    let d2 = router.resolve("yandex.ru", None);
    assert_eq!(d2.region, GeoRegion::Russia);
    // Оба решения одинаковы
    assert_eq!(d1.region, d2.region);
    assert_eq!(d1.excluded, d2.excluded);
}

#[test]
fn test_geo_router_bad_route() {
    let router = geo::GeoRouter::new_default();
    let key = "test.ru|1.2.3.4";
    assert!(!router.is_bad_route(key));
    router.mark_bad_route(key);
    assert!(router.is_bad_route(key));
    assert_eq!(router.bad_routes_len(), 1);
}

#[test]
fn test_geo_router_bad_route_makes_fallback() {
    let router = geo::GeoRouter::new_default();
    let domain = "yandex.ru";
    router.mark_bad_route(&format!("{}|{}", domain, "77.88.55.66"));
    // resolve с этим IP должен вернуть fallback
    // (но в resolve сейчас проверка по domain|ip, без IP = None, так что кэш не должен сработать)
    // Очистим кэш чтобы не было фальшивого попадания
    router.clear_cache();
    let decision = router.resolve(domain, Some("77.88.55.66".parse().unwrap()));
    // Если бы wasn't bad route, было бы Russia. Так как bad → fallback → Global
    // Но resolve сначала проверяет exclude, затем bad route по domain|ip
    assert_eq!(decision.region, GeoRegion::Global);
}

#[test]
fn test_geo_router_subdomain_match() {
    let router = geo::GeoRouter::new_default();
    // music.yandex.ru должен определяться как Russia через subdomain match
    let region = router.classify("music.yandex.ru", None);
    assert_eq!(region, GeoRegion::Russia);
}

#[test]
fn test_geo_router_add_domains() {
    let router = geo::GeoRouter::new(Default::default());
    assert_eq!(router.classify("custom.ru", None), GeoRegion::Global);
    router.add_ru_domain("custom.ru");
    assert_eq!(router.classify("custom.ru", None), GeoRegion::Russia);
}

// ==================== GeoBlockDetector ====================

#[test]
fn test_detect_geo_block_403() {
    let response = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
    assert!(detect::GeoBlockDetector::detect_geo_block(response));
}

#[test]
fn test_detect_geo_block_451() {
    let response = b"HTTP/1.1 451 Unavailable For Legal Reasons\r\n\r\n";
    assert!(detect::GeoBlockDetector::detect_geo_block(response));
}

#[test]
fn test_detect_geo_block_200() {
    let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>ok</html>";
    assert!(!detect::GeoBlockDetector::detect_geo_block(response));
}

#[test]
fn test_detect_geo_block_keywords() {
    let response = b"HTTP/1.1 200 OK\r\n\r\nThis content is not available in your region";
    assert!(detect::GeoBlockDetector::detect_geo_block(response));
}

#[test]
fn test_detect_dpi_block_rst() {
    assert!(detect::GeoBlockDetector::detect_dpi_block(
        "connection reset by peer"
    ));
}

#[test]
fn test_detect_dpi_block_timeout() {
    assert!(detect::GeoBlockDetector::detect_dpi_block(
        "connection timed out"
    ));
}

#[test]
fn test_detect_dpi_block_dns_error() {
    // DNS ошибка — не DPI
    assert!(!detect::GeoBlockDetector::detect_dpi_block(
        "no address found"
    ));
}

#[test]
fn test_detect_classify_geo() {
    let result = detect::GeoBlockDetector::classify(
        "connection reset",
        Some(&b"HTTP/1.1 403 Forbidden\r\n\r\n"[..]),
    );
    assert_eq!(result, Some(true)); // geo-block
}

#[test]
fn test_detect_classify_dpi() {
    let result = detect::GeoBlockDetector::classify("connection reset by peer", None);
    assert_eq!(result, Some(false)); // DPI block
}

#[test]
fn test_detect_classify_unknown() {
    let result = detect::GeoBlockDetector::classify("unknown error", None);
    assert_eq!(result, None);
}

// ==================== EgressChain ====================

#[test]
fn test_chain_build_attempts() {
    let chain = chain::EgressChain::new(vec![
        EgressHop::direct(),
        EgressHop::socks5("127.0.0.1", 9050),
    ]);
    let attempts = chain.build_attempts("example.com");
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].hop_index, 0);
    assert_eq!(attempts[1].hop_index, 1);
}

#[test]
fn test_chain_bad_route_skip() {
    let chain = chain::EgressChain::new(vec![
        EgressHop::direct(),
        EgressHop::socks5("127.0.0.1", 9050),
    ]);
    // Маркируем второй hop как bad
    chain.mark_bad("example.com", 1);
    let attempts = chain.build_attempts("example.com");
    // Ожидаем только первый hop (direct)
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].hop_index, 0);
}

#[test]
fn test_chain_all_bad_fallback() {
    let chain = chain::EgressChain::new(vec![EgressHop::direct()]);
    chain.mark_bad("example.com", 0);
    let attempts = chain.build_attempts("example.com");
    // Должен быть fallback direct
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].hop_index, 0);
}

#[test]
fn test_chain_clear_bad_routes() {
    let chain = chain::EgressChain::new(vec![EgressHop::direct()]);
    chain.mark_bad("example.com", 0);
    assert_eq!(chain.bad_routes_len(), 1);
    chain.clear_bad_routes();
    assert_eq!(chain.bad_routes_len(), 0);
}

#[test]
fn test_chain_default() {
    let chain = chain::EgressChain::default();
    assert_eq!(chain.hops_len(), 1);
    let attempts = chain.build_attempts("test.com");
    assert_eq!(attempts.len(), 1);
}

#[test]
fn test_chain_hops_accessor() {
    let chain = chain::EgressChain::new(vec![EgressHop::direct(), EgressHop::opera_vpn()]);
    let hops = chain.hops();
    assert_eq!(hops.len(), 2);
    assert_eq!(format!("{}", hops[1].egress), "OperaVPN");
}

// ==================== HealthChecker ====================

#[test]
fn test_health_checker_initial_state() {
    let checker = health::HealthChecker::new();
    assert_eq!(
        checker.get_status("127.0.0.1", 9050, health::ProxyType::Socks5),
        health::ProxyStatus::Unknown
    );
}

#[test]
fn test_health_checker_add_and_status() {
    let checker = health::HealthChecker::new();
    let result = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let checker = checker;
            checker.add_socks5("127.0.0.1", 9050).await;
            assert_eq!(
                checker.get_status("127.0.0.1", 9050, health::ProxyType::Socks5),
                health::ProxyStatus::Unknown
            );
            assert_eq!(checker.proxy_count().await, 1);
        });
    });
    assert!(result.join().is_ok());
}

#[test]
fn test_health_checker_status_enum() {
    assert_ne!(health::ProxyStatus::Alive, health::ProxyStatus::Dead);
    assert_ne!(health::ProxyStatus::Alive, health::ProxyStatus::Unknown);
    assert_eq!(health::ProxyStatus::Unknown, health::ProxyStatus::Unknown);
}

// ==================== OperaVpnProvider ====================

#[test]
fn test_opera_proxy_list() {
    // Проверяем, что все известные прокси корректны
    let result = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let provider = opera::OperaVpnProvider::new().await;
            assert_eq!(provider.proxy_count(), 5);
            assert!(provider.first_alive().is_none()); // ещё не проверяли здоровье
            assert!(provider.alive_proxies().is_empty());
        });
    });
    assert!(result.join().is_ok());
}

#[test]
fn test_opera_proxy_display() {
    // Проверяем формат OperaProxy
    let proxy = opera::OperaProxy {
        host: "185.167.238.201".to_string(),
        port: 1080,
        location: "Netherlands".to_string(),
        status: health::ProxyStatus::Unknown,
    };
    assert_eq!(proxy.host, "185.167.238.201");
    assert_eq!(proxy.port, 1080);
    assert_eq!(proxy.location, "Netherlands");
}
