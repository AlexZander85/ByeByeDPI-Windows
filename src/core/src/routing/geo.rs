//! Geo-Routing Engine — классификация трафика по региону.
//!
//! ## Алгоритм `resolve(domain, ip)`
//! 1. exclude_domains → `RouteDecision::excluded()` (без desync)
//! 2. bad_route_cache → `RouteDecision::fallback()` (пропускаем проблемный egress)
//! 3. `classify(domain, ip)` → `GeoRegion`
//! 4. `build_egress_chain(region)` → `Vec<EgressHop>` для sequential failover
//!
//! ## Классификация
//! | Условие | Регион | Egress |
//! |---------|--------|--------|
//! | ru_domains / ru_cidrs | Russia | Direct(desync) → SOCKS5 |
//! | eu_domains / eu_cidrs | Europe | OperaVPN → Direct(desync) |
//! | us_domains | UnitedStates | UserProxy → Direct(desync) |
//! | Всё остальное | Global | Direct(desync) |
//! | exclude_domains | Excluded | Direct(pass) |
//!
//! ## Источник
//! Адаптировано из [Nova](https://github.com/patrykkalinowski/nova) — geo-routing engine.

use crate::routing::{EgressHop, GeoRegion, RouteDecision};
use dashmap::DashMap;
use dashmap::DashSet;
use ipnet::IpNet;
use moka::sync::Cache;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tracing::debug;

/// Конфигурация GeoRouter.
#[derive(Debug, Clone)]
pub struct GeoRouterConfig {
    /// Время жизни кэша результатов resolve (default: 1 час)
    pub cache_ttl: Duration,
    /// Максимальное количество записей в кэше (default: 10_000)
    pub cache_max_capacity: u64,
    /// Время жизни bad route кэша (default: 5 минут)
    pub bad_route_ttl: Duration,
}

impl Default for GeoRouterConfig {
    fn default() -> Self {
        Self {
            cache_ttl: Duration::from_secs(3600),
            cache_max_capacity: 10_000,
            bad_route_ttl: Duration::from_secs(300),
        }
    }
}

/// Geo-Routing Engine — классификация и маршрутизация трафика по региону.
///
/// ## Потокобезопасность
/// - DashSet для списков доменов (lock-free reads)
/// - DashMap для bad route cache (TTL-based, периодическая очистка)
/// - moka `Cache` (sync) для результатов resolve (concurrent, TTL)
/// - Все операции `&self` — внутренняя синхронизация
///
/// ## Пример
/// ```rust
/// use freedpi_core::routing::geo::GeoRouter;
///
/// let router = GeoRouter::new_default();
/// let decision = router.resolve("yandex.ru", None);
/// assert!(!decision.excluded);
/// assert_eq!(decision.region.name(), "Russia");
/// ```
pub struct GeoRouter {
    /// Российские домены
    ru_domains: DashSet<String>,
    /// Европейские домены
    eu_domains: DashSet<String>,
    /// Американские домены
    us_domains: DashSet<String>,
    /// Исключённые домены (банки, госуслуги)
    exclude_domains: DashSet<String>,
    /// Российские CIDR диапазоны
    ru_cidrs: Vec<IpNet>,
    /// Европейские CIDR диапазоны
    eu_cidrs: Vec<IpNet>,
    /// Кэш результатов resolve (domain → RouteDecision)
    cache: Cache<String, RouteDecision>,
    /// Bad route cache: "domain|ip" → когда истёк
    bad_routes: DashMap<String, Instant>,
    /// TTL для bad route записей
    bad_route_ttl: Duration,
}

impl GeoRouter {
    /// Создаёт новый GeoRouter с настройками и пустыми списками.
    pub fn new(config: GeoRouterConfig) -> Self {
        let cache: Cache<String, RouteDecision> = Cache::builder()
            .max_capacity(config.cache_max_capacity)
            .time_to_live(config.cache_ttl)
            .build();

        Self {
            ru_domains: DashSet::new(),
            eu_domains: DashSet::new(),
            us_domains: DashSet::new(),
            exclude_domains: DashSet::new(),
            ru_cidrs: Vec::new(),
            eu_cidrs: Vec::new(),
            cache,
            bad_routes: DashMap::new(),
            bad_route_ttl: config.bad_route_ttl,
        }
    }

    /// Создаёт GeoRouter с встроенными списками доменов по умолчанию.
    ///
    /// Списки включают наиболее популярные сервисы для каждого региона:
    /// - RU: Yandex, VK, Sberbank, Gosuslugi, Rutube, Ozon, Wildberries и др.
    /// - EU: Netflix, OpenAI, Spotify, Telegram (EU host), Signal, Proton и др.
    /// - US: Google, Facebook, Twitter, Instagram, Reddit, GitHub и др.
    /// - Exclude: банки, госуслуги
    pub fn new_default() -> Self {
        let mut router = Self::new(GeoRouterConfig::default());

        // === Российские домены ===
        for domain in &[
            "yandex.ru", "ya.ru", "dzen.ru", "vk.com", "ok.ru",
            "sberbank.ru", "gosuslugi.ru", "nalog.ru", "cbr.ru",
            "rutube.ru", "kinopoisk.ru", "ivi.ru", "kion.ru",
            "ozon.ru", "wildberries.ru", "market.yandex.ru",
            "avito.ru", "hh.ru", "habr.com", "habr.ru",
            "tass.ru", "ria.ru", "rbc.ru", "kommersant.ru",
            "rosreestr.ru", "pfr.gov.ru", "mos.ru", "spb.ru",
            "mail.ru", "rambler.ru", "lenta.ru", "gazeta.ru",
            "mts.ru", "megafon.ru", "beeline.ru", "tele2.ru",
            "alfabank.ru", "vtb.ru", "gazprombank.ru", "raiffeisen.ru",
            "2gis.ru", "flamp.ru", "pikabu.ru", "drive2.ru",
            "mosreg.ru", "kremlin.ru", "government.ru",
        ] {
            router.ru_domains.insert(domain.to_string());
        }

        // === Европейские домены ===
        for domain in &[
            "netflix.com", "openai.com", "chatgpt.com", "spotify.com",
            "signal.org", "proton.me", "protonmail.com", "protonvpn.com",
            "t.me", "telegram.org", "telegram.me",
            "bbc.co.uk", "bbc.com", "theguardian.com", "dw.com",
            "europa.eu", "europe.eu", "coe.int",
            "booking.com", "airbnb.com", "skyscanner.net",
            "zalando.com", "zalando.de", "aboutyou.de",
            "revolut.com", "wise.com", "n26.com",
            "ing.com", "db.com", "santander.com", "boursorama.com",
            "lemonde.fr", "lefigaro.fr", "spiegel.de", "bild.de",
            "corriere.it", "repubblica.it", "elpais.es",
            "ovh.com", "ovhcloud.com", "hetzner.com", "scaleway.com",
            "github.com", "gitlab.com", "bitbucket.org",
            "deepl.com", "linguee.com", "grammarly.com",
            "telefonica.com", "orange.com", "t-mobile.com",
            "ikea.com", "h&m.com", "zara.com",
        ] {
            router.eu_domains.insert(domain.to_string());
        }

        // === Американские домены ===
        for domain in &[
            "google.com", "facebook.com", "fb.com", "instagram.com",
            "twitter.com", "x.com", "reddit.com",
            "youtube.com", "yt.be", "twitch.tv",
            "amazon.com", "aws.com", "aws.amazon.com",
            "apple.com", "icloud.com", "icloud.co.uk",
            "microsoft.com", "live.com", "outlook.com", "office.com",
            "cloudflare.com", "fastly.com", "akamai.com",
            "vercel.com", "netlify.com", "heroku.com",
            "linkedin.com", "indeed.com", "glassdoor.com",
            "nytimes.com", "wsj.com", "washingtonpost.com",
            "paypal.com", "stripe.com", "square.com",
            "salesforce.com", "hubspot.com", "zendesk.com",
            "atlassian.com", "jira.com", "confluence.com",
            "docker.com", "k8s.io", "kubernetes.io",
            "stackoverflow.com", "medium.com", "quora.com",
            "ebay.com", "etsy.com", "walmart.com",
            "adobe.com", "oracle.com", "ibm.com",
            "intel.com", "nvidia.com", "amd.com",
            "tesla.com", "spacex.com", "starlink.com",
        ] {
            router.us_domains.insert(domain.to_string());
        }

        // === Исключённые домены (без desync) ===
        for domain in &[
            "online.sberbank.ru", "login.vtb.ru", "alfabank.ru",
            "gosuslugi.ru", "lk.gosuslugi.ru",
            "my.mos.ru", "eservices.mos.ru",
            "esia.gosuslugi.ru", "esia-pub.gosuslugi.ru",
        ] {
            router.exclude_domains.insert(domain.to_string());
        }

        // === CIDR диапазоны ===
        router.add_ru_cidr("2a02:6b8::/32");     // Yandex
        router.add_ru_cidr("2a00:1450::/32");     // VK
        router.add_ru_cidr("5.45.192.0/18");      // Yandex
        router.add_ru_cidr("87.240.128.0/18");    // VK
        router.add_ru_cidr("185.12.92.0/22");     // Sberbank
        router.add_ru_cidr("195.208.0.0/14");     // Rostelecom
        router.add_ru_cidr("46.17.200.0/21");     // Beeline
        router.add_ru_cidr("213.59.0.0/16");      // MTS

        router.add_eu_cidr("2a01:4f8::/32");      // Hetzner (DE)
        router.add_eu_cidr("5.9.0.0/16");         // Hetzner (DE)
        router.add_eu_cidr("51.15.0.0/16");       // Scaleway (FR)
        router.add_eu_cidr("54.36.0.0/15");       // OVH (FR)
        router.add_eu_cidr("185.15.64.0/22");     // ProtonVPN (CH)
        router.add_eu_cidr("185.167.238.0/24");   // Opera VPN (EU)

        debug!(
            "GeoRouter initialized: {} RU domains, {} EU domains, {} US domains, \
             {} excl domains, {} RU CIDRs, {} EU CIDRs",
            router.ru_domains.len(),
            router.eu_domains.len(),
            router.us_domains.len(),
            router.exclude_domains.len(),
            router.ru_cidrs.len(),
            router.eu_cidrs.len(),
        );

        router
    }

    // ---- Добавление доменов ----

    /// Добавляет российский домен.
    pub fn add_ru_domain(&self, domain: &str) {
        self.ru_domains.insert(domain.to_string());
    }

    /// Добавляет европейский домен.
    pub fn add_eu_domain(&self, domain: &str) {
        self.eu_domains.insert(domain.to_string());
    }

    /// Добавляет американский домен.
    pub fn add_us_domain(&self, domain: &str) {
        self.us_domains.insert(domain.to_string());
    }

    /// Добавляет домен в exclude список.
    pub fn add_exclude_domain(&self, domain: &str) {
        self.exclude_domains.insert(domain.to_string());
    }

    /// Добавляет российский CIDR диапазон.
    pub fn add_ru_cidr(&mut self, cidr: &str) {
        if let Ok(net) = cidr.parse::<IpNet>() {
            self.ru_cidrs.push(net);
        }
    }

    /// Добавляет европейский CIDR диапазон.
    pub fn add_eu_cidr(&mut self, cidr: &str) {
        if let Ok(net) = cidr.parse::<IpNet>() {
            self.eu_cidrs.push(net);
        }
    }

    // ---- Основной API ----

    /// Полное разрешение маршрута для домена.
    ///
    /// 1. Проверяет кэш — если есть, возвращает сразу
    /// 2. Исключённые домены → `RouteDecision::excluded()`
    /// 3. Bad route → `RouteDecision::fallback()`
    /// 4. Классификация по региону
    /// 5. Построение egress chain
    /// 6. Сохранение в кэш
    pub fn resolve(&self, domain: &str, ip: Option<IpAddr>) -> RouteDecision {
        // Проверка кэша
        if let Some(cached) = self.cache.get(domain) {
            return cached.clone();
        }

        // Проверка exclude
        if self.exclude_domains.contains(domain) {
            return RouteDecision::excluded();
        }

        // Проверка bad route
        match ip {
            Some(ref ip) => {
                let cache_key = format!("{}|{}", domain, ip);
                if self.is_bad_route(&cache_key) {
                    debug!("Bad route: {} → fallback", cache_key);
                    return RouteDecision::fallback();
                }
            }
            None => {
                let cache_key = format!("{}|?", domain);
                if self.is_bad_route(&cache_key) {
                    debug!("Bad route: {} → fallback", cache_key);
                    return RouteDecision::fallback();
                }
            }
        }

        // Классификация
        let region = self.classify(domain, ip);

        // Построение egress chain
        let egress_chain = self.build_egress_chain(region);

        let decision = RouteDecision {
            region,
            egress_chain,
            excluded: false,
        };

        // Сохранение в кэш
        self.cache.insert(domain.to_string(), decision.clone());

        decision
    }

    /// Классифицирует домен/IP в регион.
    ///
    /// Приоритет (первое совпадение):
    /// 1. Российские CIDR (если IP известен)
    /// 2. Российские домены
    /// 3. Европейские CIDR (если IP известен)
    /// 4. Европейские домены
    /// 5. Американские домены
    /// 6. Global
    pub fn classify(&self, domain: &str, ip: Option<IpAddr>) -> GeoRegion {
        // Проверка по IP (CIDR)
        if let Some(ip) = ip {
            if self.ru_cidrs.iter().any(|c| c.contains(&ip)) {
                return GeoRegion::Russia;
            }
            if self.eu_cidrs.iter().any(|c| c.contains(&ip)) {
                return GeoRegion::Europe;
            }
        }

        // Проверка по домену (exact match + subdomain match)
        let lower = domain.to_lowercase();

        if self.ru_domains.contains(&lower) || self.matches_subdomain(&lower, &self.ru_domains) {
            return GeoRegion::Russia;
        }

        if self.eu_domains.contains(&lower) || self.matches_subdomain(&lower, &self.eu_domains) {
            return GeoRegion::Europe;
        }

        if self.us_domains.contains(&lower) || self.matches_subdomain(&lower, &self.us_domains) {
            return GeoRegion::UnitedStates;
        }

        GeoRegion::Global
    }

    /// Строит цепочку egress-попыток для региона.
    pub fn build_egress_chain(&self, region: GeoRegion) -> Vec<EgressHop> {
        match region {
            GeoRegion::Russia => vec![
                EgressHop::direct(),
                EgressHop::socks5("127.0.0.1", 1370),
            ],
            GeoRegion::Europe => vec![
                EgressHop::opera_vpn(),
                EgressHop::direct(),
            ],
            GeoRegion::UnitedStates => vec![
                EgressHop::user_proxy(),
                EgressHop::direct(),
            ],
            GeoRegion::Global | GeoRegion::Excluded => vec![
                EgressHop::direct(),
            ],
        }
    }

    // ---- Bad Route Cache ----

    /// Проверяет, помечен ли маршрут как "bad".
    pub fn is_bad_route(&self, key: &str) -> bool {
        if let Some(expires) = self.bad_routes.get(key) {
            if *expires > Instant::now() {
                return true;
            }
            // TTL истёк — удаляем
            drop(expires);
            self.bad_routes.remove(key);
        }
        false
    }

    /// Помечает маршрут как "bad" на TTL.
    pub fn mark_bad_route(&self, key: &str) {
        let expires = Instant::now() + self.bad_route_ttl;
        self.bad_routes.insert(key.to_string(), expires);
        debug!("Marked bad route: {} (TTL: {:?})", key, self.bad_route_ttl);
    }

    /// Очищает bad route кэш.
    pub fn clear_bad_routes(&self) {
        self.bad_routes.clear();
        debug!("Bad route cache cleared");
    }

    /// Количество записей в bad route кэше.
    pub fn bad_routes_len(&self) -> usize {
        self.bad_routes.len()
    }

    /// Количество записей в кэше resolve.
    pub fn cache_len(&self) -> u64 {
        self.cache.entry_count()
    }

    /// Очищает кэш resolve.
    pub fn clear_cache(&self) {
        self.cache.invalidate_all();
        debug!("GeoRouter resolve cache cleared");
    }

    // ---- Внутренние методы ----

    /// Проверяет, является ли домен subdomain'ом одного из списка.
    ///
    /// `api.yandex.ru` → matches `yandex.ru`
    fn matches_subdomain(&self, domain: &str, list: &DashSet<String>) -> bool {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() < 3 {
            return false;
        }
        // Проверяем parent domain: для "a.b.c.ru" проверяем "b.c.ru" и "c.ru"
        for i in 1..(parts.len() - 1) {
            let parent = parts[i..].join(".");
            if list.contains(&parent) {
                return true;
            }
        }
        false
    }
}
