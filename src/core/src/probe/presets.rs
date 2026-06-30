//! Preset domain lists — готовые списки доменов для тестирования DPI.
//!
//! Источник: [ByeByeDPI](https://github.com/nickspaargaren/ByeByeDPI)
//! (proxytest_*.sites файлы)

use serde::{Deserialize, Serialize};

/// Категория списка доменов.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresetCategory {
    Video,
    Messenger,
    Social,
    Cdn,
    General,
    RegionSpecific,
}

/// Встроенный список доменов.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresetDomainList {
    pub id: String,
    pub name: String,
    pub category: PresetCategory,
    pub domains: Vec<String>,
}

/// Все встроенные списки (из ByeByeDPI proxytest_*.sites).
pub fn all_presets() -> Vec<PresetDomainList> {
    vec![
        PresetDomainList {
            id: "youtube".to_string(),
            name: "YouTube".to_string(),
            category: PresetCategory::Video,
            domains: vec![
                "youtube.com".into(),
                "youtu.be".into(),
                "i.ytimg.com".into(),
                "i9.ytimg.com".into(),
                "yt3.ggpht.com".into(),
                "yt4.ggpht.com".into(),
                "googleapis.com".into(),
                "jnn-pa.googleapis.com".into(),
                "googleusercontent.com".into(),
                "signaler-pa.youtube.com".into(),
                "youtubei.googleapis.com".into(),
                "manifest.googlevideo.com".into(),
                "yt3.googleusercontent.com".into(),
            ],
        },
        PresetDomainList {
            id: "googlevideo".to_string(),
            name: "Google Video CDN".to_string(),
            category: PresetCategory::Video,
            domains: vec![
                "rr1---sn-4axm-n8vs.googlevideo.com".into(),
                "rr1---sn-gvnuxaxjvh-o8ge.googlevideo.com".into(),
                "rr1---sn-ug5onuxaxjvh-p3ul.googlevideo.com".into(),
                "rr1---sn-ug5onuxaxjvh-n8v6.googlevideo.com".into(),
                "rr4---sn-q4flrnsl.googlevideo.com".into(),
                "rr10---sn-gvnuxaxjvh-304z.googlevideo.com".into(),
                "rr14---sn-n8v7kn7r.googlevideo.com".into(),
                "rr16---sn-axq7sn76.googlevideo.com".into(),
                "rr1---sn-8ph2xajvh-5xge.googlevideo.com".into(),
                "rr1---sn-gvnuxaxjvh-5gie.googlevideo.com".into(),
                "rr12---sn-gvnuxaxjvh-bvwz.googlevideo.com".into(),
                "rr5---sn-n8v7knez.googlevideo.com".into(),
                "rr1---sn-u5uuxaxjvhg0-ocje.googlevideo.com".into(),
                "rr2---sn-q4fl6ndl.googlevideo.com".into(),
                "rr5---sn-gvnuxaxjvh-n8vk.googlevideo.com".into(),
                "rr4---sn-jvhnu5g-c35d.googlevideo.com".into(),
                "rr1---sn-q4fl6n6y.googlevideo.com".into(),
                "rr2---sn-hgn7ynek.googlevideo.com".into(),
                "rr1---sn-xguxaxjvh-gufl.googlevideo.com".into(),
            ],
        },
        PresetDomainList {
            id: "telegram".to_string(),
            name: "Telegram".to_string(),
            category: PresetCategory::Messenger,
            domains: vec![
                "telegram.org".into(),
                "core.telegram.org".into(),
                "web.telegram.org".into(),
                "webk.telegram.org".into(),
                "my.telegram.org".into(),
                "translations.telegram.org".into(),
                "instantview.telegram.org".into(),
                "blog.telegram.org".into(),
                "comments.telegram.org".into(),
                "verify.telegram.org".into(),
                "login.telegram.org".into(),
                "auth.telegram.org".into(),
                "api.telegram.org".into(),
                "promo.telegram.org".into(),
                "desktop.telegram.org".into(),
                "macos.telegram.org".into(),
                "ios.telegram.org".into(),
                "android.telegram.org".into(),
                "reactions.telegram.org".into(),
                "claims.telegram.org".into(),
                "x.telegram.org".into(),
                "help.telegram.org".into(),
                "docs.telegram.org".into(),
                "schema.telegram.org".into(),
                "dev.telegram.org".into(),
                "contest.telegram.org".into(),
                "premium.telegram.org".into(),
                "settings.telegram.org".into(),
                "qr.telegram.org".into(),
                "stickers.telegram.org".into(),
                "emoji.telegram.org".into(),
                "themes.telegram.org".into(),
                "donate.telegram.org".into(),
                "fragment.telegram.org".into(),
                "ton.telegram.org".into(),
                "wallet.telegram.org".into(),
                "pay.telegram.org".into(),
                "telegram.me".into(),
                "telegram.dog".into(),
                "telegra.ph".into(),
                "telesco.pe".into(),
                "web.telegram.me".into(),
                "zws1.web.telegram.org".into(),
                "zws2.web.telegram.org".into(),
                "zws1.web.telegram.me".into(),
                "zws2.web.telegram.me".into(),
                "venus.web.telegram.org".into(),
                "pluto.web.telegram.org".into(),
                "aurora.web.telegram.org".into(),
                "vesta.web.telegram.org".into(),
                "voice.telegram.org".into(),
                "cdn.telegram.org".into(),
            ],
        },
        PresetDomainList {
            id: "discord".to_string(),
            name: "Discord".to_string(),
            category: PresetCategory::Messenger,
            domains: vec![
                "dis.gd".into(),
                "discord.co".into(),
                "discord.gg".into(),
                "discord.app".into(),
                "discord.com".into(),
                "discord.dev".into(),
                "discord.new".into(),
                "discord.gift".into(),
                "discord.gifts".into(),
                "discord.media".into(),
                "discord.store".into(),
                "discord.design".into(),
                "discordapp.com".into(),
                "discordcdn.com".into(),
                "discordsez.com".into(),
                "discordsays.com".into(),
                "discordmerch.com".into(),
                "discordpartygames.com".into(),
                "discordactivities.com".into(),
                "stable.dl2.discordapp.net".into(),
                "discord-attachments-uploads-prd.storage.googleapis.com".into(),
            ],
        },
        PresetDomainList {
            id: "social".to_string(),
            name: "Social Media".to_string(),
            category: PresetCategory::Social,
            domains: vec![
                "snapchat.com".into(),
                "snap.com".into(),
                "linkedin.com".into(),
                "facebook.com".into(),
                "fb.com".into(),
                "fb.me".into(),
                "fbcdn.net".into(),
                "messenger.com".into(),
                "meta.com".into(),
                "instagram.com".into(),
                "static.cdninstagram.com".into(),
                "proton.me".into(),
                "medium.com".into(),
                "x.com".into(),
                "twitter.com".into(),
                "soundcloud.com".into(),
            ],
        },
        PresetDomainList {
            id: "general".to_string(),
            name: "General".to_string(),
            category: PresetCategory::General,
            domains: vec![
                "rutracker.org".into(),
                "nyaa.si".into(),
                "rutor.org".into(),
                "nnmclub.to".into(),
                "speedtest.net".into(),
                "ookla.com".into(),
            ],
        },
        PresetDomainList {
            id: "cloudflare".to_string(),
            name: "Cloudflare".to_string(),
            category: PresetCategory::Cdn,
            domains: vec![
                "cloudflare.com".into(),
                "cloudflare.net".into(),
                "cloudflarecn.net".into(),
                "cloudflare-ech.com".into(),
            ],
        },
        PresetDomainList {
            id: "turkiye".to_string(),
            name: "Türkiye".to_string(),
            category: PresetCategory::RegionSpecific,
            domains: vec![
                "roblox.com".into(),
                "wattpad.com".into(),
                "pastebin.com".into(),
                "4shared.com".into(),
                "wikileaks.org".into(),
                "bitly.com".into(),
                "cutt.ly".into(),
                "t2m.io".into(),
            ],
        },
    ]
}

/// Получить список по ID.
pub fn get_preset(id: &str) -> Option<PresetDomainList> {
    all_presets().into_iter().find(|l| l.id == id)
}

/// Получить все домены из списков с указанными ID.
pub fn get_domains_by_ids(ids: &[&str]) -> Vec<String> {
    all_presets()
        .into_iter()
        .filter(|l| ids.contains(&l.id.as_str()))
        .flat_map(|l| l.domains)
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect()
}

/// Количество доменов во всех списках.
pub fn total_domain_count() -> usize {
    all_presets().iter().map(|l| l.domains.len()).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_presets_count() {
        let presets = all_presets();
        assert_eq!(presets.len(), 8);
    }

    #[test]
    fn test_get_preset_existing() {
        let yt = get_preset("youtube");
        assert!(yt.is_some());
        assert_eq!(yt.unwrap().name, "YouTube");
    }

    #[test]
    fn test_get_preset_missing() {
        assert!(get_preset("nonexistent").is_none());
    }

    #[test]
    fn test_get_domains_by_ids() {
        let domains = get_domains_by_ids(&["youtube", "cloudflare"]);
        assert!(domains.contains(&"youtube.com".to_string()));
        assert!(domains.contains(&"cloudflare.com".to_string()));
    }

    #[test]
    fn test_telegram_domain_count() {
        let tg = get_preset("telegram").unwrap();
        assert_eq!(tg.domains.len(), 52, "Telegram should have 52 domains");
    }

    #[test]
    fn test_discord_domain_count() {
        let dc = get_preset("discord").unwrap();
        assert_eq!(dc.domains.len(), 21, "Discord should have 21 domains");
    }

    #[test]
    fn test_social_domain_count() {
        let social = get_preset("social").unwrap();
        assert_eq!(social.domains.len(), 16, "Social should have 16 domains");
    }

    #[test]
    fn test_total_domain_count() {
        let count = total_domain_count();
        assert!(count >= 139, "Total should be at least 139 domains, got {}", count);
    }
}
