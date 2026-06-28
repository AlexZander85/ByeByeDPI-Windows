//! Domain Trie — Patricia trie с wildcard-матчингом (из SpoofDPI).
//!
//! Поддерживает:
//! - `*` — wildcard одного уровня (например `*.google.com`)
//! - `**` — multi-level wildcard (например `**.com`)
//! - Точные совпадения
//! - Специфичность: `www.google.com` > `*.google.com` > `**.com`
//!
//! ## Использование
//! ```rust
//! use freedpi_core::routing::domain_trie::DomainTrie;
//!
//! let mut trie = DomainTrie::new();
//! trie.insert("www.google.com", true);
//! trie.insert("*.youtube.com", false);
//! trie.insert("**.ru", true);
//!
//! assert_eq!(trie.match_domain("www.google.com"), Some(true));
//! assert_eq!(trie.match_domain("m.youtube.com"), Some(false));
//! assert_eq!(trie.match_domain("mail.ru"), Some(true));
//! ```

use std::collections::HashMap;

/// Узел Domain Trie.
#[derive(Debug, Default)]
struct TrieNode {
    /// Дочерние узлы (один уровень домена).
    children: HashMap<String, TrieNode>,
    /// Значение для точного совпадения.
    value: Option<bool>,
    /// Wildcard `*` — совпадает с одним уровнем.
    single_wild: Option<Box<TrieNode>>,
    /// Wildcard `**` — совпадает с несколькими уровнями.
    multi_wild: Option<Box<TrieNode>>,
}

/// Patricia trie для доменных имён с wildcard-матчингом.
pub struct DomainTrie {
    root: TrieNode,
    /// Количество записей (для отладки).
    len: usize,
}

impl std::fmt::Debug for DomainTrie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DomainTrie")
            .field("len", &self.len)
            .finish()
    }
}

impl DomainTrie {
    /// Создаёт пустой trie.
    pub fn new() -> Self {
        Self {
            root: TrieNode::default(),
            len: 0,
        }
    }

    /// Добавляет домен в trie.
    ///
    /// # Arguments
    /// * `domain` — доменное имя (wildcard: `*` = один уровень, `**` = multi)
    /// * `value` — значение (true = bypass DPI, false = direct)
    pub fn insert(&mut self, domain: &str, value: bool) {
        let labels = Self::parse_labels(domain);
        let mut node = &mut self.root;

        for label in &labels {
            match label.as_str() {
                "*" => {
                    if node.single_wild.is_none() {
                        node.single_wild = Some(Box::new(TrieNode::default()));
                    }
                    node = node.single_wild.as_mut().unwrap();
                }
                "**" => {
                    if node.multi_wild.is_none() {
                        node.multi_wild = Some(Box::new(TrieNode::default()));
                    }
                    node = node.multi_wild.as_mut().unwrap();
                }
                _ => {
                    node = node
                        .children
                        .entry(label.clone())
                        .or_default();
                }
            }
        }

        if node.value.is_none() {
            self.len += 1;
        }
        node.value = Some(value);
    }

    /// Ищет домен в trie (с учётом wildcard и специфичности).
    ///
    /// Возвращает `Some(value)` для самого специфичного совпадения.
    pub fn match_domain(&self, domain: &str) -> Option<bool> {
        let labels = Self::parse_labels(domain);
        self.match_recursive(&self.root, &labels, 0, None)
    }

    /// Рекурсивный поиск с учётом wildcard и специфичности.
    ///
    /// Приоритет: точное совпадение дочернего узла > wildcard дочернего узла > inherited.
    fn match_recursive(
        &self,
        node: &TrieNode,
        labels: &[String],
        depth: usize,
        inherited: Option<bool>,
    ) -> Option<bool> {
        let current = node.value.or(inherited);

        if depth >= labels.len() {
            return current;
        }

        let label = &labels[depth];

        // Проверяем точное совпадение ребёнка (самый приоритетный путь)
        if let Some(child) = node.children.get(label) {
            if let Some(result) = self.match_recursive(child, labels, depth + 1, current) {
                return Some(result);
            }
        }

        // Single wildcard `*`
        if let Some(ref wild) = node.single_wild {
            if let Some(result) = self.match_recursive(wild, labels, depth + 1, current) {
                return Some(result);
            }
        }

        // Multi wildcard `**` — пробуем пропустить 1..N уровней
        if let Some(ref wild) = node.multi_wild {
            for skip in 1..=(labels.len() - depth) {
                if let Some(result) = self.match_recursive(wild, labels, depth + skip, current) {
                    return Some(result);
                }
            }
        }

        current
    }

    /// Разбивает домен на labels (в обратном порядке: com → google → www).
    fn parse_labels(domain: &str) -> Vec<String> {
        domain
            .split('.')
            .filter(|s| !s.is_empty())
            .rev()
            .map(|s| s.to_lowercase())
            .collect()
    }

    /// Количество записей в trie.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Пуст ли trie.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for DomainTrie {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let mut trie = DomainTrie::new();
        trie.insert("www.google.com", true);
        assert_eq!(trie.match_domain("www.google.com"), Some(true));
        assert_eq!(trie.match_domain("mail.google.com"), None);
    }

    #[test]
    fn test_single_wildcard() {
        let mut trie = DomainTrie::new();
        trie.insert("*.google.com", true);
        assert_eq!(trie.match_domain("www.google.com"), Some(true));
        assert_eq!(trie.match_domain("mail.google.com"), Some(true));
        assert_eq!(trie.match_domain("google.com"), None);
    }

    #[test]
    fn test_multi_wildcard() {
        let mut trie = DomainTrie::new();
        trie.insert("**.ru", true);
        assert_eq!(trie.match_domain("mail.ru"), Some(true));
        assert_eq!(trie.match_domain("www.mail.ru"), Some(true));
        assert_eq!(trie.match_domain("com"), None);
    }

    #[test]
    fn test_specificity() {
        let mut trie = DomainTrie::new();
        trie.insert("**.com", false); // Общий
        trie.insert("*.google.com", true); // Средний
        trie.insert("www.google.com", false); // Точный

        // Точный > средний > общий
        assert_eq!(trie.match_domain("www.google.com"), Some(false));
        assert_eq!(trie.match_domain("mail.google.com"), Some(true));
        assert_eq!(trie.match_domain("example.com"), Some(false));
    }

    #[test]
    fn test_case_insensitive() {
        let mut trie = DomainTrie::new();
        trie.insert("WWW.GOOGLE.COM", true);
        assert_eq!(trie.match_domain("www.google.com"), Some(true));
        assert_eq!(trie.match_domain("WWW.GOOGLE.COM"), Some(true));
    }

    #[test]
    fn test_len() {
        let mut trie = DomainTrie::new();
        assert_eq!(trie.len(), 0);
        trie.insert("a.com", true);
        assert_eq!(trie.len(), 1);
        trie.insert("b.com", true);
        assert_eq!(trie.len(), 2);
        // Overwrite — len не растёт
        trie.insert("a.com", false);
        assert_eq!(trie.len(), 2);
    }
}
