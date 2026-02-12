use crate::storage::PasswordEntry;

/// Configuration for search behavior
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct SearchConfig {
    pub case_sensitive: bool,
    pub search_title: bool,
    pub search_username: bool,
    #[allow(dead_code)]
    pub search_url: bool, // Future field
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            case_sensitive: false,
            search_title: true,
            search_username: true,
            search_url: false,
        }
    }
}

/// Search password entries based on query and configuration
/// 
/// Returns indices of matching entries to avoid timing attacks
/// that could leak information about entry count
#[must_use]
pub fn search_entries(
    entries: &[PasswordEntry],
    query: &str,
    config: &SearchConfig,
) -> Vec<usize> {
    // Empty query returns all entries
    if query.is_empty() {
        return (0..entries.len()).collect();
    }

    let query = if config.case_sensitive {
        query.to_string()
    } else {
        query.to_lowercase()
    };

    entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| {
            let matches_title = if config.search_title {
                let title = if config.case_sensitive {
                    entry.title.clone()
                } else {
                    entry.title.to_lowercase()
                };
                title.contains(&query)
            } else {
                false
            };

            let matches_username = if config.search_username {
                let username = if config.case_sensitive {
                    entry.username.clone()
                } else {
                    entry.username.to_lowercase()
                };
                username.contains(&query)
            } else {
                false
            };

            matches_title || matches_username
        })
        .map(|(idx, _)| idx)
        .collect()
}

/// Sort criteria for password entries
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortCriteria {
    TitleAscending,
    TitleDescending,
    DateCreatedNewest,
    DateCreatedOldest,
    UsernameAscending,
}

/// Sort entries by different criteria in-place
pub fn sort_entries(entries: &mut [PasswordEntry], criteria: SortCriteria) {
    match criteria {
        SortCriteria::TitleAscending => {
            entries.sort_by(|a, b| a.title.cmp(&b.title));
        }
        SortCriteria::TitleDescending => {
            entries.sort_by(|a, b| b.title.cmp(&a.title));
        }
        SortCriteria::DateCreatedNewest => {
            entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        }
        SortCriteria::DateCreatedOldest => {
            entries.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        }
        SortCriteria::UsernameAscending => {
            entries.sort_by(|a, b| a.username.cmp(&b.username));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_entry(title: &str, username: &str, password: &str, created_at: u64) -> PasswordEntry {
        PasswordEntry {
            title: title.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            created_at,
        }
    }

    #[test]
    fn test_search_empty_query_returns_all() {
        let entries = vec![
            create_test_entry("Gmail", "user@gmail.com", "pass1", 1000),
            create_test_entry("GitHub", "gituser", "pass2", 2000),
        ];

        let config = SearchConfig::default();
        let results = search_entries(&entries, "", &config);

        assert_eq!(results, vec![0, 1]);
    }

    #[test]
    fn test_search_case_insensitive() {
        let entries = vec![
            create_test_entry("Gmail", "user@gmail.com", "pass1", 1000),
            create_test_entry("GitHub", "gituser", "pass2", 2000),
        ];

        let config = SearchConfig::default();
        let results = search_entries(&entries, "gmail", &config);

        assert_eq!(results, vec![0]);
    }

    #[test]
    fn test_search_case_sensitive() {
        let entries = vec![
            create_test_entry("Gmail", "user@example.com", "pass1", 1000),
            create_test_entry("GitHub", "gituser", "pass2", 2000),
        ];

        let config = SearchConfig {
            case_sensitive: true,
            ..Default::default()
        };
        let results = search_entries(&entries, "gmail", &config);

        assert_eq!(results.len(), 0);

        let results = search_entries(&entries, "Gmail", &config);
        assert_eq!(results, vec![0]);
    }

    #[test]
    fn test_search_by_username() {
        let entries = vec![
            create_test_entry("Gmail", "user@gmail.com", "pass1", 1000),
            create_test_entry("GitHub", "gituser", "pass2", 2000),
        ];

        let config = SearchConfig::default();
        let results = search_entries(&entries, "gituser", &config);

        assert_eq!(results, vec![1]);
    }

    #[test]
    fn test_search_multiple_matches() {
        let entries = vec![
            create_test_entry("Gmail Work", "work@gmail.com", "pass1", 1000),
            create_test_entry("Gmail Personal", "personal@gmail.com", "pass2", 2000),
            create_test_entry("GitHub", "gituser", "pass3", 3000),
        ];

        let config = SearchConfig::default();
        let results = search_entries(&entries, "gmail", &config);

        assert_eq!(results, vec![0, 1]);
    }

    #[test]
    fn test_search_no_matches() {
        let entries = vec![
            create_test_entry("Gmail", "user@gmail.com", "pass1", 1000),
            create_test_entry("GitHub", "gituser", "pass2", 2000),
        ];

        let config = SearchConfig::default();
        let results = search_entries(&entries, "nonexistent", &config);

        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_search_special_characters() {
        let entries = vec![
            create_test_entry("Email@Work", "user+tag@example.com", "pass1", 1000),
            create_test_entry("Test-Site", "admin", "pass2", 2000),
        ];

        let config = SearchConfig::default();
        let results = search_entries(&entries, "@", &config);

        assert_eq!(results, vec![0]);

        let results = search_entries(&entries, "-", &config);
        assert_eq!(results, vec![1]);
    }

    #[test]
    fn test_sort_title_ascending() {
        let mut entries = vec![
            create_test_entry("Zebra", "user1", "pass1", 1000),
            create_test_entry("Apple", "user2", "pass2", 2000),
            create_test_entry("Mango", "user3", "pass3", 3000),
        ];

        sort_entries(&mut entries, SortCriteria::TitleAscending);

        assert_eq!(entries[0].title, "Apple");
        assert_eq!(entries[1].title, "Mango");
        assert_eq!(entries[2].title, "Zebra");
    }

    #[test]
    fn test_sort_title_descending() {
        let mut entries = vec![
            create_test_entry("Apple", "user1", "pass1", 1000),
            create_test_entry("Zebra", "user2", "pass2", 2000),
            create_test_entry("Mango", "user3", "pass3", 3000),
        ];

        sort_entries(&mut entries, SortCriteria::TitleDescending);

        assert_eq!(entries[0].title, "Zebra");
        assert_eq!(entries[1].title, "Mango");
        assert_eq!(entries[2].title, "Apple");
    }

    #[test]
    fn test_sort_date_newest() {
        let mut entries = vec![
            create_test_entry("Site1", "user1", "pass1", 1000),
            create_test_entry("Site2", "user2", "pass2", 3000),
            create_test_entry("Site3", "user3", "pass3", 2000),
        ];

        sort_entries(&mut entries, SortCriteria::DateCreatedNewest);

        assert_eq!(entries[0].created_at, 3000);
        assert_eq!(entries[1].created_at, 2000);
        assert_eq!(entries[2].created_at, 1000);
    }

    #[test]
    fn test_sort_date_oldest() {
        let mut entries = vec![
            create_test_entry("Site1", "user1", "pass1", 3000),
            create_test_entry("Site2", "user2", "pass2", 1000),
            create_test_entry("Site3", "user3", "pass3", 2000),
        ];

        sort_entries(&mut entries, SortCriteria::DateCreatedOldest);

        assert_eq!(entries[0].created_at, 1000);
        assert_eq!(entries[1].created_at, 2000);
        assert_eq!(entries[2].created_at, 3000);
    }

    #[test]
    fn test_sort_username_ascending() {
        let mut entries = vec![
            create_test_entry("Site1", "zuser", "pass1", 1000),
            create_test_entry("Site2", "auser", "pass2", 2000),
            create_test_entry("Site3", "muser", "pass3", 3000),
        ];

        sort_entries(&mut entries, SortCriteria::UsernameAscending);

        assert_eq!(entries[0].username, "auser");
        assert_eq!(entries[1].username, "muser");
        assert_eq!(entries[2].username, "zuser");
    }

    #[test]
    fn test_search_only_title() {
        let entries = vec![
            create_test_entry("Gmail", "otheruser", "pass1", 1000),
            create_test_entry("GitHub", "gmail_user", "pass2", 2000),
        ];

        let config = SearchConfig {
            search_username: false,
            ..Default::default()
        };
        let results = search_entries(&entries, "gmail", &config);

        assert_eq!(results, vec![0]); // Only matches title, not username
    }

    #[test]
    fn test_search_only_username() {
        let entries = vec![
            create_test_entry("Gmail", "testuser", "pass1", 1000),
            create_test_entry("GitHub", "gmail_user", "pass2", 2000),
        ];

        let config = SearchConfig {
            search_title: false,
            ..Default::default()
        };
        let results = search_entries(&entries, "gmail", &config);

        assert_eq!(results, vec![1]); // Only matches username, not title
    }
}
