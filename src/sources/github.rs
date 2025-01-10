use anyhow::{Context, Result};
use log::{debug, warn};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use crate::sources::{create_client, is_valid_subdomain};

#[derive(Clone)]
pub struct GitHubSource {
    client: Arc<Client>,
    api_keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubSearchResponse {
    items: Vec<GitHubItem>,
}

#[derive(Debug, Deserialize)]
struct GitHubItem {
    text_matches: Option<Vec<TextMatch>>,
}

#[derive(Debug, Deserialize)]
struct TextMatch {
    fragment: String,
}

impl GitHubSource {
    pub fn new() -> Self {
        Self {
            client: create_client(),
            api_keys: Vec::new(),
        }
    }

    pub fn add_api_keys(&mut self, keys: Vec<String>) {
        self.api_keys.extend(keys);
    }

    fn extract_subdomains(&self, text: &str, domain: &str) -> HashSet<String> {
        let mut subdomains = HashSet::new();
        
        // Match potential subdomains using basic pattern
        for word in text.split_whitespace() {
            let word = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != '-')
                .to_lowercase();
            if !word.is_empty() && is_valid_subdomain(&word, domain) {
                subdomains.insert(word);
            }
        }
        
        subdomains
    }

    pub async fn enumerate(&self, domain: &str) -> Result<HashSet<String>> {
        let start_time = Instant::now();
        let mut results = 0;
        let mut errors = 0;

        if self.api_keys.is_empty() {
            warn!("No GitHub API keys provided, skipping...");
            return Ok(HashSet::new());
        }

        // Use first API key (could be randomized like virustotal if needed)
        let api_key = &self.api_keys[0];

        debug!("Querying GitHub API for domain: {}", domain);

        let query = format!("{}+in:file", domain);
        let url = format!(
            "https://api.github.com/search/code?q={}&per_page=100",
            query
        );

        let response = match self.client
            .get(&url)
            .header("Authorization", format!("token {}", api_key))
            .header("Accept", "application/vnd.github.v3.text-match+json")
            .send()
            .await
        {
            Ok(resp) => {
                if !resp.status().is_success() {
                    errors += 1;
                    warn!("GitHub API returned error status: {}", resp.status());
                    return Ok(HashSet::new());
                }
                resp
            }
            Err(e) => {
                errors += 1;
                warn!("Failed to query GitHub API: {}", e);
                return Ok(HashSet::new());
            }
        };

        let search_results: GitHubSearchResponse = match response
            .json()
            .await
        {
            Ok(data) => data,
            Err(e) => {
                errors += 1;
                warn!("Failed to parse GitHub API response: {}", e);
                return Ok(HashSet::new());
            }
        };

        let mut subdomains = HashSet::new();
        for item in search_results.items {
            if let Some(matches) = item.text_matches {
                for text_match in matches {
                    let found = self.extract_subdomains(&text_match.fragment, domain);
                    results += found.len();
                    subdomains.extend(found);
                }
            }
        }

        let elapsed = start_time.elapsed();
        debug!(
            "GitHub finished: {} results, {} errors in {:?}",
            results, errors, elapsed
        );
        Ok(subdomains)
    }
}
