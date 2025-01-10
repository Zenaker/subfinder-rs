use anyhow::{Context, Result};
use log::{debug, warn};
use reqwest::Client;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use crate::sources::{create_client, is_valid_subdomain};

#[derive(Clone)]
pub struct HackerTargetSource {
    client: Arc<Client>,
}

impl HackerTargetSource {
    pub fn new() -> Self {
        Self {
            client: Arc::new(Client::builder()
                .user_agent("subfinder-rs")
                .build()
                .expect("Failed to build HTTP client")),
        }
    }

    pub async fn enumerate(&self, domain: &str) -> Result<HashSet<String>> {
        let start_time = Instant::now();
        let mut results = 0;
        let mut errors = 0;

        debug!("Querying HackerTarget for domain: {}", domain);

        let url = format!("https://api.hackertarget.com/hostsearch/?q={}", domain);
        let response = match self.client.get(&url).send().await {
            Ok(resp) => {
                if !resp.status().is_success() {
                    errors += 1;
                    warn!("HackerTarget returned error status: {}", resp.status());
                    return Ok(HashSet::new());
                }
                resp
            }
            Err(e) => {
                errors += 1;
                warn!("Failed to query HackerTarget: {}", e);
                return Ok(HashSet::new());
            }
        };

        let text = match response.text().await {
            Ok(t) => t,
            Err(e) => {
                errors += 1;
                warn!("Failed to read HackerTarget response: {}", e);
                return Ok(HashSet::new());
            }
        };

        let mut subdomains = HashSet::new();

        // Process each line which contains subdomain,ip format
        for line in text.lines() {
            if line.is_empty() || line.contains("API count exceeded") {
                continue;
            }
            // Extract subdomain from the line (format: subdomain,ip)
            if let Some(subdomain) = line.split(',').next() {
                let subdomain = subdomain.trim().to_lowercase();
                if is_valid_subdomain(&subdomain, domain) {
                    results += 1;
                    subdomains.insert(subdomain);
                }
            }
        }

        let elapsed = start_time.elapsed();
        debug!(
            "HackerTarget finished: {} results, {} errors in {:?}",
            results, errors, elapsed
        );
        Ok(subdomains)
    }
}
