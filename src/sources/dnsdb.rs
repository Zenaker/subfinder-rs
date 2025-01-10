use anyhow::{Context, Result};
use log::{debug, warn};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use crate::sources::{create_client, is_valid_subdomain};

#[derive(Clone)]
pub struct DNSDBSource {
    client: Arc<Client>,
    api_keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct DNSDBResponse {
    rrname: String,
}

impl DNSDBSource {
    pub fn new() -> Self {
        Self {
            client: create_client(),
            api_keys: Vec::new(),
        }
    }

    pub fn add_api_keys(&mut self, keys: Vec<String>) {
        self.api_keys.extend(keys);
    }

    pub async fn enumerate(&self, domain: &str) -> Result<HashSet<String>> {
        let start_time = Instant::now();
        let mut results = 0;
        let mut errors = 0;

        if self.api_keys.is_empty() {
            warn!("No DNSDB API keys provided, skipping...");
            return Ok(HashSet::new());
        }

        // Use first API key (could be randomized like virustotal if needed)
        let api_key = &self.api_keys[0];

        debug!("Querying DNSDB API for domain: {}", domain);

        let url = format!(
            "https://api.dnsdb.info/lookup/rrset/name/*.{}*/ANY",
            domain
        );

        let response = match self.client
            .get(&url)
            .header("X-API-Key", api_key)
            .header("Accept", "application/json")
            .send()
            .await
        {
            Ok(resp) => {
                if !resp.status().is_success() {
                    errors += 1;
                    warn!("DNSDB API returned error status: {}", resp.status());
                    return Ok(HashSet::new());
                }
                resp
            }
            Err(e) => {
                errors += 1;
                warn!("Failed to query DNSDB API: {}", e);
                return Ok(HashSet::new());
            }
        };

        let text = match response.text().await {
            Ok(t) => t,
            Err(e) => {
                errors += 1;
                warn!("Failed to read DNSDB response: {}", e);
                return Ok(HashSet::new());
            }
        };

        let mut subdomains = HashSet::new();

        // DNSDB returns one JSON object per line
        for line in text.lines() {
            if let Ok(record) = serde_json::from_str::<DNSDBResponse>(line) {
                let subdomain = record.rrname
                    .trim_end_matches('.')
                    .trim_start_matches("*.")
                    .to_lowercase();
                if is_valid_subdomain(&subdomain, domain) {
                    results += 1;
                    subdomains.insert(subdomain);
                }
            }
        }

        let elapsed = start_time.elapsed();
        debug!(
            "DNSDB finished: {} results, {} errors in {:?}",
            results, errors, elapsed
        );
        Ok(subdomains)
    }
}
