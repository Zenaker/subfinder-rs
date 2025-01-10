use anyhow::{Context, Result};
use log::{debug, warn};
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use crate::sources::{create_client, is_valid_subdomain};

#[derive(Clone)]
pub struct ChaosSource {
    client: Arc<reqwest::Client>,
    api_keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ChaosResponse {
    subdomains: Vec<String>,
}

impl ChaosSource {
    pub fn new() -> Self {
        Self {
            client: Arc::new(reqwest::Client::builder()
                .user_agent("subfinder-rs")
                .build()
                .expect("Failed to build HTTP client")),
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
            warn!("No Chaos API keys provided, skipping...");
            return Ok(HashSet::new());
        }

        // Use first API key (could be randomized like virustotal if needed)
        let api_key = &self.api_keys[0];

        debug!("Querying Chaos API for domain: {}", domain);
        
        let url = format!(
            "https://dns.projectdiscovery.io/dns/{}/subdomains",
            domain
        );

        let response = match self.client
            .get(&url)
            .header("Authorization", api_key)
            .send()
            .await
        {
            Ok(resp) => {
                if !resp.status().is_success() {
                    errors += 1;
                    warn!("Chaos API returned error status: {}", resp.status());
                    return Ok(HashSet::new());
                }
                resp
            }
            Err(e) => {
                errors += 1;
                warn!("Failed to query Chaos API: {}", e);
                return Ok(HashSet::new());
            }
        };

        let chaos_data: ChaosResponse = match response
            .json()
            .await
        {
            Ok(data) => data,
            Err(e) => {
                errors += 1;
                warn!("Failed to parse Chaos API response: {}", e);
                return Ok(HashSet::new());
            }
        };

        let mut subdomains = HashSet::new();
        for subdomain in chaos_data.subdomains {
            let full_domain = format!("{}.{}", subdomain.trim(), domain);
            let full_domain = full_domain.to_lowercase();
            if is_valid_subdomain(&full_domain, domain) {
                results += 1;
                subdomains.insert(full_domain);
            }
        }

        let elapsed = start_time.elapsed();
        debug!(
            "Chaos finished: {} results, {} errors in {:?}",
            results, errors, elapsed
        );
        Ok(subdomains)
    }
}
