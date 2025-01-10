use anyhow::{Context, Result};
use log::{debug, warn};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use crate::sources::{create_client, is_valid_subdomain};

#[derive(Clone)]
pub struct AlienVaultSource {
    client: Arc<Client>,
}

#[derive(Debug, Deserialize)]
struct Response {
    passive_dns: Vec<PassiveDNS>,
}

#[derive(Debug, Deserialize)]
struct PassiveDNS {
    hostname: String,
}

impl AlienVaultSource {
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

        debug!("Querying AlienVault for domain: {}", domain);
        
        let url = format!(
            "https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns",
            domain
        );

        let response = match self.client
            .get(&url)
            .send()
            .await
        {
            Ok(resp) => {
                if !resp.status().is_success() {
                    errors += 1;
                    warn!("AlienVault returned error status: {}", resp.status());
                    return Ok(HashSet::new());
                }
                resp
            }
            Err(e) => {
                errors += 1;
                warn!("Failed to query AlienVault: {}", e);
                return Ok(HashSet::new());
            }
        };

        let data: Response = match response
            .json()
            .await
        {
            Ok(d) => d,
            Err(e) => {
                errors += 1;
                warn!("Failed to parse AlienVault response: {}", e);
                return Ok(HashSet::new());
            }
        };

        let mut subdomains = HashSet::new();
        for entry in data.passive_dns {
            let hostname = entry.hostname.to_lowercase();
            if is_valid_subdomain(&hostname, domain) {
                results += 1;
                subdomains.insert(hostname);
            }
        }

        let elapsed = start_time.elapsed();
        debug!(
            "AlienVault finished: {} results, {} errors in {:?}",
            results, errors, elapsed
        );
        Ok(subdomains)
    }
}
