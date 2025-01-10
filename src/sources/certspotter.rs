use anyhow::{Context, Result};
use log::{debug, warn};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use crate::sources::{create_client, is_valid_subdomain};

#[derive(Clone)]
pub struct CertSpotterSource {
    client: Arc<Client>,
    api_keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Certificate {
    id: String,
    dns_names: Vec<String>,
}

impl CertSpotterSource {
    pub fn new() -> Self {
        Self {
            client: Arc::new(Client::builder()
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

        debug!("Querying CertSpotter for domain: {}", domain);

        // Check if API keys are available
        if self.api_keys.is_empty() {
            warn!("No CertSpotter API keys provided, skipping...");
            return Ok(HashSet::new());
        }

        // Use first API key (could be randomized like virustotal if needed)
        let api_key = &self.api_keys[0];

        let mut subdomains = HashSet::new();
        let mut after_id = None;

        loop {
            let mut url = format!(
                "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names",
                domain
            );

            if let Some(id) = &after_id {
                url.push_str(&format!("&after={}", id));
            }

            let response = match self.client
                .get(&url)
                .header("Authorization", format!("Bearer {}", api_key))
                .send()
                .await
            {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        errors += 1;
                        warn!("CertSpotter API returned error status: {}", resp.status());
                        break;
                    }
                    resp
                }
                Err(e) => {
                    errors += 1;
                    warn!("Failed to query CertSpotter: {}", e);
                    break;
                }
            };

            let certificates: Vec<Certificate> = match response.json().await {
                Ok(certs) => certs,
                Err(e) => {
                    errors += 1;
                    warn!("Failed to parse CertSpotter response: {}", e);
                    break;
                }
            };

            if certificates.is_empty() {
                break;
            }

            for cert in &certificates {
                for hostname in &cert.dns_names {
                    let hostname = hostname.to_lowercase();
                    if is_valid_subdomain(&hostname, domain) {
                        results += 1;
                        subdomains.insert(hostname);
                    }
                }
            }

            // Get the ID of the last certificate for pagination
            after_id = certificates.last().map(|cert| cert.id.clone());
        }

        let elapsed = start_time.elapsed();
        debug!(
            "CertSpotter finished: {} results, {} errors in {:?}",
            results, errors, elapsed
        );
        Ok(subdomains)
    }
}
