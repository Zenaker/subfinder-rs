use anyhow::{Context, Result};
use log::{debug, warn};
use reqwest::Client;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use crate::sources::{create_client, is_valid_subdomain, is_html_response};

#[derive(Clone)]
pub struct AnubisSource {
    client: Arc<Client>,
}

impl AnubisSource {
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

        debug!("Querying Anubis for domain: {}", domain);

        let url = format!("https://jldc.me/anubis/subdomains/{}", domain);
        let response = match self.client
            .get(&url)
            .send()
            .await
        {
            Ok(resp) => {
                if !resp.status().is_success() {
                    errors += 1;
                    warn!("Anubis returned error status: {}", resp.status());
                    return Ok(HashSet::new());
                }
                resp
            }
            Err(e) => {
                errors += 1;
                warn!("Failed to query Anubis: {}", e);
                return Ok(HashSet::new());
            }
        };

        let text = match response.text().await {
            Ok(t) => t,
            Err(e) => {
                errors += 1;
                warn!("Failed to read Anubis response: {}", e);
                return Ok(HashSet::new());
            }
        };
        
        let mut subdomains = HashSet::new();

        // Try to parse as JSON first
        match serde_json::from_str::<Vec<String>>(&text) {
            Ok(domains) => {
                for subdomain in domains {
                    let subdomain = subdomain.trim().to_lowercase();
                    if !subdomain.is_empty() && is_valid_subdomain(&subdomain, domain) {
                        results += 1;
                        subdomains.insert(subdomain);
                    }
                }
            }
            Err(_) => {
                // If JSON parsing fails, check if it's HTML
                if is_html_response(&text) {
                    debug!("Received HTML response from Anubis, skipping...");
                    return Ok(subdomains);
                }
                // Otherwise try to parse each line as a potential subdomain
                for line in text.lines() {
                    let line = line.trim().to_lowercase();
                    if !line.is_empty() && is_valid_subdomain(&line, domain) {
                        results += 1;
                        subdomains.insert(line);
                    }
                }
            }
        }

        let elapsed = start_time.elapsed();
        debug!(
            "Anubis finished: {} results, {} errors in {:?}",
            results, errors, elapsed
        );
        Ok(subdomains)
    }
}
