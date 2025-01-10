use anyhow::{Context, Result};
use log::{debug, warn};
use rand::seq::SliceRandom;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use crate::sources::create_client;

#[derive(Clone)]
pub struct VirusTotalSource {
    client: Arc<Client>,
    api_keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Response {
    data: Vec<SubdomainData>,
    meta: Meta,
}

#[derive(Debug, Deserialize)]
struct SubdomainData {
    id: String,
}

#[derive(Debug, Deserialize)]
struct Meta {
    cursor: Option<String>,
}

impl VirusTotalSource {
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

        debug!("Querying VirusTotal for domain: {}", domain);

        // Check if API keys are available
        if self.api_keys.is_empty() {
            warn!("No VirusTotal API keys provided, skipping...");
            return Ok(HashSet::new());
        }

        // Randomly select an API key
        let api_key = self.api_keys.choose(&mut rand::thread_rng())
            .context("Failed to select API key")?;

        let mut subdomains = HashSet::new();
        let mut cursor = None;

        loop {
            let mut url = format!(
                "https://www.virustotal.com/api/v3/domains/{}/subdomains?limit=1000",
                domain
            );

            if let Some(cur) = &cursor {
                url.push_str(&format!("&cursor={}", cur));
            }

            let response = match self.client
                .get(&url)
                .header("x-apikey", api_key)
                .send()
                .await
            {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        errors += 1;
                        warn!("VirusTotal API returned error status: {}", resp.status());
                        break;
                    }
                    resp
                }
                Err(e) => {
                    errors += 1;
                    warn!("Failed to query VirusTotal: {}", e);
                    break;
                }
            };

            let data: Response = match response.json().await {
                Ok(d) => d,
                Err(e) => {
                    errors += 1;
                    warn!("Failed to parse VirusTotal response: {}", e);
                    break;
                }
            };

            for entry in data.data {
                // VirusTotal returns full subdomain names
                if entry.id.ends_with(domain) {
                    let subdomain = entry.id.trim_end_matches(domain).trim_end_matches('.');
                    if !subdomain.is_empty() {
                        results += 1;
                        subdomains.insert(format!("{}.{}", subdomain.to_lowercase(), domain));
                    }
                }
            }

            // Check if there are more pages
            cursor = data.meta.cursor;
            if cursor.is_none() {
                break;
            }
        }

        let elapsed = start_time.elapsed();
        debug!(
            "VirusTotal finished: {} results, {} errors in {:?}",
            results, errors, elapsed
        );
        Ok(subdomains)
    }
}
