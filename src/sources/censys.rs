use anyhow::{Context, Result};
use log::{debug, warn};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use crate::sources::{create_client, is_valid_subdomain};

#[derive(Clone)]
pub struct CensysSource {
    client: Arc<Client>,
    api_keys: Vec<(String, String)>, // (api_id, api_secret) pairs
}

#[derive(Debug, Deserialize)]
struct CensysResponse {
    results: Vec<CensysResult>,
}

#[derive(Debug, Deserialize)]
struct CensysResult {
    names: Vec<String>,
}

impl CensysSource {
    pub fn new() -> Self {
        Self {
            client: create_client(),
            api_keys: Vec::new(),
        }
    }

    pub fn add_api_keys(&mut self, keys: Vec<(String, String)>) {
        self.api_keys.extend(keys);
    }

    pub async fn enumerate(&self, domain: &str) -> Result<HashSet<String>> {
        let start_time = Instant::now();
        let mut results = 0;
        let mut errors = 0;

        if self.api_keys.is_empty() {
            warn!("No Censys API keys provided, skipping...");
            return Ok(HashSet::new());
        }

        // Use first API key pair (could be randomized like virustotal if needed)
        let (api_id, api_secret) = &self.api_keys[0];

        debug!("Querying Censys API for domain: {}", domain);

        let url = "https://search.censys.io/api/v2/hosts/search";
        let query = format!("names: {}", domain);

        let response = match self.client
            .post(url)
            .basic_auth(api_id, Some(api_secret))
            .json(&serde_json::json!({
                "q": query,
                "per_page": 100,
                "virtual_hosts": "INCLUDE"
            }))
            .send()
            .await
        {
            Ok(resp) => {
                if !resp.status().is_success() {
                    errors += 1;
                    warn!("Censys API returned error status: {}", resp.status());
                    return Ok(HashSet::new());
                }
                resp
            }
            Err(e) => {
                errors += 1;
                warn!("Failed to query Censys API: {}", e);
                return Ok(HashSet::new());
            }
        };

        let censys_data: CensysResponse = match response
            .json()
            .await
        {
            Ok(data) => data,
            Err(e) => {
                errors += 1;
                warn!("Failed to parse Censys API response: {}", e);
                return Ok(HashSet::new());
            }
        };

        let mut subdomains = HashSet::new();
        for result in censys_data.results {
            for name in result.names {
                let name = name.to_lowercase();
                if is_valid_subdomain(&name, domain) {
                    results += 1;
                    subdomains.insert(name);
                }
            }
        }

        let elapsed = start_time.elapsed();
        debug!(
            "Censys finished: {} results, {} errors in {:?}",
            results, errors, elapsed
        );
        Ok(subdomains)
    }
}
