use anyhow::{Context, Result};
use log::{debug, warn};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use crate::sources::{create_client, is_valid_subdomain};

#[derive(Clone)]
pub struct CrtShSource {
    client: Arc<Client>,
}

#[derive(Debug, Deserialize)]
struct CrtShEntry {
    #[serde(rename = "name_value")]
    name_value: Option<String>,
    #[serde(rename = "common_name")]
    common_name: Option<String>,
}

impl CrtShSource {
    pub fn new() -> Self {
        Self {
            client: create_client(),
        }
    }

    fn process_name(&self, name: &str, domain: &str, subdomains: &mut HashSet<String>) -> usize {
        let mut count = 0;
        for name in name.split('\n') {
            let name = name.trim()
                .trim_start_matches("*.")
                .trim_start_matches('.')
                .to_lowercase();
            
            if !name.is_empty() && is_valid_subdomain(&name, domain) {
                count += 1;
                subdomains.insert(name);
            }
        }
        count
    }

    pub async fn enumerate(&self, domain: &str) -> Result<HashSet<String>> {
        let start_time = Instant::now();
        let mut results = 0;
        let mut errors = 0;

        debug!("Querying crt.sh for domain: {}", domain);
        
        let url = format!(
            "https://crt.sh/?q=%.{}&output=json",
            domain
        );

        // Use connection pooling and keep-alive
        let response = match self.client
            .get(&url)
            .header("Connection", "keep-alive")
            .header("Keep-Alive", "timeout=60")
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                errors += 1;
                warn!("Failed to query crt.sh: {}", e);
                return Ok(HashSet::new());
            }
        };

        // First get the response text
        let text = match response.text().await {
            Ok(t) => t,
            Err(e) => {
                errors += 1;
                warn!("Failed to read crt.sh response: {}", e);
                return Ok(HashSet::new());
            }
        };

        // Try to parse as JSON
        let entries: Vec<CrtShEntry> = match serde_json::from_str(&text) {
            Ok(e) => e,
            Err(e) => {
                errors += 1;
                warn!("Failed to parse crt.sh response: {} (Response: {})", e, text);
                return Ok(HashSet::new());
            }
        };

        let mut subdomains = HashSet::new();
        for entry in entries {
            if let Some(name) = entry.name_value {
                results += self.process_name(&name, domain, &mut subdomains);
            }
            if let Some(name) = entry.common_name {
                results += self.process_name(&name, domain, &mut subdomains);
            }
        }

        let elapsed = start_time.elapsed();
        debug!(
            "crt.sh finished: {} results, {} errors in {:?}",
            results, errors, elapsed
        );
        Ok(subdomains)
    }
}
