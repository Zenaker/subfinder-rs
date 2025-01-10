use anyhow::{Context, Result};
use log::{debug, warn};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;
use url::Url;

use crate::sources::{create_client, is_valid_subdomain};

#[derive(Clone)]
pub struct WebArchiveSource {
    client: Arc<Client>,
}

#[derive(Debug, Deserialize)]
struct WaybackResponse {
    archived_snapshots: ArchivedSnapshots,
}

#[derive(Debug, Deserialize)]
struct ArchivedSnapshots {
    closest: Option<Snapshot>,
}

#[derive(Debug, Deserialize)]
struct Snapshot {
    url: String,
}

impl WebArchiveSource {
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

        debug!("Querying web archive for domain: {}", domain);
        
        let url = format!(
            "https://archive.org/wayback/available?url={}&timestamp=*",
            domain
        );

        // Use optimized connection settings
        let response = match self.client
            .get(&url)
            .header("Connection", "keep-alive")
            .header("Keep-Alive", "timeout=60")
            .header("Accept", "application/json")
            .header("Accept-Language", "en-US,en;q=0.9")
            .send()
            .await
        {
            Ok(resp) => {
                if !resp.status().is_success() {
                    errors += 1;
                    warn!("Web Archive returned error status: {}", resp.status());
                    return Ok(HashSet::new());
                }
                resp
            }
            Err(e) => {
                errors += 1;
                warn!("Failed to query web archive: {}", e);
                return Ok(HashSet::new());
            }
        };

        let wayback_data: WaybackResponse = match response
            .json()
            .await
        {
            Ok(data) => data,
            Err(e) => {
                errors += 1;
                warn!("Failed to parse web archive response: {}", e);
                return Ok(HashSet::new());
            }
        };

        let mut subdomains = HashSet::new();
        if let Some(snapshot) = wayback_data.archived_snapshots.closest {
            if let Ok(url) = Url::parse(&snapshot.url) {
                if let Some(host) = url.host_str() {
                    let host = host.to_lowercase();
                    if is_valid_subdomain(&host, domain) {
                        results += 1;
                        subdomains.insert(host);
                    }
                }
            }
        }

        let elapsed = start_time.elapsed();
        debug!(
            "Web Archive finished: {} results, {} errors in {:?}",
            results, errors, elapsed
        );
        Ok(subdomains)
    }
}
