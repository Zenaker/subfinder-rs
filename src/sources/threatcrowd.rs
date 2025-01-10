use anyhow::{Context, Result};
use log::{debug, warn};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;

use crate::sources::{create_client, is_valid_subdomain};

const MAX_RETRIES: u32 = 3;
const RETRY_DELAY: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub struct ThreatCrowdSource {
    client: Arc<Client>,
}

#[derive(Debug, Deserialize)]
struct Response {
    #[serde(default)]
    subdomains: Vec<String>,
    response_code: String,
}

impl ThreatCrowdSource {
    pub fn new() -> Self {
        Self {
            client: create_client(),
        }
    }

    pub async fn enumerate(&self, domain: &str) -> Result<HashSet<String>> {
        let start_time = Instant::now();
        let mut results = 0;
        let mut errors = 0;

        debug!("Querying ThreatCrowd for domain: {}", domain);
        
        let url = format!(
            "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={}",
            domain
        );

        let mut retry_count = 0;
        let mut last_error = None;

        while retry_count < MAX_RETRIES {
            if retry_count > 0 {
                debug!("Retrying ThreatCrowd request (attempt {})", retry_count + 1);
                sleep(RETRY_DELAY).await;
            }

            match self.try_request(&url).await {
                Ok(data) => {
                    let mut subdomains = HashSet::new();
                    if data.response_code == "1" {
                        for hostname in data.subdomains {
                            let hostname = hostname.to_lowercase();
                            if is_valid_subdomain(&hostname, domain) {
                                results += 1;
                                subdomains.insert(hostname);
                            }
                        }
                    }
                    
                    let elapsed = start_time.elapsed();
                    debug!(
                        "ThreatCrowd finished: {} results, {} errors in {:?}",
                        results, errors, elapsed
                    );
                    return Ok(subdomains);
                }
                Err(e) => {
                    last_error = Some(e);
                    errors += 1;
                    retry_count += 1;
                }
            }
        }

        warn!("ThreatCrowd failed after {} retries: {}", MAX_RETRIES, last_error.unwrap_or_else(|| anyhow::anyhow!("Unknown error")));
        Ok(HashSet::new())
    }

    async fn try_request(&self, url: &str) -> Result<Response> {
        let response = self.client
            .get(url)
            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
            .send()
            .await
            .context("Failed to query ThreatCrowd")?;

        let status = response.status();
        if status.is_server_error() {
            return Err(anyhow::anyhow!("ThreatCrowd server error: {}", status));
        }

        if !status.is_success() {
            return Err(anyhow::anyhow!("ThreatCrowd returned error status: {}", status));
        }

        let text = response.text().await
            .context("Failed to read ThreatCrowd response")?;

        serde_json::from_str(&text)
            .context("Failed to parse ThreatCrowd response")
    }
}
