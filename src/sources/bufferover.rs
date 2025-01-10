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
pub struct BufferOverSource {
    client: Arc<Client>,
}

#[derive(Debug, Deserialize)]
struct Response {
    #[serde(rename = "FDNS_A")]
    #[serde(default)]
    records: Vec<String>,
    #[serde(rename = "Meta")]
    meta: Option<Meta>,
}

#[derive(Debug, Deserialize)]
struct Meta {
    #[serde(default)]
    error: String,
}

impl BufferOverSource {
    pub fn new() -> Self {
        Self {
            client: create_client(),
        }
    }

    pub async fn enumerate(&self, domain: &str) -> Result<HashSet<String>> {
        let start_time = Instant::now();
        let mut results = 0;
        let mut errors = 0;

        // Note: BufferOver's dns.bufferover.run service might be deprecated
        debug!("Querying BufferOver for domain: {} (Note: Service might be deprecated)", domain);
        
        let urls = vec![
            format!("https://dns.bufferover.run/dns?q=.{}", domain),
            format!("https://tls.bufferover.run/dns?q=.{}", domain),
        ];

        let mut final_data = None;
        let mut last_error = None;

        'endpoint_loop: for url in &urls {
            let mut retry_count = 0;
            
            while retry_count < MAX_RETRIES {
                if retry_count > 0 {
                    debug!("Retrying BufferOver request to {} (attempt {})", url, retry_count + 1);
                    sleep(RETRY_DELAY).await;
                }

                match self.try_request(url).await {
                    Ok(data) => {
                        final_data = Some(data);
                        break 'endpoint_loop;
                    }
                    Err(e) => {
                        last_error = Some(e);
                        errors += 1;
                        retry_count += 1;
                    }
                }
            }
        }

        let data = match final_data {
            Some(d) => d,
            None => {
                warn!("Failed to query all BufferOver endpoints: {}", 
                    last_error.unwrap_or_else(|| anyhow::anyhow!("Unknown error")));
                return Ok(HashSet::new());
            }
        };


        let mut subdomains = HashSet::new();
        for record in data.records {
            // BufferOver returns records in format "ip,domain"
            if let Some(hostname) = record.split(',').nth(1) {
                let hostname = hostname.to_lowercase();
                if is_valid_subdomain(&hostname, domain) {
                    results += 1;
                    subdomains.insert(hostname);
                }
            }
        }

        let elapsed = start_time.elapsed();
        debug!(
            "BufferOver finished: {} results, {} errors in {:?}",
            results, errors, elapsed
        );
        Ok(subdomains)
    }

    async fn try_request(&self, url: &str) -> Result<Response> {
        let response = self.client
            .get(url)
            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
            .send()
            .await
            .context("Failed to query BufferOver")?;

        let status = response.status();
        if status.is_server_error() {
            return Err(anyhow::anyhow!("BufferOver server error: {}", status));
        }

        if !status.is_success() {
            return Err(anyhow::anyhow!("BufferOver returned error status: {}", status));
        }

        let data: Response = response.json().await
            .context("Failed to parse BufferOver response")?;

        // Check for API errors
        if let Some(meta) = &data.meta {
            if !meta.error.is_empty() {
                return Err(anyhow::anyhow!("BufferOver API error: {}", meta.error));
            }
        }

        Ok(data)
    }
}
