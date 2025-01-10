use anyhow::{Context, Result};
use log::{debug, warn};
use reqwest::Client;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use crate::sources::{create_client, is_valid_subdomain};

#[derive(Clone)]
pub struct RiddlerSource {
    client: Arc<Client>,
}

impl RiddlerSource {
    pub fn new() -> Self {
        Self {
            client: create_client(),
        }
    }

    pub async fn enumerate(&self, domain: &str) -> Result<HashSet<String>> {
        let start_time = Instant::now();
        let mut results = 0;
        let mut errors = 0;

        debug!("Querying Riddler for domain: {}", domain);

        // Try both HTTPS and HTTP endpoints
        let urls = vec![
            format!("https://riddler.io/search/exportcsv?q=pld:{}", domain),
            format!("http://riddler.io/search/exportcsv?q=pld:{}", domain),
        ];

        let mut final_response = None;
        for url in urls {
            let result = self.client
                .get(&url)
                .send()
                .await;
            
            match result {
                Ok(resp) => {
                    if resp.status().is_success() {
                        final_response = Some(resp);
                        break;
                    }
                    debug!("Riddler endpoint {} returned status: {}", url, resp.status());
                }
                Err(e) => {
                    debug!("Failed to query Riddler endpoint {}: {}", url, e);
                }
            }
        }

        let response = match final_response {
            Some(resp) => resp,
            None => {
                errors += 1;
                warn!("Failed to query all Riddler endpoints");
                return Ok(HashSet::new());
            }
        };

        let text = match response.text().await {
            Ok(t) => t,
            Err(e) => {
                errors += 1;
                warn!("Failed to read Riddler response: {}", e);
                return Ok(HashSet::new());
            }
        };

        let mut subdomains = HashSet::new();

        // Process each line of the CSV
        for line in text.lines() {
            let subdomain = line.trim().to_lowercase();
            if !subdomain.is_empty() && is_valid_subdomain(&subdomain, domain) {
                results += 1;
                subdomains.insert(subdomain);
            }
        }

        let elapsed = start_time.elapsed();
        debug!(
            "Riddler finished: {} results, {} errors in {:?}",
            results, errors, elapsed
        );
        Ok(subdomains)
    }
}
