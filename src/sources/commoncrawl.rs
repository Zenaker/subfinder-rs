use anyhow::{Context, Result};
use log::{debug, warn};
use reqwest::Client;
use serde::Deserialize;
use std::collections::{HashSet, HashMap};
use std::sync::Arc;
use std::time::Instant;
use url::Url;
use chrono::{Datelike, Utc};

use crate::sources::{create_client, is_valid_subdomain};

const MAX_YEARS_BACK: i32 = 5;

#[derive(Clone)]
pub struct CommonCrawlSource {
    client: Arc<Client>,
}

#[derive(Debug, Deserialize)]
struct CommonCrawlIndex {
    id: String,
    #[serde(rename = "cdx-api")]
    api_url: String,
}

impl CommonCrawlSource {
    pub fn new() -> Self {
        Self {
            client: create_client(),
        }
    }

    pub async fn enumerate(&self, domain: &str) -> Result<HashSet<String>> {
        let start_time = Instant::now();
        let mut results = 0;
        let mut errors = 0;

        debug!("Querying CommonCrawl for domain: {}", domain);

        let mut subdomains = HashSet::new();

        // Get all available indexes
        let response = match self.client
            .get("https://index.commoncrawl.org/collinfo.json")
            .send()
            .await
        {
            Ok(resp) => {
                if !resp.status().is_success() {
                    errors += 1;
                    warn!("CommonCrawl returned error status: {}", resp.status());
                    return Ok(HashSet::new());
                }
                resp
            }
            Err(e) => {
                errors += 1;
                warn!("Failed to query CommonCrawl indexes: {}", e);
                return Ok(HashSet::new());
            }
        };

        let indices: Vec<CommonCrawlIndex> = match response.json().await {
            Ok(idx) => idx,
            Err(e) => {
                errors += 1;
                warn!("Failed to parse CommonCrawl indexes: {}", e);
                return Ok(HashSet::new());
            }
        };

        // Get current year and filter indexes for last MAX_YEARS_BACK years
        let current_year = Utc::now().year();
        let mut search_indexes = HashMap::new();
        
        for year in (current_year - MAX_YEARS_BACK..=current_year).rev() {
            let year_str = year.to_string();
            for index in &indices {
                if index.id.contains(&year_str) {
                    if !search_indexes.contains_key(&year_str) {
                        search_indexes.insert(year_str.clone(), index.api_url.clone());
                        break;
                    }
                }
            }
        }

        // Query each year's index
        for api_url in search_indexes.values() {
            let url = format!("{}?url=*.{}", api_url, domain);
            
            let response = match self.client
                .get(&url)
                .header("Host", "index.commoncrawl.org")
                .send()
                .await
            {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        errors += 1;
                        warn!("CommonCrawl API returned error status: {}", resp.status());
                        continue;
                    }
                    resp
                }
                Err(e) => {
                    errors += 1;
                    warn!("Failed to query CommonCrawl API: {}", e);
                    continue;
                }
            };

            let text = match response.text().await {
                Ok(t) => t,
                Err(e) => {
                    errors += 1;
                    warn!("Failed to read CommonCrawl response: {}", e);
                    continue;
                }
            };

            // Process each line
            for line in text.lines() {
                if line.is_empty() {
                    continue;
                }

                // URL decode the line
                let decoded = match urlencoding::decode(line) {
                    Ok(d) => d.to_string(),
                    Err(_) => continue,
                };

                // Extract and process URLs from the line
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&decoded) {
                    if let Some(url_str) = json["url"].as_str() {
                        if let Ok(url) = Url::parse(url_str) {
                            if let Some(host_str) = url.host_str() {
                                let host = host_str.to_lowercase();
                                let host = host.trim_start_matches("25") // Fix for triple encoded URLs
                                    .trim_start_matches("2f")
                                    .to_string();
                                
                                if is_valid_subdomain(&host, domain) {
                                    results += 1;
                                    subdomains.insert(host);
                                }
                            }
                        }
                    }
                }
            }
        }

        let elapsed = start_time.elapsed();
        debug!(
            "CommonCrawl finished: {} results, {} errors in {:?}",
            results, errors, elapsed
        );
        Ok(subdomains)
    }
}
