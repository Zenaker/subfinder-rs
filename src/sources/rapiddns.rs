use anyhow::{Context, Result};
use log::{debug, warn};
use reqwest::Client;
use scraper::{Html, Selector};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use crate::sources::{create_client, is_valid_subdomain, is_html_response};

#[derive(Clone)]
pub struct RapidDNSSource {
    client: Arc<Client>,
}

impl RapidDNSSource {
    pub fn new() -> Self {
        Self {
            client: create_client(),
        }
    }

    pub async fn enumerate(&self, domain: &str) -> Result<HashSet<String>> {
        let start_time = Instant::now();
        let mut results = 0;
        let mut errors = 0;

        debug!("Querying RapidDNS for domain: {}", domain);

        let mut subdomains = HashSet::new();
        let mut page = 1;
        let mut max_pages = 1;

        // Regex for extracting max page number
        let page_pattern = regex::Regex::new(r#"class="page-link" href="/subdomain/[^"]+\?page=(\d+)""#)?;

        // Prepare selector once
        let row_selector = match Selector::parse("table#table > tbody > tr > td:first-child") {
            Ok(selector) => selector,
            Err(e) => {
                errors += 1;
                warn!("Failed to parse row selector: {}", e);
                return Ok(HashSet::new());
            }
        };

        loop {
            let url = format!("https://rapiddns.io/subdomain/{}?page={}&full=1", domain, page);
            let response = match self.client
                .get(&url)
                .send()
                .await
            {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        errors += 1;
                        warn!("RapidDNS returned error status: {}", resp.status());
                        break;
                    }
                    resp
                }
                Err(e) => {
                    errors += 1;
                    warn!("Failed to query RapidDNS page {}: {}", page, e);
                    break;
                }
            };

            let text = match response.text().await {
                Ok(t) => t,
                Err(e) => {
                    errors += 1;
                    warn!("Failed to read RapidDNS response for page {}: {}", page, e);
                    break;
                }
            };

            // Check if it's a valid HTML response
            if !is_html_response(&text) {
                debug!("Received non-HTML response from RapidDNS, skipping...");
                break;
            }

            // Parse the table rows which contain subdomains
            let document = Html::parse_document(&text);
            for element in document.select(&row_selector) {
                let subdomain = element.text().collect::<String>().trim().to_lowercase();
                if !subdomain.is_empty() && is_valid_subdomain(&subdomain, domain) {
                    results += 1;
                    subdomains.insert(subdomain);
                }
            }

            // Update max pages on first page
            if page == 1 {
                if let Some(captures) = page_pattern.captures_iter(&text).last() {
                    if let Some(last_page) = captures.get(1) {
                        if let Ok(num) = last_page.as_str().parse::<usize>() {
                            max_pages = num;
                            debug!("Found {} total pages on RapidDNS", max_pages);
                        }
                    }
                }
            }

            if page >= max_pages {
                break;
            }
            page += 1;
        }

        let elapsed = start_time.elapsed();
        debug!(
            "RapidDNS finished: {} results, {} errors in {:?}",
            results, errors, elapsed
        );
        Ok(subdomains)
    }
}
