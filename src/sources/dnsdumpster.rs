use anyhow::{Context, Result};
use log::{debug, warn};
use reqwest::Client;
use scraper::{Html, Selector};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use crate::sources::{create_client, is_valid_subdomain};

#[derive(Clone)]
pub struct DNSDumpsterSource {
    client: Arc<Client>,
}

impl DNSDumpsterSource {
    pub fn new() -> Self {
        Self {
            client: create_client(),
        }
    }

    pub async fn enumerate(&self, domain: &str) -> Result<HashSet<String>> {
        let start_time = Instant::now();
        let mut results = 0;
        let mut errors = 0;

        debug!("Querying DNSDumpster for domain: {}", domain);

        let mut subdomains = HashSet::new();

        // First get the CSRF token and cookie
        let initial_response = match self.client
            .get("https://dnsdumpster.com/")
            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
            .send()
            .await
        {
            Ok(resp) => {
                if !resp.status().is_success() {
                    errors += 1;
                    warn!("DNSDumpster returned error status: {}", resp.status());
                    return Ok(HashSet::new());
                }
                resp
            }
            Err(e) => {
                errors += 1;
                warn!("Failed to get initial DNSDumpster page: {}", e);
                return Ok(HashSet::new());
            }
        };

        // Get cookie and text from initial response
        let cookie = initial_response
            .headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let text = match initial_response.text().await {
            Ok(t) => t,
            Err(e) => {
                errors += 1;
                warn!("Failed to read initial DNSDumpster response: {}", e);
                return Ok(HashSet::new());
            }
        };

        // Parse HTML and get CSRF token
        let document = Html::parse_document(&text);
        let selector = match Selector::parse("input[name='csrfmiddlewaretoken']") {
            Ok(s) => s,
            Err(e) => {
                errors += 1;
                warn!("Failed to parse CSRF token selector: {}", e);
                return Ok(HashSet::new());
            }
        };

        let csrf_token = match document.select(&selector).next()
            .and_then(|el| el.value().attr("value"))
            .map(|v| v.to_string())
        {
            Some(token) => token,
            None => {
                errors += 1;
                warn!("Failed to extract CSRF token from DNSDumpster");
                return Ok(HashSet::new());
            }
        };

        // Post form with all required parameters and headers
        let response = match self.client
            .post("https://dnsdumpster.com/")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Referer", "https://dnsdumpster.com/")
            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
            .header("Cookie", format!("csrftoken={}; {}", csrf_token, cookie))
            .form(&[
                ("csrfmiddlewaretoken", csrf_token.clone()),
                ("targetip", domain.to_string()),
                ("user", "free".to_string()),
            ])
            .send()
            .await
        {
            Ok(resp) => {
                if !resp.status().is_success() {
                    errors += 1;
                    warn!("DNSDumpster form submission returned error status: {}", resp.status());
                    return Ok(HashSet::new());
                }
                resp
            }
            Err(e) => {
                errors += 1;
                warn!("Failed to submit DNSDumpster form: {}", e);
                return Ok(HashSet::new());
            }
        };

        let text = match response.text().await {
            Ok(t) => t,
            Err(e) => {
                errors += 1;
                warn!("Failed to read DNSDumpster response: {}", e);
                return Ok(HashSet::new());
            }
        };
        
        let document = Html::parse_document(&text);

        // Parse only the DNS records table that contains A/AAAA/CNAME records
        let table_selector = match Selector::parse("div#dns-records-table table.table") {
            Ok(s) => s,
            Err(e) => {
                errors += 1;
                warn!("Failed to parse table selector: {}", e);
                return Ok(HashSet::new());
            }
        };
        let row_selector = match Selector::parse("tr") {
            Ok(s) => s,
            Err(e) => {
                errors += 1;
                warn!("Failed to parse row selector: {}", e);
                return Ok(HashSet::new());
            }
        };
        let cell_selector = match Selector::parse("td") {
            Ok(s) => s,
            Err(e) => {
                errors += 1;
                warn!("Failed to parse cell selector: {}", e);
                return Ok(HashSet::new());
            }
        };

        if let Some(table) = document.select(&table_selector).next() {
            for row in table.select(&row_selector) {
                let cells: Vec<_> = row.select(&cell_selector).collect();
                if cells.len() >= 2 {
                    // The first cell usually contains the record type (A, AAAA, CNAME)
                    let record_type = cells[0].text().collect::<String>().to_lowercase();
                    if record_type.contains('a') || record_type.contains("cname") {
                        // The second cell contains the hostname
                        let hostname = cells[1].text().collect::<String>();
                        for part in hostname.split_whitespace() {
                            let part = part.trim().to_lowercase();
                            if !part.is_empty() && is_valid_subdomain(&part, domain) {
                                results += 1;
                                subdomains.insert(part);
                            }
                        }
                    }
                }
            }
        }

        let elapsed = start_time.elapsed();
        debug!(
            "DNSDumpster finished: {} results, {} errors in {:?}",
            results, errors, elapsed
        );
        Ok(subdomains)
    }
}
