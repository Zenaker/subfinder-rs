use anyhow::{Context, Result};
use futures::stream::{FuturesUnordered, StreamExt};
use log::{debug, info, warn};
use serde_json::Value;
use std::collections::{HashSet, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Instant};

use crate::sources::{SourceProvider, SourceType};

pub struct Config {
    pub threads: usize,
    pub timeout: Duration,
    pub max_enumeration_time: Duration,
    pub verbose: bool,
    pub api_keys: Option<Value>,
    pub proxy: Option<String>,
}

pub struct Runner {
    config: Config,
    sources: Vec<SourceType>,
    active_tasks: Arc<AtomicUsize>,
}

impl Runner {
    pub fn new(config: Config) -> Self {
        // Override the default client with proxy if configured
        if let Some(ref proxy) = config.proxy {
            crate::sources::create_client_with_proxy(Some(proxy.clone()));
        }

        let sources = if let Some(ref keys) = config.api_keys {
            SourceProvider::get_sources_with_keys(keys)
        } else {
            SourceProvider::get_sources()
        };

        Runner { 
            config, 
            sources,
            active_tasks: Arc::new(AtomicUsize::new(0)),
        }
    }

    async fn test_proxy(&self) -> Result<()> {
        if let Some(proxy_url) = &self.config.proxy {
            if self.config.verbose {
                info!("Testing proxy connection...");
            }
            
            let client = crate::sources::create_client_with_proxy(Some(proxy_url.clone()));
            match client.get("https://ipv4.icanhazip.com/").send().await {
                Ok(response) => {
                    let ip = response.text().await?.trim().to_string();
                    if self.config.verbose {
                        info!("Proxy test successful - Using IP: {}", ip);
                    }
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("Proxy test failed: {}", e));
                }
            }
        }
        Ok(())
    }

    pub async fn enumerate_domain(&self, domain: &str) -> Result<HashSet<String>> {
        let enumeration_start = Instant::now();
        let mut all_subdomains = HashSet::new();
        let mut source_map: HashMap<String, HashSet<String>> = HashMap::new();
        let mut source_timings: HashMap<String, Duration> = HashMap::new();
        
        // Test proxy before starting enumeration
        self.test_proxy().await?;
        
        if self.config.verbose {
            info!("Starting enumeration for domain: {}", domain);
        }

        // Use semaphore for concurrency control
        let semaphore = Arc::new(Semaphore::new(self.config.threads));
        let tasks = FuturesUnordered::new();

        // Initialize tasks for each source
        for source in &self.sources {
            let domain = domain.to_string();
            let timeout_duration = self.config.timeout;
            let source = (*source).clone();
            let sem = semaphore.clone();
            let active_tasks = self.active_tasks.clone();
            let verbose = self.config.verbose;
            
            let task = async move {
                // Acquire semaphore permit
                let _permit = sem.acquire().await.context("Failed to acquire semaphore")?;
                active_tasks.fetch_add(1, Ordering::SeqCst);

                let source_name = source.name();
                let source_start = Instant::now();
                let result = async {
                    let source_future = source.enumerate(&domain);
                    match timeout(timeout_duration, source_future).await {
                        Ok(result) => {
                            match result {
                                Ok(domains) => {
                                    Ok((domains, source_name.clone(), source_start.elapsed()))
                                }
                                Err(e) => {
                                    if verbose {
                                        warn!("Source error: {}", e);
                                    }
                                    Err(e)
                                }
                            }
                        }
                        Err(_) => {
                            if verbose {
                                warn!("Source timed out");
                            }
                            Ok((HashSet::new(), source_name.clone(), timeout_duration))
                        }
                    }
                }.await;

                active_tasks.fetch_sub(1, Ordering::SeqCst);
                result
            };

            tasks.push(task);
        }

        // Process results with timeout and progress tracking
        let overall_timeout = tokio::time::sleep(self.config.max_enumeration_time);
        tokio::pin!(overall_timeout);

        let mut tasks = tasks;
        let mut completed_sources = 0;
        let total_sources = self.sources.len();

        loop {
            tokio::select! {
                result = tasks.next() => {
                    match result {
                        Some(result) => {
                            completed_sources += 1;
                            match result {
                                Ok((domains, source_name, elapsed)) => {
                                    let new_domains = domains.len();
                                    source_timings.insert(source_name.clone(), elapsed);
                                    for subdomain in domains {
                                        // Track sources for each subdomain
                                        source_map.entry(subdomain.clone())
                                            .or_default()
                                            .insert(source_name.clone());
                                        all_subdomains.insert(subdomain);
                                    }
                                    if self.config.verbose && new_domains > 0 {
                                        info!(
                                            "[+] Source {}/{} completed | {} subdomains found in {:?}", 
                                            completed_sources, 
                                            total_sources,
                                            new_domains,
                                            elapsed
                                        );
                                    }
                                }
                                Err(e) => {
                                    // Only log critical errors
                                    if self.config.verbose && 
                                       !e.to_string().contains("API_KEY") && 
                                       !e.to_string().contains("404") &&
                                       !e.to_string().contains("timeout") {
                                        warn!("Source error: {}", e);
                                    }
                                }
                            }
                        }
                        None => break,
                    }
                }
                _ = &mut overall_timeout => {
                    if self.config.verbose {
                        warn!(
                            "[!] Maximum enumeration time reached | {}/{} sources completed", 
                            completed_sources,
                            total_sources
                        );
                    }
                    break;
                }
            }
        }

        // Filter and sort subdomains
        let mut filtered: Vec<_> = all_subdomains
            .into_iter()
            .filter(|s| crate::sources::is_valid_subdomain(s, domain))
            .collect();
        filtered.sort();

        // Print final statistics
        let elapsed = enumeration_start.elapsed();
        info!("[+] Enumeration completed in {:?}", elapsed);
        if self.config.verbose {
            info!("[+] Source statistics:");
            let mut source_stats: Vec<_> = source_map.iter()
                .map(|(_, sources)| {
                    sources.iter()
                        .map(|source| (source.clone(), 1))
                        .collect::<Vec<_>>()
                })
                .flatten()
                .fold(HashMap::new(), |mut acc, (source, count)| {
                    *acc.entry(source).or_insert(0) += count;
                    acc
                })
                .into_iter()
                .map(|(source, count)| {
                    let timing = source_timings.get(&source)
                        .cloned()
                        .unwrap_or_else(|| Duration::from_secs(0));
                    (source, count, timing)
                })
                .collect();

            source_stats.sort_by(|a, b| b.1.cmp(&a.1));  // Sort by count descending
            for (source, count, timing) in source_stats {
                info!(
                    "    - {}: {} results in {:?}",
                    source, count, timing
                );
            }
        }

        Ok(filtered.into_iter().collect())
    }
}
