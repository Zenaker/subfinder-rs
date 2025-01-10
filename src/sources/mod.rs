use anyhow::Result;
use reqwest::Client;
use serde_json::Value;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

// Module declarations
mod alienvault;
mod anubis;
mod bufferover;
mod censys;
mod certspotter;
mod chaos;
mod commoncrawl;
mod crtsh;
mod dnsdb;
mod dnsdumpster;
mod github;
mod hackertarget;
mod rapiddns;
mod riddler;
mod threatcrowd;
mod virustotal;
mod webarchive;

// Use declarations
use self::alienvault::AlienVaultSource;
use self::anubis::AnubisSource;
use self::bufferover::BufferOverSource;
use self::censys::CensysSource;
use self::certspotter::CertSpotterSource;
use self::chaos::ChaosSource;
use self::commoncrawl::CommonCrawlSource;
use self::crtsh::CrtShSource;
use self::dnsdb::DNSDBSource;
use self::dnsdumpster::DNSDumpsterSource;
use self::github::GitHubSource;
use self::hackertarget::HackerTargetSource;
use self::rapiddns::RapidDNSSource;
use self::riddler::RiddlerSource;
use self::threatcrowd::ThreatCrowdSource;
use self::virustotal::VirusTotalSource;
use self::webarchive::WebArchiveSource;

/// Creates a new HTTP client with optimized settings
pub(crate) fn create_client() -> Arc<Client> {
    create_client_with_proxy(None)
}

/// Creates a new HTTP client with proxy support
pub(crate) fn create_client_with_proxy(proxy: Option<String>) -> Arc<Client> {
    let mut builder = Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")  // Use a more common user agent
        .timeout(Duration::from_secs(60))  // Increase timeout
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(20)  // Increase connection pool
        .connection_verbose(false)  // Disable connection debugging
        .tcp_keepalive(Duration::from_secs(30))
        .danger_accept_invalid_certs(true)  // Accept invalid certificates
        .http1_only()  // Disable HTTP/2 to avoid frame size issues
        .connect_timeout(Duration::from_secs(30))  // Increase connect timeout
        .local_address(Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))));  // Allow any local interface

    // Add proxy if configured
    if let Some(proxy_url) = proxy {
        if let Ok(proxy) = reqwest::Proxy::all(&proxy_url) {
            builder = builder.proxy(proxy);
        }
    }

    Arc::new(builder.build().expect("Failed to build HTTP client"))
}

// Helper function to check if a response is HTML
pub(crate) fn is_html_response(text: &str) -> bool {
    text.contains("<html") || text.contains("<!DOCTYPE")
}

// Helper function to validate a subdomain
pub(crate) fn is_valid_subdomain(subdomain: &str, domain: &str) -> bool {
    // Basic validation
    if !subdomain.ends_with(&format!(".{}", domain)) ||  // Must be a valid subdomain of target domain
       subdomain == domain ||                            // Must not be the domain itself
       subdomain.len() <= domain.len() + 1 ||           // Must be longer than domain
       subdomain.starts_with('.') ||                    // Must not start with dot
       !subdomain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') { // Valid chars only
        return false;
    }

    // Split subdomain into parts
    let parts: Vec<&str> = subdomain.split('.').collect();
    
    // Must have at least one part before the domain
    if parts.len() < 2 {
        return false;
    }

    // Check each part for invalid patterns
    for part in &parts {
        // Skip empty parts or parts that are too short/long
        if part.is_empty() || part.len() > 63 {
            return false;
        }

        // Check for invalid characters in each part
        if !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }

        // Parts cannot start or end with hyphen
        if part.starts_with('-') || part.ends_with('-') {
            return false;
        }
    }

    // Convert subdomain to lowercase for case-insensitive matching
    let subdomain_lower = subdomain.to_lowercase();
    
    // Check for invalid patterns in full domain
    let invalid_full_patterns = [
        // Special characters
        "..", "@", "//", "http", "\\", "[", "]", "_",
        // Wildcard patterns
        "*", "%", "?", "+",
    ];
    if invalid_full_patterns.iter().any(|&pattern| subdomain_lower.contains(pattern)) {
        return false;
    }

    true
}

#[derive(Clone)]
pub enum SourceType {
    CrtSh(CrtShSource),
    WebArchive(WebArchiveSource),
    Chaos(ChaosSource),
    GitHub(GitHubSource),
    DNSDB(DNSDBSource),
    Censys(CensysSource),
    AlienVault(AlienVaultSource),
    BufferOver(BufferOverSource),
    CertSpotter(CertSpotterSource),
    ThreatCrowd(ThreatCrowdSource),
    VirusTotal(VirusTotalSource),
    HackerTarget(HackerTargetSource),
    Anubis(AnubisSource),
    RapidDNS(RapidDNSSource),
    DNSDumpster(DNSDumpsterSource),
    CommonCrawl(CommonCrawlSource),
    Riddler(RiddlerSource),
}

impl SourceType {
    pub fn name(&self) -> String {
        match self {
            SourceType::CrtSh(_) => "crtsh".to_string(),
            SourceType::WebArchive(_) => "webarchive".to_string(),
            SourceType::Chaos(_) => "chaos".to_string(),
            SourceType::GitHub(_) => "github".to_string(),
            SourceType::DNSDB(_) => "dnsdb".to_string(),
            SourceType::Censys(_) => "censys".to_string(),
            SourceType::AlienVault(_) => "alienvault".to_string(),
            SourceType::BufferOver(_) => "bufferover".to_string(),
            SourceType::CertSpotter(_) => "certspotter".to_string(),
            SourceType::ThreatCrowd(_) => "threatcrowd".to_string(),
            SourceType::VirusTotal(_) => "virustotal".to_string(),
            SourceType::HackerTarget(_) => "hackertarget".to_string(),
            SourceType::Anubis(_) => "anubis".to_string(),
            SourceType::RapidDNS(_) => "rapiddns".to_string(),
            SourceType::DNSDumpster(_) => "dnsdumpster".to_string(),
            SourceType::CommonCrawl(_) => "commoncrawl".to_string(),
            SourceType::Riddler(_) => "riddler".to_string(),
        }
    }

    pub async fn enumerate(&self, domain: &str) -> Result<HashSet<String>> {
        match self {
            SourceType::CrtSh(source) => source.enumerate(domain).await,
            SourceType::WebArchive(source) => source.enumerate(domain).await,
            SourceType::Chaos(source) => source.enumerate(domain).await,
            SourceType::GitHub(source) => source.enumerate(domain).await,
            SourceType::DNSDB(source) => source.enumerate(domain).await,
            SourceType::Censys(source) => source.enumerate(domain).await,
            SourceType::AlienVault(source) => source.enumerate(domain).await,
            SourceType::BufferOver(source) => source.enumerate(domain).await,
            SourceType::CertSpotter(source) => source.enumerate(domain).await,
            SourceType::ThreatCrowd(source) => source.enumerate(domain).await,
            SourceType::VirusTotal(source) => source.enumerate(domain).await,
            SourceType::HackerTarget(source) => source.enumerate(domain).await,
            SourceType::Anubis(source) => source.enumerate(domain).await,
            SourceType::RapidDNS(source) => source.enumerate(domain).await,
            SourceType::DNSDumpster(source) => source.enumerate(domain).await,
            SourceType::CommonCrawl(source) => source.enumerate(domain).await,
            SourceType::Riddler(source) => source.enumerate(domain).await,
        }
    }
}

pub struct SourceProvider;

impl SourceProvider {
    pub fn get_sources() -> Vec<SourceType> {
        vec![
            SourceType::CrtSh(CrtShSource::new()),
            SourceType::WebArchive(WebArchiveSource::new()),
            SourceType::Chaos(ChaosSource::new()),
            SourceType::GitHub(GitHubSource::new()),
            SourceType::DNSDB(DNSDBSource::new()),
            SourceType::Censys(CensysSource::new()),
            SourceType::AlienVault(AlienVaultSource::new()),
            SourceType::BufferOver(BufferOverSource::new()),
            SourceType::CertSpotter(CertSpotterSource::new()),
            SourceType::ThreatCrowd(ThreatCrowdSource::new()),
            SourceType::VirusTotal(VirusTotalSource::new()),
            SourceType::HackerTarget(HackerTargetSource::new()),
            SourceType::Anubis(AnubisSource::new()),
            SourceType::RapidDNS(RapidDNSSource::new()),
            SourceType::DNSDumpster(DNSDumpsterSource::new()),
            SourceType::CommonCrawl(CommonCrawlSource::new()),
            SourceType::Riddler(RiddlerSource::new()),
        ]
    }

    pub fn get_sources_with_keys(api_keys: &Value) -> Vec<SourceType> {
        let mut sources = Vec::new();

        // Initialize each source with its API key if available
        let mut github = GitHubSource::new();
        if let Some(key) = api_keys.get("github").and_then(|v| v.as_str()) {
            github.add_api_keys(vec![key.to_string()]);
        }
        sources.push(SourceType::GitHub(github));

        let mut dnsdb = DNSDBSource::new();
        if let Some(key) = api_keys.get("dnsdb").and_then(|v| v.as_str()) {
            dnsdb.add_api_keys(vec![key.to_string()]);
        }
        sources.push(SourceType::DNSDB(dnsdb));

        let mut censys = CensysSource::new();
        if let Some(obj) = api_keys.get("censys").and_then(|v| v.as_object()) {
            if let (Some(id), Some(secret)) = (
                obj.get("id").and_then(|v| v.as_str()),
                obj.get("secret").and_then(|v| v.as_str())
            ) {
                censys.add_api_keys(vec![(id.to_string(), secret.to_string())]);
            }
        }
        sources.push(SourceType::Censys(censys));

        let mut virustotal = VirusTotalSource::new();
        if let Some(key) = api_keys.get("virustotal").and_then(|v| v.as_str()) {
            virustotal.add_api_keys(vec![key.to_string()]);
        }
        sources.push(SourceType::VirusTotal(virustotal));

        let mut certspotter = CertSpotterSource::new();
        if let Some(key) = api_keys.get("certspotter").and_then(|v| v.as_str()) {
            certspotter.add_api_keys(vec![key.to_string()]);
        }
        sources.push(SourceType::CertSpotter(certspotter));

        let mut chaos = ChaosSource::new();
        if let Some(key) = api_keys.get("chaos").and_then(|v| v.as_str()) {
            chaos.add_api_keys(vec![key.to_string()]);
        }
        sources.push(SourceType::Chaos(chaos));

        // Add sources that don't require API keys
        sources.extend(vec![
            SourceType::CrtSh(CrtShSource::new()),
            SourceType::WebArchive(WebArchiveSource::new()),
            SourceType::AlienVault(AlienVaultSource::new()),
            SourceType::BufferOver(BufferOverSource::new()),
            SourceType::ThreatCrowd(ThreatCrowdSource::new()),
            SourceType::HackerTarget(HackerTargetSource::new()),
            SourceType::Anubis(AnubisSource::new()),
            SourceType::RapidDNS(RapidDNSSource::new()),
            SourceType::DNSDumpster(DNSDumpsterSource::new()),
            SourceType::CommonCrawl(CommonCrawlSource::new()),
            SourceType::Riddler(RiddlerSource::new()),
        ]);

        sources
    }
}
