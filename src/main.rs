use anyhow::Result;
use clap::Parser;
use colored::*;
use log::{error, info};
use serde_json::Value;
use std::time::{Duration, Instant};

mod runner;
mod sources;

const BANNER: &str = r#"
     ____        _     _____ _           _           
    / ___| _   _| |__ |  ___(_)_ __   __| | ___ _ __ 
    \___ \| | | | '_ \| |_  | | '_ \ / _` |/ _ \ '__|
     ___) | |_| | |_) |  _| | | | | | (_| |  __/ |   
    |____/ \__,_|_.__/|_|   |_|_| |_|\__,_|\___|_|   
                                                      
    "#;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Domain to find subdomains for
    #[arg(required = true)]
    domain: String,

    /// Number of concurrent threads
    #[arg(short = 'n', long, default_value = "10")]
    threads: usize,

    /// Timeout in seconds for requests
    #[arg(short = 't', long, default_value = "30")]
    timeout: u64,

    /// Maximum enumeration time in minutes
    #[arg(short, long, default_value = "10")]
    max_time: u64,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// API keys file path
    #[arg(short = 'k', long)]
    keys_file: Option<String>,

    /// Proxy URL (e.g., http://proxy.infiniteproxies.com:1111)
    #[arg(short = 'p', long)]
    proxy: Option<String>,
}

fn load_api_keys(path: &str) -> Result<Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Failed to read keys file: {}", e))?;
    serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to parse keys file: {}", e))
}

fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs();
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;
    let millis = duration.subsec_millis();

    if hours > 0 {
        format!("{}h {}m {}s {}ms", hours, minutes, seconds, millis)
    } else if minutes > 0 {
        format!("{}m {}s {}ms", minutes, seconds, millis)
    } else if seconds > 0 {
        format!("{}s {}ms", seconds, millis)
    } else {
        format!("{}ms", millis)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let start_time = Instant::now();

    // Initialize logging with appropriate filters
    if args.verbose {
        // Clear any existing RUST_LOG environment variable
        std::env::remove_var("RUST_LOG");

        let mut builder = env_logger::Builder::new();
        
        // Set default level to Info
        builder.filter_level(log::LevelFilter::Info);
        
        // Filter out noisy dependencies
        let noisy_modules = [
            "scraper", "html5ever", "selectors", "mio", "want",
            "tokio_util", "hyper", "rustls", "tungstenite"
        ];
        for module in noisy_modules.iter() {
            builder.filter_module(module, log::LevelFilter::Off);
        }
        
        // Only show warnings from HTTP client
        builder.filter_module("reqwest", log::LevelFilter::Warn);
        
        // Initialize without terminal colors in logs
        builder.write_style(env_logger::WriteStyle::Never).init();

        // Print banner in verbose mode
        println!("{}", BANNER.bright_cyan());
        println!("{}", "[ Subdomain Enumeration Tool ]".bright_blue());
        println!();
        
        info!("Starting subdomain enumeration for: {}", args.domain);
    }

    // Load API keys if provided
    let api_keys = if let Some(keys_path) = args.keys_file.as_ref() {
        match load_api_keys(keys_path) {
            Ok(keys) => {
                if args.verbose {
                    info!("Using API keys from: {}", keys_path);
                }
                Some(keys)
            }
            Err(e) => {
                eprintln!("Failed to load API keys: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Format proxy URL with credentials if provided
    let proxy = args.proxy.map(|p| {
        if p.contains("@") {
            p
        } else if p.matches(':').count() == 3 {
            // Format: proxy:port:user:pass
            let parts: Vec<&str> = p.split(':').collect();
            format!("http://{}:{}@{}:{}", parts[2], parts[3], parts[0], parts[1])
        } else {
            p // Use proxy without default credentials
        }
    });

    let config = runner::Config {
        threads: args.threads,
        timeout: Duration::from_secs(args.timeout),
        max_enumeration_time: Duration::from_secs(args.max_time * 60),
        verbose: args.verbose,
        api_keys: api_keys.clone(),
        proxy: proxy.clone(),
    };

    let runner = runner::Runner::new(config);

    match runner.enumerate_domain(&args.domain).await {
        Ok(subdomains) => {
            if args.verbose {
                println!("\n{}", "[+] Found Subdomains:".green());
                println!("{}", "-".repeat(50).dimmed());
            }
            
            let mut sorted: Vec<_> = subdomains.into_iter().collect();
            sorted.sort();
            
            // Print each subdomain with proper indentation
            if !sorted.is_empty() {
                for subdomain in &sorted {
                    if args.verbose {
                        println!("  {}", subdomain.yellow());
                    } else {
                        println!("{}", subdomain);
                    }
                }

                if args.verbose {
                    println!();
                    println!("{}", "-".repeat(50).dimmed());
                    println!("Total unique subdomains found: {}", sorted.len());
                    println!("Total enumeration time: {}", format_duration(start_time.elapsed()));
                    println!("{}", "-".repeat(50).dimmed());
                }
            } else if args.verbose {
                println!("  No subdomains found");
                println!();
                println!("{}", "-".repeat(50).dimmed());
                println!("Total enumeration time: {}", format_duration(start_time.elapsed()));
                println!("{}", "-".repeat(50).dimmed());
            }
            Ok(())
        }
        Err(e) => {
            error!("{} {}", "[!]".red(), e);
            Err(e)
        }
    }
}
