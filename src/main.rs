use anyhow::{Context, Result};
use clap::Parser;
use reqwest::blocking::Client;
use reqwest::{Certificate, Method};
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(author, version, about = "HTTP benchmarking tool", long_about = None)]
struct Args {
    /// Target URL (required)
    #[arg(short = 'h', long)]
    url: String,

    /// HTTP method
    #[arg(short = 'm', long, default_value = "GET")]
    method: String,

    /// Number of concurrent connections
    #[arg(short = 'c', long, default_value_t = 1)]
    connections: usize,

    /// Number of threads
    #[arg(short = 't', long, default_value_t = 1)]
    threads: usize,

    /// Duration of test (e.g., 10s, 1m)
    #[arg(short = 'd', long, default_value = "10s")]
    duration: String,

    /// Custom headers (can be used multiple times, format: "Key: Value")
    #[arg(short = 'H', long)]
    headers: Vec<String>,

    /// Request body
    #[arg(long)]
    body: Option<String>,

    /// Path to client certificate file (PEM)
    #[arg(long)]
    cert: Option<String>,

    /// Path to client key file (PEM)
    #[arg(long)]
    key: Option<String>,

    /// Path to server CA certificate file (PEM) for verification
    #[arg(long)]
    tls_cert: Option<String>,

    /// Skip TLS certificate verification
    #[arg(long)]
    insecure: bool,
}

#[derive(Debug, Default)]
struct BenchmarkResult {
    total_requests: AtomicU64,
    success_requests: AtomicU64,
    failed_requests: AtomicU64,
    total_latency_ns: AtomicU64,
    min_latency_ns: AtomicU64,
    max_latency_ns: AtomicU64,
}

impl BenchmarkResult {
    fn new() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            success_requests: AtomicU64::new(0),
            failed_requests: AtomicU64::new(0),
            total_latency_ns: AtomicU64::new(0),
            min_latency_ns: AtomicU64::new(u64::MAX),
            max_latency_ns: AtomicU64::new(0),
        }
    }

    fn record_request(&self, success: bool, latency: Duration) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        if success {
            self.success_requests.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed_requests.fetch_add(1, Ordering::Relaxed);
        }

        let latency_ns = latency.as_nanos() as u64;
        self.total_latency_ns
            .fetch_add(latency_ns, Ordering::Relaxed);

        // Update min latency
        let mut current_min = self.min_latency_ns.load(Ordering::Relaxed);
        while latency_ns < current_min {
            match self.min_latency_ns.compare_exchange_weak(
                current_min,
                latency_ns,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(x) => current_min = x,
            }
        }

        // Update max latency
        let mut current_max = self.max_latency_ns.load(Ordering::Relaxed);
        while latency_ns > current_max {
            match self.max_latency_ns.compare_exchange_weak(
                current_max,
                latency_ns,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(x) => current_max = x,
            }
        }
    }
}

fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("Duration cannot be empty");
    }

    let (num_str, unit) = if s.ends_with("ms") {
        (&s[..s.len() - 2], "ms")
    } else if s.ends_with('s') {
        (&s[..s.len() - 1], "s")
    } else if s.ends_with('m') {
        (&s[..s.len() - 1], "m")
    } else if s.ends_with('h') {
        (&s[..s.len() - 1], "h")
    } else {
        (s, "s") // default to seconds
    };

    let num: u64 = num_str.parse().context("Invalid duration number")?;

    Ok(match unit {
        "ms" => Duration::from_millis(num),
        "s" => Duration::from_secs(num),
        "m" => Duration::from_secs(num * 60),
        "h" => Duration::from_secs(num * 3600),
        _ => unreachable!(),
    })
}

fn create_client(args: &Args) -> Result<Client> {
    let mut builder = Client::builder()
        .danger_accept_invalid_certs(args.insecure)
        .pool_max_idle_per_host(10000)
        .pool_idle_timeout(Duration::from_secs(90))
        .timeout(Duration::from_secs(30));

    // Note: Client certificate (mutual TLS) is not supported with rustls-tls backend
    if args.cert.is_some() || args.key.is_some() {
        eprintln!(
            "Warning: Client certificate authentication (--cert/--key) is not supported with rustls backend"
        );
    }

    // Load server CA certificate for verification
    if let Some(tls_cert_path) = &args.tls_cert {
        let ca_cert = fs::read(tls_cert_path).context("Failed to read CA certificate")?;
        let cert =
            Certificate::from_pem(&ca_cert).context("Failed to parse CA certificate")?;
        builder = builder.add_root_certificate(cert);
    }

    builder.build().context("Failed to build HTTP client")
}

fn make_request(
    client: &Client,
    method: &Method,
    url: &str,
    headers: &[(String, String)],
    body: &Option<String>,
) -> bool {
    let mut request = client.request(method.clone(), url);

    for (key, value) in headers {
        request = request.header(key, value);
    }

    if let Some(body_content) = body {
        request = request.body(body_content.clone());
    }

    match request.send() {
        Ok(response) => {
            let status = response.status();
            // Consume the body
            let _ = response.bytes();
            status.is_success() || status.is_redirection()
        }
        Err(_) => false,
    }
}

fn run_benchmark(
    args: Arc<Args>,
    client: Client,
    result: Arc<BenchmarkResult>,
    duration: Duration,
) -> Result<()> {
    let method =
        Method::from_bytes(args.method.as_bytes()).context("Invalid HTTP method")?;

    // Parse headers
    let headers: Arc<Vec<(String, String)>> = Arc::new(
        args.headers
            .iter()
            .filter_map(|h| {
                let parts: Vec<&str> = h.splitn(2, ':').collect();
                if parts.len() == 2 {
                    Some((parts[0].trim().to_string(), parts[1].trim().to_string()))
                } else {
                    None
                }
            })
            .collect(),
    );

    let end_time = Instant::now() + duration;
    let connections_per_thread = args.connections / args.threads.max(1);
    let connections_per_thread = connections_per_thread.max(1);

    let mut handles = vec![];

    for _ in 0..args.threads {
        for _ in 0..connections_per_thread {
            let client = client.clone();
            let method = method.clone();
            let url = args.url.clone();
            let headers = headers.clone();
            let body = args.body.clone();
            let result = result.clone();

            let handle = thread::spawn(move || {
                while Instant::now() < end_time {
                    let start = Instant::now();
                    let success = make_request(&client, &method, &url, &headers, &body);
                    let latency = start.elapsed();
                    result.record_request(success, latency);
                }
            });

            handles.push(handle);
        }
    }

    for handle in handles {
        handle.join().unwrap();
    }

    Ok(())
}

fn print_results(result: &BenchmarkResult, total_duration: Duration) {
    let total = result.total_requests.load(Ordering::Relaxed);
    let success = result.success_requests.load(Ordering::Relaxed);
    let failed = result.failed_requests.load(Ordering::Relaxed);
    let total_latency_ns = result.total_latency_ns.load(Ordering::Relaxed);
    let min_latency_ns = result.min_latency_ns.load(Ordering::Relaxed);
    let max_latency_ns = result.max_latency_ns.load(Ordering::Relaxed);

    println!("\n=== Benchmark Results ===");
    println!("Total Requests:   {}", total);
    println!("Successful:       {}", success);
    println!("Failed:           {}", failed);
    println!("Duration:         {:.2}s", total_duration.as_secs_f64());
    println!(
        "Requests/sec:     {:.2}",
        total as f64 / total_duration.as_secs_f64()
    );

    if total > 0 {
        let avg_latency_ns = total_latency_ns / total;
        println!("\nLatency Statistics:");
        println!(
            "  Min:            {:.2}ms",
            min_latency_ns as f64 / 1_000_000.0
        );
        println!(
            "  Max:            {:.2}ms",
            max_latency_ns as f64 / 1_000_000.0
        );
        println!(
            "  Average:        {:.2}ms",
            avg_latency_ns as f64 / 1_000_000.0
        );
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let duration = parse_duration(&args.duration)?;

    println!("Starting benchmark...");
    println!("URL: {}", args.url);
    println!("Method: {}", args.method);
    println!("Connections: {}", args.connections);
    println!("Threads: {}", args.threads);
    println!("Duration: {:?}", duration);
    println!("Headers: {:?}", args.headers);
    if let Some(body) = &args.body {
        println!("Body: {}", body);
    }
    println!();

    let args = Arc::new(args);
    let client = create_client(&args)?;
    let result = Arc::new(BenchmarkResult::new());

    let start = Instant::now();
    run_benchmark(args, client, result.clone(), duration)?;
    let total_duration = start.elapsed();

    print_results(&result, total_duration);

    Ok(())
}

// Made with Bob
