use anyhow::{Context, Result};
use clap::Parser;
use http_body_util::BodyExt;
use hyper::client::conn::http1;
use hyper::{Method, Request, Uri};
use hyper_util::rt::TokioIo;
use rustls::RootCertStore;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

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

fn create_tls_config(args: &Args) -> Result<Option<Arc<rustls::ClientConfig>>> {
    if !args.url.starts_with("https://") {
        return Ok(None);
    }

    let tls_config = if let Some(tls_cert_path) = &args.tls_cert {
        let ca_cert_pem = fs::read(tls_cert_path).context("Failed to read CA certificate")?;
        let certs = rustls_pemfile::certs(&mut ca_cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse CA certificate")?;

        let mut root_store = RootCertStore::empty();
        for cert in certs {
            root_store
                .add(cert)
                .context("Failed to add certificate to root store")?;
        }

        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    } else if args.insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    if args.cert.is_some() || args.key.is_some() {
        eprintln!("Warning: Client certificate authentication (--cert/--key) is not yet implemented");
    }

    Ok(Some(Arc::new(tls_config)))
}

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

async fn run_worker(
    _worker_id: usize,
    connections_per_worker: usize,
    args: Arc<Args>,
    result: Arc<BenchmarkResult>,
    duration: Duration,
    tls_config: Option<Arc<rustls::ClientConfig>>,
) -> Result<()> {
    let uri: Uri = args.url.parse().context("Invalid URL")?;
    let method = Method::from_bytes(args.method.as_bytes()).context("Invalid HTTP method")?;

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

    let host = uri.host().context("No host in URL")?;
    let port = uri.port_u16().unwrap_or(if uri.scheme_str() == Some("https") { 443 } else { 80 });
    let addr = format!("{}:{}", host, port);

    let end_time = Instant::now() + duration;

    let mut tasks = Vec::new();

    for _ in 0..connections_per_worker {
        let addr = addr.clone();
        let uri = uri.clone();
        let method = method.clone();
        let headers = headers.clone();
        let body = args.body.clone();
        let result = result.clone();
        let tls_config = tls_config.clone();
        let host = host.to_string();

        let task = tokio::spawn(async move {
            // Establish persistent connection
            let stream = match TcpStream::connect(&addr).await {
                Ok(s) => s,
                Err(_) => return,
            };

            if let Some(tls_cfg) = tls_config {
                let connector = tokio_rustls::TlsConnector::from(tls_cfg);
                let domain = rustls::pki_types::ServerName::try_from(host)
                    .unwrap()
                    .to_owned();
                let tls_stream = match connector.connect(domain, stream).await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let io = TokioIo::new(tls_stream);
                let (mut sender, conn) = match http1::handshake(io).await {
                    Ok(c) => c,
                    Err(_) => return,
                };

                tokio::spawn(async move {
                    let _ = conn.await;
                });

                while Instant::now() < end_time {
                    let mut req = Request::builder()
                        .method(method.clone())
                        .uri(uri.clone());

                    for (key, value) in headers.iter() {
                        req = req.header(key, value);
                    }

                    let req = if let Some(body_content) = &body {
                        req.body(body_content.clone()).unwrap()
                    } else {
                        req.body(String::new()).unwrap()
                    };

                    let start = Instant::now();
                    let success = match sender.send_request(req).await {
                        Ok(response) => {
                            let status = response.status();
                            let _ = response.into_body().collect().await;
                            status.is_success() || status.is_redirection()
                        }
                        Err(_) => false,
                    };
                    let latency = start.elapsed();

                    result.record_request(success, latency);
                }
            } else {
                let io = TokioIo::new(stream);
                let (mut sender, conn) = match http1::handshake(io).await {
                    Ok(c) => c,
                    Err(_) => return,
                };

                tokio::spawn(async move {
                    let _ = conn.await;
                });

                while Instant::now() < end_time {
                    let mut req = Request::builder()
                        .method(method.clone())
                        .uri(uri.clone());

                    for (key, value) in headers.iter() {
                        req = req.header(key, value);
                    }

                    let req = if let Some(body_content) = &body {
                        req.body(body_content.clone()).unwrap()
                    } else {
                        req.body(String::new()).unwrap()
                    };

                    let start = Instant::now();
                    let success = match sender.send_request(req).await {
                        Ok(response) => {
                            let status = response.status();
                            let _ = response.into_body().collect().await;
                            status.is_success() || status.is_redirection()
                        }
                        Err(_) => false,
                    };
                    let latency = start.elapsed();

                    result.record_request(success, latency);
                }
            }
        });

        tasks.push(task);
    }

    for task in tasks {
        let _ = task.await;
    }

    Ok(())
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
    let result = Arc::new(BenchmarkResult::new());
    let tls_config = create_tls_config(&args)?;

    let connections_per_thread = args.connections / args.threads;
    let mut remaining = args.connections % args.threads;

    let start = Instant::now();
    let mut handles = Vec::new();

    for worker_id in 0..args.threads {
        let connections = connections_per_thread + if remaining > 0 { remaining -= 1; 1 } else { 0 };
        let args = args.clone();
        let result = result.clone();
        let tls_config = tls_config.clone();

        let handle = std::thread::Builder::new()
            .name(format!("rewrk-worker-{}", worker_id))
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();

                rt.block_on(run_worker(worker_id, connections, args, result, duration, tls_config))
            })
            .unwrap();

        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.join();
    }

    let total_duration = start.elapsed();

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

    Ok(())
}

// Made with Bob
