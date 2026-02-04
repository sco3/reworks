package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Config struct {
	URL         string
	Method      string
	Connections int
	Threads     int
	Duration    time.Duration
	Headers     []string
	Body        string
	CertFile    string
	KeyFile     string
	TLSCertFile string
	Insecure    bool
}

type Result struct {
	TotalRequests   int64
	SuccessRequests int64
	FailedRequests  int64
	TotalDuration   time.Duration
	MinLatency      time.Duration
	MaxLatency      time.Duration
	TotalLatency    time.Duration
}

type HeaderFlags []string

func (h *HeaderFlags) String() string {
	return strings.Join(*h, ", ")
}

func (h *HeaderFlags) Set(value string) error {
	*h = append(*h, value)
	return nil
}

func main() {
	config := Config{}
	var headers HeaderFlags
	var durationStr string

	flag.StringVar(&config.URL, "h", "", "Target URL (required)")
	flag.StringVar(&config.Method, "m", "GET", "HTTP method")
	flag.IntVar(&config.Connections, "c", 1, "Number of concurrent connections")
	flag.IntVar(&config.Threads, "t", 1, "Number of threads")
	flag.StringVar(&durationStr, "d", "10s", "Duration of test (e.g., 10s, 1m)")
	flag.Var(&headers, "H", "Custom headers (can be used multiple times)")
	flag.StringVar(&config.Body, "body", "", "Request body")
	flag.StringVar(&config.CertFile, "cert", "", "Path to client certificate file (PEM)")
	flag.StringVar(&config.KeyFile, "key", "", "Path to client key file (PEM)")
	flag.StringVar(&config.TLSCertFile, "tls-cert", "", "Path to server CA certificate file (PEM) for verification")
	flag.BoolVar(&config.Insecure, "insecure", false, "Skip TLS certificate verification")

	flag.Parse()

	if config.URL == "" {
		fmt.Println("Error: URL is required")
		flag.Usage()
		os.Exit(1)
	}

	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		fmt.Printf("Error parsing duration: %v\n", err)
		os.Exit(1)
	}
	config.Duration = duration
	config.Headers = headers

	fmt.Printf("Starting benchmark...\n")
	fmt.Printf("URL: %s\n", config.URL)
	fmt.Printf("Method: %s\n", config.Method)
	fmt.Printf("Connections: %d\n", config.Connections)
	fmt.Printf("Threads: %d\n", config.Threads)
	fmt.Printf("Duration: %s\n", config.Duration)
	fmt.Printf("Headers: %v\n", config.Headers)
	if config.Body != "" {
		fmt.Printf("Body: %s\n", config.Body)
	}
	fmt.Println()

	result := runBenchmark(config)
	printResults(result)
}

func runBenchmark(config Config) Result {
	result := Result{
		MinLatency: time.Hour,
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	client := createHTTPClient(config)
	endTime := time.Now().Add(config.Duration)

	connectionsPerThread := config.Connections / config.Threads
	if connectionsPerThread < 1 {
		connectionsPerThread = 1
	}

	for t := 0; t < config.Threads; t++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for c := 0; c < connectionsPerThread; c++ {
				wg.Add(1)
				go func() {
					defer wg.Done()

					for time.Now().Before(endTime) {
						start := time.Now()
						success := makeRequest(client, config)
						latency := time.Since(start)

						mu.Lock()
						result.TotalRequests++
						if success {
							result.SuccessRequests++
						} else {
							result.FailedRequests++
						}
						result.TotalLatency += latency
						if latency < result.MinLatency {
							result.MinLatency = latency
						}
						if latency > result.MaxLatency {
							result.MaxLatency = latency
						}
						mu.Unlock()
					}
				}()
			}
		}()
	}

	startTime := time.Now()
	wg.Wait()
	result.TotalDuration = time.Since(startTime)

	return result
}

func createHTTPClient(config Config) *http.Client {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.Insecure,
	}

	// Load client certificate for mutual TLS
	if config.CertFile != "" && config.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			fmt.Printf("Warning: Failed to load client certificate: %v\n", err)
		} else {
			tlsConfig.Certificates = []tls.Certificate{cert}
		}
	}

	// Load server CA certificate for verification
	if config.TLSCertFile != "" {
		caCert, err := os.ReadFile(config.TLSCertFile)
		if err != nil {
			fmt.Printf("Warning: Failed to read CA certificate: %v\n", err)
		} else {
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				fmt.Printf("Warning: Failed to parse CA certificate\n")
			} else {
				tlsConfig.RootCAs = caCertPool
			}
		}
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

func makeRequest(client *http.Client, config Config) bool {
	var body io.Reader
	if config.Body != "" {
		body = strings.NewReader(config.Body)
	}

	req, err := http.NewRequest(config.Method, config.URL, body)
	if err != nil {
		return false
	}

	for _, header := range config.Headers {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	io.Copy(io.Discard, resp.Body)

	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

func printResults(result Result) {
	fmt.Println("=== Benchmark Results ===")
	fmt.Printf("Total Requests:   %d\n", result.TotalRequests)
	fmt.Printf("Successful:       %d\n", result.SuccessRequests)
	fmt.Printf("Failed:           %d\n", result.FailedRequests)
	fmt.Printf("Duration:         %s\n", result.TotalDuration)
	fmt.Printf("Requests/sec:     %.2f\n", float64(result.TotalRequests)/result.TotalDuration.Seconds())

	if result.TotalRequests > 0 {
		avgLatency := result.TotalLatency / time.Duration(result.TotalRequests)
		fmt.Printf("\nLatency Statistics:\n")
		fmt.Printf("  Min:            %s\n", result.MinLatency)
		fmt.Printf("  Max:            %s\n", result.MaxLatency)
		fmt.Printf("  Average:        %s\n", avgLatency)
	}
}

// Made with Bob
