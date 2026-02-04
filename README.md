# rewrk2 - HTTP(S) Benchmarking Tool

A Go-based HTTP(S) benchmarking utility with support for concurrent connections, custom headers, request bodies, and TLS client certificates.

## Features

- Multiple concurrent connections and threads
- Custom HTTP methods (GET, POST, PUT, DELETE, etc.)
- Custom headers support
- Request body support
- TLS/HTTPS support with client certificates
- Insecure mode for self-signed certificates
- Detailed latency statistics
- Token-based authentication from file

## Building

```bash
go build -o rewrk2 main.go
# Or use make
make build
```

## Quick Start

The easiest way to run the benchmark with authentication is using the provided script:

```bash
./run-bench.sh
```

This script:
1. Sources `token-from-file.sh` to load the bearer token from `~/.local/mcpgateway-bearer-token.txt`
2. Runs the benchmark with the same parameters as the original `bench-rewrk.sh`

## Usage

```bash
./rewrk2 [flags]
```

### Flags

- `-h` : Target URL (required)
- `-m` : HTTP method (default: GET)
- `-c` : Number of concurrent connections (default: 1)
- `-t` : Number of threads (default: 1)
- `-d` : Duration of test, e.g., 10s, 1m (default: 10s)
- `-H` : Custom headers (can be used multiple times)
- `-body` : Request body
- `-cert` : Path to client certificate file (PEM)
- `-key` : Path to client key file (PEM)
- `-insecure` : Skip TLS certificate verification

## Examples

### Basic GET request

```bash
./rewrk2 -h https://example.com -c 10 -t 4 -d 30s
```

### POST request with headers and body (matching the original shell script)

```bash
./rewrk2 -c 8 -t 8 -d 10s \
  -m POST \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -body '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_system_time","arguments":{"timezone":"UTC"}}}' \
  -h https://localhost:3000/mcp/
```

### Using client certificates

```bash
./rewrk2 -h https://localhost:3000 \
  -cert cert.pem \
  -key key.pem \
  -c 10 -t 4 -d 10s
```

### Self-signed certificates (insecure mode)

```bash
./rewrk2 -h https://localhost:3000 \
  -insecure \
  -c 10 -t 4 -d 10s
```

## Output

The tool provides detailed statistics including:
- Total requests made
- Successful and failed requests
- Requests per second
- Latency statistics (min, max, average)

Example output:
```
Starting benchmark...
URL: https://localhost:3000/mcp/
Method: POST
Connections: 8
Threads: 8
Duration: 10s
Headers: [Authorization: Bearer token, Content-Type: application/json]
Body: {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_system_time","arguments":{"timezone":"UTC"}}}

=== Benchmark Results ===
Total Requests:   12543
Successful:       12543
Failed:           0
Duration:         10.002s
Requests/sec:     1253.75

Latency Statistics:
  Min:            2.145ms
  Max:            45.231ms
  Average:        6.378ms
```

## Certificate Files

The repository includes sample certificate files:
- `cert.pem` - Server/client certificate
- `key.pem` - Server/client private key

These can be used for testing HTTPS endpoints with client certificate authentication.