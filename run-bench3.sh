#!/usr/bin/env bash

set -ueo pipefail

# Source the token file to get AUTH variable
source ./token-from-file.sh

# Run the benchmark with the same parameters as bench-rewrk.sh
time target/release/rewrk3 -c 10 -t 1 -d 10s \
  -m POST \
  -H "Authorization: $AUTH" \
  -H "Content-Type: application/json" \
  --body '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_system_time","arguments":{"timezone":"UTC"}}}' \
    --tls-cert cert.pem \
  -h https://localhost:3000/mcp/

exit 
# Made with Bob
--insecure \

