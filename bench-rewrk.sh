
source ./token-from-file.sh

rewrk -c 8 -t 8 -d 10s \
  -m POST \
  -H "Authorization: $AUTH" \
  -H "Content-Type: application/json" \
  --body '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_system_time","arguments":{"timezone":"UTC"}}}' \
  -h https://localhost:3000/mcp/