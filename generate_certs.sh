#!/usr/bin/env bash

set -euo pipefail

if ! command -v openssl &>/dev/null; then
  echo "Error: openssl is not installed. Please install it to generate certificates." >&2
  exit 1
fi

echo "Generating private key (key.pem)..."
openssl genpkey -algorithm RSA -out key.pem

echo "Generating self-signed certificate (cert.pem)..."
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost" \
  -addext "basicConstraints=CA:FALSE"


echo "TLS certificate and key generated successfully:"
echo "  - key.pem"
echo "  - cert.pem"
