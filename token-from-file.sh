#!/usr/bin/env -S bash

set -ueo pipefail

#export RUST_LOG="reqwest=trace,hyper=trace"

TOKEN_FILE="$HOME/.local/mcpgateway-bearer-token.txt"
if [ ! -f "$TOKEN_FILE" ]; then
	echo "Error: Token file not found at $TOKEN_FILE" >&2
	exit 1
fi

AUTH="Bearer $(tr -d '\r\n' <"$TOKEN_FILE")"
ITERS=1
