#!/usr/bin/env bash
# Installs the ProjectDiscovery OSS chain that gridscan orchestrates.
# Requires Go >= 1.21 (https://go.dev/dl/). Binaries land in $(go env GOPATH)/bin.
set -euo pipefail

if ! command -v go >/dev/null 2>&1; then
  echo "Go not found. Install Go >= 1.21 first: https://go.dev/dl/" >&2
  exit 1
fi

echo "Installing ProjectDiscovery tools via 'go install'..."
GO111MODULE=on
tools=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"      # needs libpcap-dev
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
)
for t in "${tools[@]}"; do
  echo "  -> $t"
  go install -v "$t"
done

echo
echo "Ensure \$(go env GOPATH)/bin is on your PATH:"
echo "  export PATH=\"\$PATH:\$(go env GOPATH)/bin\""
echo
echo "Fetching Nuclei templates..."
"$(go env GOPATH)/bin/nuclei" -update-templates || true

echo
echo "Note: naabu needs libpcap (Debian/Ubuntu: sudo apt install -y libpcap-dev)."
echo "gridscan runs fine without naabu — httpx just probes default web ports."
echo "Done."
