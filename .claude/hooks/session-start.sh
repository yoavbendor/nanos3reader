#!/bin/bash
# SessionStart hook for Claude Code on the web.
#
# nanos3reader builds on libcurl (range GETs) + OpenSSL libcrypto (SigV4 SHA-256), resolved via
# find_package(CURL) / find_package(OpenSSL). A fresh web sandbox doesn't ship the -dev headers, so a
# standalone `cmake -S . -B build` fails at find_package(CURL). Install them here.
#
# Note on `apt-get update`: this environment's network policy 403s a couple of third-party PPAs
# (deadsnakes, ondrej/php), which makes a normal `apt-get update` exit non-zero. The main Ubuntu archive
# IS reachable, so we update from ubuntu.sources only and leave the PPAs untouched.
set -euo pipefail

# Only meaningful in the remote (web) sandbox; a local machine manages its own toolchain.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

# Idempotent: skip the apt work entirely if the headers are already present (e.g. hook re-run on resume).
if [ -f /usr/include/x86_64-linux-gnu/curl/curl.h ] && [ -f /usr/include/openssl/sha.h ]; then
  echo "nanos3reader: libcurl + openssl dev headers already present, nothing to do."
  exit 0
fi

export DEBIAN_FRONTEND=noninteractive

# Update from the main Ubuntu archive only (skip the policy-blocked PPAs that would fail the whole update).
sudo apt-get update \
  -o Dir::Etc::SourceParts=/dev/null \
  -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/ubuntu.sources

sudo apt-get install -y --no-install-recommends libcurl4-openssl-dev libssl-dev

echo "nanos3reader: installed libcurl4-openssl-dev + libssl-dev."
