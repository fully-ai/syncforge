#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo clippy --all-targets -- -D warnings
cargo test --verbose
