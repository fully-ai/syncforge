$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
cargo clippy --all-targets -- -D warnings
cargo test --verbose
