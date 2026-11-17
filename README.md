# Anubis POW Solver RS

[![Solvers](https://github.com/PixelMelt/anubis-solver-rs/actions/workflows/solvers.yml/badge.svg)](https://github.com/PixelMelt/anubis-solver-rs/actions/workflows/solvers.yml)
![fast](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/PixelMelt/anubis-solver-rs/status/fast.json)
![slow](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/PixelMelt/anubis-solver-rs/status/slow.json)
![preact](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/PixelMelt/anubis-solver-rs/status/preact.json)
![metarefresh](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/PixelMelt/anubis-solver-rs/status/metarefresh.json)
![sha256](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/PixelMelt/anubis-solver-rs/status/sha256.json)
![hashx](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/PixelMelt/anubis-solver-rs/status/hashx.json)
![argon2id](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/PixelMelt/anubis-solver-rs/status/argon2id.json)

![Rust logo](./docs/rusty.png)

Solves proof-of-work challenges served by [TecharoHQ/anubis](https://github.com/TecharoHQ/anubis) (e.g., https://anubis.techaro.lol/).

This is a Rust implementation designed for speed and efficiency.

## Usage

### Proxy Server

A proxy server is included that automatically solves Anubis challenges

The proxy caches cookies per host, so subsequent requests to the same host reuse the solved challenge.


```bash
# Start the proxy (default port 8192)
cargo run --release --bin anubis-proxy

# Or with custom port
PORT=3000 cargo run --release --bin anubis-proxy

# Give up on challenges that take longer than 30s to solve (default 60)
SOLVE_TIMEOUT_SECS=30 cargo run --release --bin anubis-proxy
```

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8192` | Port the proxy listens on |
| `SOLVE_TIMEOUT_SECS` | `60` | Longest a challenge may take to solve. Past it the solve is stopped and the proxy answers `504 Gateway Timeout` |

#### Docker

```bash
# Using docker compose
docker compose up -d

# Or build and run directly
docker build -t anubis-proxy .
docker run -p 8192:8192 anubis-proxy
```

#### Usage

`GET /proxy/<host>/<path>`

```bash
# Fetch a page through the proxy
curl http://localhost:8192/proxy/example.com/some/path

# Health check
curl http://localhost:8192/health
```

## Supported Challenge Types

| Algorithm | Type | Description |
|-----------|------|-------------|
| `fast` | PoW | Find nonce where SHA256(data + nonce) has N leading zero nibbles |
| `slow` | PoW | Same as `fast`, typically with higher difficulty |
| `preact` | Time-based | SHA256 hash + 125ms × difficulty wait |
| `metarefresh` | Time-based | Echo challenge data + (difficulty + 1)s wait |
| `sha256` | PoW (WASM) | Find u32 nonce where SHA256(data bytes + nonce) has N leading zero bits |
| `hashx` | PoW (WASM) | Find u32 nonce where HashX(seed = data bytes)(nonce) has N leading zero bits |
| `argon2id` | PoW (WASM) | Find u32 nonce where Argon2id(password = data bytes, salt = nonce) has N leading zero bits |

Every solver is checked daily against the latest Anubis release. To run the same check locally (needs Docker):

```bash
.github/scripts/check-solvers.sh
```


### Library

Add to your `Cargo.toml`:

```toml
[dependencies]
anubis_solver = { git = "https://github.com/pix/anubis-solver-rs" }
```

Basic usage:

```rust
use anubis_solver::{
    parse_challenge_from_html, parse_base_prefix, parse_prefetch_urls,
    solve_challenge, build_submission_url_with_prefix,
    AnubisChallenge, SolverResult,
};

// Parse challenge from HTML response
let html = /* fetch challenge page */;
if let Some(parsed) = parse_challenge_from_html(&html) {
    let challenge = &parsed.challenge;

    // Fetch what the page loads that the server checks for (e.g. the css-load
    // extension), resolved against the page URL, with the same cookies
    for url in parse_prefetch_urls(&html) {
        /* GET url */
    }

    // Solve the challenge (auto-detects algorithm)
    let result = solve_challenge::<fn(u64)>(challenge, None)?;

    // Wait if required (time-based challenges)
    if let Some(min_wait) = challenge.min_wait() {
        std::thread::sleep(min_wait);
    }

    // Build submission URL, under the path prefix Anubis is served at (if any)
    let url = build_submission_url_with_prefix(
        "https",
        "example.com",
        &parse_base_prefix(&html),
        challenge,
        &result,
        "https://example.com/original",
        elapsed_ms,
    );

    // Submit to url with the same cookies, expect 302 redirect
}
```

For PoW challenges with progress reporting:

```rust
let callback = |nonce: u64| {
    println!("Trying nonce: {}", nonce);
};
let result = solve_challenge(&challenge, Some(callback))?;
```

To give up on a solve, e.g. after a timeout, use `solve_challenge_with_cancel` and set the flag from another thread. It then returns `Err`:

```rust
let cancel = std::sync::atomic::AtomicBool::new(false);
let result = solve_challenge_with_cancel::<fn(u64)>(&challenge, None, &cancel);
```