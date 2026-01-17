# Anubis POW Solver RS

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
```

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
| `preact` | Time-based | SHA256 hash + 80ms × difficulty wait |
| `metarefresh` | Time-based | Echo challenge data + 800ms × difficulty wait |


### Library

Add to your `Cargo.toml`:

```toml
[dependencies]
anubis_solver = { git = "https://github.com/pix/anubis-solver-rs" }
```

Basic usage:

```rust
use anubis_solver::{
    parse_challenge_from_html, solve_challenge, build_submission_url,
    AnubisChallenge, SolverResult,
};

// Parse challenge from HTML response
let html = /* fetch challenge page */;
if let Some(parsed) = parse_challenge_from_html(&html) {
    let challenge = &parsed.challenge;
    
    // Solve the challenge (auto-detects algorithm)
    let result = solve_challenge::<fn(u64)>(challenge, None)?;
    
    // Wait if required (time-based challenges)
    if let Some(min_wait) = challenge.min_wait() {
        std::thread::sleep(min_wait);
    }
    
    // Build submission URL
    let url = build_submission_url(
        "https",
        "example.com",
        challenge,
        &result,
        "https://example.com/original",
        elapsed_ms,
    );
    
    // Submit to url, expect 302 redirect
}
```

For PoW challenges with progress reporting:

```rust
let callback = |nonce: u64| {
    println!("Trying nonce: {}", nonce);
};
let result = solve_challenge(&challenge, Some(callback))?;
```