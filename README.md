# Anubis POW Solver RS

![Rust logo](./docs/rusty.png)

Solves proof-of-work challenges served by [TecharoHQ/anubis](https://github.com/TecharoHQ/anubis) (e.g., https://anubis.techaro.lol/).

This is a Rust implementation designed for speed and efficiency.

## Why?

If I dont need a browser to get past your WAF, its not great. This Rust version focuses on providing a fast, native solver.

## Usage

### Prerequisites

-   [Rust](https://www.rust-lang.org/tools/install) (latest stable version recommended)

### Building

Build the optimized release binary:

```bash
cargo build --release
```

### Running

To run the solver, provide the target URL using the `--url` flag:

```bash
cargo run --release -- --url <CHALLENGE_URL>

# Example using the alias from .cargo/config.toml
# cargo run-anubis # Runs with https://anubis.techaro.lol

# Running the compiled binary directly
./target/release/rust_solver --url <CHALLENGE_URL>
```

Replace `<CHALLENGE_URL>` with the actual URL of the Anubis challenge page (e.g., `https://anubis.techaro.lol`).

**Optional Flags:**

-   `--progress`: Show nonce checking progress updates during solving.
-   `--print-html`: After successfully solving and submitting the challenge, fetch and print the final HTML content of the target page. By default, the final HTML is not fetched.

Example with flags:

```bash
./target/release/rust_solver --url https://anubis.techaro.lol --progress --print-html
```

## License

[MIT](./LICENSE)
