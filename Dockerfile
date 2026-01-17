FROM rust:1.83-slim-bookworm AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock* ./

RUN mkdir -p src/bin && \
    echo "pub fn dummy() {}" > src/lib.rs && \
    echo "fn main() {}" > src/bin/proxy.rs

RUN cargo build --release --bin anubis-proxy && \
    rm -rf src

COPY src ./src

RUN touch src/lib.rs src/bin/proxy.rs && \
    cargo build --release --bin anubis-proxy

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/anubis-proxy /usr/local/bin/anubis-proxy

ENV PORT=8192

EXPOSE 8192

CMD ["anubis-proxy"]
