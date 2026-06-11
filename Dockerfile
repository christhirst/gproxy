# Build stage
FROM docker.io/library/rust:1.85-slim AS builder

# Install build dependencies for Pingora
RUN apt-get update && apt-get install -y \
    cmake \
    build-essential \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/gproxy
COPY . .
RUN cargo build --release

# Runtime stage
FROM docker.io/library/debian:bookworm-slim

# Install runtime dependencies (OpenSSL 3 and CA certificates)
RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy build artifacts and config
COPY --from=builder /usr/src/gproxy/target/release/gproxy /usr/local/bin/gproxy
COPY config.yaml /etc/gproxy/config.yaml

WORKDIR /etc/gproxy
EXPOSE 8080

CMD ["gproxy"]
