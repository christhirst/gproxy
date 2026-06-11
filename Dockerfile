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

# Runtime stage - Distroless CC (contains glibc)
FROM gcr.io/distroless/cc-debian12

# Copy dynamic SSL libraries from builder stage
COPY --from=builder /usr/lib/x86_64-linux-gnu/libssl.so.3 /usr/lib/x86_64-linux-gnu/libssl.so.3
COPY --from=builder /usr/lib/x86_64-linux-gnu/libcrypto.so.3 /usr/lib/x86_64-linux-gnu/libcrypto.so.3

# Copy build artifacts and config
COPY --from=builder /usr/src/gproxy/target/release/gproxy /usr/local/bin/gproxy
COPY config.yaml /etc/gproxy/config.yaml

WORKDIR /etc/gproxy
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/gproxy"]
