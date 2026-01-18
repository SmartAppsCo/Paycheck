# Build stage
FROM rust:1.92-bookworm AS builder

# Build dependencies for boring-sys (BoringSSL) - enables FIPS compliance
RUN apt-get update && apt-get install -y \
    cmake \
    build-essential \
    golang \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependencies by building a dummy project first
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs
RUN cargo build --release && rm -rf src

# Build the actual application
COPY src ./src
RUN touch src/main.rs src/lib.rs && cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    sqlite3 \
    gosu \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user with high UID to avoid conflicts with host system users
RUN useradd --system --uid 10001 --shell /usr/sbin/nologin --create-home paycheck

# Create directories
RUN mkdir -p /var/lib/paycheck /etc/paycheck \
    && chown paycheck:paycheck /var/lib/paycheck /etc/paycheck

# Copy binary and entrypoint
COPY --from=builder /build/target/release/paycheck /usr/local/bin/paycheck
COPY docker/docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

WORKDIR /var/lib/paycheck

# Default environment
ENV HOST=0.0.0.0
ENV PORT=4242
ENV DATABASE_PATH=/var/lib/paycheck/paycheck.db
ENV AUDIT_DATABASE_PATH=/var/lib/paycheck/paycheck_audit.db
ENV RUST_LOG=paycheck=info,tower_http=info

EXPOSE 4242

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD sqlite3 /var/lib/paycheck/paycheck.db "SELECT 1" || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/usr/local/bin/paycheck"]
