# Build
FROM rust:slim AS builder
WORKDIR /app
COPY Cargo.toml ./
COPY src ./src
COPY assets ./assets
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/* \
    && cargo build --release

# Run
FROM debian:trixie-slim
WORKDIR /app
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/telegrambot /app/bot
COPY --from=builder /app/assets /app/assets
CMD ["/app/bot"]
