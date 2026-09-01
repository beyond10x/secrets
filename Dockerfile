# syntax=docker/dockerfile:1.7
FROM rust:1.97.0-bookworm AS builder
WORKDIR /source
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY docs ./docs
RUN --mount=type=cache,id=secrets-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=secrets-target,target=/source/target,sharing=locked \
    cargo build --locked --release -p secrets-app -p secretsctl && \
    install -D /source/target/release/secrets /out/secrets && \
    install -D /source/target/release/secretsctl /out/secretsctl

FROM gcr.io/distroless/cc-debian12:nonroot
ARG SOURCE_SHA=unknown
LABEL org.opencontainers.image.source="https://github.com/beyond10x/secrets" \
      org.opencontainers.image.revision=$SOURCE_SHA \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=builder /out/secrets /usr/local/bin/secrets
COPY --from=builder /out/secretsctl /usr/local/bin/secretsctl
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/secrets"]

