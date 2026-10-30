# One image with every binary; compose and the cluster pick which one to run.
FROM rust:1.99-trixie AS build
WORKDIR /src
COPY . .
# Extra features, e.g. "hub/alloc-stats,edge/alloc-stats" for measurements (docker-compose.perf.yml).
ARG CARGO_FEATURES=""
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p hub -p edge -p test-api -p org-sync ${CARGO_FEATURES:+--features "$CARGO_FEATURES"} \
 && mkdir /out \
 && cp target/release/hub target/release/edge target/release/test-api target/release/org-sync /out/

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin broker
COPY --from=build /out/ /usr/local/bin/
USER broker
