FROM rust:1.99-trixie AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p test-helpers \
 && cp target/release/test-helpers /test-helpers

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin echo
COPY --from=build /test-helpers /usr/local/bin/test-helpers
USER echo
EXPOSE 8000 8081
ENTRYPOINT ["/usr/local/bin/test-helpers"]
