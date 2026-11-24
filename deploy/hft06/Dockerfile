# Build from the repository root: docker build -f deploy/hft06/Dockerfile .
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p shz-relay --bins --features live

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 shz
COPY --from=build /src/target/release/shz-relay /src/target/release/shz-collator /usr/local/bin/
USER shz
WORKDIR /var/lib/shz
ENTRYPOINT ["shz-relay"]
