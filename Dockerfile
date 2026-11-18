FROM rust:1.83-slim AS build
WORKDIR /src
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN useradd -m -u 10001 syncforge
COPY --from=build /src/target/release/syncforge /usr/local/bin/syncforge
RUN mkdir -p /vault /source && chown syncforge:syncforge /vault /source
USER syncforge
ENV SYNCFORGE_REPO=/vault
ENTRYPOINT ["syncforge"]
CMD ["--help"]
