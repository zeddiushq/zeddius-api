FROM rust:1-slim-bookworm AS build
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY .sqlx .sqlx
COPY migrations migrations
COPY src src

ENV SQLX_OFFLINE=true
RUN cargo build --release

FROM debian:bookworm-slim AS runtime
WORKDIR /app

COPY --from=build /app/target/release/zeddius-api /app/zeddius-api

EXPOSE 8080
CMD ["/app/zeddius-api"]
