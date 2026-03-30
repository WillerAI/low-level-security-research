FROM rust:1.75 as builder
WORKDIR /usr/src/msik
COPY . .
RUN cargo install --path .

FROM debian:bookworm-slim
COPY --from=builder /usr/local/cargo/bin/msik /usr/local/bin/msik
CMD ["msik"]
