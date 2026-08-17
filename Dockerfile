FROM rust:1.97.1-slim-trixie AS build
WORKDIR /build
COPY Cargo.toml ./
COPY src ./src
RUN cargo build --release

FROM debian:trixie-slim
RUN useradd --system --uid 10001 --create-home kipp
COPY --from=build /build/target/release/kipp /usr/local/bin/kipp
USER kipp
WORKDIR /home/kipp
ENV KIPP_DATA=/data KIPP_CONFIG=/etc/kipp/kipp.toml
EXPOSE 2222
ENTRYPOINT ["/usr/local/bin/kipp"]
