FROM rust:1-trixie AS builder

RUN mkdir -p /usr/src/pterodapter
WORKDIR /usr/src/pterodapter

COPY . /usr/src/pterodapter

RUN apt-get update &&\
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libcap2-bin &&\
    apt-get dist-clean

ARG RUSTFLAGS

RUN cd /usr/src/pterodapter &&\
    cargo build --release &&\
    chmod 755 target/release/pterodapter &&\
    chown root:root target/release/pterodapter &&\
    setcap cap_net_raw,cap_net_admin+eip target/release/pterodapter

FROM gcr.io/distroless/cc-debian13:nonroot

COPY --from=builder /usr/src/pterodapter/target/release/pterodapter /usr/local/bin/

ENV RUST_TRACEBACK=full

ENTRYPOINT ["pterodapter"]
