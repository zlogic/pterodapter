FROM registry.access.redhat.com/hi/rust:latest AS builder

RUN mkdir -p /usr/src/pterodapter
WORKDIR /usr/src/pterodapter

COPY . /usr/src/pterodapter

ARG RUSTFLAGS

RUN cd /usr/src/pterodapter &&\
    cargo build --release &&\
    chmod 755 target/release/pterodapter &&\
    chown root:root target/release/pterodapter &&\
    setcap cap_net_raw,cap_net_admin+eip target/release/pterodapter

FROM registry.access.redhat.com/hi/core-runtime:latest

COPY --from=builder /usr/src/pterodapter/target/release/pterodapter /usr/local/bin/

ENV RUST_TRACEBACK=full

ENTRYPOINT ["pterodapter"]
