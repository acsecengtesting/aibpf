FROM ubuntu:24.04

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
    git curl python3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /workspace /run/secrets /opt/aibpf/bpf /opt/aibpf/bin

WORKDIR /workspace
