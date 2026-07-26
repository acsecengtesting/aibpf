FROM ubuntu:24.04

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
    git curl python3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /workspace /run/secrets /opt/aibpf/bpf /opt/aibpf/bin \
    /usr/lib/aibpf /etc/aibpf

# Git credential helper and config go in read-only layer
COPY git-credential-aibpf /usr/lib/aibpf/git-credential-aibpf
COPY gitconfig /etc/gitconfig
COPY policy.yaml /etc/aibpf/policy.yaml

WORKDIR /workspace
