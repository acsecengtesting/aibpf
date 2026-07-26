FROM ubuntu:24.04

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
    git curl python3 socat ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /workspace /var/run/aibpf /usr/lib/aibpf

# Thin credential client (talks to sidecar via socket)
COPY credential-client.sh /usr/lib/aibpf/git-credential-aibpf
RUN chmod +x /usr/lib/aibpf/git-credential-aibpf

# Locked-down git config
COPY gitconfig /etc/gitconfig

WORKDIR /workspace
