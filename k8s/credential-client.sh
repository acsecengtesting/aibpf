#!/bin/sh
# Thin credential helper client for inside the agent container.
# Talks to the credential service sidecar over unix socket.
# Install at /usr/lib/aibpf/git-credential-aibpf in the agent image.
#
# Usage: git credential helper protocol (stdin/stdout)

SOCKET="/var/run/aibpf/cred.sock"

if [ "$1" != "get" ]; then
    exit 0
fi

if [ ! -S "$SOCKET" ]; then
    echo "aibpf-credential: socket not found: $SOCKET" >&2
    exit 1
fi

# Forward stdin to socket, read response
exec socat - UNIX-CONNECT:"$SOCKET"
