#!/bin/bash
# write_file.sh - Workaround for Kiro permission loop on backslash paths (kirodotdev/Kiro#9507)
# Usage: write_context.sh <filepath> <content>
# Or pipe content: echo "content" | write_context.sh <filepath>

set -e

TARGET="$1"

if [ -z "$TARGET" ]; then
  echo "Usage: write_context.sh <filepath> [content]" >&2
  echo "  If content is not provided, reads from stdin" >&2
  exit 1
fi

# Ensure parent directory exists
mkdir -p "$(dirname "$TARGET")"

if [ -n "$2" ]; then
  # Content passed as second argument
  printf '%s' "$2" > "$TARGET"
else
  # Read from stdin
  cat > "$TARGET"
fi

echo "Wrote: $TARGET"
