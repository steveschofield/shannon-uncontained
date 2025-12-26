#!/usr/bin/env bash
set -euo pipefail

# Install repository Git hooks via core.hooksPath to .githooks

if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "❌ Not a git repository" >&2; exit 1
fi

echo "🔗 Setting hooks path to .githooks"
git config core.hooksPath .githooks

echo "🔧 Making hooks executable"
chmod +x .githooks/* || true

echo "✅ Git hooks installed"
