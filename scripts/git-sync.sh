#!/usr/bin/env bash
set -euo pipefail

# git-sync.sh — Safe rebase-based sync between local and remote
# - Stashes uncommitted changes
# - Fetches remotes
# - Rebases local branch onto upstream (upstream/<branch> if present, else origin/<branch>)
# - Pushes to your push remote (default: origin)
# - Restores your stashed work
#
# Usage:
#   ./scripts/git-sync.sh [--branch <name>] [--from <remote>] [--push <remote>] [--force]
#
# Examples:
#   ./scripts/git-sync.sh                # auto: rebase onto upstream/main if exists, else origin/main, push to origin
#   ./scripts/git-sync.sh --branch dev   # rebase dev branch
#   ./scripts/git-sync.sh --from origin  # rebase from origin/<branch>
#   ./scripts/git-sync.sh --force        # use --force-with-lease on push (only when needed)

BRANCH=""
FROM_REMOTE=""
PUSH_REMOTE="origin"
FORCE_PUSH="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --branch)
      BRANCH="$2"; shift 2;;
    --from)
      FROM_REMOTE="$2"; shift 2;;
    --push)
      PUSH_REMOTE="$2"; shift 2;;
    --force)
      FORCE_PUSH="true"; shift;;
    -h|--help)
      echo "Usage: $0 [--branch <name>] [--from <remote>] [--push <remote>] [--force]"; exit 0;;
    *) echo "Unknown option: $1"; exit 1;;
  esac
done

if ! git rev-parse --git-dir > /dev/null 2>&1; then
  echo "❌ Not a git repository" >&2; exit 1
fi

# Current branch
if [[ -z "$BRANCH" ]]; then
  BRANCH=$(git rev-parse --abbrev-ref HEAD)
fi

# Decide upstream (source of truth for rebase)
if [[ -z "$FROM_REMOTE" ]]; then
  if git remote get-url upstream >/dev/null 2>&1; then
    FROM_REMOTE="upstream"
  else
    FROM_REMOTE="origin"
  fi
fi

echo "🔎 Branch: $BRANCH"
echo "⬇️  Rebase from: $FROM_REMOTE/$BRANCH"
echo "⬆️  Push to:     $PUSH_REMOTE/$BRANCH"

# Ensure rebase on pull for this repo
git config pull.rebase true || true

# Stash uncommitted work
STASHED="false"
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "📦 Stashing uncommitted changes..."
  git stash push -u -m "git-sync: auto-stash $(date -Iseconds)" >/dev/null
  STASHED="true"
fi

echo "📥 Fetching remotes..."
git fetch "$FROM_REMOTE" --prune
if [[ "$PUSH_REMOTE" != "$FROM_REMOTE" ]]; then
  git fetch "$PUSH_REMOTE" --prune || true
fi

# Ensure branch tracks push remote if not already
if ! git rev-parse --abbrev-ref --symbolic-full-name @{u} >/dev/null 2>&1; then
  echo "🔗 Setting upstream to $PUSH_REMOTE/$BRANCH"
  git branch --set-upstream-to="$PUSH_REMOTE/$BRANCH" "$BRANCH" || true
fi

echo "🧱 Rebasing $BRANCH onto $FROM_REMOTE/$BRANCH..."
set +e
git rebase "$FROM_REMOTE/$BRANCH"
REB=$?
set -e

if [[ $REB -ne 0 ]]; then
  echo "⚠️  Rebase stopped due to conflicts. Resolve, then run:"
  echo "   git add -A && git rebase --continue"
  echo "   (or abort) git rebase --abort"
  exit $REB
fi

echo "🚀 Pushing to $PUSH_REMOTE/$BRANCH..."
if [[ "$FORCE_PUSH" == "true" ]]; then
  git push --force-with-lease "$PUSH_REMOTE" "$BRANCH"
else
  set +e
  git push "$PUSH_REMOTE" "$BRANCH"
  PUSHRC=$?
  set -e
  if [[ $PUSHRC -ne 0 ]]; then
    echo "⚠️  Non fast-forward push blocked. If remote moved again, rerun with --force"
    exit $PUSHRC
  fi
fi

# Restore stash if any
if [[ "$STASHED" == "true" ]]; then
  echo "📦 Restoring stashed changes..."
  set +e
  git stash pop
  POPRC=$?
  set -e
  if [[ $POPRC -ne 0 ]]; then
    echo "⚠️  Stash pop had conflicts. Resolve them, then continue as usual."
  fi
fi

echo "✅ Sync complete: $BRANCH is up to date with $FROM_REMOTE/$BRANCH and pushed to $PUSH_REMOTE"

