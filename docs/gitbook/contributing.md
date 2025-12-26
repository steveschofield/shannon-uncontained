# Contributing

This project favors a simple, reliable developer workflow. You only need your usual commit commands plus one safe push step.

## Simple Push Workflow

1) Stage and commit

```bash
git add -A
git commit -m "feat(lsg-v2): your change"
```

2) Push (rebases + tests)

```bash
# Makefile target
make push

# or NPM script
npm run push
```

Under the hood this will:

- Stash uncommitted changes
- Fetch remotes
- Rebase your branch onto `upstream/<branch>` if present, otherwise `origin/<branch>`
- Run tests (pre-push hook); block on failures
- Push to `origin`
- Restore your stash

Emergency skip tests (not recommended):

```bash
SKIP_TESTS=1 npm run push
```

## VS Code One‑Click

- Command Palette → “Tasks: Run Task” → “Git: Sync (Rebase + Push)”
- NPM Scripts view → run “push”
- Pull/Sync uses rebase by default in this repo

## First‑Time Setup

Hooks install automatically on `npm install`. Manual install:

```bash
./scripts/install-git-hooks.sh
```

## Commit Message Format

Enforced by a commit-msg hook (bypass with `SKIP_COMMIT_LINT=1`):

```
type(scope): Short description

Types: feat, fix, docs, refactor, test, chore
Example: feat(lsg-v2): Register APISchemaGenerator
```

