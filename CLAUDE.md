# Agent Blocker

Claude Code PreToolUse hook that auto-allows safe tool calls and blocks dangerous ones.

## Language & Tooling

- Go 1.26 — use modern features like `new(value)` for pointer literals instead of helper functions.
- Lint: `mise run lint` (runs `go fix`, `golangci-lint fmt`, `golangci-lint run --fix`).
- Test: `go test ./...`
- Install: `mise run install`

## Code Style

- Wrap new code at 100 characters. Leave existing formatting unchanged.
- Prefer minimal, targeted fixes over over-engineered solutions.
- `errcheck` linter is enabled. Use `//nolint:errcheck` only where errors are intentionally
  discarded (e.g., fire-and-forget logging). Do not add unused nolint directives — `nolintlint`
  will reject them.

## Version Control

Use jj (jujutsu), not git. Create new commits rather than editing existing ones.

```bash
jj new <parent>         # create mutable working revision
jj commit -m "message"  # commit and create fresh working revision
jj bookmark set -r @- tim/<name>  # or `jj tug` if bookmark exists
```

## Project Structure

- `cmd/main.go` — entry point, reads hook JSON from stdin, writes decision to stdout
- `pkg/rules/` — rule types (Bash, Read, Edit, Glob, Grep, etc.), harness, path matching
- `pkg/logging/` — per-session JSON Lines logging to `~/Library/Logs/agent-blocker/`
