# agent-blocker

A [Claude Code](https://docs.anthropic.com/en/docs/claude-code) `PreToolUse` hook that evaluates
every tool call before it executes and decides whether to **allow**, **deny**, or **ask** (prompt
you for confirmation).

Its goal is to eliminate approval fatigue by reasoning through commands with more intelligence than the 
built-in logic. It DOES NOT guarantee safe execution, nor that approved commands are safe.

## How it works

Claude Code invokes `agent-blocker` as a hook before every tool use. The hook receives a JSON event
on stdin describing the tool and its arguments, evaluates it against a set of rules, and writes a
JSON decision to stdout.

```
Claude Code ──stdin──▶ agent-blocker ──stdout──▶ { "decision": "allow" | "deny" | "ask" }
```

Rules come from two sources:

1. **Built-in defaults** — these matchers (see `pkg/rules`) allow for more complicated logic than 
   Claude Code's permissions system
2. **Your Claude Code settings** — permissions defined in `~/.claude/settings.json`,
   `~/.claude/settings.local.json`, and the project-level equivalents under `.claude/`

When multiple rules match, the most specific one wins. At equal specificity, the strictest decision
wins (deny > ask > allow).

### What it understands

- **Bash commands** — glob patterns with shell-aware quoting; compound commands (`&&`, `||`, `;`,
  `|`) are split and each sub-command is evaluated independently
- **Command wrappers** — sees through `timeout`, `xargs`, and output redirects to evaluate the
  underlying command
- **File operations** (Read, Edit, Grep, Glob) — gitignore-style path patterns with `~` and
  project-relative resolution; specificity ranking (exact path > glob > match-all)
- **`cd`** — allows navigation within the project root or `/tmp`, blocks everything else
- **`find` / `fd`** — allows searches within the project tree, blocks dangerous flags like `-exec`
  and `-delete`
- **`echo`** — auto-allows echo/printf (safe, read-only operations)
- **`mkdir`** — allows directory creation within the project root or `/tmp`
- **Local scripts** — auto-allows execution of programs within the project directory tree
  (e.g., `./script.sh`, `bin/test`)
- **MCP tools** — glob matching on MCP tool names (e.g., `mcp__gopls__go_*`)
- **`ctx_batch_execute`** — evaluates each command in the batch through the full Bash pipeline

### Logging

Every invocation is logged as JSON Lines to `~/Library/Logs/agent-blocker/<project>.log` (macOS).
Logs are capped at 5 MB per project and include the tool name, decision, reason, and sanitized
input (large content from Write/Edit is replaced with byte lengths).

## Installation

### From source (requires Go 1.24+)

```bash
go install github.com/tdeebswihart/agent-blocker/cmd@latest
# The binary is named "cmd" — rename it:
mv "$(go env GOPATH)/bin/cmd" "$(go env GOPATH)/bin/agent-blocker"
```

### With mise

If you've cloned the repo:

```bash
mise run install
# Installs to ~/.local/bin/agent-blocker
```

### With Nix

```bash
nix run github.com/tdeebswihart/agent-blocker
# Or add to your flake inputs:
# agent-blocker.url = "github.com/tdeebswihart/agent-blocker";
```

## Configuration

### 1. Register the hook

Add agent-blocker as a `PreToolUse` hook in your Claude Code settings. The empty `matcher` means it
runs for every tool call.

**`~/.claude/settings.json`** (global) or **`<project>/.claude/settings.json`** (per-project):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "agent-blocker"
          }
        ]
      }
    ]
  }
}
```

### 2. Define permissions

agent-blocker reads the `permissions` block from all four Claude Code settings files (global,
global-local, project, project-local). These rules are then enforced using the more powerful
matcher primitives in `pkg/rules`.

```json
{
  "permissions": {
    "allow": [
      "Read",
      "Edit",
      "Glob",
      "Grep",
      "Bash(go test:*)",
      "Bash(go build:*)",
      "Bash(jj log:*)",
      "Bash(jj diff:*)",
      "mcp__gopls__*"
    ],
    "deny": [
      "Bash(rm -rf:*)",
      "Read(~/.ssh/**)"
    ]
  }
}
```

#### Permission syntax

| Format | Example | Matches |
|---|---|---|
| `ToolName` | `Read` | All invocations of that tool |
| `ToolName(pattern)` | `Bash(go test:*)` | Tool invocations matching the pattern |
| `mcp__*` glob | `mcp__gopls__go_*` | MCP tools matching the glob |

For **Bash** rules, `:*` is shorthand for ` *` (space-star), which matches the command with any
trailing arguments or no arguments at all. For example, `Bash(go test:*)` matches both `go test`
and `go test ./...`.

For **Read**, **Edit**, **Grep**, and **Glob** rules, the pattern argument is a gitignore-style path
pattern. `~` expands to your home directory, and relative paths are resolved against the project
root.

## How decisions are resolved

1. All matching rules are collected from both built-in defaults and settings
2. The **most specific** match wins (exact path > glob path > match-all)
3. At equal specificity, the **strictest** decision wins (deny > ask > allow)
4. If nothing matches, the hook returns no output (passes through to Claude Code's default behavior)

For compound Bash commands, each sub-command is evaluated independently and the most restrictive
result across all sub-commands is returned.
