# agent-blocker

A [Claude Code](https://docs.anthropic.com/en/docs/claude-code) `PreToolUse` hook that evaluates
every tool call before it executes and decides whether to **allow**, **deny**, or **ask** (prompt
you for confirmation).

Its goal is to reduce approval fatigue by applying richer matching logic than Claude Code's built-in
permission system. It does **not** guarantee that approved commands are safe.

## How it works

Claude Code invokes `agent-blocker` as a hook before every tool use. The hook receives a JSON event
on stdin describing the tool and its arguments, evaluates it against a set of rules, and writes a
JSON decision to stdout.

```
Claude Code ──stdin──▶ agent-blocker ──stdout──▶ { "decision": "allow" | "deny" | "ask" }
```

Rules come from two sources:

1. **Built-in defaults** (`pkg/rules/default.go`) — semantic matchers for `echo`, `mkdir`, `cd`,
   and local scripts that require argument-level validation beyond simple glob patterns
2. **Your Claude Code settings** — permissions defined in `~/.claude/settings.json`,
   `~/.claude/settings.local.json`, and the project-level equivalents under `.claude/`

When multiple rules match, the most specific one wins. At equal specificity, the strictest decision
wins (deny > ask > allow).

### What it understands

- **Bash commands** — glob patterns with shell-aware quoting; compound commands (`&&`, `||`, `;`,
  `|`) are split and each sub-command is evaluated independently
- **Command wrappers** — sees through `timeout`, `xargs`, and output redirects to evaluate the
  underlying command
- **File operations** (Read, Edit, Grep, Glob, Search) — gitignore-style path patterns with `~`
  and project-relative resolution; specificity ranking (exact path > glob > match-all)
- **`cd`** — allows navigation within the project root or `/tmp`, blocks everything else
- **`find` / `fd`** — allows searches within the project tree, blocks dangerous flags like `-exec`
  and `-delete`
- **`grep` / `rg`** — allows searches within the project tree; blocks file-reading flags (`-f`,
  `--file`, `--pre`, `--ignore-file`) that bypass path validation
- **`head` / `tail`** — allows invocations reading from stdin or safe file paths
- **`echo`** — auto-allows `echo`/`printf` (read-only)
- **`mkdir`** — allows directory creation within the project root or `/tmp`
- **`jj edit` / `jj abandon`** — allows only when the target revision(s) are empty; denies if any
  revision has changes
- **Local scripts** — auto-allows execution of programs within the project directory tree
  (e.g., `./script.sh`, `bin/test`)
- **MCP tools** — glob matching on MCP tool names (e.g., `mcp__gopls__go_*`)
- **WebFetch / WebSearch** — domain-based matching (e.g., `WebFetch(domain:docs.rs)`)
- **Agent / Skill** — glob matching on agent name/type or skill name
- **`ctx_batch_execute`** — evaluates each command in the batch through the full Bash pipeline

### Logging

Every invocation is logged as JSON Lines to `~/Library/Logs/agent-blocker/<project>.log` (macOS).
Logs are capped at 5 MB per project and include the tool name, decision, reason, and sanitized
input (large content from Write/Edit is replaced with byte lengths).

## Installation

### From source (requires Go 1.26+)

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
nix run github:tdeebswihart/agent-blocker
# Or add to your flake inputs:
# agent-blocker.url = "github:tdeebswihart/agent-blocker";
```

## Configuration

### 1. Register the hook

Add agent-blocker as a `PreToolUse` hook in your Claude Code settings. The `"*"` matcher means it
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
      "mcp__gopls__*",
      "WebFetch(domain:pkg.go.dev)"
    ],
    "deny": [
      "Bash(rm -rf:*)",
      "Read(~/.ssh/**)"
    ],
    "ask": [
      "Bash(curl:*)"
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
| `WebFetch(domain:host)` | `WebFetch(domain:pkg.go.dev)` | Fetch/search requests to a domain |
| `Agent(pattern)` | `Agent(task*)` | Agent invocations matching name or subagent type |
| `Skill(pattern)` | `Skill(/verify*)` | Skill invocations matching skill name |

For **Bash** rules, `:*` is shorthand for ` *` (space-star), which matches the command with any
trailing arguments or no arguments at all. For example, `Bash(go test:*)` matches both `go test`
and `go test ./...`.

For **Read**, **Edit**, **Grep**, **Glob**, and **Search** rules, the pattern argument is a
gitignore-style path pattern. `~` expands to your home directory, and relative paths are resolved
against the project root.

## How decisions are resolved

1. All matching rules are collected from both built-in defaults and settings.
2. The **most specific** match wins (exact path > glob path > match-all).
3. At equal specificity, the **strictest** decision wins (deny > ask > allow).
4. If nothing matches, the hook produces no output and Claude Code falls through to its own
   permission logic.

For compound Bash commands (`&&`, `||`, `;`, `|`), each sub-command is evaluated independently and
the most restrictive result across all sub-commands is returned.
