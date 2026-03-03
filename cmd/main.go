package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"codeberg.org/timods/agent-blocker/pkg/rules"
)

func main() {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fatal("reading stdin: %v", err)
	}

	var hook rules.HookInput
	if err := json.Unmarshal(input, &hook); err != nil {
		fatal("parsing hook input: %v", err)
	}

	harness := rules.NewHarness(buildRules(hook.CWD)...)
	result := harness.Evaluate(hook)

	out, err := json.Marshal(result)
	if err != nil {
		fatal("marshaling result: %v", err)
	}
	fmt.Println(string(out))
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// buildRules returns the configured permission rules.
// TODO: load from config file instead of hardcoding.
func buildRules(cwd string) []rules.Matcher {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.Getenv("HOME")
	}
	opts := rules.PathOpts{CWD: cwd, Home: home, ProjectRoot: cwd}

	return []rules.Matcher{
		// ================================================================
		// DENY — evaluated first, highest priority
		// ================================================================

		// 1Password CLI
		rules.Bash(rules.Deny, "op:*"),

		// Secrets & env files
		rules.Read(rules.Deny, "./.env", opts),
		rules.Read(rules.Deny, "./.envrc", opts),
		rules.Read(rules.Deny, "./.env.*", opts),
		rules.Read(rules.Deny, "./.secrets/**", opts),
		rules.Read(rules.Deny, "./.secret/**", opts),
		rules.Read(rules.Deny, "~/.secret/**", opts),

		// Destructive shell commands (Trail of Bits)
		rules.Bash(rules.Deny, "rm -rf:*"),
		rules.Bash(rules.Deny, "rm -fr:*"),
		rules.Bash(rules.Deny, "rm -f:*"),
		rules.Bash(rules.Deny, "sudo:*"),
		rules.Bash(rules.Deny, "mkfs:*"),
		rules.Bash(rules.Deny, "dd:*"),
		rules.Bash(rules.Deny, "diskutil:*"),
		rules.Bash(rules.Deny, "curl:*|bash*"),
		rules.Bash(rules.Deny, "wget:*|bash*"),

		// Destructive git ops
		rules.Bash(rules.Deny, "git push --force*"),
		rules.Bash(rules.Deny, "git push:*--force*"),
		rules.Bash(rules.Deny, "git reset --hard*"),

		// No reflog
		rules.Bash(rules.Deny, "git reflog:*"),

		// Disallow gh api calls with non-GET method
		rules.Bash(rules.Deny, "gh api:*-X*"),
		rules.Bash(rules.Deny, "gh api:*--method*"),

		// Shell config and SSH
		rules.Edit(rules.Deny, "~/.bashrc", opts),
		rules.Edit(rules.Deny, "~/.zshrc", opts),
		rules.Edit(rules.Deny, "~/.ssh/**", opts),

		// No go doc HTTP server
		rules.Bash(rules.Deny, "go doc:*-http:*"),

		// Sensitive directories
		rules.Read(rules.Deny, "~/.ssh/**", opts),
		rules.Read(rules.Deny, "~/.gnupg/**", opts),
		rules.Read(rules.Deny, "~/.aws/**", opts),
		rules.Read(rules.Deny, "~/.azure/**", opts),
		rules.Read(rules.Deny, "~/.config/gh/**", opts),
		rules.Read(rules.Deny, "~/.git-credentials", opts),
		rules.Read(rules.Deny, "~/.docker/config.json", opts),
		rules.Read(rules.Deny, "~/.kube/**", opts),
		rules.Read(rules.Deny, "~/.npmrc", opts),
		rules.Read(rules.Deny, "~/.npm/**", opts),
		rules.Read(rules.Deny, "~/.pypirc", opts),
		rules.Read(rules.Deny, "~/.gem/credentials", opts),
		rules.Read(rules.Deny, "~/Library/Keychains/**", opts),

		// ================================================================
		// ASK — evaluated second
		// ================================================================

		rules.Bash(rules.Ask, "git push"),
		rules.Bash(rules.Ask, "jj git push"),
		rules.Bash(rules.Ask, "jj tug"),
		rules.Bash(rules.Ask, "rm:*"),
		rules.Bash(rules.Ask, "jj bookmark create:*"),
		rules.Bash(rules.Ask, "jj bookmark set:*"),
		rules.WebSearch(rules.Ask),
		rules.Bash(rules.Ask, "wget:*"),
		rules.Bash(rules.Ask, "curl:*"),
		rules.Bash(rules.Ask, "http:*"),
		rules.Bash(rules.Ask, "xh:*"),

		// ================================================================
		// ALLOW — evaluated last, lowest priority
		// ================================================================

		// Normal repo actions
		rules.Bash(rules.Allow, "make lint"),
		rules.Bash(rules.Allow, "mise run test"),
		rules.Bash(rules.Allow, "make walker-test*"),

		// File tools (bare = allow all)
		rules.Edit(rules.Allow, opts),
		rules.Search(rules.Allow, opts),
		rules.Grep(rules.Allow, opts),
		rules.GlobRule(rules.Allow, opts),
		rules.Read(rules.Allow, opts),

		// Go module cache
		rules.Read(rules.Allow, "~/go/pkg/mod/**/*.go", opts),

		// Shell utilities
		rules.Bash(rules.Allow, "rg:*"),
		rules.Bash(rules.Allow, "grep:*"),
		rules.Bash(rules.Allow, "fd:*"),
		rules.Bash(rules.Allow, "find:*"),
		rules.Bash(rules.Allow, "fastmod:*"),
		rules.Bash(rules.Allow, "sed:*"),
		rules.Bash(rules.Allow, "ls:*"),
		rules.Bash(rules.Allow, "cut:*"),
		rules.Bash(rules.Allow, "cat:*"),
		rules.Bash(rules.Allow, "wc:*"),
		rules.Bash(rules.Allow, "head:*"),
		rules.Bash(rules.Allow, "jq:*"),
		rules.Bash(rules.Allow, "yq:*"),

		// Git ops
		rules.Bash(rules.Allow, "git show:*"),
		rules.Bash(rules.Allow, "git diff:*"),
		rules.Bash(rules.Allow, "git add:*"),
		rules.Bash(rules.Allow, "git mv:*"),
		rules.Bash(rules.Allow, "git log:*"),
		rules.Bash(rules.Allow, "git grep:*"),
		rules.Bash(rules.Allow, "jj diff:*"),
		rules.Bash(rules.Allow, "jj log:*"),
		rules.Bash(rules.Allow, "jj status:*"),
		rules.Bash(rules.Allow, "jj new:*"),
		rules.Bash(rules.Allow, "jj file show:*"),
		rules.Bash(rules.Allow, "jj file search:*"),
		rules.Bash(rules.Allow, "jj file annotate:*"),
		rules.Bash(rules.Allow, "jj cat:*"),
		rules.Bash(rules.Allow, "jj show:*"),
		rules.Bash(rules.Allow, "jj commit:*"),
		rules.Bash(rules.Allow, "jj squash:*"),
		rules.Bash(rules.Allow, "jj evolog:*"),
		rules.Bash(rules.Allow, "jj op log:*"),
		rules.Bash(rules.Allow, "jj bookmark list:*"),
		rules.Bash(rules.Allow, "jj bookmark create tim/:*"),
		rules.Bash(rules.Allow, "gh run view:*"),
		rules.Bash(rules.Allow, "gh pr view:*"),
		rules.Bash(rules.Allow, "gh repo view:*"),
		rules.Bash(rules.Allow, "gh pr diff:*"),
		rules.Bash(rules.Allow, "gh-pr-info:*"),
		rules.Bash(rules.Allow, "gh api:*"),
		rules.Read(rules.Allow, "~/.config/gh/config.yaml", opts),
		rules.Read(rules.Allow, "~/.config/gh/hosts.yaml", opts),
		rules.Bash(rules.Allow, "curr-pr-info"),

		// Go
		rules.MCP(rules.Allow, "mcp__gopls__go_*"),
		rules.Bash(rules.Allow, "go test:*"),
		rules.Bash(rules.Allow, "go build:*"),
		rules.Bash(rules.Allow, "go mod:*"),
		rules.Bash(rules.Allow, "go list:*"),
		rules.Bash(rules.Allow, "go doc:*"),
		rules.Bash(rules.Allow, "go generate:*"),
		rules.MCP(rules.Allow, "mcp__codespelunker_*"),
		rules.Read(rules.Allow, "~/go/pkg/mod/**", opts),

		// Skills
		rules.Skill(rules.Allow, "code-review:code-review"),

		// Web
		rules.WebFetch(rules.Allow, "domain:github.com"),
	}
}
