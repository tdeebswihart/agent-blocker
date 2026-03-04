package rules

import "os"

// DefaultRules returns the built-in permission rules.
// CONSIDER: load from config file instead of hardcoding.
func DefaultRules(cwd string) []Matcher {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.Getenv("HOME")
	}
	opts := PathOpts{CWD: cwd, Home: home, ProjectRoot: cwd}

	return []Matcher{
		// ================================================================
		// DENY — evaluated first, highest priority
		// ================================================================

		// 1Password CLI
		Bash(Deny, "op:*"),

		// Secrets & env files
		Read(Deny, "./.env", opts),
		Read(Deny, "./.envrc", opts),
		Read(Deny, "./.env.*", opts),
		Read(Deny, "./.secrets/**", opts),
		Read(Deny, "./.secret/**", opts),
		Read(Deny, "~/.secret/**", opts),

		// Destructive shell commands (Trail of Bits)
		Bash(Deny, "rm -rf:*"),
		Bash(Deny, "rm -fr:*"),
		Bash(Deny, "rm -f:*"),
		Bash(Deny, "sudo:*"),
		Bash(Deny, "mkfs:*"),
		Bash(Deny, "dd:*"),
		Bash(Deny, "diskutil:*"),
		Bash(Deny, "curl:*|bash*"),
		Bash(Deny, "wget:*|bash*"),

		// Destructive git ops
		Bash(Deny, "git push --force*"),
		Bash(Deny, "git push:*--force*"),
		Bash(Deny, "git reset --hard*"),

		// No reflog
		Bash(Deny, "git reflog:*"),

		// Disallow gh api calls with non-GET method
		Bash(Deny, "gh api:*-X*"),
		Bash(Deny, "gh api:*--method*"),

		// Shell config and SSH
		Edit(Deny, "~/.bashrc", opts),
		Edit(Deny, "~/.zshrc", opts),
		Edit(Deny, "~/.ssh/**", opts),

		// No go doc HTTP server
		Bash(Deny, "go doc:*-http:*"),

		// Sensitive directories
		Read(Deny, "~/.ssh/**", opts),
		Read(Deny, "~/.gnupg/**", opts),
		Read(Deny, "~/.aws/**", opts),
		Read(Deny, "~/.azure/**", opts),
		Read(Deny, "~/.config/gh/**", opts),
		Read(Deny, "~/.git-credentials", opts),
		Read(Deny, "~/.docker/config.json", opts),
		Read(Deny, "~/.kube/**", opts),
		Read(Deny, "~/.npmrc", opts),
		Read(Deny, "~/.npm/**", opts),
		Read(Deny, "~/.pypirc", opts),
		Read(Deny, "~/.gem/credentials", opts),
		Read(Deny, "~/Library/Keychains/**", opts),

		// ================================================================
		// ASK — evaluated second
		// ================================================================

		Bash(Ask, "git push"),
		Bash(Ask, "jj git push"),
		Bash(Ask, "jj tug"),
		Bash(Ask, "rm:*"),
		Bash(Ask, "jj bookmark create:*"),
		Bash(Ask, "jj bookmark set:*"),
		WebSearch(Ask),
		Bash(Ask, "wget:*"),
		Bash(Ask, "curl:*"),
		Bash(Ask, "http:*"),
		Bash(Ask, "xh:*"),

		// ================================================================
		// ALLOW — evaluated last, lowest priority
		// ================================================================

		// Normal repo actions
		Bash(Allow, "make lint"),
		Bash(Allow, "mise run test"),
		Bash(Allow, "make walker-test*"),

		// File tools (bare = allow all)
		Edit(Allow, opts),
		Search(Allow, opts),
		Grep(Allow, opts),
		GlobRule(Allow, opts),
		Read(Allow, opts),

		// Go module cache
		Read(Allow, "~/go/pkg/mod/**/*.go", opts),

		// Shell utilities
		BashGrep(),
		Bash(Allow, "fd:*"),
		Bash(Allow, "find:*"),
		Bash(Allow, "fastmod:*"),
		Bash(Allow, "sed:*"),
		Bash(Allow, "ls:*"),
		Bash(Allow, "cut:*"),
		Bash(Allow, "cat:*"),
		Bash(Allow, "wc:*"),
		BashEcho(),
		BashHeadTail(),
		Bash(Allow, "jq:*"),
		Bash(Allow, "yq:*"),

		// Git ops
		Bash(Allow, "git show:*"),
		Bash(Allow, "git diff:*"),
		Bash(Allow, "git add:*"),
		Bash(Allow, "git mv:*"),
		Bash(Allow, "git log:*"),
		Bash(Allow, "git grep:*"),
		Bash(Allow, "jj diff:*"),
		Bash(Allow, "jj log:*"),
		Bash(Allow, "jj status:*"),
		Bash(Allow, "jj new:*"),
		Bash(Allow, "jj file show:*"),
		Bash(Allow, "jj file search:*"),
		Bash(Allow, "jj file annotate:*"),
		Bash(Allow, "jj cat:*"),
		Bash(Allow, "jj show:*"),
		Bash(Allow, "jj commit:*"),
		Bash(Allow, "jj squash:*"),
		Bash(Allow, "jj evolog:*"),
		Bash(Allow, "jj op log:*"),
		Bash(Allow, "jj bookmark list:*"),
		Bash(Allow, "jj bookmark create tim/:*"),
		Bash(Allow, "gh run view:*"),
		Bash(Allow, "gh pr view:*"),
		Bash(Allow, "gh repo view:*"),
		Bash(Allow, "gh pr diff:*"),
		Bash(Allow, "gh-pr-info:*"),
		Bash(Allow, "gh api:*"),
		Read(Allow, "~/.config/gh/config.yaml", opts),
		Read(Allow, "~/.config/gh/hosts.yaml", opts),
		Bash(Allow, "curr-pr-info"),

		// Go
		MCP(Allow, "mcp__gopls__go_*"),
		Bash(Allow, "go test:*"),
		Bash(Allow, "go build:*"),
		Bash(Allow, "go mod:*"),
		Bash(Allow, "go list:*"),
		Bash(Allow, "go doc:*"),
		Bash(Allow, "go generate:*"),
		MCP(Allow, "mcp__codespelunker_*"),
		Read(Allow, "~/go/pkg/mod/**", opts),

		// Skills
		Skill(Allow, "code-review:code-review"),

		// Web
		WebFetch(Allow, "domain:github.com"),
	}
}
