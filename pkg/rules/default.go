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
		Bash(Deny, cwd, "op:*"),

		// Secrets & env files
		Read(Deny, "./.env", opts),
		Read(Deny, "./.envrc", opts),
		Read(Deny, "./.env.*", opts),
		Read(Deny, "./.secrets/**", opts),
		Read(Deny, "./.secret/**", opts),
		Read(Deny, "~/.secret/**", opts),

		// Destructive shell commands (Trail of Bits)
		Bash(Deny, cwd, "rm -rf:*"),
		Bash(Deny, cwd, "rm -fr:*"),
		Bash(Deny, cwd, "rm -f:*"),
		Bash(Deny, cwd, "sudo:*"),
		Bash(Deny, cwd, "mkfs:*"),
		Bash(Deny, cwd, "dd:*"),
		Bash(Deny, cwd, "diskutil:*"),
		Bash(Deny, cwd, "curl:*|bash*"),
		Bash(Deny, cwd, "wget:*|bash*"),

		// Destructive git ops
		Bash(Deny, cwd, "git push --force*"),
		Bash(Deny, cwd, "git push:*--force*"),
		Bash(Deny, cwd, "git reset --hard*"),

		// No reflog
		Bash(Deny, cwd, "git reflog:*"),

		// Disallow gh api calls with non-GET method
		Bash(Deny, cwd, "gh api:*-X*"),
		Bash(Deny, cwd, "gh api:*--method*"),
		Bash(Deny, cwd, "make install:*"),

		// Shell config and SSH
		Edit(Deny, "~/.bashrc", opts),
		Edit(Deny, "~/.zshrc", opts),
		Edit(Deny, "~/.ssh/**", opts),

		// No go doc HTTP server
		Bash(Deny, cwd, "go doc:*-http:*"),

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
		Bash(Deny, cwd, "mise run install:*"),

		// ================================================================
		// ASK — evaluated second
		// ================================================================

		Bash(Ask, cwd, "git push"),
		Bash(Ask, cwd, "jj git push"),
		Bash(Ask, cwd, "jj tug"),
		Bash(Ask, cwd, "rm:*"),
		Bash(Ask, cwd, "jj bookmark set:*"),
		WebSearch(Ask),
		Bash(Ask, cwd, "wget:*"),
		Bash(Ask, cwd, "curl:*"),
		Bash(Ask, cwd, "http:*"),
		Bash(Ask, cwd, "xh:*"),

		// ================================================================
		// ALLOW — evaluated last, lowest priority
		// ================================================================
		Bash(Allow, cwd, "jj bookmark create:*"),
		Bash(Allow, cwd, "mise run:*"),
		Bash(Allow, cwd, "mise tasks:*"),
		Bash(Allow, cwd, "mise fmt:*"),
		Bash(Allow, cwd, "sed:*"),
		Bash(Allow, cwd, "true:*"),
		Bash(Allow, cwd, "false:*"),
		Bash(Allow, cwd, "printf:*"),
		Bash(Allow, cwd, "nix search:*"),
		Bash(Allow, cwd, "nix eval:*"),

		// Normal repo actions
		Bash(Allow, cwd, "make:*"),
		Bash(Allow, cwd, "mise run test"),

		// File tools (bare = allow all)
		Edit(Allow, opts),
		Search(Allow, opts),
		Grep(Allow, opts),
		GlobRule(Allow, opts),
		Read(Allow, opts),

		// Go module cache
		Read(Allow, "~/go/pkg/mod/**/*.go", opts),

		// Shell utilities
		BashGrep(cwd),
		BashFind(cwd),
		Bash(Allow, cwd, "fastmod:*"),
		Bash(Allow, cwd, "sed:*"),
		Bash(Allow, cwd, "ls:*"),
		Bash(Allow, cwd, "wc:*"),
		Bash(Allow, cwd, "cut:*"),
		Bash(Allow, cwd, "cat:*"),
		Bash(Allow, cwd, "wc:*"),
		BashEcho(cwd),
		BashHeadTail(cwd),
		Mkdir(cwd),
		BashCD(cwd),
		BashLocalCmd(cwd),
		Bash(Allow, cwd, "jq:*"),
		Bash(Allow, cwd, "yq:*"),

		// Git ops
		Bash(Allow, cwd, "git show:*"),
		Bash(Allow, cwd, "git ls-files:*"),
		Bash(Allow, cwd, "git diff:*"),
		Bash(Allow, cwd, "git add:*"),
		Bash(Allow, cwd, "git mv:*"),
		Bash(Allow, cwd, "git log:*"),
		Bash(Allow, cwd, "git grep:*"),
		Bash(Allow, cwd, "jj diff:*"),
		Bash(Allow, cwd, "jj log:*"),
		Bash(Allow, cwd, "jj status:*"),
		Bash(Allow, cwd, "jj new:*"),
		Bash(Allow, cwd, "jj file show:*"),
		Bash(Allow, cwd, "jj file search:*"),
		Bash(Allow, cwd, "jj file annotate:*"),
		Bash(Allow, cwd, "jj cat:*"),
		Bash(Allow, cwd, "jj show:*"),
		Bash(Allow, cwd, "jj commit:*"),
		Bash(Allow, cwd, "jj squash:*"),
		Bash(Allow, cwd, "jj evolog:*"),
		Bash(Allow, cwd, "jj op log:*"),
		Bash(Allow, cwd, "jj (st|status):*"),
		Bash(Allow, cwd, "jj (b|bookmark) list:*"),
		Bash(Allow, cwd, "jj (b|bookmark) create tim/:*"),
		Bash(Allow, cwd, "gh run view:*"),
		Bash(Allow, cwd, "gh pr view:*"),
		Bash(Allow, cwd, "gh repo view:*"),
		Bash(Allow, cwd, "gh pr diff:*"),
		Bash(Allow, cwd, "gh-pr-info:*"),
		Bash(Allow, cwd, "gh api:*"),
		Read(Allow, "~/.config/gh/config.yaml", opts),
		Read(Allow, "~/.config/gh/hosts.yaml", opts),
		Bash(Allow, cwd, "curr-pr-info"),

		// Go
		MCP(Allow, "mcp__gopls__go_*"),
		Bash(Allow, cwd, "go (test|build|mod|list|doc|vet|generate):*"),
		Bash(Allow, cwd, "golangci-lint:*"),
		Read(Allow, "~/go/pkg/mod/**", opts),

		// Web
		WebFetch(Allow, "domain:github.com"),
		MCP(Allow, "mcp__codespelunker_*"),
		MCP(Allow, "mcp__plugin_compound-engineering_context7__*"),
	}
}
