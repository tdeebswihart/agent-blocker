package rules

import "os"

// DefaultRules returns built-in permission rules for tools/patterns not
// covered by ~/.claude/settings.json. Most rules now live in settings.json
// and are loaded by SettingsRules; these cover edge cases and composite
// matchers that settings.json's simple pattern syntax can't express.
func DefaultRules(cwd string) []Matcher {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.Getenv("HOME")
	}
	_ = PathOpts{CWD: cwd, Home: home, ProjectRoot: cwd}

	return []Matcher{
		// ================================================================
		// DENY
		// ================================================================
		Bash(Deny, cwd, "mise run install:*"),

		// ================================================================
		// ALLOW — composite matchers and patterns not expressible in
		// settings.json's simple permission syntax.
		// ================================================================

		// Composite matchers that validate arguments beyond simple globs.
		BashEcho(cwd),
		Mkdir(cwd),
		BashCD(cwd),
		BashLocalCmd(cwd),

		// jj shorthand aliases (settings.json only has the long forms).
		Bash(Allow, cwd, "jj st:*"),
		Bash(Allow, cwd, "jj b list:*"),
		Bash(Allow, cwd, "jj b create tim/:*"),

		// go vet not in settings.json.
		Bash(Allow, cwd, "go vet:*"),
		Bash(Allow, cwd, "golangci-lint:*"),

		// Broader than settings.json's ctx_* pattern.
		MCP(Allow, "mcp__plugin_context-mode_context-mode__*"),
	}
}
