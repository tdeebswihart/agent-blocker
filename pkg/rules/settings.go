package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/valyala/fastjson"
)

// AllSettingsRules loads permissions from all Claude Code settings files:
// global (~/.claude/settings.json), global-local (~/.claude/settings.local.json),
// project (<cwd>/.claude/settings.json), project-local (<cwd>/.claude/settings.local.json).
func AllSettingsRules(home, cwd string) []Matcher {
	paths := []string{
		filepath.Join(home, ".claude", "settings.json"),
		filepath.Join(home, ".claude", "settings.local.json"),
		filepath.Join(cwd, ".claude", "settings.json"),
		filepath.Join(cwd, ".claude", "settings.local.json"),
	}
	var matchers []Matcher
	for _, p := range paths {
		matchers = append(matchers, SettingsRules(p, cwd)...)
	}
	return matchers
}

// SettingsRules reads a Claude settings file and converts its permission
// strings into Matchers. Returns nil on any error (missing file, bad JSON).
func SettingsRules(settingsPath, cwd string) []Matcher {
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		return nil
	}

	var p fastjson.Parser
	root, err := p.ParseBytes(data)
	if err != nil {
		return nil
	}

	perms := root.Get("permissions")
	if perms == nil {
		return nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		home = os.Getenv("HOME")
	}
	opts := PathOpts{CWD: cwd, Home: home, ProjectRoot: cwd}

	var matchers []Matcher
	for _, kv := range []struct {
		key      string
		decision Decision
	}{
		{"deny", Deny},
		{"ask", Ask},
		{"allow", Allow},
	} {
		arr := perms.GetArray(kv.key)
		for _, v := range arr {
			perm := string(v.GetStringBytes())
			if m := parsePermission(perm, kv.decision, cwd, opts); m != nil {
				matchers = append(matchers, m)
			}
		}
	}
	return matchers
}

// knownBareTools maps tool names that have dedicated constructors accepting
// only a decision (and PathOpts for path-based tools).
var knownBareTools = map[string]func(Decision, PathOpts) Matcher{
	"Edit":      func(d Decision, o PathOpts) Matcher { return Edit(d, o) },
	"Read":      func(d Decision, o PathOpts) Matcher { return Read(d, o) },
	"Grep":      func(d Decision, o PathOpts) Matcher { return Grep(d, o) },
	"Glob":      func(d Decision, o PathOpts) Matcher { return GlobRule(d, o) },
	"Search":    func(d Decision, o PathOpts) Matcher { return Search(d, o) },
	"WebSearch": func(d Decision, _ PathOpts) Matcher { return WebSearch(d) },
	"WebFetch":  func(d Decision, _ PathOpts) Matcher { return WebFetch(d) },
}

// parsePermission converts a Claude Code permission string (e.g. "Bash(make:*)",
// "Read(~/.ssh/**)", "Edit", "mcp__gopls__go_*") into a Matcher.
// Returns nil for unrecognized or malformed permissions.
func parsePermission(perm string, decision Decision, cwd string, opts PathOpts) Matcher {
	perm = strings.TrimSpace(perm)
	if perm == "" {
		return nil
	}

	open := strings.IndexByte(perm, '(')
	if open == -1 {
		return parseBarePerm(perm, decision, opts)
	}
	return parseParenPerm(perm, open, decision, cwd, opts)
}

// parseBarePerm handles permission strings without parentheses.
func parseBarePerm(perm string, decision Decision, opts PathOpts) Matcher {
	if strings.HasPrefix(perm, "mcp_") || strings.Contains(perm, "*") {
		return MCP(decision, perm)
	}
	if fn, ok := knownBareTools[perm]; ok {
		return fn(decision, opts)
	}
	return BareTool(decision, perm)
}

// parseParenPerm handles permission strings with parenthesized arguments.
func parseParenPerm(
	perm string, open int, decision Decision, cwd string, opts PathOpts,
) Matcher {
	toolName := perm[:open]
	// Find matching closing paren (last ')' in string).
	close := strings.LastIndexByte(perm, ')')
	if close <= open {
		return nil // mismatched parens
	}
	args := perm[open+1 : close]

	switch toolName {
	case "Bash":
		return Bash(decision, cwd, args)
	case "Read":
		return Read(decision, args, opts)
	case "Edit":
		return Edit(decision, args, opts)
	case "Grep":
		return Grep(decision, args, opts)
	case "Glob":
		return GlobRule(decision, args, opts)
	case "Search":
		return Search(decision, args, opts)
	case "WebFetch":
		return WebFetch(decision, args)
	case "WebSearch":
		return WebSearch(decision, args)
	case "Skill":
		return Skill(decision, args)
	case "Agent":
		return Agent(decision, args)
	default:
		fmt.Fprintf(os.Stderr, "agent-blocker: unknown tool in permission %q\n", perm)
		return nil
	}
}
