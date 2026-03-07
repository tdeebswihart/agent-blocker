package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func testOpts() PathOpts {
	return PathOpts{CWD: "/work", Home: "/home/user", ProjectRoot: "/work"}
}

func TestParsePermission_Bash(t *testing.T) {
	tests := []struct {
		perm    string
		command string
		want    Decision
	}{
		{"Bash(make:*)", "make test", Allow},
		{"Bash(git push)", "git push", Allow},
		{"Bash(rm -rf:*)", "rm -rf /tmp/foo", Allow},
	}
	opts := testOpts()
	for _, tt := range tests {
		t.Run(tt.perm, func(t *testing.T) {
			m := parsePermission(tt.perm, tt.want, opts.CWD, opts)
			if m == nil {
				t.Fatal("parsePermission returned nil")
			}
			input, _ := json.Marshal(BashInput{Command: tt.command})
			result := m.Match("Bash", input)
			if result == nil {
				t.Fatalf("expected match for command %q", tt.command)
			}
			got := result.HookSpecificOutput.PermissionDecision
			if got != tt.want {
				t.Errorf("got decision %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParsePermission_PathTools(t *testing.T) {
	tests := []struct {
		perm     string
		tool     string
		filePath string
		want     Decision
	}{
		{"Read(~/.ssh/**)", "Read", "/home/user/.ssh/id_rsa", Deny},
		{"Edit(~/.bashrc)", "Edit", "/home/user/.bashrc", Deny},
		{"Read(./.env)", "Read", "/work/.env", Deny},
	}
	opts := testOpts()
	for _, tt := range tests {
		t.Run(tt.perm, func(t *testing.T) {
			m := parsePermission(tt.perm, tt.want, opts.CWD, opts)
			if m == nil {
				t.Fatal("parsePermission returned nil")
			}
			var input json.RawMessage
			switch tt.tool {
			case "Read":
				input, _ = json.Marshal(ReadInput{FilePath: tt.filePath})
			case "Edit":
				input, _ = json.Marshal(EditInput{FilePath: tt.filePath})
			}
			result := m.Match(tt.tool, input)
			if result == nil {
				t.Fatalf("expected match for path %q", tt.filePath)
			}
			got := result.HookSpecificOutput.PermissionDecision
			if got != tt.want {
				t.Errorf("got decision %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParsePermission_BareTools(t *testing.T) {
	bareTools := []struct {
		perm string
		tool string
	}{
		{"Edit", "Edit"},
		{"Read", "Read"},
		{"Grep", "Grep"},
		{"Glob", "Glob"},
		{"Search", "Search"},
		{"WebSearch", "WebSearch"},
		{"WebFetch", "WebFetch"},
	}
	opts := testOpts()
	for _, tt := range bareTools {
		t.Run(tt.perm, func(t *testing.T) {
			m := parsePermission(tt.perm, Allow, opts.CWD, opts)
			if m == nil {
				t.Fatalf("parsePermission returned nil for %q", tt.perm)
			}
			if m.ToolName() != tt.tool {
				// WebSearch/WebFetch share the same rule type
				if m.ToolName() != tt.tool {
					t.Errorf("got tool name %q, want %q", m.ToolName(), tt.tool)
				}
			}
		})
	}
}

func TestParsePermission_MCP(t *testing.T) {
	tests := []string{
		"mcp__gopls__go_*",
		"mcp__plugin_*",
	}
	opts := testOpts()
	for _, perm := range tests {
		t.Run(perm, func(t *testing.T) {
			m := parsePermission(perm, Allow, opts.CWD, opts)
			if m == nil {
				t.Fatal("parsePermission returned nil")
			}
			// MCP rules are wildcards (ToolName()="")
			if m.ToolName() != "" {
				t.Errorf("expected wildcard (empty) tool name, got %q", m.ToolName())
			}
		})
	}
}

func TestParsePermission_WebFetch(t *testing.T) {
	opts := testOpts()
	m := parsePermission("WebFetch(domain:github.com)", Allow, opts.CWD, opts)
	if m == nil {
		t.Fatal("parsePermission returned nil")
	}
	input, _ := json.Marshal(WebFetchInput{URL: "https://github.com/foo/bar"})
	result := m.Match("WebFetch", input)
	if result == nil {
		t.Fatal("expected match for github.com URL")
	}
	if result.HookSpecificOutput.PermissionDecision != Allow {
		t.Errorf("got %q, want allow", result.HookSpecificOutput.PermissionDecision)
	}

	// Non-matching domain
	input, _ = json.Marshal(WebFetchInput{URL: "https://evil.com/steal"})
	result = m.Match("WebFetch", input)
	if result != nil {
		t.Error("expected no match for evil.com")
	}
}

func TestParsePermission_Skill(t *testing.T) {
	opts := testOpts()
	m := parsePermission("Skill(code-review:code-review)", Allow, opts.CWD, opts)
	if m == nil {
		t.Fatal("parsePermission returned nil")
	}
	input, _ := json.Marshal(SkillInput{Skill: "code-review:code-review"})
	result := m.Match("Skill", input)
	if result == nil {
		t.Fatal("expected match")
	}
}

func TestParsePermission_Agent(t *testing.T) {
	opts := testOpts()
	m := parsePermission("Agent(Explore)", Allow, opts.CWD, opts)
	if m == nil {
		t.Fatal("parsePermission returned nil")
	}
	input, _ := json.Marshal(AgentInput{SubagentType: "Explore"})
	result := m.Match("Agent", input)
	if result == nil {
		t.Fatal("expected match")
	}
}

func TestParsePermission_EdgeCases(t *testing.T) {
	opts := testOpts()

	// Empty string
	if m := parsePermission("", Allow, opts.CWD, opts); m != nil {
		t.Error("expected nil for empty string")
	}

	// Mismatched parens
	if m := parsePermission("Bash(make:*", Allow, opts.CWD, opts); m != nil {
		t.Error("expected nil for mismatched parens")
	}

	// Unknown tool with parens
	if m := parsePermission("FooTool(bar)", Allow, opts.CWD, opts); m != nil {
		t.Error("expected nil for unknown tool")
	}

	// Unknown bare tool => BareTool
	m := parsePermission("NotebookEdit", Allow, opts.CWD, opts)
	if m == nil {
		t.Fatal("expected BareTool for unknown bare identifier")
	}
	if m.ToolName() != "NotebookEdit" {
		t.Errorf("got %q, want NotebookEdit", m.ToolName())
	}
}

func TestSettingsRules_Integration(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "settings.json")

	data := fmt.Appendf(nil, `{
		"permissions": {
			"allow": ["Bash(make:*)", "Read", "mcp__gopls__go_*"],
			"ask":   ["Bash(git push)"],
			"deny":  ["Bash(rm -rf:*)"]
		}
	}`)
	if err := os.WriteFile(settingsPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	matchers := SettingsRules(settingsPath, "/work")
	if len(matchers) == 0 {
		t.Fatal("expected matchers from settings")
	}

	// Verify ordering: deny first, then ask, then allow
	harness := NewHarness(matchers...)

	// rm -rf should be denied
	rmInput := HookInput{
		Event: "PreToolUse", Name: "Bash", CWD: "/work",
		Input: mustMarshal(BashInput{Command: "rm -rf /tmp"}),
	}
	result := harness.Evaluate(rmInput)
	if result == nil || result.HookSpecificOutput.PermissionDecision != Deny {
		t.Errorf("expected deny for rm -rf, got %v", result)
	}

	// make test should be allowed
	makeInput := HookInput{
		Event: "PreToolUse", Name: "Bash", CWD: "/work",
		Input: mustMarshal(BashInput{Command: "make test"}),
	}
	result = harness.Evaluate(makeInput)
	if result == nil || result.HookSpecificOutput.PermissionDecision != Allow {
		t.Errorf("expected allow for make test, got %v", result)
	}

	// git push should ask
	pushInput := HookInput{
		Event: "PreToolUse", Name: "Bash", CWD: "/work",
		Input: mustMarshal(BashInput{Command: "git push"}),
	}
	result = harness.Evaluate(pushInput)
	if result == nil || result.HookSpecificOutput.PermissionDecision != Ask {
		t.Errorf("expected ask for git push, got %v", result)
	}
}

func TestSettingsRules_MissingFile(t *testing.T) {
	matchers := SettingsRules("/nonexistent/path/settings.json", "/work")
	if matchers != nil {
		t.Error("expected nil for missing file")
	}
}

func TestSettingsRules_BadJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte("{bad json}"), 0o644); err != nil {
		t.Fatal(err)
	}
	matchers := SettingsRules(path, "/work")
	if matchers != nil {
		t.Error("expected nil for bad JSON")
	}
}
