package rules

import "testing"

func TestLogMCPRule_PathMatch(t *testing.T) {
	rule := LogMCP(Deny, "./.secrets/**",
		PathOpts{CWD: "/proj", Home: "/Users/me", ProjectRoot: "/proj"},
	)

	if result := rule.Apply(LogMCPInput{
		FilePath:   "/proj/.secrets/api.log",
		Pattern:    "error",
		MaxResults: 20,
	}); result == nil {
		t.Fatal("expected match for .secrets log file")
	}

	if result := rule.Apply(LogMCPInput{
		FilePath:   "/proj/test.log",
		Pattern:    "error",
		MaxResults: 20,
	}); result != nil {
		t.Fatal("expected no match for test.log")
	}
}

func TestLogMCPRule_BareMatchAll(t *testing.T) {
	rule := LogMCP(Allow, PathOpts{})

	if result := rule.Apply(LogMCPInput{
		FilePath: "/any/file.log",
	}); result == nil {
		t.Fatal("expected bare LogMCP to match all")
	}
}

func TestLogMCPRule_HomePattern(t *testing.T) {
	rule := LogMCP(Deny, "~/.config/**",
		PathOpts{CWD: "/proj", Home: "/Users/me", ProjectRoot: "/proj"},
	)

	if result := rule.Apply(LogMCPInput{
		FilePath: "/Users/me/.config/app/debug.log",
	}); result == nil {
		t.Fatal("expected match for ~/.config log")
	}
}
