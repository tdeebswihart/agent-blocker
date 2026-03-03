package rules

import "testing"

func TestGlobRule_BareMatchAll(t *testing.T) {
	rule := GlobRule(Allow, PathOpts{})

	if result := rule.Apply(GlobInput{Pattern: "**/*.go"}); result == nil {
		t.Fatal("expected bare Glob to match all")
	}
}

func TestGlobRule_PathMatching(t *testing.T) {
	rule := GlobRule(Deny, "~/.ssh/**",
		PathOpts{CWD: "/proj", Home: "/Users/me", ProjectRoot: "/proj"},
	)

	if result := rule.Apply(GlobInput{
		Pattern: "*.pem",
		Path:    "/Users/me/.ssh",
	}); result == nil {
		t.Fatal("expected match for glob targeting .ssh")
	}

	if result := rule.Apply(GlobInput{
		Pattern: "**/*.go",
		Path:    "/proj",
	}); result != nil {
		t.Fatal("expected no match for glob targeting project")
	}
}
