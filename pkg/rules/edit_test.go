package rules

import "testing"

func TestEditRule_DenyHomeRC(t *testing.T) {
	rule := Edit(Deny, "~/.bashrc", "~/.zshrc", "~/.ssh/**",
		PathOpts{CWD: "/proj", Home: "/Users/me", ProjectRoot: "/proj"},
	)

	if result := rule.Apply(EditInput{FilePath: "/Users/me/.bashrc"}); result == nil {
		t.Fatal("expected match for .bashrc")
	} else if result.HookSpecificOutput.PermissionDecision != Deny {
		t.Fatalf("expected Deny, got %s", result.HookSpecificOutput.PermissionDecision)
	}

	if result := rule.Apply(EditInput{FilePath: "/Users/me/.ssh/config"}); result == nil {
		t.Fatal("expected match for .ssh/config")
	}

	if result := rule.Apply(EditInput{FilePath: "/proj/main.go"}); result != nil {
		t.Fatal("expected no match for project file")
	}
}

func TestEditRule_BareMatchAll(t *testing.T) {
	rule := Edit(Allow, PathOpts{})

	if result := rule.Apply(EditInput{FilePath: "/any/file.go"}); result == nil {
		t.Fatal("expected bare Edit to match all")
	}
}
