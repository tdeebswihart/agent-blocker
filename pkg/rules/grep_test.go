package rules

import "testing"

func TestGrepRule_BareMatchAll(t *testing.T) {
	rule := Grep(Allow, PathOpts{})

	if result := rule.Apply(GrepInput{Pattern: "foo", Path: "/any/dir"}); result == nil {
		t.Fatal("expected bare Grep to match all")
	}
}

func TestGrepRule_PathMatching(t *testing.T) {
	rule := Grep(Deny, "./.secrets/**",
		PathOpts{CWD: "/proj", Home: "/Users/me", ProjectRoot: "/proj"},
	)

	if result := rule.Apply(GrepInput{
		Pattern: "password",
		Path:    "/proj/.secrets/keys.txt",
	}); result == nil {
		t.Fatal("expected match for grep targeting .secrets")
	}

	if result := rule.Apply(GrepInput{
		Pattern: "foo",
		Path:    "/proj/main.go",
	}); result != nil {
		t.Fatal("expected no match for grep targeting main.go")
	}
}
