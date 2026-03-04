package rules

import "testing"

func TestReadRule_DenyEnvFiles(t *testing.T) {
	rule := Read(Deny, "./.env", "./.envrc", "./.env.*",
		PathOpts{CWD: "/proj", Home: "/home/me", ProjectRoot: "/proj"},
	)

	if result := rule.Apply(ReadInput{FilePath: "/proj/.env"}); result == nil {
		t.Fatal("expected match for .env")
	} else if result.decision != Deny {
		t.Fatalf("expected Deny, got %s", result.decision)
	}

	if result := rule.Apply(ReadInput{FilePath: "/proj/.envrc"}); result == nil {
		t.Fatal("expected match for .envrc")
	}

	if result := rule.Apply(ReadInput{FilePath: "/proj/.env.local"}); result == nil {
		t.Fatal("expected match for .env.local")
	}

	if result := rule.Apply(ReadInput{FilePath: "/proj/main.go"}); result != nil {
		t.Fatal("expected no match for main.go")
	}
}

func TestReadRule_AllowGoModCache(t *testing.T) {
	rule := Read(Allow, "~/go/pkg/mod/**/*.go",
		PathOpts{CWD: "/proj", Home: "/Users/me", ProjectRoot: "/proj"},
	)

	if result := rule.Apply(ReadInput{
		FilePath: "/Users/me/go/pkg/mod/github.com/foo/bar.go",
	}); result == nil {
		t.Fatal("expected match for go mod cache file")
	}
}

func TestReadRule_DenySSHKeys(t *testing.T) {
	rule := Read(Deny, "~/.ssh/**",
		PathOpts{CWD: "/proj", Home: "/Users/me", ProjectRoot: "/proj"},
	)

	if result := rule.Apply(ReadInput{FilePath: "/Users/me/.ssh/id_rsa"}); result == nil {
		t.Fatal("expected match for ssh key")
	}
	if result := rule.Apply(ReadInput{FilePath: "/Users/me/.ssh/config"}); result == nil {
		t.Fatal("expected match for ssh config")
	}
}

func TestReadRule_BareMatchAll(t *testing.T) {
	rule := Read(Allow, PathOpts{})

	if result := rule.Apply(ReadInput{FilePath: "/any/file"}); result == nil {
		t.Fatal("expected bare Read to match all")
	}
}

func TestReadRule_MultiplePatterns(t *testing.T) {
	rule := Read(Deny, "./.env", "~/.ssh/**",
		PathOpts{CWD: "/proj", Home: "/Users/me", ProjectRoot: "/proj"},
	)

	if result := rule.Apply(ReadInput{FilePath: "/proj/.env"}); result == nil {
		t.Fatal("expected match for .env")
	}
	if result := rule.Apply(ReadInput{FilePath: "/Users/me/.ssh/id_rsa"}); result == nil {
		t.Fatal("expected match for ssh key")
	}
	if result := rule.Apply(ReadInput{FilePath: "/proj/main.go"}); result != nil {
		t.Fatal("expected no match for main.go")
	}
}
