package rules

import "testing"

func TestPathMatch_AbsolutePrefix(t *testing.T) {
	// // prefix means absolute filesystem path
	pm := newPathMatcher(
		"/Users/me/project",
		"/Users/me",
		"/Users/me/project",
		"//Users/me/secrets/**",
	)

	if !pm.match("/Users/me/secrets/key.pem") {
		t.Fatal("expected match for absolute path under secrets")
	}
	if pm.match("/Users/me/project/main.go") {
		t.Fatal("expected no match for project file")
	}
}

func TestPathMatch_HomePrefix(t *testing.T) {
	pm := newPathMatcher(
		"/Users/me/project",
		"/Users/me",
		"/Users/me/project",
		"~/.ssh/**",
	)

	if !pm.match("/Users/me/.ssh/id_rsa") {
		t.Fatal("expected match for ~/.ssh file")
	}
	if pm.match("/Users/me/project/main.go") {
		t.Fatal("expected no match for project file")
	}
}

func TestPathMatch_ProjectRootPrefix(t *testing.T) {
	// /path means relative to project root
	pm := newPathMatcher(
		"/Users/me/project",
		"/Users/me",
		"/Users/me/project",
		"/src/**/*.ts",
	)

	if !pm.match("/Users/me/project/src/index.ts") {
		t.Fatal("expected match for project src file")
	}
	if !pm.match("/Users/me/project/src/deep/nested.ts") {
		t.Fatal("expected match for deeply nested project src file")
	}
	if pm.match("/other/src/index.ts") {
		t.Fatal("expected no match for file outside project")
	}
}

func TestPathMatch_CwdRelative(t *testing.T) {
	pm := newPathMatcher(
		"/Users/me/project",
		"/Users/me",
		"/Users/me/project",
		"./.env",
	)

	if !pm.match("/Users/me/project/.env") {
		t.Fatal("expected match for .env in cwd")
	}
	if pm.match("/Users/me/project/src/.env") {
		t.Fatal("expected no match for .env in subdir")
	}
}

func TestPathMatch_CwdRelativeBare(t *testing.T) {
	// bare pattern (no prefix) is also relative to cwd
	pm := newPathMatcher(
		"/Users/me/project",
		"/Users/me",
		"/Users/me/project",
		"*.env",
	)

	if !pm.match("/Users/me/project/.env") {
		t.Fatal("expected match for .env in cwd")
	}
}

func TestPathMatch_DoubleStarRecursive(t *testing.T) {
	pm := newPathMatcher(
		"/Users/me/project",
		"/Users/me",
		"/Users/me/project",
		"~/go/pkg/mod/**/*.go",
	)

	if !pm.match("/Users/me/go/pkg/mod/github.com/foo/bar/baz.go") {
		t.Fatal("expected match for deep go mod file")
	}
	if pm.match("/Users/me/go/pkg/mod/github.com/foo/bar/baz.txt") {
		t.Fatal("expected no match for non-go file")
	}
}

func TestPathMatch_DotSlashPattern(t *testing.T) {
	pm := newPathMatcher(
		"/Users/me/project",
		"/Users/me",
		"/Users/me/project",
		"./.env.*",
	)

	if !pm.match("/Users/me/project/.env.local") {
		t.Fatal("expected match for .env.local")
	}
	if !pm.match("/Users/me/project/.env.production") {
		t.Fatal("expected match for .env.production")
	}
	if pm.match("/Users/me/project/src/.env.local") {
		t.Fatal("expected no match for .env.local in subdir")
	}
}

func TestPathMatcher_Specificity(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    Specificity
	}{
		{"exact file", "./.env", ExactPath},
		{"exact absolute", "//Users/me/.config/gh/config.yaml", ExactPath},
		{"glob star", "./.config/gh/**", GlobPath},
		{"glob question", "./file?.txt", GlobPath},
		{"glob bracket", "./file[0-9].txt", GlobPath},
		{"home glob", "~/.ssh/**", GlobPath},
		{"home exact", "~/.ssh/config", ExactPath},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := newPathMatcher("/proj", "/home/me", "/proj", tt.pattern)
			if got := pm.specificity(); got != tt.want {
				t.Errorf("specificity(%q) = %d, want %d", tt.pattern, got, tt.want)
			}
		})
	}
}

func TestPathMatch_RecursiveSecrets(t *testing.T) {
	pm := newPathMatcher(
		"/Users/me/project",
		"/Users/me",
		"/Users/me/project",
		"./.secrets/**",
	)

	if !pm.match("/Users/me/project/.secrets/api_key") {
		t.Fatal("expected match for file in .secrets")
	}
	if !pm.match("/Users/me/project/.secrets/deep/nested/key") {
		t.Fatal("expected match for deeply nested secret")
	}
}
