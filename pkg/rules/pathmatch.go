package rules

import (
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// pathMatcher handles gitignore-style path matching with support for:
//   - //path  → absolute filesystem path
//   - ~/path  → relative to home directory
//   - /path   → relative to project root
//   - ./path or bare path → relative to current working directory
//
// Uses doublestar for ** recursive glob matching.
type pathMatcher struct {
	// resolved is the pattern after prefix resolution to an absolute path.
	resolved string
}

// newPathMatcher creates a matcher that resolves a pattern against the given
// directory context. cwd, home, and projectRoot should be absolute paths.
func newPathMatcher(cwd, home, projectRoot, pattern string) pathMatcher {
	resolved := resolvePattern(cwd, home, projectRoot, pattern)
	return pathMatcher{resolved: resolved}
}

func (pm pathMatcher) match(filePath string) bool {
	filePath = filepath.Clean(filePath)
	matched, _ := doublestar.PathMatch(pm.resolved, filePath)
	return matched
}

// resolvePattern converts a gitignore-style pattern prefix to an absolute
// path pattern.
func resolvePattern(cwd, home, projectRoot, pattern string) string {
	switch {
	case strings.HasPrefix(pattern, "//"):
		// Absolute path: //Users/alice/file → /Users/alice/file
		return filepath.Clean(pattern[1:])
	case strings.HasPrefix(pattern, "~/"):
		// Home-relative: ~/path → /home/user/path
		return filepath.Clean(filepath.Join(home, pattern[2:]))
	case strings.HasPrefix(pattern, "/"):
		// Project-root-relative: /src → /project/src
		return filepath.Clean(filepath.Join(projectRoot, pattern[1:]))
	case strings.HasPrefix(pattern, "./"):
		// CWD-relative: ./path → /cwd/path
		return filepath.Clean(filepath.Join(cwd, pattern[2:]))
	default:
		// Bare pattern: also CWD-relative
		return filepath.Clean(filepath.Join(cwd, pattern))
	}
}
