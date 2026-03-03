package rules

import (
	"strings"

	"github.com/buildkite/shellwords"
)

type BashInput struct {
	Command     string `json:"command"`
	Description string `json:"description,omitempty"`
	Timeout     int    `json:"timeout,omitempty"`
}

type BashRule struct {
	decision Decision
	patterns []string
}

// Bash creates a rule that matches bash commands against glob patterns.
// Legacy ":*" suffix syntax is normalized to " *".
// If no patterns are given, the rule matches all bash commands.
func Bash(decision Decision, patterns ...string) *BashRule {
	normalized := make([]string, len(patterns))
	for i, p := range patterns {
		normalized[i] = normalizeColonStar(p)
	}
	return &BashRule{decision: decision, patterns: normalized}
}

func (r *BashRule) Apply(input BashInput) *Result {
	if len(r.patterns) == 0 {
		return NewResult(r.decision, "matches all Bash commands")
	}
	for _, pattern := range r.patterns {
		if bashMatch(pattern, input.Command) {
			return NewResult(r.decision, "matched pattern: "+pattern)
		}
	}
	return nil
}

// normalizeColonStar replaces every ":*" with " *".
// The docs say `:*` is the legacy suffix syntax equivalent to ` *`.
func normalizeColonStar(pattern string) string {
	return strings.ReplaceAll(pattern, ":*", " *")
}

// bashMatch checks if a command matches a glob pattern, with shell operator
// safety: if the command contains shell operators (&&, ||, ;, |) but the
// pattern does not, the match fails.
func bashMatch(pattern, command string) bool {
	patternOps := hasShellOperators(pattern)
	commandOps := hasShellOperators(command)

	if commandOps && !patternOps {
		return false
	}
	if globMatch(pattern, command) {
		return true
	}
	// Word boundary: "ls *" also matches "ls" (end-of-string).
	// The docs say: space before * "enforces a word boundary, requiring the
	// prefix to be followed by a space or end-of-string."
	if prefix, ok := strings.CutSuffix(pattern, " *"); ok {
		return globMatch(prefix, command)
	}
	return false
}

// shellOperators are the operators that indicate command chaining.
// Redirects (>, 2>&1) are NOT included — they don't chain commands.
var shellOperators = []string{"&&", "||", ";", "|"}

func hasShellOperators(s string) bool {
	// Use shellwords to respect quoting — operators inside quotes don't count.
	// We scan through the raw string but skip quoted regions.
	tokens, err := shellwords.Split(s)
	if err != nil {
		// If shellwords can't parse it, fall back to simple string check
		return containsAnyOperator(s)
	}
	for _, tok := range tokens {
		for _, op := range shellOperators {
			if tok == op {
				return true
			}
			// Check for operators embedded in tokens (e.g., "foo;bar")
			if strings.Contains(tok, op) && op != "|" {
				return true
			}
		}
	}
	// shellwords strips operators — check if the original has more tokens
	// than shellwords returned (indicating operators were present)
	return containsUnquotedOperator(s)
}

// containsUnquotedOperator scans for shell operators outside of quotes.
func containsUnquotedOperator(s string) bool {
	inSingle := false
	inDouble := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '\'' && !inDouble:
			inSingle = !inSingle
		case ch == '"' && !inSingle:
			inDouble = !inDouble
		case inSingle || inDouble:
			continue
		case ch == ';':
			return true
		case ch == '|':
			if i+1 < len(s) && s[i+1] == '|' {
				return true // ||
			}
			return true // |
		case ch == '&' && i+1 < len(s) && s[i+1] == '&':
			return true // &&
		}
	}
	return false
}

func containsAnyOperator(s string) bool {
	for _, op := range shellOperators {
		if strings.Contains(s, op) {
			return true
		}
	}
	return false
}

// globMatch performs glob-style pattern matching where * matches any sequence
// of characters (including spaces). This is string globbing, not path globbing.
func globMatch(pattern, s string) bool {
	px, sx := 0, 0
	nextpx, nextsx := 0, -1

	for sx < len(s) {
		switch {
		case px < len(pattern) && pattern[px] == '*':
			nextpx = px
			nextsx = sx
			px++
		case px < len(pattern) && pattern[px] == s[sx]:
			px++
			sx++
		case nextsx >= 0:
			nextsx++
			sx = nextsx
			px = nextpx + 1
		default:
			return false
		}
	}
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}
