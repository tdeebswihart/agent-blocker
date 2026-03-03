package rules

import (
	"encoding/json"
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

// normalizeColonStar replaces ":*" with " *" when preceded by a word character
// (the usual command:args separator), or with just "*" when preceded by a
// non-word character like "/" (e.g., "jj bookmark create tim/:*" → "…tim/*").
func normalizeColonStar(pattern string) string {
	var b strings.Builder
	for i := 0; i < len(pattern); i++ {
		if i+1 < len(pattern) && pattern[i] == ':' && pattern[i+1] == '*' {
			if i > 0 && isWordChar(pattern[i-1]) {
				b.WriteByte(' ')
			}
			b.WriteByte('*')
			i++ // skip '*'
		} else {
			b.WriteByte(pattern[i])
		}
	}
	return b.String()
}

func isWordChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '-' || c == '_'
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
		if globMatch(prefix, command) {
			return true
		}
	}
	// See through a `timeout` wrapper to match the underlying command.
	if stripped, ok := stripTimeoutPrefix(command); ok {
		return bashMatch(pattern, stripped)
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

// stripTimeoutPrefix removes a leading `timeout [flags] <duration>` from a
// command string, returning the actual command that follows. Returns ("", false)
// if the command doesn't start with "timeout " or has no command after the
// timeout arguments.
func stripTimeoutPrefix(command string) (string, bool) {
	s := strings.TrimSpace(command)
	if !strings.HasPrefix(s, "timeout ") {
		return "", false
	}
	s = strings.TrimSpace(s[len("timeout"):])

	// Skip flags and their arguments.
	for strings.HasPrefix(s, "-") {
		end := strings.IndexByte(s, ' ')
		if end == -1 {
			return "", false
		}
		flag := s[:end]
		s = strings.TrimSpace(s[end:])

		// Flags that take a separate argument (without =).
		if flag == "-k" || flag == "-s" || flag == "--kill-after" || flag == "--signal" {
			end = strings.IndexByte(s, ' ')
			if end == -1 {
				return "", false
			}
			s = strings.TrimSpace(s[end:])
		}
	}

	// Skip the duration (one word).
	end := strings.IndexByte(s, ' ')
	if end == -1 {
		return "", false
	}
	s = strings.TrimSpace(s[end:])
	if s == "" {
		return "", false
	}
	return s, true
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

func (r *BashRule) ToolName() string       { return "Bash" }
func (r *BashRule) Decision() Decision     { return r.decision }
func (r *BashRule) Match(_ string, input json.RawMessage) *Result {
	var in BashInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil
	}
	return r.Apply(in)
}
