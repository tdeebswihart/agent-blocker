package rules

import (
	"encoding/json"
	"strings"
)

// BashEchoRule is a semantic matcher for echo commands. It allows echo when the
// command contains no unsafe variable substitutions. Safe builtins ($?, $#, $*,
// $@) are permitted. Any other $ expansion or backtick substitution outside
// single quotes is rejected to prevent environment variable exfiltration.
type BashEchoRule struct{}

// BashEcho creates a semantic matcher for echo commands.
func BashEcho() *BashEchoRule { return &BashEchoRule{} }

func (r *BashEchoRule) ToolName() string { return "Bash" }

func (r *BashEchoRule) Match(_ string, input json.RawMessage) *Result[PreToolUseOutput] {
	var bi BashInput
	if err := json.Unmarshal(input, &bi); err != nil {
		return nil
	}
	return r.Apply(bi)
}

func (r *BashEchoRule) Apply(input BashInput) *Result[PreToolUseOutput] {
	cmd := strings.TrimSpace(unwrapCommand(input.Command))

	if !strings.HasPrefix(cmd, "echo ") && cmd != "echo" {
		return nil
	}

	// Scan the portion after "echo" for unsafe substitutions.
	rest := cmd[len("echo"):]
	if !echoIsSafe(rest) {
		return nil
	}

	return NewResult(Allow, "echo: safe invocation")
}

// echoIsSafe scans s for unsafe shell substitutions. Returns false if any
// variable expansion (other than $?, $#, $*, $@), command substitution ($()),
// or backtick is found outside single quotes.
func echoIsSafe(s string) bool {
	inSingle := false
	for i := 0; i < len(s); i++ {
		ch := s[i]

		if ch == '\'' && !inSingle {
			inSingle = true
			continue
		}
		if ch == '\'' && inSingle {
			inSingle = false
			continue
		}
		if inSingle {
			continue
		}

		if ch == '`' {
			return false
		}

		if ch == '$' && i+1 < len(s) {
			next := s[i+1]
			// Safe builtins.
			if next == '?' || next == '#' || next == '*' || next == '@' {
				i++ // skip the safe char
				continue
			}
			// Unsafe: letter, digit, underscore, {, (
			if isVarStart(next) {
				return false
			}
			// Bare $ at end or followed by something else (e.g., space) is fine.
			continue
		}
	}
	return true
}

func isVarStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '_' || c == '{' || c == '('
}
