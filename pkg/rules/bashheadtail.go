package rules

import (
	"encoding/json"
	"strings"

	"github.com/buildkite/shellwords"
)

// BashHeadTailRule is a semantic matcher for head and tail commands. It allows
// invocations that read from STDIN or read safe file paths (relative without
// ".." or under /tmp/).
type BashHeadTailRule struct{}

// BashHeadTail creates a semantic matcher for head/tail commands.
func BashHeadTail() *BashHeadTailRule { return &BashHeadTailRule{} }

func (r *BashHeadTailRule) ToolName() string { return "Bash" }

func (r *BashHeadTailRule) Match(_ string, input json.RawMessage) *Result[PreToolUseOutput] {
	var bi BashInput
	if err := json.Unmarshal(input, &bi); err != nil {
		return nil
	}
	return r.Apply(bi)
}

func (r *BashHeadTailRule) Apply(input BashInput) *Result[PreToolUseOutput] {
	cmd := input.Command
	if stripped, ok := stripTimeoutPrefix(cmd); ok {
		cmd = stripped
	}
	if stripped, ok := stripRedirects(cmd); ok {
		cmd = stripped
	}

	tokens, err := shellwords.Split(cmd)
	if err != nil || len(tokens) == 0 {
		return nil
	}

	tool := tokens[0]
	if tool != "head" && tool != "tail" {
		return nil
	}

	// Flags that consume the next token as their argument.
	argFlags := map[string]bool{
		"-n": true, "-c": true,
	}
	if tool == "tail" {
		argFlags["-s"] = true
		argFlags["--pid"] = true
	}
	longArgFlags := map[string]bool{
		"--lines": true, "--bytes": true,
	}
	if tool == "tail" {
		longArgFlags["--sleep-interval"] = true
		longArgFlags["--pid"] = true
	}

	var filePaths []string

	for i := 1; i < len(tokens); i++ {
		tok := tokens[i]

		if strings.HasPrefix(tok, "--") {
			if found := strings.Contains(tok, "="); found {
				// Self-contained long flag (e.g., --lines=5).
				continue
			}
			if longArgFlags[tok] {
				i++ // consume next token as argument
				continue
			}
			// Other long flags (e.g., --follow, --quiet).
			continue
		}

		if strings.HasPrefix(tok, "-") && len(tok) > 1 {
			// Handle combined short flags. The last flag char determines
			// whether the next token is consumed.
			lastChar := string(tok[len(tok)-1:])
			flag := "-" + lastChar
			if argFlags[flag] {
				i++ // consume next token as argument
			}
			continue
		}

		// Positional — file path.
		filePaths = append(filePaths, tok)
	}

	for _, fp := range filePaths {
		if !isSafeRedirectTarget(fp) {
			return nil
		}
	}

	return NewResult(Allow, tool+": safe invocation")
}
