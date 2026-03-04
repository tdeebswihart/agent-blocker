package rules

import (
	"encoding/json"
	"strings"

	"github.com/buildkite/shellwords"
)

// BashGrepRule is a semantic matcher for grep and rg commands. It allows
// invocations that read from STDIN or search safe file paths (relative without
// ".." or under /tmp/). Commands that use file-reading flags (-f, --file,
// --pre, --ignore-file) are rejected because they bypass positional path
// validation.
type BashGrepRule struct{}

// BashGrep creates a semantic matcher for grep/rg commands.
func BashGrep() *BashGrepRule { return &BashGrepRule{} }

func (r *BashGrepRule) ToolName() string { return "Bash" }

func (r *BashGrepRule) Match(_ string, input json.RawMessage) *Result[PreToolUseOutput] {
	var bi BashInput
	if err := json.Unmarshal(input, &bi); err != nil {
		return nil
	}
	return r.Apply(bi)
}

func (r *BashGrepRule) Apply(input BashInput) *Result[PreToolUseOutput] {
	cmd := unwrapCommand(input.Command)

	tokens, err := shellwords.Split(cmd)
	if err != nil || len(tokens) == 0 {
		return nil
	}

	tool := tokens[0]
	if tool != "grep" && tool != "rg" {
		return nil
	}

	// Flags that read files — reject the entire command.
	blockedFlags := map[string]bool{
		"-f": true, "--file": true, "--pre": true, "--ignore-file": true,
	}

	// Flags that consume the next token as their argument.
	grepArgFlags := map[string]bool{
		"-e": true, "-m": true, "-A": true, "-B": true, "-C": true,
		"-D": true, "-d": true,
	}
	rgArgFlags := map[string]bool{
		"-e": true, "-g": true, "-t": true, "-T": true, "-m": true,
		"-A": true, "-B": true, "-C": true, "-j": true,
	}
	// Long flags that consume a separate argument (no =).
	longArgFlags := map[string]bool{
		"--regexp": true, "--max-count": true, "--after-context": true,
		"--before-context": true, "--context": true, "--glob": true,
		"--type": true, "--type-not": true, "--threads": true,
	}

	argFlags := grepArgFlags
	if tool == "rg" {
		argFlags = rgArgFlags
	}

	hasE := false
	var positionals []string

	for i := 1; i < len(tokens); i++ {
		tok := tokens[i]

		// Check blocked flags.
		if blockedFlags[tok] {
			return nil
		}
		// Long flag with = (e.g., --file=patterns.txt).
		if strings.HasPrefix(tok, "--") {
			if before, _, ok := strings.Cut(tok, "="); ok {
				flag := before
				if blockedFlags[flag] {
					return nil
				}
				// Self-contained; no next-token consumption.
				continue
			}
			// Long flag without =.
			if longArgFlags[tok] {
				i++ // consume next token as argument
				continue
			}
			// Other long flags (e.g., --color, --invert-match) — no arg.
			continue
		}

		// Short flag(s).
		if strings.HasPrefix(tok, "-") && len(tok) > 1 {
			// Could be combined flags like -rin. Check last char for arg flags.
			lastChar := string(tok[len(tok)-1:])
			flag := "-" + lastChar
			if blockedFlags[flag] {
				return nil
			}
			if flag == "-e" {
				hasE = true
			}
			if argFlags[flag] {
				i++ // consume next token as argument
			}
			continue
		}

		// Positional argument.
		positionals = append(positionals, tok)
	}

	// With -e, pattern is consumed by the flag — all positionals are file paths.
	// Without -e, first positional is the pattern; rest are file paths.
	var filePaths []string
	if hasE {
		filePaths = positionals
	} else if len(positionals) > 1 {
		filePaths = positionals[1:]
	}

	for _, fp := range filePaths {
		if !isSafeRedirectTarget(fp) {
			return nil
		}
	}

	return NewResult(Allow, tool+": safe invocation")
}
