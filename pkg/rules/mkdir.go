package rules

import (
	"encoding/json"

	"github.com/buildkite/shellwords"
)

// MkdirRule matches `mkdir` bash commands and allows them only when every
// target directory is within the current directory tree (relative path without
// "..") or under /tmp. Uses the same safety semantics as redirect-target
// validation (isSafeRedirectTarget).
type MkdirRule struct{ cwd string }

func Mkdir(cwd string) *MkdirRule { return &MkdirRule{cwd: cwd} }

func (r *MkdirRule) ToolName() string { return "Bash" }

func (r *MkdirRule) Match(_ string, input json.RawMessage) *Result[PreToolUseOutput] {
	var in BashInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil
	}
	return r.Apply(in)
}

func (r *MkdirRule) Apply(input BashInput) *Result[PreToolUseOutput] {
	dirs := parseMkdirTargets(input.Command, r.cwd)
	if dirs == nil {
		return nil
	}
	for _, d := range dirs {
		if !isSafeRedirectTarget(d, r.cwd) {
			return nil
		}
	}
	return NewResult(Allow, "mkdir: all targets are within cwd or /tmp")
}

// parseMkdirTargets extracts target directory paths from a mkdir command.
// Returns nil if the command is not a mkdir command or has no targets.
func parseMkdirTargets(command, cwd string) []string {
	cmd := unwrapCommand(command, cwd)
	words, err := shellwords.Split(cmd)
	if err != nil || len(words) < 1 {
		return nil
	}
	if words[0] != "mkdir" {
		return nil
	}

	// Known mkdir flags that consume a following argument.
	argFlags := map[string]bool{
		"-m": true, "--mode": true,
	}

	var dirs []string
	pastOptions := false
	for i := 1; i < len(words); i++ {
		arg := words[i]
		if !pastOptions && arg == "--" {
			pastOptions = true
			continue
		}
		if pastOptions {
			dirs = append(dirs, arg)
			continue
		}
		if arg[0] != '-' {
			dirs = append(dirs, arg)
			continue
		}
		// Long flag with = is self-contained (--mode=0755).
		if len(arg) > 2 && arg[0] == '-' && arg[1] == '-' {
			if containsByte(arg, '=') {
				continue
			}
			if argFlags[arg] {
				i++ // skip value
			}
			continue
		}
		// Short flags: the last character determines if the next token is
		// consumed as an argument (e.g., -pm 0755 → -p is boolean, -m eats
		// the next word).
		last := string(arg[len(arg)-1:])
		if argFlags["-"+last] {
			i++ // skip value
		}
	}
	if len(dirs) == 0 {
		return nil
	}
	return dirs
}

func containsByte(s string, b byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return true
		}
	}
	return false
}
