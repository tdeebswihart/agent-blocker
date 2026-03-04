package rules

import (
	"encoding/json"
	"path/filepath"

	"github.com/buildkite/shellwords"
)

// BashLocalCmdRule matches Bash commands where the program being invoked is
// within the project directory tree. This allows execution of local scripts,
// built binaries, and other project-local commands (e.g., ./script.sh,
// bin/test, /absolute/path/within/project/cmd).
//
// Only commands whose first token contains a "/" are considered — bare commands
// like "ls" or "go" are PATH lookups and are not matched by this rule.
type BashLocalCmdRule struct {
	projectRoot string
}

func BashLocalCmd(projectRoot string) *BashLocalCmdRule {
	return &BashLocalCmdRule{projectRoot: projectRoot}
}

func (r *BashLocalCmdRule) ToolName() string { return "Bash" }

func (r *BashLocalCmdRule) Match(_ string, input json.RawMessage) *Result[PreToolUseOutput] {
	var in BashInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil
	}
	return r.Apply(in)
}

func (r *BashLocalCmdRule) Apply(input BashInput) *Result[PreToolUseOutput] {
	program := parseProgram(input.Command, r.projectRoot)
	if program == "" {
		return nil
	}

	// Resolve relative paths against project root.
	if !filepath.IsAbs(program) {
		program = filepath.Join(r.projectRoot, program)
	}
	program = filepath.Clean(program)

	if isDescendantOf(program, r.projectRoot) {
		return NewResult(Allow, "local command: program is within project root")
	}
	return nil
}

// parseProgram extracts the program path from a command string. Returns ""
// if the program is a bare command (no "/") or cannot be parsed.
func parseProgram(command, cwd string) string {
	cmd := unwrapCommand(command, cwd)
	words, err := shellwords.Split(cmd)
	if err != nil || len(words) == 0 {
		return ""
	}
	prog := words[0]
	// Only match paths — bare commands like "ls" are PATH lookups.
	if !containsByte(prog, '/') {
		return ""
	}
	return prog
}
