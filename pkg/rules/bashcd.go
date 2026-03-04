package rules

import (
	"encoding/json"
	"path"
	"path/filepath"
	"strings"

	"github.com/buildkite/shellwords"
)

// BashCDRule matches `cd` bash commands and allows them only when the target
// directory is descended from the project root or under /tmp.
type BashCDRule struct {
	projectRoot string
}

func BashCD(projectRoot string) *BashCDRule {
	return &BashCDRule{projectRoot: projectRoot}
}

func (r *BashCDRule) ToolName() string { return "Bash" }

func (r *BashCDRule) Match(_ string, input json.RawMessage) *Result[PreToolUseOutput] {
	var in BashInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil
	}
	return r.Apply(in)
}

func (r *BashCDRule) Apply(input BashInput) *Result[PreToolUseOutput] {
	target := parseCDTarget(input.Command, r.projectRoot)
	if target == nil {
		return nil
	}

	dir := *target
	// Resolve relative paths against project root.
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(r.projectRoot, dir)
	}
	dir = filepath.Clean(dir)

	if isDescendantOf(dir, r.projectRoot) || isTmpPath(dir) {
		return NewResult(Allow, "cd: target is within project root or /tmp")
	}
	return nil
}

// parseCDTarget extracts the target directory from a cd command.
// Returns nil if the command is not a cd command.
func parseCDTarget(command, cwd string) *string {
	cmd := unwrapCommand(command, cwd)
	words, err := shellwords.Split(cmd)
	if err != nil || len(words) < 1 {
		return nil
	}
	if words[0] != "cd" {
		return nil
	}
	// cd with no args goes to $HOME — not safe to auto-allow.
	if len(words) < 2 {
		return nil
	}
	target := words[1]
	return &target
}

// isDescendantOf returns true if child is equal to or a subdirectory of parent.
// Both paths should be cleaned absolute paths.
func isDescendantOf(child, parent string) bool {
	return child == parent || strings.HasPrefix(child, parent+"/")
}

// isTmpPath returns true if the path is /tmp or under /tmp/.
func isTmpPath(p string) bool {
	cleaned := path.Clean(p)
	return cleaned == "/tmp" || strings.HasPrefix(cleaned, "/tmp/")
}
