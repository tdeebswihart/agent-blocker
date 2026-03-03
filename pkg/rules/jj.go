package rules

import (
	"encoding/json"
	"os/exec"
	"strings"

	"github.com/buildkite/shellwords"
)

// jjEmptyChecker runs jj log and returns whether all resolved revisions are empty.
type jjEmptyChecker func(revsets []string) (bool, error)

func defaultJJCheck(revsets []string) (bool, error) {
	args := []string{"log", "--no-graph", "-T", `if(empty, "EMPTY\n", "NOTEMPTY\n")`}
	for _, r := range revsets {
		args = append(args, "-r", r)
	}
	out, err := exec.Command("jj", args...).Output()
	if err != nil {
		return false, err
	}
	return jjLogAllEmpty(string(out)), nil
}

// jjLogAllEmpty returns true if every line of jj log output indicates an empty
// revision. Returns false for empty output (no revisions resolved).
func jjLogAllEmpty(output string) bool {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return false
	}
	for line := range strings.SplitSeq(trimmed, "\n") {
		if strings.TrimSpace(line) != "EMPTY" {
			return false
		}
	}
	return true
}

// JJEditEmptyRule matches `jj edit`/`jj e` commands and allows them only when
// the target revision is empty. Returns Deny if the revision has changes.
type JJEditEmptyRule struct {
	check jjEmptyChecker
}

func JJEditEmpty() *JJEditEmptyRule {
	return &JJEditEmptyRule{check: defaultJJCheck}
}

func (r *JJEditEmptyRule) ToolName() string { return "Bash" }

func (r *JJEditEmptyRule) Match(_ string, input json.RawMessage) *Result {
	var in BashInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil
	}
	return r.Apply(in)
}

func (r *JJEditEmptyRule) Apply(input BashInput) *Result {
	revsets := parseJJEditRevsets(input.Command)
	if revsets == nil {
		return nil
	}
	empty, err := r.check(revsets)
	if err != nil {
		return nil
	}
	if empty {
		return NewResult(Allow, "jj edit: revision is empty")
	}
	return NewResult(Deny, "jj edit: revision is not empty")
}

// JJAbandonEmptyRule matches `jj abandon` commands and allows them only when
// ALL specified revisions are empty. Returns Deny if any revision has changes.
type JJAbandonEmptyRule struct {
	check jjEmptyChecker
}

func JJAbandonEmpty() *JJAbandonEmptyRule {
	return &JJAbandonEmptyRule{check: defaultJJCheck}
}

func (r *JJAbandonEmptyRule) ToolName() string { return "Bash" }

func (r *JJAbandonEmptyRule) Match(_ string, input json.RawMessage) *Result {
	var in BashInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil
	}
	return r.Apply(in)
}

func (r *JJAbandonEmptyRule) Apply(input BashInput) *Result {
	revsets := parseJJAbandonRevsets(input.Command)
	if revsets == nil {
		return nil
	}
	empty, err := r.check(revsets)
	if err != nil {
		return nil
	}
	if empty {
		return NewResult(Allow, "jj abandon: all revisions are empty")
	}
	return NewResult(Deny, "jj abandon: not all revisions are empty")
}

// parseJJEditRevsets extracts revsets from a `jj edit`/`jj e` command.
// Returns nil if the command is not a jj edit/e command.
func parseJJEditRevsets(command string) []string {
	cmd := command
	if stripped, ok := stripTimeoutPrefix(cmd); ok {
		cmd = stripped
	}
	words, err := shellwords.Split(cmd)
	if err != nil || len(words) < 2 {
		return nil
	}
	if words[0] != "jj" || (words[1] != "edit" && words[1] != "e") {
		return nil
	}
	return extractJJRevsets(words[2:], "--revision")
}

// parseJJAbandonRevsets extracts revsets from a `jj abandon` command.
// Returns nil if the command is not a jj abandon command.
func parseJJAbandonRevsets(command string) []string {
	cmd := command
	if stripped, ok := stripTimeoutPrefix(cmd); ok {
		cmd = stripped
	}
	words, err := shellwords.Split(cmd)
	if err != nil || len(words) < 2 {
		return nil
	}
	if words[0] != "jj" || words[1] != "abandon" {
		return nil
	}
	return extractJJRevsets(words[2:], "--revisions")
}

// extractJJRevsets walks args after the subcommand, collecting revsets from
// positional arguments and -r/--revision(s) flags. Skips known jj global
// flags that take values. Defaults to ["@"] if no revsets found.
func extractJJRevsets(args []string, longFlag string) []string {
	var revsets []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			revsets = append(revsets, args[i+1:]...)
			break
		}
		if arg == "-r" || arg == longFlag {
			if i+1 < len(args) {
				i++
				revsets = append(revsets, args[i])
			}
		} else if strings.HasPrefix(arg, "-") {
			// Skip flags. For --flag=value, nothing extra to skip.
			if !strings.Contains(arg, "=") {
				switch arg {
				case "-R", "--repository", "--color", "--config",
					"--config-file", "--at-operation", "--at-op":
					i++ // skip the value argument
				}
			}
		} else {
			revsets = append(revsets, arg)
		}
	}
	if len(revsets) == 0 {
		revsets = []string{"@"}
	}
	return revsets
}
