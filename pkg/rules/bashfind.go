package rules

import (
	"encoding/json"
	"strings"

	"github.com/buildkite/shellwords"
)

// BashFindRule matches `find` and `fd` bash commands and allows them only when
// all search paths are within the current directory tree (relative path without
// "..") or under /tmp. Commands containing action flags (-exec, -delete, etc.)
// are not matched, falling through to Ask.
type BashFindRule struct{}

func BashFind() *BashFindRule { return &BashFindRule{} }

func (r *BashFindRule) ToolName() string { return "Bash" }

func (r *BashFindRule) Match(_ string, input json.RawMessage) *Result[PreToolUseOutput] {
	var in BashInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil
	}
	return r.Apply(in)
}

func (r *BashFindRule) Apply(input BashInput) *Result[PreToolUseOutput] {
	cmd := unwrapCommand(input.Command)
	words, err := shellwords.Split(cmd)
	if err != nil || len(words) < 1 {
		return nil
	}
	switch words[0] {
	case "find":
		return applyFind(words)
	case "fd", "fdfind":
		return applyFd(words)
	default:
		return nil
	}
}

// dangerousFindFlags are find expression tokens that perform actions beyond
// searching. We don't auto-allow commands containing these.
var dangerousFindFlags = map[string]bool{
	"-exec": true, "-execdir": true, "-ok": true, "-okdir": true,
	"-delete": true,
}

// applyFind handles GNU/BSD find: find [options] [starting-point...] [expression]
// Options: -H, -L, -P, -D (with arg), -Olevel
// Starting points: positional args before the first expression token
// Expression tokens start with: -, (, ), !, ,
func applyFind(words []string) *Result[PreToolUseOutput] {
	i := 1

	// Skip leading options: -H, -L, -P, -D debugopts, -Olevel
	for i < len(words) {
		arg := words[i]
		switch {
		case arg == "-H" || arg == "-L" || arg == "-P":
			i++
		case arg == "-D":
			i += 2 // skip -D and its argument
		case strings.HasPrefix(arg, "-O"):
			i++ // -O0, -O1, etc.
		default:
			goto paths
		}
	}
paths:
	// Collect starting-point paths: anything before the first expression token.
	// Expression tokens start with -, (, ), !, or ,
	var paths []string
	for i < len(words) {
		arg := words[i]
		if isExpressionToken(arg) {
			break
		}
		paths = append(paths, arg)
		i++
	}

	// Check remaining expression for dangerous actions.
	for j := i; j < len(words); j++ {
		if dangerousFindFlags[words[j]] {
			return nil
		}
	}

	// No explicit paths means find defaults to "." (safe).
	if len(paths) == 0 {
		return NewResult(Allow, "find: defaults to cwd")
	}
	for _, p := range paths {
		if !isSafeRedirectTarget(p) {
			return nil
		}
	}
	return NewResult(Allow, "find: all search paths are within cwd or /tmp")
}

// isExpressionToken returns true if the argument looks like a find expression
// token rather than a starting-point path.
func isExpressionToken(arg string) bool {
	if len(arg) == 0 {
		return false
	}
	switch arg[0] {
	case '-', '(', ')', '!', ',':
		return true
	}
	return false
}

// dangerousFdFlags are fd flags that execute external commands.
var dangerousFdFlags = map[string]bool{
	"--exec": true, "--exec-batch": true, "-x": true, "-X": true,
}

// fdArgFlags are fd flags that consume the next argument as a value.
var fdArgFlags = map[string]bool{
	"-d": true, "--max-depth": true, "--min-depth": true,
	"-t": true, "--type": true,
	"-e": true, "--extension": true,
	"-E": true, "--exclude": true,
	"-c": true, "--color": true,
	"-j": true, "--threads": true,
	"-S": true, "--size": true,
	"--changed-within": true, "--changed-before": true,
	"--newer": true, "--older": true,
	"-o": true, "--owner": true,
	"--search-path": true, "--base-directory": true,
	"--path-separator": true, "--max-results": true,
	"--batch-size": true, "--gen-completions": true,
	"--max-buffer-time": true,
}

// applyFd handles fd/fdfind: fd [FLAGS/OPTIONS] [pattern] [path...]
// Paths are trailing positional arguments or --search-path/--base-directory.
func applyFd(words []string) *Result[PreToolUseOutput] {
	var paths []string
	var positionals []string
	seenDoubleDash := false

	for i := 1; i < len(words); i++ {
		arg := words[i]

		if arg == "--" {
			seenDoubleDash = true
			continue
		}
		if seenDoubleDash {
			positionals = append(positionals, arg)
			continue
		}

		// Check for dangerous flags early.
		if dangerousFdFlags[arg] {
			return nil
		}

		if strings.HasPrefix(arg, "--") {
			// Long flag with = is self-contained.
			if strings.Contains(arg, "=") {
				name := arg[:strings.IndexByte(arg, '=')]
				if name == "--search-path" || name == "--base-directory" {
					paths = append(paths, arg[strings.IndexByte(arg, '=')+1:])
				}
				continue
			}
			if arg == "--search-path" || arg == "--base-directory" {
				if i+1 < len(words) {
					i++
					paths = append(paths, words[i])
				}
				continue
			}
			if fdArgFlags[arg] {
				i++ // skip value
			}
			continue
		}

		if strings.HasPrefix(arg, "-") && len(arg) > 1 {
			// Short flags. The last character determines if the next token is
			// consumed (e.g., -td consumes next as type value... actually fd
			// short flags are single-character, not combined). Handle known
			// dangerous ones.
			if arg == "-x" || arg == "-X" {
				return nil
			}
			if fdArgFlags[arg] {
				i++ // skip value
			}
			continue
		}

		positionals = append(positionals, arg)
	}

	// fd positionals: [pattern] [path...] — first is pattern, rest are paths.
	// With --search-path or --base-directory, all positionals could be patterns,
	// but we only care about path arguments for safety. If explicit paths were
	// given via flags, use those. Otherwise, paths come from positionals[1:].
	if len(paths) == 0 && len(positionals) > 1 {
		paths = positionals[1:]
	}

	// No explicit paths means fd defaults to "." (safe).
	if len(paths) == 0 {
		return NewResult(Allow, "fd: defaults to cwd")
	}
	for _, p := range paths {
		if !isSafeRedirectTarget(p) {
			return nil
		}
	}
	return NewResult(Allow, "fd: all search paths are within cwd or /tmp")
}
