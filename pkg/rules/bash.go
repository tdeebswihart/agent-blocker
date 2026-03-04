package rules

import (
	"encoding/json"
	"path"
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
	cwd      string
	patterns []string
}

// Bash creates a rule that matches bash commands against glob patterns.
// Legacy ":*" suffix syntax is normalized to " *".
// If no patterns are given, the rule matches all bash commands.
func Bash(decision Decision, cwd string, patterns ...string) *BashRule {
	normalized := make([]string, len(patterns))
	for i, p := range patterns {
		normalized[i] = normalizeColonStar(p)
	}
	return &BashRule{decision: decision, cwd: cwd, patterns: normalized}
}

func (r *BashRule) Apply(input BashInput) *Result[PreToolUseOutput] {
	if len(r.patterns) == 0 {
		return NewResult(r.decision, "matches all Bash commands")
	}
	for _, pattern := range r.patterns {
		if bashMatch(pattern, input.Command, r.cwd) {
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
func bashMatch(pattern, command, cwd string) bool {
	// Strip known safe suffixes before any checks — the exit-code echo
	// contains a semicolon that would otherwise trigger operator rejection.
	command = stripExitCodeSuffix(command)

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
		return bashMatch(pattern, stripped, cwd)
	}
	// See through an `xargs` wrapper to match the underlying command.
	if stripped, ok := stripXargsPrefix(command); ok {
		return bashMatch(pattern, stripped, cwd)
	}
	// See through output redirects to safe locations (current dir or /tmp/).
	if stripped, ok := stripRedirects(command, cwd); ok {
		return bashMatch(pattern, stripped, cwd)
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
	return len(splitCompoundCommand(s)) > 1
}

func containsAnyOperator(s string) bool {
	for _, op := range shellOperators {
		if strings.Contains(s, op) {
			return true
		}
	}
	return false
}

// stripExitCodeSuffix removes a trailing `; echo "Exit code: $?"` from a
// command string. Some tools append this suffix to capture the exit code;
// it is not part of the actual command being authorized.
func stripExitCodeSuffix(command string) string {
	const suffix = `; echo "Exit code: $?"`
	if s, ok := strings.CutSuffix(strings.TrimSpace(command), suffix); ok {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			return trimmed
		}
	}
	return command
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

// unwrapCommand strips known safe wrappers (timeout, xargs) and output
// redirects from a command string, returning the underlying command. Wrappers
// are stripped in a loop so that any nesting order (e.g., timeout wrapping
// xargs or vice versa) is handled.
func unwrapCommand(cmd, cwd string) string {
	for {
		if stripped, ok := stripTimeoutPrefix(cmd); ok {
			cmd = stripped
			continue
		}
		if stripped, ok := stripXargsPrefix(cmd); ok {
			cmd = stripped
			continue
		}
		break
	}
	if stripped, ok := stripRedirects(cmd, cwd); ok {
		cmd = stripped
	}
	return cmd
}

// stripXargsPrefix removes a leading `xargs [flags]` from a command string,
// returning the actual command that follows. Returns ("", false) if the command
// doesn't start with "xargs " or has no command after the flags.
func stripXargsPrefix(command string) (string, bool) {
	s := strings.TrimSpace(command)
	if !strings.HasPrefix(s, "xargs ") {
		return "", false
	}
	s = strings.TrimSpace(s[len("xargs"):])

	// Short flags that take a separate argument.
	argFlags := map[byte]bool{
		'I': true, 'd': true, 'L': true, 'n': true,
		'P': true, 's': true, 'E': true,
	}
	// Long flags that take a separate argument (when written without =).
	longArgFlags := map[string]bool{
		"--replace": true, "--delimiter": true, "--max-lines": true,
		"--max-args": true, "--max-procs": true, "--max-chars": true,
		"--eof": true,
	}

	for strings.HasPrefix(s, "-") {
		end := strings.IndexByte(s, ' ')
		if end == -1 {
			return "", false // flag with no command following
		}
		flag := s[:end]
		s = strings.TrimSpace(s[end:])

		if strings.HasPrefix(flag, "--") {
			// Long flag with = is self-contained (e.g., --max-procs=4).
			if strings.Contains(flag, "=") {
				continue
			}
			// Long flag needing a separate argument.
			if longArgFlags[flag] {
				end = strings.IndexByte(s, ' ')
				if end == -1 {
					return "", false
				}
				s = strings.TrimSpace(s[end:])
			}
			continue
		}

		// Short flags: could be combined (e.g., -0rt). The last char
		// determines whether the next token is consumed as an argument.
		last := flag[len(flag)-1]
		if argFlags[last] {
			end = strings.IndexByte(s, ' ')
			if end == -1 {
				return "", false
			}
			s = strings.TrimSpace(s[end:])
		}
	}

	if s == "" {
		return "", false
	}
	return s, true
}

// stripRedirects removes output redirect operators and their targets from a
// command, returning the underlying command. Only redirects to safe locations
// (relative paths without ".." or absolute paths under /tmp/) are stripped.
// Fd dups like 2>&1 are always stripped. Returns ("", false) if no redirects
// are found or any redirect target is unsafe.
func stripRedirects(command, cwd string) (string, bool) {
	var buf strings.Builder
	found := false
	i := 0
	n := len(command)

	for i < n {
		ch := command[i]

		// Preserve quoted regions as-is.
		if ch == '\'' || ch == '"' {
			j := i + 1
			for j < n && command[j] != ch {
				j++
			}
			if j < n {
				j++ // include closing quote
			}
			buf.WriteString(command[i:j])
			i = j
			continue
		}

		// A redirect operator must be preceded by whitespace or be at position 0.
		if i > 0 && command[i-1] != ' ' && command[i-1] != '\t' {
			buf.WriteByte(ch)
			i++
			continue
		}

		// Quick check: redirect must start with digit, &, or >.
		if ch != '>' && !(ch >= '0' && ch <= '9') && ch != '&' {
			buf.WriteByte(ch)
			i++
			continue
		}

		if consumed, target, ok := consumeRedirect(command, i); ok {
			if target != "" && !isSafeRedirectTarget(target, cwd) {
				return "", false
			}
			found = true
			i = consumed
			continue
		}

		buf.WriteByte(ch)
		i++
	}

	if !found {
		return "", false
	}
	result := strings.TrimSpace(buf.String())
	if result == "" {
		return "", false
	}
	return result, true
}

// consumeRedirect tries to consume a redirect operator and its target starting
// at position pos in command. Returns (newPos, target, true) on success, where
// target is the file path (empty string for fd dups like 2>&1).
func consumeRedirect(command string, pos int) (int, string, bool) {
	i := pos
	n := len(command)

	// Optional fd number: single digit directly before > (e.g., "2>" in "2> err.log").
	if i < n && command[i] >= '0' && command[i] <= '9' &&
		i+1 < n && command[i+1] == '>' {
		i++ // consume fd digit
	}

	// &> or &>> (redirect both stdout and stderr).
	if i == pos && i < n && command[i] == '&' &&
		i+1 < n && command[i+1] == '>' {
		i++ // consume &
	}

	if i >= n || command[i] != '>' {
		return pos, "", false
	}
	i++ // consume first >

	// >> (append mode).
	isAppend := false
	if i < n && command[i] == '>' {
		i++
		isAppend = true
	}

	// Fd dup: >&N — only valid after single >, not >>.
	if !isAppend && i < n && command[i] == '&' &&
		i+1 < n && command[i+1] >= '0' && command[i+1] <= '9' {
		i += 2 // consume &N
		for i < n && (command[i] == ' ' || command[i] == '\t') {
			i++
		}
		return i, "", true
	}

	// Skip whitespace between operator and target.
	for i < n && (command[i] == ' ' || command[i] == '\t') {
		i++
	}

	// Read target filename.
	tStart := i
	for i < n && command[i] != ' ' && command[i] != '\t' &&
		command[i] != '>' && command[i] != '<' &&
		command[i] != '|' && command[i] != ';' && command[i] != '&' {
		i++
	}
	if i == tStart {
		return pos, "", false // no target
	}

	target := command[tStart:i]

	// Skip trailing whitespace.
	for i < n && (command[i] == ' ' || command[i] == '\t') {
		i++
	}

	return i, target, true
}

// isSafeRedirectTarget returns true if the target path is within the current
// directory (relative path without ".."), under /tmp/, or an absolute path
// that is a descendant of cwd.
func isSafeRedirectTarget(target, cwd string) bool {
	cleaned := path.Clean(target)
	if strings.HasPrefix(cleaned, "/tmp/") || cleaned == "/tmp" {
		return true
	}
	if strings.HasPrefix(cleaned, "/") {
		if cwd != "" {
			return isDescendantOf(cleaned, path.Clean(cwd))
		}
		return false
	}
	// After cleaning, any ".." prefix means the path escapes the current directory.
	return !strings.HasPrefix(cleaned, "..")
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

// splitCompoundCommand splits a command string on unquoted shell operators
// (||, &&, ;, |). Respects single and double quotes. Returns individual
// commands trimmed of whitespace. Returns a single-element slice when no
// unquoted operators are found.
func splitCompoundCommand(command string) []string {
	var parts []string
	start := 0
	inSingle := false
	inDouble := false

	for i := 0; i < len(command); i++ {
		ch := command[i]
		switch {
		case ch == '\'' && !inDouble:
			inSingle = !inSingle
		case ch == '"' && !inSingle:
			inDouble = !inDouble
		case inSingle || inDouble:
			continue
		case ch == '&' && i+1 < len(command) && command[i+1] == '&':
			if part := strings.TrimSpace(command[start:i]); part != "" {
				parts = append(parts, part)
			}
			i++ // skip second &
			start = i + 1
		case ch == '|' && i+1 < len(command) && command[i+1] == '|':
			if part := strings.TrimSpace(command[start:i]); part != "" {
				parts = append(parts, part)
			}
			i++ // skip second |
			start = i + 1
		case ch == '|':
			if part := strings.TrimSpace(command[start:i]); part != "" {
				parts = append(parts, part)
			}
			start = i + 1
		case ch == ';':
			if part := strings.TrimSpace(command[start:i]); part != "" {
				parts = append(parts, part)
			}
			start = i + 1
		}
	}
	if part := strings.TrimSpace(command[start:]); part != "" {
		parts = append(parts, part)
	}
	if len(parts) == 0 {
		return []string{command}
	}
	return parts
}

func (r *BashRule) ToolName() string { return "Bash" }
func (r *BashRule) Match(_ string, input json.RawMessage) *Result[PreToolUseOutput] {
	var in BashInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil
	}
	return r.Apply(in)
}
