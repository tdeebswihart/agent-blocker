package logging

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"codeberg.org/timods/agent-blocker/pkg/rules"
)

const maxLogSize = 5 * 1024 * 1024 // 5 MB

// Entry is a single JSON Lines record written to the session log.
type Entry struct {
	Timestamp string          `json:"ts"`
	SessionID string          `json:"session_id"`
	Tool      string          `json:"tool"`
	Decision  string          `json:"decision"`
	Reason    string          `json:"reason"`
	ToolInput json.RawMessage `json:"tool_input"`
}

// LogInvocation logs a hook evaluation to the per-project log file.
// Fire-and-forget: all errors are silently ignored.
func LogInvocation(
	input rules.HookInput,
	result *rules.Result[rules.PreToolUseOutput],
) {
	logDir := filepath.Join(
		os.Getenv("HOME"), "Library", "Logs", "agent-blocker",
	)
	name := safeProjectName(input.CWD)
	path := filepath.Join(logDir, name+".log")
	writeLogEntry(path, input, result) //nolint:errcheck
}

// writeLogEntry marshals and appends a log entry to the given path.
// Exported for testing with explicit paths.
func writeLogEntry(
	path string,
	input rules.HookInput,
	result *rules.Result[rules.PreToolUseOutput],
) error {
	var decision, reason string
	if result != nil {
		decision = string(result.HookSpecificOutput.PermissionDecision)
		reason = result.HookSpecificOutput.PermissionDecisionReason
	}

	entry := Entry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		SessionID: input.SessionID,
		Tool:      input.Name,
		Decision:  decision,
		Reason:    reason,
		ToolInput: sanitizeInput(input.Name, input.Input),
	}

	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	f, err := openLogFile(path)
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck

	_, err = f.Write(line)
	return err
}

var unsafeChars = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// safeProjectName returns a deterministic, filesystem-safe name derived from
// cwd: sanitized basename + "-" + first 8 hex chars of sha256(cwd).
func safeProjectName(cwd string) string {
	base := filepath.Base(cwd)
	if base == "" || base == "." || base == "/" {
		base = "root"
	}
	base = unsafeChars.ReplaceAllString(base, "_")

	hash := sha256.Sum256([]byte(cwd))
	return fmt.Sprintf("%s-%x", base, hash[:4])
}

// sanitizeInput strips large content from Write and Edit tool inputs,
// replacing it with byte lengths. Other tools pass through unchanged.
func sanitizeInput(
	toolName string,
	raw json.RawMessage,
) json.RawMessage {
	switch toolName {
	case "Write":
		return sanitizeWriteInput(raw)
	case "Edit":
		return sanitizeEditInput(raw)
	default:
		return raw
	}
}

func sanitizeWriteInput(raw json.RawMessage) json.RawMessage {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw
	}
	if content, ok := m["content"]; ok {
		var s string
		if err := json.Unmarshal(content, &s); err == nil {
			length, _ := json.Marshal(len(s))
			m["content_length"] = length
			delete(m, "content")
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return out
}

func sanitizeEditInput(raw json.RawMessage) json.RawMessage {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw
	}
	for _, key := range []string{"old_string", "new_string"} {
		if val, ok := m[key]; ok {
			var s string
			if err := json.Unmarshal(val, &s); err == nil {
				length, _ := json.Marshal(len(s))
				m[key+"_length"] = length
				delete(m, key)
			}
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return out
}

// openLogFile creates the log directory if needed, truncates the file if it
// exceeds maxLogSize, and opens it for appending.
func openLogFile(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	info, err := os.Stat(path)
	if err == nil && info.Size() >= maxLogSize {
		if err := os.Truncate(path, 0); err != nil {
			return nil, err
		}
	}

	return os.OpenFile(
		path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644,
	)
}
