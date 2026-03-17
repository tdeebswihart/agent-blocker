package logging

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tdeebswihart/agent-blocker/pkg/rules"
)

func TestSafeProjectName(t *testing.T) {
	tests := []struct {
		name string
		cwd  string
		want string // just the prefix before the hash
	}{
		{"normal", "/Users/tim/git/myproj", "myproj-"},
		{"spaces", "/Users/tim/my project", "my_project-"},
		{"root", "/", "root-"},
		{"empty", "", "root-"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := safeProjectName(tt.cwd)
			if !strings.HasPrefix(got, tt.want) {
				t.Fatalf("safeProjectName(%q) = %q, want prefix %q",
					tt.cwd, got, tt.want)
			}
			// Should have 8 hex chars after the prefix.
			suffix := got[len(tt.want):]
			if len(suffix) != 8 {
				t.Fatalf("expected 8-char hex suffix, got %q", suffix)
			}
		})
	}
}

func TestSafeProjectNameCollision(t *testing.T) {
	a := safeProjectName("/Users/alice/myproj")
	b := safeProjectName("/Users/bob/myproj")
	if a == b {
		t.Fatalf("different paths with same basename should produce "+
			"different names, both got %q", a)
	}
}

func TestSanitizeInput_Write(t *testing.T) {
	raw := json.RawMessage(`{
		"file_path":"/tmp/foo.txt",
		"content":"hello world"
	}`)
	got := sanitizeInput("Write", raw)

	var m map[string]json.RawMessage
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["content"]; ok {
		t.Fatal("content should have been removed")
	}
	if _, ok := m["content_length"]; !ok {
		t.Fatal("content_length should be present")
	}
	var length int
	if err := json.Unmarshal(m["content_length"], &length); err != nil {
		t.Fatal(err)
	}
	if length != len("hello world") {
		t.Fatalf("content_length = %d, want %d", length, len("hello world"))
	}
	if _, ok := m["file_path"]; !ok {
		t.Fatal("file_path should be preserved")
	}
}

func TestSanitizeInput_Edit(t *testing.T) {
	raw := json.RawMessage(`{
		"file_path":"/tmp/foo.go",
		"old_string":"func old(){}",
		"new_string":"func new(){}"
	}`)
	got := sanitizeInput("Edit", raw)

	var m map[string]json.RawMessage
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["old_string"]; ok {
		t.Fatal("old_string should have been removed")
	}
	if _, ok := m["new_string"]; ok {
		t.Fatal("new_string should have been removed")
	}

	var oldLen, newLen int
	if err := json.Unmarshal(m["old_string_length"], &oldLen); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(m["new_string_length"], &newLen); err != nil {
		t.Fatal(err)
	}
	if oldLen != len("func old(){}") {
		t.Fatalf("old_string_length = %d, want %d", oldLen, len("func old(){}"))
	}
	if newLen != len("func new(){}") {
		t.Fatalf("new_string_length = %d, want %d", newLen, len("func new(){}"))
	}
}

func TestSanitizeInput_Passthrough(t *testing.T) {
	raw := json.RawMessage(`{"command":"ls -la"}`)
	got := sanitizeInput("Bash", raw)
	if string(got) != string(raw) {
		t.Fatalf("Bash input should pass through unchanged, got %s", got)
	}
}

func TestWriteLogEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	input := rules.HookInput{
		SessionID: "sess-123",
		Name:      "Bash",
		CWD:       "/tmp/proj",
		Input:     json.RawMessage(`{"command":"ls"}`),
	}
	result := rules.NewResult(rules.Allow, "matched pattern: ls")

	if err := writeLogEntry(path, input, result); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var entry Entry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("invalid JSON line: %v\ndata: %s", err, data)
	}
	if entry.SessionID != "sess-123" {
		t.Fatalf("session_id = %q, want %q", entry.SessionID, "sess-123")
	}
	if entry.Tool != "Bash" {
		t.Fatalf("tool = %q, want %q", entry.Tool, "Bash")
	}
	if entry.Decision != "allow" {
		t.Fatalf("decision = %q, want %q", entry.Decision, "allow")
	}
	if entry.Reason != "matched pattern: ls" {
		t.Fatalf("reason = %q, want %q", entry.Reason, "matched pattern: ls")
	}
	if entry.Timestamp == "" {
		t.Fatal("timestamp should not be empty")
	}
}

func TestLogRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.log")

	// Create a file larger than 5MB.
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, 6*1024*1024); err != nil {
		t.Fatal(err)
	}

	input := rules.HookInput{
		SessionID: "sess-rot",
		Name:      "Bash",
		CWD:       "/tmp/proj",
		Input:     json.RawMessage(`{"command":"echo hi"}`),
	}
	result := rules.NewResult(rules.Allow, "test rotation")

	if err := writeLogEntry(path, input, result); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// After truncation + one JSON line, should be well under 5MB.
	if info.Size() >= maxLogSize {
		t.Fatalf("file should have been truncated, size = %d", info.Size())
	}
}

func TestWriteLogEntry_NilResult(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nil.log")

	input := rules.HookInput{
		SessionID: "sess-nil",
		Name:      "Read",
		CWD:       "/tmp/proj",
		Input:     json.RawMessage(`{"file_path":"/tmp/foo"}`),
	}

	if err := writeLogEntry(path, input, nil); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var entry Entry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("invalid JSON line: %v", err)
	}
	if entry.Decision != "" {
		t.Fatalf("decision = %q, want empty for nil result", entry.Decision)
	}
}
