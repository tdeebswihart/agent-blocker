package rules

import "encoding/json"

type Decision string

const (
	Allow Decision = "allow"
	Ask   Decision = "ask"
	Deny  Decision = "deny"
)

type Result struct {
	Decision           Decision        `json:"decision"`
	Reason             string          `json:"reason"`
	HookSpecificOutput json.RawMessage `json:"hookSpecificOutput"`
}

// PreToolUseOutput is the hook-specific output for PreToolUse events.
// Claude Code reads permissionDecision from hookSpecificOutput rather than
// the deprecated top-level decision/reason fields.
type PreToolUseOutput struct {
	HookEventName      string   `json:"hookEventName"`
	PermissionDecision Decision `json:"permissionDecision"`
	AdditionalContext  string   `json:"additionalContext,omitempty"`
}

func NewResult(decision Decision, reason string) *Result {
	output := PreToolUseOutput{
		HookEventName:      "PreToolUse",
		PermissionDecision: decision,
		AdditionalContext:  reason,
	}
	raw, _ := json.Marshal(output)
	return &Result{
		Decision:           decision,
		Reason:             reason,
		HookSpecificOutput: raw,
	}
}
