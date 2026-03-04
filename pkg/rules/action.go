package rules

import "encoding/json"

type Decision string

const (
	Allow Decision = "allow"
	Ask   Decision = "ask"
	Deny  Decision = "deny"
)

// Specificity ranks how precise a matching rule is. Higher values are more
// specific and win over lower values when rules conflict.
type Specificity int

const (
	Unspecified Specificity = iota // non-path rules, bare match-all
	GlobPath                       // pattern contains *, ?, or [
	ExactPath                      // no glob metacharacters
)

// Result carries the outcome of a rule evaluation. The type parameter T holds
// the hook-specific output (e.g. PreToolUseOutput for PreToolUse events).
type Result[T any] struct {
	Continue           bool        `json:"continue"`
	StopReason         string      `json:"stopReason,omitempty"`
	Specificity        Specificity `json:"-"`
	HookSpecificOutput T           `json:"hookSpecificOutput"`
}

// PreToolUseOutput is the hook-specific output for PreToolUse events.
// Claude Code reads permissionDecision from hookSpecificOutput.
type PreToolUseOutput struct {
	HookEventName            string   `json:"hookEventName"`
	PermissionDecision       Decision `json:"permissionDecision"`
	PermissionDecisionReason string   `json:"permissionDecisionReason,omitempty"`
	AdditionalContext        string   `json:"additionalContext,omitempty"`
}

// Matcher is the common interface for all rule types. Each matcher knows which
// tool it applies to and produces a Result (with decision and specificity) when
// the input matches.
type Matcher interface {
	ToolName() string
	Match(toolName string, input json.RawMessage) *Result[PreToolUseOutput]
}

// HookInput is the JSON structure received from Claude Code's PreToolUse hook.
type HookInput struct {
	Event string          `json:"hook_event_name"`
	Name  string          `json:"tool_name"`
	CWD   string          `json:"cwd"`
	Input json.RawMessage `json:"tool_input"`
}

func (r *Result[T]) WithSpecificity(s Specificity) *Result[T] {
	r.Specificity = s
	return r
}

func NewResult(decision Decision, reason string) *Result[PreToolUseOutput] {
	return &Result[PreToolUseOutput]{
		Continue: true,
		HookSpecificOutput: PreToolUseOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       decision,
			PermissionDecisionReason: reason,
		},
	}
}
