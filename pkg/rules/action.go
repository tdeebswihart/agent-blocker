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

type Result struct {
	Decision           Decision        `json:"decision"`
	Reason             string          `json:"reason"`
	Specificity        Specificity     `json:"-"` // not serialized
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

// Matcher is the common interface for all rule types. The harness uses this
// to group rules by tool name and decision priority.
type Matcher interface {
	ToolName() string
	Decision() Decision
	Match(toolName string, input json.RawMessage) *Result
}

// HookInput is the JSON structure received from Claude Code's PreToolUse hook.
type HookInput struct {
	Event string          `json:"hook_event_name"`
	Name  string          `json:"tool_name"`
	CWD   string          `json:"cwd"`
	Input json.RawMessage `json:"tool_input"`
}

func (r *Result) WithSpecificity(s Specificity) *Result {
	r.Specificity = s
	return r
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
