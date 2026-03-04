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
	// decision and reason are internal — Claude Code reads these from
	// hookSpecificOutput.PermissionDecision/PermissionDecisionReason.
	decision    Decision
	reason      string
	Continue    bool            `json:"continue"`
	StopReason  string          `json:"stopReason,omitempty"`
	Specificity Specificity     `json:"-"`
	HookSpecificOutput json.RawMessage `json:"hookSpecificOutput"`
}

// PreToolUseOutput is the hook-specific output for PreToolUse events.
// Claude Code reads permissionDecision from hookSpecificOutput rather than
// the deprecated top-level decision/reason fields.
type PreToolUseOutput struct {
	HookEventName           string   `json:"hookEventName"`
	PermissionDecision      Decision `json:"permissionDecision"`
	PermissionDecisionReason string  `json:"permissionDecisionReason,omitempty"`
	AdditionalContext       string   `json:"additionalContext,omitempty"`
}

// Matcher is the common interface for all rule types. Each matcher knows which
// tool it applies to and produces a Result (with decision and specificity) when
// the input matches.
type Matcher interface {
	ToolName() string
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
		HookEventName:            "PreToolUse",
		PermissionDecision:       decision,
		PermissionDecisionReason: reason,
	}
	raw, _ := json.Marshal(output)
	return &Result{
		decision:           decision,
		reason:             reason,
		Continue:           true,
		HookSpecificOutput: raw,
	}
}
