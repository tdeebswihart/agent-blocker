package rules

import "encoding/json"

// BareToolRule matches any invocation of a specific tool name, regardless of input.
// Use this for tools that don't need input-level matching (e.g., Search, Task, WebSearch).
type BareToolRule struct {
	decision Decision
	toolName string
}

// BareTool creates a rule that matches all invocations of the named tool.
func BareTool(decision Decision, toolName string) *BareToolRule {
	return &BareToolRule{decision: decision, toolName: toolName}
}

func (r *BareToolRule) ToolName() string { return r.toolName }
func (r *BareToolRule) Match(toolName string, _ json.RawMessage) *Result {
	if toolName == r.toolName {
		return NewResult(r.decision, "matches all "+r.toolName+" operations")
	}
	return nil
}
