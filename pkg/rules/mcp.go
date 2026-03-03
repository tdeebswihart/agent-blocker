package rules

type MCPRule struct {
	decision Decision
	patterns []string
}

// MCP creates a rule that matches MCP tool invocations by tool name.
// Patterns support glob wildcards (e.g., "mcp__gopls__go_*").
func MCP(decision Decision, patterns ...string) *MCPRule {
	return &MCPRule{decision: decision, patterns: patterns}
}

func (r *MCPRule) Apply(toolName string) *Result {
	if len(r.patterns) == 0 {
		return NewResult(r.decision, "matches all MCP operations")
	}
	for _, p := range r.patterns {
		if globMatch(p, toolName) {
			return NewResult(r.decision, "matched MCP pattern: "+p)
		}
	}
	return nil
}
