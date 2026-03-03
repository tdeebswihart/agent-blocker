package rules

type AgentInput struct {
	Description  string `json:"description,omitempty"`
	Prompt       string `json:"prompt,omitempty"`
	SubagentType string `json:"subagent_type,omitempty"`
	Name         string `json:"name,omitempty"`
}

type AgentRule struct {
	decision Decision
	patterns []string
}

// Agent creates a rule that matches Agent tool invocations by agent name or
// subagent type. Patterns support glob wildcards. If no patterns are given,
// the rule matches all Agent operations.
func Agent(decision Decision, patterns ...string) *AgentRule {
	return &AgentRule{decision: decision, patterns: patterns}
}

func (r *AgentRule) Apply(input AgentInput) *Result {
	if len(r.patterns) == 0 {
		return NewResult(r.decision, "matches all Agent operations")
	}
	for _, p := range r.patterns {
		// Match against both subagent_type and name
		if globMatch(p, input.SubagentType) || globMatch(p, input.Name) {
			return NewResult(r.decision, "matched agent pattern: "+p)
		}
	}
	return nil
}
