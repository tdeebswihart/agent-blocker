package rules

// Harness groups matchers by tool name and decision priority, then evaluates
// incoming hook events. Evaluation order: deny → ask → allow. First match wins.
// If nothing matches, returns Ask.
type Harness struct {
	// byTool maps tool name → decision → list of matchers.
	byTool map[string]map[Decision][]Matcher
	// wildcards are matchers with ToolName()="" (e.g., MCP patterns)
	// that are checked for every incoming tool.
	wildcards map[Decision][]Matcher
}

// NewHarness creates a harness from a list of matchers, grouping them by
// tool name and decision.
func NewHarness(matchers ...Matcher) *Harness {
	h := &Harness{
		byTool:    make(map[string]map[Decision][]Matcher),
		wildcards: make(map[Decision][]Matcher),
	}
	for _, m := range matchers {
		name := m.ToolName()
		d := m.Decision()
		if name == "" {
			h.wildcards[d] = append(h.wildcards[d], m)
		} else {
			if h.byTool[name] == nil {
				h.byTool[name] = make(map[Decision][]Matcher)
			}
			h.byTool[name][d] = append(h.byTool[name][d], m)
		}
	}
	return h
}

// priority is the evaluation order: deny rules beat ask rules beat allow rules.
var priority = []Decision{Deny, Ask, Allow}

// Evaluate runs all matching rules against the input in priority order
// (deny → ask → allow). Returns the first match, or Ask if nothing matches.
func (h *Harness) Evaluate(input HookInput) *Result {
	toolRules := h.byTool[input.Name]

	for _, d := range priority {
		// Check tool-specific rules
		for _, m := range toolRules[d] {
			if result := m.Match(input.Name, input.Input); result != nil {
				return result
			}
		}
		// Check wildcard rules (MCP patterns, etc.)
		for _, m := range h.wildcards[d] {
			if result := m.Match(input.Name, input.Input); result != nil {
				return result
			}
		}
	}

	return NewResult(Ask, "no matching rule")
}
