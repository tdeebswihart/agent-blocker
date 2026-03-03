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

// decisionRank maps decisions to a numeric rank where lower is stricter.
// Deny < Ask < Allow, so deny wins ties at equal specificity.
func decisionRank(d Decision) int {
	switch d {
	case Deny:
		return 0
	case Ask:
		return 1
	case Allow:
		return 2
	default:
		return 3
	}
}

// pickBest returns the more specific/stricter of two results.
// Higher Specificity wins; ties broken by decision rank (deny > ask > allow);
// ties broken by insertion order (a wins).
func pickBest(a, b *Result) *Result {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if b.Specificity > a.Specificity {
		return b
	}
	if a.Specificity > b.Specificity {
		return a
	}
	// Equal specificity: lower decision rank (stricter) wins.
	if decisionRank(b.Decision) < decisionRank(a.Decision) {
		return b
	}
	return a
}

// Evaluate runs all matching rules against the input and picks the best match.
// The best match has the highest specificity; ties broken by decision strictness
// (deny > ask > allow), then by insertion order. Returns Ask if nothing matches.
func (h *Harness) Evaluate(input HookInput) *Result {
	toolRules := h.byTool[input.Name]

	var best *Result
	for _, d := range priority {
		// Check tool-specific rules
		for _, m := range toolRules[d] {
			if result := m.Match(input.Name, input.Input); result != nil {
				best = pickBest(best, result)
			}
		}
		// Check wildcard rules (MCP patterns, etc.)
		for _, m := range h.wildcards[d] {
			if result := m.Match(input.Name, input.Input); result != nil {
				best = pickBest(best, result)
			}
		}
	}

	if best != nil {
		return best
	}
	return NewResult(Ask, "no matching rule")
}
