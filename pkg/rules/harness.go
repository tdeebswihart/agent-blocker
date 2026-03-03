package rules

// Harness groups matchers by tool name, then evaluates incoming hook events.
// All matching rules are applied and the best result wins: highest specificity,
// then strictest decision (deny > ask > allow), then insertion order.
// If nothing matches, returns Ask.
type Harness struct {
	// byTool maps tool name → list of matchers.
	byTool map[string][]Matcher
	// wildcards are matchers with ToolName()="" (e.g., MCP patterns)
	// that are checked for every incoming tool.
	wildcards []Matcher
}

// NewHarness creates a harness from a list of matchers, grouping them by
// tool name.
func NewHarness(matchers ...Matcher) *Harness {
	h := &Harness{
		byTool: make(map[string][]Matcher),
	}
	for _, m := range matchers {
		name := m.ToolName()
		if name == "" {
			h.wildcards = append(h.wildcards, m)
		} else {
			h.byTool[name] = append(h.byTool[name], m)
		}
	}
	return h
}

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
	var best *Result
	for _, m := range h.byTool[input.Name] {
		if result := m.Match(input.Name, input.Input); result != nil {
			best = pickBest(best, result)
		}
	}
	for _, m := range h.wildcards {
		if result := m.Match(input.Name, input.Input); result != nil {
			best = pickBest(best, result)
		}
	}

	if best != nil {
		return best
	}
	return NewResult(Ask, "no matching rule")
}
