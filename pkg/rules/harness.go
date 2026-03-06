package rules

import "encoding/json"

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
func pickBest(a, b *Result[PreToolUseOutput]) *Result[PreToolUseOutput] {
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
	if decisionRank(b.HookSpecificOutput.PermissionDecision) <
		decisionRank(a.HookSpecificOutput.PermissionDecision) {
		return b
	}
	return a
}

// evaluateMatchers runs all matching rules against the input and picks the best
// match. Returns nil when nothing matches (callers supply their own default).
func (h *Harness) evaluateMatchers(input HookInput) *Result[PreToolUseOutput] {
	var best *Result[PreToolUseOutput]
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
	return best
}

// pickMostRestrictive returns the stricter of two results, ignoring specificity.
// Deny > Ask > Allow. Used only for combining sub-command results.
func pickMostRestrictive(
	a, b *Result[PreToolUseOutput],
) *Result[PreToolUseOutput] {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if decisionRank(a.HookSpecificOutput.PermissionDecision) <=
		decisionRank(b.HookSpecificOutput.PermissionDecision) {
		return a
	}
	return b
}

// evaluateBashCompound handles compound Bash commands (those containing
// unquoted &&, ||, ;, or |). It splits the command into sub-commands, evaluates
// each independently, and returns the most restrictive result. Returns nil if
// the command is not compound, letting the caller fall through to normal eval.
func (h *Harness) evaluateBashCompound(input HookInput) *Result[PreToolUseOutput] {
	var bi BashInput
	if err := json.Unmarshal(input.Input, &bi); err != nil {
		return nil
	}

	command := stripExitCodeSuffix(bi.Command)
	parts := splitCompoundCommand(command)
	if len(parts) <= 1 {
		return nil
	}

	// Evaluate the full (unsplit) command first — catches operator-containing
	// patterns like "curl *| bash*".
	var combined *Result[PreToolUseOutput]
	if result := h.evaluateMatchers(input); result != nil {
		combined = result
	}

	for _, part := range parts {
		subInput := HookInput{
			Event: input.Event,
			Name:  input.Name,
			CWD:   input.CWD,
			Input: mustMarshal(BashInput{Command: part}),
		}
		result := h.evaluateMatchers(subInput)
		if result == nil {
			result = NewResult(Ask, "no matching rule for: "+part)
		}
		combined = pickMostRestrictive(combined, result)
	}

	if combined == nil {
		// always ask for unmatched bash commands
		return NewResult(Ask, "no matching rule")
	}
	return combined
}

func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic("rules: mustMarshal: " + err.Error())
	}
	return b
}

// evaluateCtxBatchExecute handles ctx_batch_execute calls by evaluating each
// command through the full Bash evaluation pipeline. Returns the most
// restrictive result across all commands. Returns nil if parsing fails.
func (h *Harness) evaluateCtxBatchExecute(input HookInput) *Result[PreToolUseOutput] {
	var batch CtxBatchExecuteInput
	if err := json.Unmarshal(input.Input, &batch); err != nil {
		return nil
	}

	if len(batch.Commands) == 0 {
		return NewResult(Allow, "ctx_batch_execute: queries-only batch")
	}

	var combined *Result[PreToolUseOutput]
	for _, cmd := range batch.Commands {
		subInput := HookInput{
			Event: input.Event,
			Name:  "Bash",
			CWD:   input.CWD,
			Input: mustMarshal(BashInput{Command: cmd.Command}),
		}
		result := h.Evaluate(subInput)
		if result == nil {
			result = NewResult(Ask, "no matching rule for: "+cmd.Command)
		}
		combined = pickMostRestrictive(combined, result)
	}
	return combined
}

// Evaluate runs all matching rules against the input and picks the best match.
// For compound Bash commands, each sub-command is evaluated independently and
// the most restrictive result wins. Returns Ask if nothing matches.
func (h *Harness) Evaluate(input HookInput) *Result[PreToolUseOutput] {
	if input.Name == "Bash" {
		if result := h.evaluateBashCompound(input); result != nil {
			return result
		}
	}
	if input.Name == ctxBatchExecuteTool {
		if result := h.evaluateCtxBatchExecute(input); result != nil {
			return result
		}
	}
	if result := h.evaluateMatchers(input); result != nil {
		return result
	}
	return nil
}
