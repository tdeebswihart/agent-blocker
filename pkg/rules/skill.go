package rules

import "encoding/json"

type SkillInput struct {
	Skill string `json:"skill"`
	Args  string `json:"args,omitempty"`
}

type SkillRule struct {
	decision Decision
	patterns []string
}

// Skill creates a rule that matches Skill tool invocations by skill name.
// Patterns support glob wildcards. If no patterns are given, the rule matches
// all Skill operations.
func Skill(decision Decision, patterns ...string) *SkillRule {
	return &SkillRule{decision: decision, patterns: patterns}
}

func (r *SkillRule) Apply(input SkillInput) *Result[PreToolUseOutput] {
	if len(r.patterns) == 0 {
		return NewResult(r.decision, "matches all Skill operations")
	}
	for _, p := range r.patterns {
		if globMatch(p, input.Skill) {
			return NewResult(r.decision, "matched skill pattern: "+p)
		}
	}
	return nil
}

func (r *SkillRule) ToolName() string { return "Skill" }
func (r *SkillRule) Match(_ string, input json.RawMessage) *Result[PreToolUseOutput] {
	var in SkillInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil
	}
	return r.Apply(in)
}
