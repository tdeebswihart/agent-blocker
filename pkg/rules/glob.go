package rules

import "encoding/json"

type GlobInput struct {
	Pattern string `json:"pattern"`
	Path    string `json:"path,omitempty"`
}

type GlobRuleT struct {
	decision Decision
	matchers []pathMatcher
}

// GlobRule creates a rule that matches Glob tool operations. Per Claude Code docs,
// "Read rules apply to all built-in tools that read files like Grep and Glob."
// Patterns match against the Glob input's Path field using gitignore-style matching.
// If no patterns are given, the rule matches all Glob operations.
func GlobRule(decision Decision, args ...any) *GlobRuleT {
	patterns, opts := parsePathArgs(args)
	matchers := make([]pathMatcher, len(patterns))
	for i, p := range patterns {
		matchers[i] = newPathMatcher(opts.CWD, opts.Home, opts.ProjectRoot, p)
	}
	return &GlobRuleT{decision: decision, matchers: matchers}
}

func (r *GlobRuleT) Apply(input GlobInput) *Result {
	if len(r.matchers) == 0 {
		return NewResult(r.decision, "matches all Glob operations")
	}
	for _, m := range r.matchers {
		if m.match(input.Path) {
			return NewResult(r.decision, "matched path pattern: "+m.resolved).
				WithSpecificity(m.specificity())
		}
	}
	return nil
}

func (r *GlobRuleT) ToolName() string       { return "Glob" }
func (r *GlobRuleT) Decision() Decision     { return r.decision }
func (r *GlobRuleT) Match(_ string, input json.RawMessage) *Result {
	var in GlobInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil
	}
	return r.Apply(in)
}
