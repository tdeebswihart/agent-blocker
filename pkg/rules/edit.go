package rules

import "encoding/json"

type EditInput struct {
	FilePath   string `json:"file_path"`
	OldString  string `json:"old_string,omitempty"`
	NewString  string `json:"new_string,omitempty"`
	ReplaceAll bool   `json:"replace_all,omitempty"`
}

type EditRule struct {
	decision Decision
	matchers []pathMatcher
}

// Edit creates a rule that matches file edit operations against gitignore-style
// path patterns. Same matching semantics as Read.
func Edit(decision Decision, args ...any) *EditRule {
	patterns, opts := parsePathArgs(args)
	matchers := make([]pathMatcher, len(patterns))
	for i, p := range patterns {
		matchers[i] = newPathMatcher(opts.CWD, opts.Home, opts.ProjectRoot, p)
	}
	return &EditRule{decision: decision, matchers: matchers}
}

func (r *EditRule) Apply(input EditInput) *Result {
	if len(r.matchers) == 0 {
		return NewResult(r.decision, "matches all Edit operations")
	}
	for _, m := range r.matchers {
		if m.match(input.FilePath) {
			return NewResult(r.decision, "matched path pattern: "+m.resolved).
				WithSpecificity(m.specificity())
		}
	}
	return nil
}

func (r *EditRule) ToolName() string { return "Edit" }
func (r *EditRule) Match(_ string, input json.RawMessage) *Result {
	var in EditInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil
	}
	return r.Apply(in)
}
