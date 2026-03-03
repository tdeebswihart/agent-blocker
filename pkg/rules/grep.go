package rules

import "encoding/json"

type GrepInput struct {
	Pattern    string `json:"pattern"`
	Path       string `json:"path,omitempty"`
	OutputMode string `json:"output_mode,omitempty"`
	HeadLimit  int    `json:"head_limit,omitempty"`
	After      int    `json:"-A,omitempty"`
	Before     int    `json:"-B,omitempty"`
}

type GrepRule struct {
	toolName string
	decision Decision
	matchers []pathMatcher
}

// Grep creates a rule that matches grep operations. Per Claude Code docs,
// "Read rules apply to all built-in tools that read files like Grep and Glob."
// Patterns match against the Grep input's Path field using gitignore-style matching.
// If no patterns are given, the rule matches all Grep operations.
func Grep(decision Decision, args ...any) *GrepRule {
	patterns, opts := parsePathArgs(args)
	matchers := make([]pathMatcher, len(patterns))
	for i, p := range patterns {
		matchers[i] = newPathMatcher(opts.CWD, opts.Home, opts.ProjectRoot, p)
	}
	return &GrepRule{toolName: "Grep", decision: decision, matchers: matchers}
}

// Search creates a rule that matches Search tool operations. Search is an alias
// for Grep — same path matching semantics, different tool name.
func Search(decision Decision, args ...any) *GrepRule {
	patterns, opts := parsePathArgs(args)
	matchers := make([]pathMatcher, len(patterns))
	for i, p := range patterns {
		matchers[i] = newPathMatcher(opts.CWD, opts.Home, opts.ProjectRoot, p)
	}
	return &GrepRule{toolName: "Search", decision: decision, matchers: matchers}
}

func (r *GrepRule) Apply(input GrepInput) *Result {
	if len(r.matchers) == 0 {
		return NewResult(r.decision, "matches all "+r.toolName+" operations")
	}
	for _, m := range r.matchers {
		if m.match(input.Path) {
			return NewResult(r.decision, "matched path pattern: "+m.resolved).
				WithSpecificity(m.specificity())
		}
	}
	return nil
}

func (r *GrepRule) ToolName() string       { return r.toolName }
func (r *GrepRule) Decision() Decision     { return r.decision }
func (r *GrepRule) Match(_ string, input json.RawMessage) *Result {
	var in GrepInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil
	}
	return r.Apply(in)
}
