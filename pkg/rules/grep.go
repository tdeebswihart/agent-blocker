package rules

type GrepInput struct {
	Pattern    string `json:"pattern"`
	Path       string `json:"path,omitempty"`
	OutputMode string `json:"output_mode,omitempty"`
	HeadLimit  int    `json:"head_limit,omitempty"`
	After      int    `json:"-A,omitempty"`
	Before     int    `json:"-B,omitempty"`
}

type GrepRule struct {
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
	return &GrepRule{decision: decision, matchers: matchers}
}

func (r *GrepRule) Apply(input GrepInput) *Result {
	if len(r.matchers) == 0 {
		return NewResult(r.decision, "matches all Grep operations")
	}
	for _, m := range r.matchers {
		if m.match(input.Path) {
			return NewResult(r.decision, "matched path pattern: "+m.resolved)
		}
	}
	return nil
}
