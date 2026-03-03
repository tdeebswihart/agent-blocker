package rules

type ReadInput struct {
	FilePath string `json:"file_path"`
	Offset   int    `json:"offset,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

// PathOpts provides directory context for resolving gitignore-style path
// patterns. Shared by Read, Edit, Grep, Glob, and LogMCP rules.
type PathOpts struct {
	CWD         string
	Home        string
	ProjectRoot string
}

type ReadRule struct {
	decision Decision
	matchers []pathMatcher
}

// Read creates a rule that matches file read operations against gitignore-style
// path patterns. The last argument must be a PathOpts providing directory context.
// If no patterns are given (only PathOpts), the rule matches all reads.
func Read(decision Decision, args ...any) *ReadRule {
	patterns, opts := parsePathArgs(args)
	matchers := make([]pathMatcher, len(patterns))
	for i, p := range patterns {
		matchers[i] = newPathMatcher(opts.CWD, opts.Home, opts.ProjectRoot, p)
	}
	return &ReadRule{decision: decision, matchers: matchers}
}

func (r *ReadRule) Apply(input ReadInput) *Result {
	if len(r.matchers) == 0 {
		return NewResult(r.decision, "matches all Read operations")
	}
	for _, m := range r.matchers {
		if m.match(input.FilePath) {
			return NewResult(r.decision, "matched path pattern: "+m.resolved)
		}
	}
	return nil
}

// parsePathArgs extracts string patterns and a PathOpts from a variadic any
// slice. This allows the API: Read(Deny, "./.env", "~/.ssh/**", PathOpts{...})
func parsePathArgs(args []any) ([]string, PathOpts) {
	var patterns []string
	var opts PathOpts
	for _, arg := range args {
		switch v := arg.(type) {
		case string:
			patterns = append(patterns, v)
		case PathOpts:
			opts = v
		}
	}
	return patterns, opts
}
