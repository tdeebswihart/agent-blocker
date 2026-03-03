package rules

import "encoding/json"

type LogMCPInput struct {
	FilePath   string `json:"file_path"`
	Pattern    string `json:"pattern,omitempty"`
	MaxResults int    `json:"max_results,omitempty"`
}

type LogMCPRule struct {
	decision Decision
	matchers []pathMatcher
}

// LogMCP creates a rule that matches mcp__log-mcp__search_logs invocations.
// Patterns match against the file_path input using gitignore-style path matching,
// same as Read/Edit/Grep rules.
func LogMCP(decision Decision, args ...any) *LogMCPRule {
	patterns, opts := parsePathArgs(args)
	matchers := make([]pathMatcher, len(patterns))
	for i, p := range patterns {
		matchers[i] = newPathMatcher(opts.CWD, opts.Home, opts.ProjectRoot, p)
	}
	return &LogMCPRule{decision: decision, matchers: matchers}
}

func (r *LogMCPRule) Apply(input LogMCPInput) *Result {
	if len(r.matchers) == 0 {
		return NewResult(r.decision, "matches all LogMCP operations")
	}
	for _, m := range r.matchers {
		if m.match(input.FilePath) {
			return NewResult(r.decision, "matched path pattern: "+m.resolved)
		}
	}
	return nil
}

func (r *LogMCPRule) ToolName() string       { return "mcp__log-mcp__search_logs" }
func (r *LogMCPRule) Decision() Decision     { return r.decision }
func (r *LogMCPRule) Match(_ string, input json.RawMessage) *Result {
	var in LogMCPInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil
	}
	return r.Apply(in)
}
