package rules

import (
	"encoding/json"
	"net/url"
	"strings"
)

type WebFetchInput struct {
	URL    string `json:"url"`
	Prompt string `json:"prompt,omitempty"`
}

type WebFetchRule struct {
	toolName string
	decision Decision
	domains  []string
}

// WebFetch creates a rule that matches web fetch operations. Specifiers should
// be in the format "domain:example.com". If no specifiers are given, the rule
// matches all WebFetch operations.
func WebFetch(decision Decision, specifiers ...string) *WebFetchRule {
	var domains []string
	for _, s := range specifiers {
		if d, ok := strings.CutPrefix(s, "domain:"); ok {
			domains = append(domains, d)
		}
	}
	return &WebFetchRule{toolName: "WebFetch", decision: decision, domains: domains}
}

// WebSearch creates a rule that matches WebSearch operations using the same
// domain matching semantics as WebFetch.
func WebSearch(decision Decision, specifiers ...string) *WebFetchRule {
	var domains []string
	for _, s := range specifiers {
		if d, ok := strings.CutPrefix(s, "domain:"); ok {
			domains = append(domains, d)
		}
	}
	return &WebFetchRule{toolName: "WebSearch", decision: decision, domains: domains}
}

func (r *WebFetchRule) Apply(input WebFetchInput) *Result {
	if len(r.domains) == 0 {
		return NewResult(r.decision, "matches all "+r.toolName+" operations")
	}
	parsed, err := url.Parse(input.URL)
	if err != nil {
		return nil
	}
	host := parsed.Hostname()
	for _, domain := range r.domains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return NewResult(r.decision, "matched domain: "+domain)
		}
	}
	return nil
}

func (r *WebFetchRule) ToolName() string       { return r.toolName }
func (r *WebFetchRule) Decision() Decision     { return r.decision }
func (r *WebFetchRule) Match(_ string, input json.RawMessage) *Result {
	var in WebFetchInput
	if err := json.Unmarshal(input, &in); err != nil {
		return nil
	}
	return r.Apply(in)
}
