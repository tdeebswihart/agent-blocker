package rules

import (
	"net/url"
	"strings"
)

type WebFetchInput struct {
	URL    string `json:"url"`
	Prompt string `json:"prompt,omitempty"`
}

type WebFetchRule struct {
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
	return &WebFetchRule{decision: decision, domains: domains}
}

func (r *WebFetchRule) Apply(input WebFetchInput) *Result {
	if len(r.domains) == 0 {
		return NewResult(r.decision, "matches all WebFetch operations")
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
