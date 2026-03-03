package rules

import "testing"

func TestWebFetchRule_DomainMatch(t *testing.T) {
	rule := WebFetch(Allow, "domain:github.com")

	if result := rule.Apply(WebFetchInput{
		URL: "https://github.com/foo/bar",
	}); result == nil {
		t.Fatal("expected match for github.com URL")
	}

	if result := rule.Apply(WebFetchInput{
		URL: "https://example.com/page",
	}); result != nil {
		t.Fatal("expected no match for example.com URL")
	}
}

func TestWebFetchRule_DomainMatchSubdomain(t *testing.T) {
	rule := WebFetch(Allow, "domain:github.com")

	// Subdomains should match
	if result := rule.Apply(WebFetchInput{
		URL: "https://api.github.com/repos",
	}); result == nil {
		t.Fatal("expected match for subdomain of github.com")
	}
}

func TestWebFetchRule_BareMatchAll(t *testing.T) {
	rule := WebFetch(Ask)

	if result := rule.Apply(WebFetchInput{URL: "https://anything.com"}); result == nil {
		t.Fatal("expected bare WebFetch to match all")
	}
}

func TestWebFetchRule_MultipleDomains(t *testing.T) {
	rule := WebFetch(Allow, "domain:github.com", "domain:docs.rs")

	if result := rule.Apply(WebFetchInput{URL: "https://docs.rs/foo"}); result == nil {
		t.Fatal("expected match for docs.rs")
	}
	if result := rule.Apply(WebFetchInput{URL: "https://evil.com"}); result != nil {
		t.Fatal("expected no match for evil.com")
	}
}
