package rules

import "testing"

func TestBareToolRule_MatchesAll(t *testing.T) {
	rule := BareTool(Allow, "Search")

	if result := rule.Match("Search", nil); result == nil {
		t.Fatal("expected match for Search")
	} else if result.Decision != Allow {
		t.Fatalf("expected Allow, got %s", result.Decision)
	}
}

func TestBareToolRule_ToolName(t *testing.T) {
	rule := BareTool(Ask, "WebSearch")
	if rule.ToolName() != "WebSearch" {
		t.Fatalf("expected WebSearch, got %s", rule.ToolName())
	}
	// Decision is embedded in the result, not on the rule
	if result := rule.Match("WebSearch", nil); result == nil {
		t.Fatal("expected match")
	} else if result.Decision != Ask {
		t.Fatalf("expected Ask, got %s", result.Decision)
	}
}
