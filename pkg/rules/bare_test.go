package rules

import "testing"

func TestBareToolRule_MatchesAll(t *testing.T) {
	rule := BareTool(Allow, "Search")

	if result := rule.Match("Search", nil); result == nil {
		t.Fatal("expected match for Search")
	} else if result.HookSpecificOutput.PermissionDecision != Allow {
		t.Fatalf("expected Allow, got %s", result.HookSpecificOutput.PermissionDecision)
	}
}

func TestBareToolRule_ToolName(t *testing.T) {
	rule := BareTool(Ask, "WebSearch")
	if rule.ToolName() != "WebSearch" {
		t.Fatalf("expected WebSearch, got %s", rule.ToolName())
	}
	// decision is embedded in the result, not on the rule
	if result := rule.Match("WebSearch", nil); result == nil {
		t.Fatal("expected match")
	} else if result.HookSpecificOutput.PermissionDecision != Ask {
		t.Fatalf("expected Ask, got %s", result.HookSpecificOutput.PermissionDecision)
	}
}
