package rules

import "testing"

func TestMCPRule_ExactMatch(t *testing.T) {
	rule := MCP(Allow, "mcp__gopls__go_doc")

	if result := rule.Apply("mcp__gopls__go_doc"); result == nil {
		t.Fatal("expected match for exact tool name")
	}
	if result := rule.Apply("mcp__gopls__go_build"); result != nil {
		t.Fatal("expected no match for different tool")
	}
}

func TestMCPRule_WildcardSuffix(t *testing.T) {
	rule := MCP(Allow, "mcp__gopls__go_*")

	if result := rule.Apply("mcp__gopls__go_doc"); result == nil {
		t.Fatal("expected match for go_doc")
	}
	if result := rule.Apply("mcp__gopls__go_build"); result == nil {
		t.Fatal("expected match for go_build")
	}
	if result := rule.Apply("mcp__other__something"); result != nil {
		t.Fatal("expected no match for different server")
	}
}

func TestMCPRule_ServerWildcard(t *testing.T) {
	// mcp__puppeteer matches all tools from puppeteer server
	rule := MCP(Allow, "mcp__codespelunker_*")

	if result := rule.Apply("mcp__codespelunker_search"); result == nil {
		t.Fatal("expected match for codespelunker_search")
	}
	if result := rule.Apply("mcp__codespelunker_inspect"); result == nil {
		t.Fatal("expected match for codespelunker_inspect")
	}
}

func TestMCPRule_MultiplePatterns(t *testing.T) {
	rule := MCP(Allow, "mcp__gopls__go_*", "mcp__codespelunker_*")

	if result := rule.Apply("mcp__gopls__go_doc"); result == nil {
		t.Fatal("expected match for gopls")
	}
	if result := rule.Apply("mcp__codespelunker_search"); result == nil {
		t.Fatal("expected match for codespelunker")
	}
	if result := rule.Apply("mcp__unknown__tool"); result != nil {
		t.Fatal("expected no match for unknown server")
	}
}
