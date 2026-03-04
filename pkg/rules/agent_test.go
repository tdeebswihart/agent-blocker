package rules

import "testing"

func TestAgentRule_ExactMatch(t *testing.T) {
	rule := Agent(Deny, "Explore")

	if result := rule.Apply(AgentInput{SubagentType: "Explore"}); result == nil {
		t.Fatal("expected match for Explore")
	} else if result.HookSpecificOutput.PermissionDecision != Deny {
		t.Fatalf("expected Deny, got %s", result.HookSpecificOutput.PermissionDecision)
	}

	if result := rule.Apply(AgentInput{SubagentType: "Plan"}); result != nil {
		t.Fatal("expected no match for Plan")
	}
}

func TestAgentRule_BareMatchAll(t *testing.T) {
	rule := Agent(Ask)

	if result := rule.Apply(AgentInput{SubagentType: "anything"}); result == nil {
		t.Fatal("expected bare Agent to match all")
	}
}

func TestAgentRule_NameMatch(t *testing.T) {
	// Agent rules can also match on the agent name
	rule := Agent(Allow, "my-custom-agent")

	if result := rule.Apply(AgentInput{
		SubagentType: "general-purpose",
		Name:         "my-custom-agent",
	}); result == nil {
		t.Fatal("expected match on agent name")
	}
}
