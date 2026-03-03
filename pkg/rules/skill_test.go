package rules

import "testing"

func TestSkillRule_ExactMatch(t *testing.T) {
	rule := Skill(Allow, "code-review:code-review")

	if result := rule.Apply(SkillInput{Skill: "code-review:code-review"}); result == nil {
		t.Fatal("expected match for exact skill name")
	}
	if result := rule.Apply(SkillInput{Skill: "brainstorming"}); result != nil {
		t.Fatal("expected no match for different skill")
	}
}

func TestSkillRule_BareMatchAll(t *testing.T) {
	rule := Skill(Allow)

	if result := rule.Apply(SkillInput{Skill: "anything"}); result == nil {
		t.Fatal("expected bare Skill to match all")
	}
}

func TestSkillRule_WildcardMatch(t *testing.T) {
	rule := Skill(Allow, "code-review:*")

	if result := rule.Apply(SkillInput{Skill: "code-review:code-review"}); result == nil {
		t.Fatal("expected match for wildcard")
	}
	if result := rule.Apply(SkillInput{Skill: "brainstorming"}); result != nil {
		t.Fatal("expected no match")
	}
}
