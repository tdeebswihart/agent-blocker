package rules

import "testing"

func TestBashHeadTailRule(t *testing.T) {
	rule := BashHeadTail("")

	tests := []struct {
		name    string
		command string
		want    *Decision // nil means no match
	}{
		{"head STDIN", `head`, new(Allow)},
		{"head -n STDIN", `head -n 5`, new(Allow)},
		{"head safe file", `head file.txt`, new(Allow)},
		{"head unsafe absolute", `head /etc/passwd`, nil},
		{"head safe /tmp", `head /tmp/out.log`, new(Allow)},
		{"tail -n STDIN", `tail -n 10`, new(Allow)},
		{"tail safe file", `tail file.txt`, new(Allow)},
		{"tail -f safe file", `tail -f file.txt`, new(Allow)},
		{"tail unsafe absolute", `tail /etc/shadow`, nil},
		{"tail unsafe dotdot", `tail ../secret`, nil},
		{"not head/tail", `wc -l`, nil},
		{"head nested safe path", `head src/main.go`, new(Allow)},
		{"tail safe /tmp", `tail /tmp/debug.log`, new(Allow)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rule.Apply(BashInput{Command: tt.command})
			if tt.want == nil {
				if result != nil {
					t.Fatalf("expected nil, got %s (%s)",
						result.HookSpecificOutput.PermissionDecision,
						result.HookSpecificOutput.PermissionDecisionReason)
				}
				return
			}
			if result == nil {
				t.Fatal("expected match, got nil")
			}
			if result.HookSpecificOutput.PermissionDecision != *tt.want {
				t.Fatalf("expected %s, got %s (%s)", *tt.want,
					result.HookSpecificOutput.PermissionDecision,
					result.HookSpecificOutput.PermissionDecisionReason)
			}
		})
	}
}
