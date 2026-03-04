package rules

import "testing"

func TestBashEchoRule(t *testing.T) {
	rule := BashEcho()

	tests := []struct {
		name    string
		command string
		want    *Decision // nil means no match
	}{
		{"simple echo", `echo "hello world"`, new(Allow)},
		{"safe $?", `echo "Exit code: $?"`, new(Allow)},
		{"safe $#", `echo "$#"`, new(Allow)},
		{"unsafe $HOME", `echo $HOME`, nil},
		{"unsafe ${PATH}", `echo ${PATH}`, nil},
		{"unsafe $(whoami)", `echo $(whoami)`, nil},
		{"unsafe backtick", "echo `whoami`", nil},
		{"single-quoted safe", `echo '$HOME'`, new(Allow)},
		{"safe $@", `echo "hello $@ world"`, new(Allow)},
		{"safe $*", `echo "args: $*"`, new(Allow)},
		{"bare echo", `echo`, new(Allow)},
		{"not echo", `cat foo`, nil},
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
