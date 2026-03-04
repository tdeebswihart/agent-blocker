package rules

import "testing"

func TestBashGrepRule(t *testing.T) {
	rule := BashGrep("")

	tests := []struct {
		name    string
		command string
		want    *Decision // nil means no match
	}{
		{"grep STDIN", `grep "pattern"`, new(Allow)},
		{"grep -i STDIN", `grep -i "pattern"`, new(Allow)},
		{"grep -e STDIN", `grep -e "pattern"`, new(Allow)},
		{"grep safe relative file", `grep "pattern" file.txt`, new(Allow)},
		{"grep safe nested file", `grep "pattern" src/main.go`, new(Allow)},
		{"grep unsafe absolute path", `grep "pattern" /etc/passwd`, nil},
		{"grep unsafe dotdot", `grep "pattern" ../secret`, nil},
		{"grep safe /tmp path", `grep "pattern" /tmp/out.log`, new(Allow)},
		{"grep -e with safe file", `grep -e "pattern" file.txt`, new(Allow)},
		{"grep -f reads file via flag", `grep -f /etc/patterns file.txt`, nil},
		{"rg CWD recursive", `rg "pattern"`, new(Allow)},
		{"rg safe relative dir", `rg "pattern" src/`, new(Allow)},
		{"rg unsafe absolute path", `rg "pattern" /etc/`, nil},
		{"rg -g consumes glob", `rg -g "*.go" "pattern"`, new(Allow)},
		{"rg --pre rejected", `rg --pre cat "pattern"`, nil},
		{"rg --ignore-file rejected", `rg --ignore-file .gitignore "pattern"`, nil},
		{"not grep/rg", `sed foo`, nil},
		{"grep --file= blocked", `grep --file=patterns.txt foo`, nil},
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

//go:fix inline
func ptr(d Decision) *Decision { return new(d) }
