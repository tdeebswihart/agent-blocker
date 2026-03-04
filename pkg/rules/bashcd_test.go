package rules

import "testing"

func TestParseCDTarget(t *testing.T) {
	tests := []struct {
		command string
		want    *string
	}{
		{"cd foo", new("foo")},
		{"cd /tmp/test", new("/tmp/test")},
		{"cd ../parent", new("../parent")},
		{`cd "path with spaces"`, new("path with spaces")},

		// cd with no args (goes to $HOME)
		{"cd", nil},

		// Not cd
		{"ls -la", nil},
		{"echo cd foo", nil},

		// Transparent wrappers (unusual but handled)
		{"timeout 5m cd foo", new("foo")},
	}
	for _, tt := range tests {
		got := parseCDTarget(tt.command, "")
		if tt.want == nil {
			if got != nil {
				t.Errorf("parseCDTarget(%q) = %q, want nil", tt.command, *got)
			}
			continue
		}
		if got == nil {
			t.Errorf("parseCDTarget(%q) = nil, want %q", tt.command, *tt.want)
			continue
		}
		if *got != *tt.want {
			t.Errorf("parseCDTarget(%q) = %q, want %q", tt.command, *got, *tt.want)
		}
	}
}

//go:fix inline
func strPtr(s string) *string { return new(s) }

func TestBashCDRule(t *testing.T) {
	rule := BashCD("/home/user/project")

	tests := []struct {
		command string
		want    *Decision
	}{
		// Safe: relative paths within project root
		{"cd src", new(Allow)},
		{"cd src/pkg", new(Allow)},
		{"cd .", new(Allow)},
		{"cd ./tests", new(Allow)},

		// Safe: absolute path within project root
		{"cd /home/user/project", new(Allow)},
		{"cd /home/user/project/src", new(Allow)},
		{"cd /home/user/project/deep/nested/dir", new(Allow)},

		// Safe: /tmp paths
		{"cd /tmp", new(Allow)},
		{"cd /tmp/test", new(Allow)},

		// Unsafe: absolute path outside project root
		{"cd /etc", nil},
		{"cd /home/user", nil},
		{"cd /home/user/other-project", nil},

		// Unsafe: relative path escaping project root
		{"cd ..", nil},
		{"cd ../other", nil},
		{"cd src/../../escape", nil},

		// Unsafe: no args (goes to $HOME)
		{"cd", nil},

		// Not cd
		{"ls -la", nil},
	}
	for _, tt := range tests {
		result := rule.Apply(BashInput{Command: tt.command})
		if tt.want == nil {
			if result != nil {
				t.Errorf("BashCD.Apply(%q) = %s, want nil",
					tt.command, result.HookSpecificOutput.PermissionDecision)
			}
			continue
		}
		if result == nil {
			t.Errorf("BashCD.Apply(%q) = nil, want %s", tt.command, *tt.want)
			continue
		}
		if result.HookSpecificOutput.PermissionDecision != *tt.want {
			t.Errorf("BashCD.Apply(%q) = %s, want %s",
				tt.command,
				result.HookSpecificOutput.PermissionDecision,
				*tt.want)
		}
	}
}
