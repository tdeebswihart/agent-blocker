package rules

import "testing"

func TestParseMkdirTargets(t *testing.T) {
	tests := []struct {
		command string
		want    []string
	}{
		// Basic usage
		{"mkdir foo", []string{"foo"}},
		{"mkdir foo bar", []string{"foo", "bar"}},
		{"mkdir -p foo/bar/baz", []string{"foo/bar/baz"}},

		// Flags with arguments
		{"mkdir -m 0755 foo", []string{"foo"}},
		{"mkdir --mode 0755 foo", []string{"foo"}},
		{"mkdir --mode=0755 foo", []string{"foo"}},
		{"mkdir -pm 0755 foo", []string{"foo"}},

		// Boolean flags
		{"mkdir -v foo", []string{"foo"}},
		{"mkdir -pv foo/bar", []string{"foo/bar"}},
		{"mkdir --parents --verbose foo", []string{"foo"}},

		// End-of-options
		{"mkdir -- -weird-dir", []string{"-weird-dir"}},
		{"mkdir -p -- -starts-with-dash", []string{"-starts-with-dash"}},

		// Transparent wrappers
		{"timeout 5m mkdir foo", []string{"foo"}},

		// Not mkdir commands
		{"ls -la", nil},
		{"rmdir foo", nil},
		{"mkdirp foo", nil},

		// No targets
		{"mkdir -p", nil},
		{"mkdir", nil},
	}
	for _, tt := range tests {
		got := parseMkdirTargets(tt.command, "")
		if tt.want == nil {
			if got != nil {
				t.Errorf("parseMkdirTargets(%q) = %v, want nil", tt.command, got)
			}
			continue
		}
		if len(got) != len(tt.want) {
			t.Errorf("parseMkdirTargets(%q) = %v, want %v", tt.command, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("parseMkdirTargets(%q)[%d] = %q, want %q",
					tt.command, i, got[i], tt.want[i])
			}
		}
	}
}

func TestMkdirRule(t *testing.T) {
	rule := Mkdir("")

	tests := []struct {
		command string
		want    *Decision // nil = no match, non-nil = expected decision
	}{
		// Safe: relative paths (under cwd)
		{"mkdir foo", ptr(Allow)},
		{"mkdir -p foo/bar/baz", ptr(Allow)},
		{"mkdir subdir", ptr(Allow)},

		// Safe: /tmp paths
		{"mkdir /tmp/test", ptr(Allow)},
		{"mkdir /tmp/test/nested", ptr(Allow)},
		{"mkdir -p /tmp/deep/nested/dir", ptr(Allow)},

		// Safe: mixed relative and /tmp
		{"mkdir foo /tmp/bar", ptr(Allow)},

		// Unsafe: absolute paths outside /tmp
		{"mkdir /etc/something", nil},
		{"mkdir /var/log/test", nil},

		// Unsafe: escapes cwd
		{"mkdir ../escape", nil},
		{"mkdir foo/../../escape", nil},

		// Unsafe: one bad target poisons the whole command
		{"mkdir foo /etc/bad", nil},

		// Not mkdir
		{"ls -la", nil},
		{"rm -rf foo", nil},
	}
	for _, tt := range tests {
		result := rule.Apply(BashInput{Command: tt.command})
		if tt.want == nil {
			if result != nil {
				t.Errorf("Mkdir.Apply(%q) = %s, want nil",
					tt.command, result.HookSpecificOutput.PermissionDecision)
			}
			continue
		}
		if result == nil {
			t.Errorf("Mkdir.Apply(%q) = nil, want %s", tt.command, *tt.want)
			continue
		}
		if result.HookSpecificOutput.PermissionDecision != *tt.want {
			t.Errorf("Mkdir.Apply(%q) = %s, want %s",
				tt.command,
				result.HookSpecificOutput.PermissionDecision,
				*tt.want)
		}
	}
}