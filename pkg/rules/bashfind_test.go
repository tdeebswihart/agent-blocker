package rules

import "testing"

func TestBashFindRule_Find(t *testing.T) {
	rule := BashFind()

	tests := []struct {
		command string
		want    *Decision
	}{
		// Safe: no explicit path (defaults to .)
		{`find -name "*.go"`, ptr(Allow)},
		{`find -type f`, ptr(Allow)},

		// Safe: explicit cwd-relative paths
		{`find . -name "*.go"`, ptr(Allow)},
		{`find ./src -name "*.go" -type f`, ptr(Allow)},
		{`find src tests -name "*.go"`, ptr(Allow)},

		// Safe: /tmp paths
		{`find /tmp -name "*.log"`, ptr(Allow)},
		{`find /tmp/test -type f`, ptr(Allow)},

		// Safe: leading options then safe path
		{`find -L . -name "*.go"`, ptr(Allow)},
		{`find -H -L . -name "*.go"`, ptr(Allow)},

		// Unsafe: absolute path outside /tmp
		{`find / -name "*.conf"`, nil},
		{`find /etc -name "passwd"`, nil},

		// Unsafe: escapes cwd
		{`find ../other -name "*.go"`, nil},

		// Unsafe: dangerous actions
		{`find . -delete`, nil},
		{`find . -exec rm {} \;`, nil},
		{`find . -execdir cat {} \;`, nil},
		{`find . -ok rm {} \;`, nil},

		// Not find
		{"ls -la", nil},
		{"grep foo", nil},

		// Transparent wrappers
		{`timeout 5m find . -name "*.go"`, ptr(Allow)},
	}
	for _, tt := range tests {
		result := rule.Apply(BashInput{Command: tt.command})
		if tt.want == nil {
			if result != nil {
				t.Errorf("Find(%q) = %s, want nil",
					tt.command, result.HookSpecificOutput.PermissionDecision)
			}
			continue
		}
		if result == nil {
			t.Errorf("Find(%q) = nil, want %s", tt.command, *tt.want)
			continue
		}
		if result.HookSpecificOutput.PermissionDecision != *tt.want {
			t.Errorf("Find(%q) = %s, want %s",
				tt.command,
				result.HookSpecificOutput.PermissionDecision,
				*tt.want)
		}
	}
}

func TestBashFindRule_Fd(t *testing.T) {
	rule := BashFind()

	tests := []struct {
		command string
		want    *Decision
	}{
		// Safe: no explicit path (defaults to .)
		{`fd "*.go"`, ptr(Allow)},
		{`fd -t f pattern`, ptr(Allow)},
		{`fd`, ptr(Allow)},

		// Safe: explicit relative paths
		{`fd pattern ./src`, ptr(Allow)},
		{`fd pattern src tests`, ptr(Allow)},

		// Safe: /tmp paths
		{`fd pattern /tmp`, ptr(Allow)},
		{`fd pattern /tmp/test`, ptr(Allow)},

		// Safe: --search-path and --base-directory
		{`fd --search-path ./src pattern`, ptr(Allow)},
		{`fd --base-directory src pattern`, ptr(Allow)},
		{`fd --search-path=./src pattern`, ptr(Allow)},
		{`fd --base-directory=src pattern`, ptr(Allow)},

		// Unsafe: absolute path outside /tmp
		{`fd pattern /etc`, nil},
		{`fd pattern /`, nil},

		// Unsafe: escapes cwd
		{`fd pattern ../other`, nil},

		// Unsafe: --search-path to dangerous location
		{`fd --search-path /etc pattern`, nil},
		{`fd --base-directory=/etc pattern`, nil},

		// Unsafe: exec flags
		{`fd pattern --exec rm`, nil},
		{`fd pattern --exec-batch rm`, nil},
		{`fd pattern -x rm`, nil},
		{`fd pattern -X rm`, nil},

		// Not fd
		{"ls -la", nil},

		// fdfind alias
		{`fdfind "*.go"`, ptr(Allow)},

		// Transparent wrappers
		{`timeout 5m fd pattern ./src`, ptr(Allow)},
	}
	for _, tt := range tests {
		result := rule.Apply(BashInput{Command: tt.command})
		if tt.want == nil {
			if result != nil {
				t.Errorf("Fd(%q) = %s, want nil",
					tt.command, result.HookSpecificOutput.PermissionDecision)
			}
			continue
		}
		if result == nil {
			t.Errorf("Fd(%q) = nil, want %s", tt.command, *tt.want)
			continue
		}
		if result.HookSpecificOutput.PermissionDecision != *tt.want {
			t.Errorf("Fd(%q) = %s, want %s",
				tt.command,
				result.HookSpecificOutput.PermissionDecision,
				*tt.want)
		}
	}
}
