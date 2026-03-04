package rules

import "testing"

func TestBashFindRule_Find(t *testing.T) {
	rule := BashFind("")

	tests := []struct {
		command string
		want    *Decision
	}{
		// Safe: no explicit path (defaults to .)
		{`find -name "*.go"`, new(Allow)},
		{`find -type f`, new(Allow)},

		// Safe: explicit cwd-relative paths
		{`find . -name "*.go"`, new(Allow)},
		{`find ./src -name "*.go" -type f`, new(Allow)},
		{`find src tests -name "*.go"`, new(Allow)},

		// Safe: /tmp paths
		{`find /tmp -name "*.log"`, new(Allow)},
		{`find /tmp/test -type f`, new(Allow)},

		// Safe: leading options then safe path
		{`find -L . -name "*.go"`, new(Allow)},
		{`find -H -L . -name "*.go"`, new(Allow)},

		// Safe: absolute path within cwd (only with cwd-aware rule)
		// — tested in TestBashFindRule_FindWithCwd

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
		{`timeout 5m find . -name "*.go"`, new(Allow)},
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
	rule := BashFind("")

	tests := []struct {
		command string
		want    *Decision
	}{
		// Safe: no explicit path (defaults to .)
		{`fd "*.go"`, new(Allow)},
		{`fd -t f pattern`, new(Allow)},
		{`fd`, new(Allow)},

		// Safe: explicit relative paths
		{`fd pattern ./src`, new(Allow)},
		{`fd pattern src tests`, new(Allow)},

		// Safe: /tmp paths
		{`fd pattern /tmp`, new(Allow)},
		{`fd pattern /tmp/test`, new(Allow)},

		// Safe: --search-path and --base-directory
		{`fd --search-path ./src pattern`, new(Allow)},
		{`fd --base-directory src pattern`, new(Allow)},
		{`fd --search-path=./src pattern`, new(Allow)},
		{`fd --base-directory=src pattern`, new(Allow)},

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
		{`fdfind "*.go"`, new(Allow)},

		// Transparent wrappers
		{`timeout 5m fd pattern ./src`, new(Allow)},
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

func TestBashFindRule_FindWithCwd(t *testing.T) {
	cwd := "/Users/tim/git/project"
	rule := BashFind(cwd)

	tests := []struct {
		command string
		want    *Decision
	}{
		// Absolute path equal to cwd
		{`find /Users/tim/git/project -type f -name "*.md"`, new(Allow)},
		// Absolute path within cwd
		{`find /Users/tim/git/project/subdir -name "*.go"`, new(Allow)},
		// Absolute path outside cwd — still blocked
		{`find /Users/tim/git/other -name "*.go"`, nil},
		{`find /etc -name "passwd"`, nil},
		// Relative paths still work
		{`find . -name "*.go"`, new(Allow)},
		{`find src -name "*.go"`, new(Allow)},
		// /tmp still works
		{`find /tmp -name "*.log"`, new(Allow)},
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

func TestBashFindRule_FdWithCwd(t *testing.T) {
	cwd := "/Users/tim/git/project"
	rule := BashFind(cwd)

	tests := []struct {
		command string
		want    *Decision
	}{
		// Absolute path within cwd
		{`fd pattern /Users/tim/git/project/src`, new(Allow)},
		// Absolute path outside cwd
		{`fd pattern /etc`, nil},
		// --search-path with absolute cwd path
		{`fd --search-path /Users/tim/git/project/src pattern`, new(Allow)},
		{`fd --search-path=/Users/tim/git/project/src pattern`, new(Allow)},
		// --search-path outside cwd
		{`fd --search-path /etc pattern`, nil},
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
