package rules

import "testing"

func TestBashLocalCmd(t *testing.T) {
	const root = "/project"
	rule := BashLocalCmd(root)

	tests := []struct {
		name    string
		command string
		allow   bool
	}{
		// Should allow — relative paths within project
		{"dot-slash script", "./script.sh", true},
		{"dot-slash nested", "./build/myapp arg1 arg2", true},
		{"relative subdir", "bin/test", true},
		{"relative deep path", "tools/lint/run.sh --fix", true},

		// Should allow — absolute paths within project root
		{"absolute within root", "/project/bin/test", true},
		{"absolute nested", "/project/build/output/cmd --flag", true},

		// Should NOT match — bare commands (PATH lookups)
		{"bare command", "ls -la", false},
		{"bare go", "go test ./...", false},
		{"bare make", "make build", false},
		{"bare python", "python script.py", false},

		// Should NOT match — paths escaping project root
		{"dot-dot escape", "../other/script.sh", false},
		{"dot-dot deep escape", "./foo/../../other/script.sh", false},
		{"absolute outside", "/usr/bin/something", false},
		{"absolute other project", "/other/project/bin/test", false},

		// Should NOT match — project root prefix that isn't a descendant
		{"prefix trick", "/project-evil/bin/test", false},

		// Edge cases
		{"with timeout wrapper", "timeout 30 ./build/myapp", true},
		{"with xargs wrapper", "xargs -I {} ./script.sh {}", true},
		{"with rtk wrapper", "rtk proxy ./build/myapp", true},
		{"with rtk flags wrapper", "rtk -u ./build/myapp arg1", true},
		{"with redirect", "./build/myapp > output.txt", true},
		{"empty command", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rule.Apply(BashInput{Command: tt.command})
			if tt.allow {
				if result == nil {
					t.Fatal("expected Allow, got nil (no match)")
				}
				if result.HookSpecificOutput.PermissionDecision != Allow {
					t.Fatalf("expected Allow, got %s",
						result.HookSpecificOutput.PermissionDecision)
				}
			} else {
				if result != nil {
					t.Fatalf("expected nil (no match), got %s: %s",
						result.HookSpecificOutput.PermissionDecision,
						result.HookSpecificOutput.PermissionDecisionReason)
				}
			}
		})
	}
}
