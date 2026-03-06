package rules

import "testing"

func TestCtxBatch_AllAllowed(t *testing.T) {
	h := NewHarness(
		Bash(Allow, "", "go test *"),
		Bash(Allow, "", "golangci-lint *"),
	)

	result := h.Evaluate(HookInput{
		Name: ctxBatchExecuteTool,
		Input: mustJSON(CtxBatchExecuteInput{
			Commands: []CtxBatchCommand{
				{Label: "test", Command: "go test ./..."},
				{Label: "lint", Command: "golangci-lint run"},
			},
		}),
	})
	if result == nil || result.HookSpecificOutput.PermissionDecision != Allow {
		t.Fatalf("expected Allow for all-allowed batch, got %+v", result)
	}
}

func TestCtxBatch_OneDenied(t *testing.T) {
	h := NewHarness(
		Bash(Allow, "", "go test *"),
		Bash(Deny, "", "rm -rf *"),
	)

	result := h.Evaluate(HookInput{
		Name: ctxBatchExecuteTool,
		Input: mustJSON(CtxBatchExecuteInput{
			Commands: []CtxBatchCommand{
				{Label: "test", Command: "go test ./..."},
				{Label: "destroy", Command: "rm -rf /"},
			},
		}),
	})
	if result == nil || result.HookSpecificOutput.PermissionDecision != Deny {
		t.Fatalf("expected Deny when one command is denied, got %+v", result)
	}
}

func TestCtxBatch_UnmatchedCommand(t *testing.T) {
	h := NewHarness(
		Bash(Allow, "", "go test *"),
	)

	result := h.Evaluate(HookInput{
		Name: ctxBatchExecuteTool,
		Input: mustJSON(CtxBatchExecuteInput{
			Commands: []CtxBatchCommand{
				{Label: "test", Command: "go test ./..."},
				{Label: "unknown", Command: "some-unknown-command"},
			},
		}),
	})
	if result == nil || result.HookSpecificOutput.PermissionDecision != Ask {
		t.Fatalf("expected Ask for unmatched command, got %+v", result)
	}
}

func TestCtxBatch_EmptyCommands(t *testing.T) {
	h := NewHarness(
		Bash(Allow, "", "go test *"),
	)

	result := h.Evaluate(HookInput{
		Name: ctxBatchExecuteTool,
		Input: mustJSON(CtxBatchExecuteInput{
			Queries: []string{"what is foo?"},
		}),
	})
	if result == nil || result.HookSpecificOutput.PermissionDecision != Allow {
		t.Fatalf("expected Allow for queries-only batch, got %+v", result)
	}
}

func TestCtxBatch_CompoundCommandInBatch(t *testing.T) {
	h := NewHarness(
		Bash(Allow, "", "go test *"),
		Bash(Allow, "", "golangci-lint *"),
		Bash(Deny, "", "rm -rf *"),
	)

	// A batch command that is itself a compound command should be split.
	result := h.Evaluate(HookInput{
		Name: ctxBatchExecuteTool,
		Input: mustJSON(CtxBatchExecuteInput{
			Commands: []CtxBatchCommand{
				{Label: "compound", Command: "go test ./... && golangci-lint run"},
			},
		}),
	})
	if result == nil || result.HookSpecificOutput.PermissionDecision != Allow {
		t.Fatalf("expected Allow for compound command in batch, got %+v", result)
	}

	// Compound with a denied sub-command.
	result = h.Evaluate(HookInput{
		Name: ctxBatchExecuteTool,
		Input: mustJSON(CtxBatchExecuteInput{
			Commands: []CtxBatchCommand{
				{Label: "bad compound", Command: "go test ./... && rm -rf /"},
			},
		}),
	})
	if result == nil || result.HookSpecificOutput.PermissionDecision != Deny {
		t.Fatalf("expected Deny for compound with denied sub-command, got %+v", result)
	}
}

func TestCtxBatch_RealWorldGrepSed(t *testing.T) {
	h := NewHarness(
		BashGrep(""),
		Bash(Allow, "", "sed *"),
		Bash(Allow, "", "head *"),
		Bash(Allow, "", "cat *"),
	)

	result := h.Evaluate(HookInput{
		Name: ctxBatchExecuteTool,
		Input: mustJSON(CtxBatchExecuteInput{
			Commands: []CtxBatchCommand{
				{Label: "grep", Command: `grep -rn "TODO" .`},
				{Label: "sed", Command: `sed -n '1,10p' main.go`},
				{Label: "head", Command: "head -20 README.md"},
			},
			Queries: []string{"summarize findings"},
		}),
	})
	if result == nil || result.HookSpecificOutput.PermissionDecision != Allow {
		t.Fatalf("expected Allow for real-world grep/sed batch, got %+v", result)
	}
}
