package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/tdeebswihart/agent-blocker/pkg/logging"
	"github.com/tdeebswihart/agent-blocker/pkg/rules"
)

const usage = `agent-blocker — a Claude Code PreToolUse hook that auto-allows safe
tool calls and blocks dangerous ones.

Usage:
  agent-blocker reads a Claude Code hook event from STDIN and writes a
  JSON decision to STDOUT.

  Configure it in .claude/settings.json:

    {
      "hooks": {
        "PreToolUse": [
          {
            "matcher": "",
            "hooks": ["agent-blocker"]
          }
        ]
      }
    }

Input (STDIN):
  A JSON object with the following fields:

    {
      "hook_event_name": "PreToolUse",
      "tool_name":       "Bash",
      "cwd":             "/path/to/project",
      "tool_input":      { "command": "go test ./..." }
    }

Output (STDOUT):
  A JSON object with the decision and hook-specific output:

    {
      "decision": "allow",
      "reason":   "matched pattern: go test *",
      "hookSpecificOutput": {
        "hookEventName":      "PreToolUse",
        "permissionDecision": "allow",
        "additionalContext":  "matched pattern: go test *"
      }
    }

  Decisions: "allow", "deny", or "ask" (prompt the user).
`

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "-help" || os.Args[1] == "--help") {
		fmt.Print(usage)
		os.Exit(0)
	}

	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fatal("reading stdin: %v", err)
	}

	var hook rules.HookInput
	if err := json.Unmarshal(input, &hook); err != nil {
		fatal("parsing hook input: %v", err)
	}

	home, _ := os.UserHomeDir()
	allRules := append(rules.DefaultRules(hook.CWD), rules.AllSettingsRules(home, hook.CWD)...)
	harness := rules.NewHarness(allRules...)
	result := harness.Evaluate(hook)
	logging.LogInvocation(hook, result)
	if result == nil {
		return
	}

	out, err := json.Marshal(result)
	if err != nil {
		fatal("marshaling result: %v", err)
	}
	fmt.Println(string(out))
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
