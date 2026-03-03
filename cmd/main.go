package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"codeberg.org/timods/agent-blocker/pkg/rules"
)

func main() {
	harness := rules.NewHarness(buildRules()...)

	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fatal("reading stdin: %v", err)
	}

	var hook rules.HookInput
	if err := json.Unmarshal(input, &hook); err != nil {
		fatal("parsing hook input: %v", err)
	}

	result := harness.Evaluate(hook)

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

// buildRules returns the configured permission rules.
// TODO: load from config file instead of hardcoding.
func buildRules() []rules.Matcher {
	return []rules.Matcher{}
}
