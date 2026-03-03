package rules

import (
	"errors"
	"testing"
)

func TestParseJJEditRevsets(t *testing.T) {
	tests := []struct {
		command string
		want    []string // nil means "not a jj edit command"
	}{
		{"jj edit abc", []string{"abc"}},
		{"jj e abc", []string{"abc"}},
		{"jj edit -r abc", []string{"abc"}},
		{"jj edit --revision abc", []string{"abc"}},
		{"jj edit", []string{"@"}},
		{"jj e", []string{"@"}},
		{"jj edit --color auto abc", []string{"abc"}},
		{"jj edit -R /repo abc", []string{"abc"}},
		{"jj edit -- -weird-rev", []string{"-weird-rev"}},
		{"timeout 5m jj edit abc", []string{"abc"}},
		// Not jj edit commands:
		{"jj abandon abc", nil},
		{"ls -la", nil},
		{"jj log", nil},
	}
	for _, tt := range tests {
		got := parseJJEditRevsets(tt.command)
		if tt.want == nil {
			if got != nil {
				t.Errorf("parseJJEditRevsets(%q) = %v, want nil", tt.command, got)
			}
			continue
		}
		if len(got) != len(tt.want) {
			t.Errorf("parseJJEditRevsets(%q) = %v, want %v", tt.command, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("parseJJEditRevsets(%q)[%d] = %q, want %q",
					tt.command, i, got[i], tt.want[i])
			}
		}
	}
}

func TestParseJJAbandonRevsets(t *testing.T) {
	tests := []struct {
		command string
		want    []string
	}{
		{"jj abandon abc", []string{"abc"}},
		{"jj abandon abc def", []string{"abc", "def"}},
		{"jj abandon -r abc -r def", []string{"abc", "def"}},
		{"jj abandon --revisions abc", []string{"abc"}},
		{"jj abandon", []string{"@"}},
		{"jj abandon --color auto abc def", []string{"abc", "def"}},
		{"timeout 5m jj abandon abc", []string{"abc"}},
		// Not jj abandon commands:
		{"jj edit abc", nil},
		{"ls -la", nil},
	}
	for _, tt := range tests {
		got := parseJJAbandonRevsets(tt.command)
		if tt.want == nil {
			if got != nil {
				t.Errorf("parseJJAbandonRevsets(%q) = %v, want nil", tt.command, got)
			}
			continue
		}
		if len(got) != len(tt.want) {
			t.Errorf("parseJJAbandonRevsets(%q) = %v, want %v", tt.command, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("parseJJAbandonRevsets(%q)[%d] = %q, want %q",
					tt.command, i, got[i], tt.want[i])
			}
		}
	}
}

func TestJJLogAllEmpty(t *testing.T) {
	tests := []struct {
		output string
		want   bool
	}{
		{"EMPTY\n", true},
		{"EMPTY\nEMPTY\n", true},
		{"EMPTY\nNOTEMPTY\n", false},
		{"NOTEMPTY\n", false},
		{"EMPTY", true}, // no trailing newline
		{"", false},     // empty output = no revisions resolved
		{"NOTEMPTY\nEMPTY\n", false},
	}
	for _, tt := range tests {
		got := jjLogAllEmpty(tt.output)
		if got != tt.want {
			t.Errorf("jjLogAllEmpty(%q) = %v, want %v", tt.output, got, tt.want)
		}
	}
}

func TestJJEditEmptyRule_AllowsEmpty(t *testing.T) {
	rule := &JJEditEmptyRule{check: func(revsets []string) (bool, error) {
		return true, nil
	}}

	result := rule.Apply(BashInput{Command: "jj edit abc"})
	if result == nil {
		t.Fatal("expected result for jj edit command")
	}
	if result.Decision != Allow {
		t.Fatalf("expected Allow for empty revision, got %s", result.Decision)
	}
}

func TestJJEditEmptyRule_DeniesNonEmpty(t *testing.T) {
	rule := &JJEditEmptyRule{check: func(revsets []string) (bool, error) {
		return false, nil
	}}

	result := rule.Apply(BashInput{Command: "jj edit abc"})
	if result == nil {
		t.Fatal("expected result for jj edit command")
	}
	if result.Decision != Deny {
		t.Fatalf("expected Deny for non-empty revision, got %s", result.Decision)
	}
}

func TestJJEditEmptyRule_NilOnError(t *testing.T) {
	rule := &JJEditEmptyRule{check: func(revsets []string) (bool, error) {
		return false, errors.New("jj not found")
	}}

	result := rule.Apply(BashInput{Command: "jj edit abc"})
	if result != nil {
		t.Fatal("expected nil result on error")
	}
}

func TestJJEditEmptyRule_NilForNonEditCommand(t *testing.T) {
	rule := &JJEditEmptyRule{check: func(revsets []string) (bool, error) {
		t.Fatal("check should not be called for non-edit command")
		return false, nil
	}}

	result := rule.Apply(BashInput{Command: "jj log"})
	if result != nil {
		t.Fatal("expected nil result for non-edit command")
	}
}

func TestJJAbandonEmptyRule_AllowsAllEmpty(t *testing.T) {
	rule := &JJAbandonEmptyRule{check: func(revsets []string) (bool, error) {
		return true, nil
	}}

	result := rule.Apply(BashInput{Command: "jj abandon abc def"})
	if result == nil {
		t.Fatal("expected result for jj abandon command")
	}
	if result.Decision != Allow {
		t.Fatalf("expected Allow when all revisions empty, got %s", result.Decision)
	}
}

func TestJJAbandonEmptyRule_DeniesAnyNonEmpty(t *testing.T) {
	rule := &JJAbandonEmptyRule{check: func(revsets []string) (bool, error) {
		return false, nil
	}}

	result := rule.Apply(BashInput{Command: "jj abandon abc def"})
	if result == nil {
		t.Fatal("expected result for jj abandon command")
	}
	if result.Decision != Deny {
		t.Fatalf("expected Deny when any revision non-empty, got %s", result.Decision)
	}
}

func TestJJAbandonEmptyRule_PassesRevsets(t *testing.T) {
	var captured []string
	rule := &JJAbandonEmptyRule{check: func(revsets []string) (bool, error) {
		captured = revsets
		return true, nil
	}}

	rule.Apply(BashInput{Command: "jj abandon abc def"})
	if len(captured) != 2 || captured[0] != "abc" || captured[1] != "def" {
		t.Fatalf("expected [abc def], got %v", captured)
	}
}
