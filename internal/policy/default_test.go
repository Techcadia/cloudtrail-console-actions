package policy

import (
	"slices"
	"testing"
)

func TestDefaultParses(t *testing.T) {
	p := Default()

	if got := len(p.Preprocess); got != 2 {
		t.Errorf("preprocess fields = %d, want 2", got)
	}
	if p.Preprocess[0].Name != "eventName" || p.Preprocess[1].Name != "userName" {
		t.Errorf("preprocess order = %v", []string{p.Preprocess[0].Name, p.Preprocess[1].Name})
	}
	if len(p.Keep) != 1 {
		t.Errorf("keep rules = %d, want 1", len(p.Keep))
	}

	names := make([]string, 0, len(p.Filters))
	for _, f := range p.Filters {
		names = append(names, f.Name)
	}

	// Every v1 (v0.3.2) behavior must have a corresponding rule, including
	// the ones added after the v0.2.3 policy draft.
	for _, want := range []string{
		"drop-aws-internal-invoked",
		"drop-codecommit-all",
		"drop-consolelogin-nonroot",
		"drop-new-client-connection",
		"drop-ssm-guiconnect-cancel",
		"drop-inspector2-telemetry",
		"drop-non-console-user-agent",
	} {
		if !slices.Contains(names, want) {
			t.Errorf("default policy is missing rule %q", want)
		}
	}

	// ConsoleLogin must be the guarded rule, not part of the exact-name drops.
	for _, f := range p.Filters {
		if f.Name == "drop-read-exact-names" {
			list := f.Match.All[0].Value.([]any)
			if slices.Contains(list, any("ConsoleLogin")) {
				t.Error("ConsoleLogin must not be in drop-read-exact-names; v1 keeps Root logins")
			}
		}
		if f.Name == "drop-consolelogin-nonroot" && f.Exclude == nil {
			t.Error("drop-consolelogin-nonroot must exclude Root identities")
		}
	}
}

func TestDefaultSourceRoundTrips(t *testing.T) {
	if _, err := Parse(DefaultSource()); err != nil {
		t.Fatalf("DefaultSource does not re-parse: %v", err)
	}
}
