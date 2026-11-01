package app

import (
	"log/slog"
	"strings"
	"testing"
)

func env(pairs map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := pairs[k]
		return v, ok
	}
}

func TestParseOptionsDefaults(t *testing.T) {
	opts, err := ParseOptions(nil, env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if opts.PolicyFile != "" {
		t.Errorf("PolicyFile = %q, want embedded default", opts.PolicyFile)
	}
	if !opts.Dedupe {
		t.Error("Dedupe must default to enabled")
	}
	if opts.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel = %v, want info", opts.LogLevel)
	}
	if opts.ValidateOnly || opts.DumpDefaultPolicy {
		t.Error("action flags must default off")
	}
}

func TestParseOptionsFromEnv(t *testing.T) {
	opts, err := ParseOptions(nil, env(map[string]string{
		"CCA_POLICY_FILE": "/etc/cca/policy.yaml",
		"CCA_DEDUPE":      "false",
		"LOG_LEVEL":       "debug",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if opts.PolicyFile != "/etc/cca/policy.yaml" {
		t.Errorf("PolicyFile = %q", opts.PolicyFile)
	}
	if opts.Dedupe {
		t.Error("CCA_DEDUPE=false not honored")
	}
	if opts.LogLevel != slog.LevelDebug {
		t.Errorf("LogLevel = %v, want debug", opts.LogLevel)
	}
}

func TestParseOptionsFlagsBeatEnv(t *testing.T) {
	opts, err := ParseOptions(
		[]string{"--config-file", "/tmp/override.yaml", "--dedupe=true", "--log-level", "warn"},
		env(map[string]string{
			"CCA_POLICY_FILE": "/etc/cca/policy.yaml",
			"CCA_DEDUPE":      "false",
			"LOG_LEVEL":       "debug",
		}))
	if err != nil {
		t.Fatal(err)
	}
	if opts.PolicyFile != "/tmp/override.yaml" {
		t.Errorf("PolicyFile = %q, flag must beat env", opts.PolicyFile)
	}
	if !opts.Dedupe {
		t.Error("--dedupe=true must beat CCA_DEDUPE=false")
	}
	if opts.LogLevel != slog.LevelWarn {
		t.Errorf("LogLevel = %v, want warn", opts.LogLevel)
	}
}

func TestParseOptionsErrors(t *testing.T) {
	if _, err := ParseOptions(nil, env(map[string]string{"CCA_DEDUPE": "sometimes"})); err == nil || !strings.Contains(err.Error(), "CCA_DEDUPE") {
		t.Errorf("invalid CCA_DEDUPE: err = %v", err)
	}
	if _, err := ParseOptions(nil, env(map[string]string{"LOG_LEVEL": "loud"})); err == nil || !strings.Contains(err.Error(), "LOG_LEVEL") {
		t.Errorf("invalid LOG_LEVEL: err = %v", err)
	}
	if _, err := ParseOptions([]string{"--bogus"}, env(nil)); err == nil {
		t.Error("unknown flag: want error")
	}
}
