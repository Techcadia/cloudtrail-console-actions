// Package app wires the pieces into the Lambda handler: option resolution,
// per-invocation processing, and alert fan-out.
package app

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
)

// Options is the resolved runtime configuration. Flags beat environment
// variables beat defaults.
type Options struct {
	// PolicyFile overrides the embedded default policy.
	// Flag --config-file, env CCA_POLICY_FILE.
	PolicyFile string
	// Dedupe groups identical (user, event, error) records into one
	// notification. Flag --dedupe, env CCA_DEDUPE. Default true.
	Dedupe bool
	// LogLevel for the JSON logger. Flag --log-level, env LOG_LEVEL.
	LogLevel slog.Level
	// ValidateOnly parses and compiles the policy, reports, and exits.
	ValidateOnly bool
	// DumpDefaultPolicy writes the embedded policy to stdout and exits.
	DumpDefaultPolicy bool
}

// ParseOptions resolves configuration from CLI args and the environment.
func ParseOptions(args []string, lookupEnv func(string) (string, bool)) (*Options, error) {
	opts := &Options{Dedupe: true, LogLevel: slog.LevelInfo}

	if v, ok := lookupEnv("CCA_POLICY_FILE"); ok && v != "" {
		opts.PolicyFile = v
	}
	if v, ok := lookupEnv("CCA_DEDUPE"); ok && v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("CCA_DEDUPE: %q is not a boolean", v)
		}
		opts.Dedupe = b
	}
	if v, ok := lookupEnv("LOG_LEVEL"); ok && v != "" {
		level, err := parseLevel(v)
		if err != nil {
			return nil, fmt.Errorf("LOG_LEVEL: %w", err)
		}
		opts.LogLevel = level
	}

	fs := flag.NewFlagSet("cloudtrail-console-actions", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configFile := fs.String("config-file", opts.PolicyFile, "policy YAML overriding the embedded default")
	dedupe := fs.Bool("dedupe", opts.Dedupe, "group identical events into one notification")
	logLevel := fs.String("log-level", "", "debug, info, warn or error")
	fs.BoolVar(&opts.ValidateOnly, "validate-only", false, "validate the policy and exit")
	fs.BoolVar(&opts.DumpDefaultPolicy, "dump-default-policy", false, "print the embedded policy and exit")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	opts.PolicyFile = *configFile
	opts.Dedupe = *dedupe
	if *logLevel != "" {
		level, err := parseLevel(*logLevel)
		if err != nil {
			return nil, fmt.Errorf("--log-level: %w", err)
		}
		opts.LogLevel = level
	}
	return opts, nil
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown level %q (want debug, info, warn or error)", s)
	}
}
