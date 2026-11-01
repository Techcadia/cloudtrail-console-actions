package policy

import (
	_ "embed"
	"fmt"
	"os"
	"sync"
)

// defaultYAML is the v0.4.0-compatible ruleset baked into the deployment.
//
//go:embed default.yaml
var defaultYAML []byte

// Default returns the embedded v0.4.0-compatible policy. The document is part
// of the binary, so a parse failure is a build defect and panics.
var Default = sync.OnceValue(func() *Policy {
	p, err := Parse(defaultYAML)
	if err != nil {
		panic(fmt.Sprintf("embedded default policy is invalid: %v", err))
	}
	return p
})

// DefaultSource returns the raw YAML of the embedded policy, so operators can
// dump it as a starting point for a custom --config-file.
func DefaultSource() []byte { return defaultYAML }

// LoadFile parses a policy override from disk.
func LoadFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}
	p, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}
