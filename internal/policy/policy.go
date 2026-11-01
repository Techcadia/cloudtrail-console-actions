// Package policy defines the FilterPolicy document (see policy.schema.json)
// and its YAML loader. Parsing is strict — unknown fields are rejected — and
// structural validation happens here; expression and operator compilation
// (and their errors) belong to the engine.
package policy

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Policy is a parsed FilterPolicy document.
//
// Evaluation semantics (per CloudTrail record):
//  1. Preprocess computes working values addressed as preprocess.*.
//  2. A record is dropped when any filter rule applies (match ∧ ¬exclude)
//     and no keep rule matches; keep beats skip. Default action is emit.
//  3. Outputs project an emitted record to the log/Slack schema.
type Policy struct {
	APIVersion string       `yaml:"apiVersion"`
	Kind       string       `yaml:"kind"`
	Preprocess Fields       `yaml:"preprocess"`
	Keep       []KeepRule   `yaml:"keep"`
	Filters    []FilterRule `yaml:"filters"`
	Outputs    Fields       `yaml:"outputs"`
}

// FilterRule drops matching records unless carved out by exclude.
type FilterRule struct {
	Name    string      `yaml:"name"`
	Action  string      `yaml:"action"`
	Match   Conditions  `yaml:"match"`
	Exclude *Conditions `yaml:"exclude"`
}

// KeepRule vetoes every filter rule. Exclude is intentionally not part of
// the type: the veto is absolute, which keeps the policy provably terminating.
type KeepRule struct {
	Name  string     `yaml:"name"`
	Match Conditions `yaml:"match"`
}

// Conditions groups conditions: any = OR, all = AND; when both are present
// they are ANDed together. Conditions do not nest.
type Conditions struct {
	Any []Condition `yaml:"any"`
	All []Condition `yaml:"all"`
}

// Condition compares a {{ }} key expression against a policy value.
type Condition struct {
	Key      string `yaml:"key"`
	Operator string `yaml:"operator"`
	Value    any    `yaml:"value"`
}

// Fields is an ordered set of named output fields (preprocess: and outputs:).
// YAML mappings lose their order under map[string]; order matters because
// later preprocess fields may read earlier ones.
type Fields []Field

// Field is one named entry: either sugar (a bare template string) or an
// ordered rule list where the first matching `when` wins.
type Field struct {
	Name  string
	Rules []Rule
}

// Rule is one {when, value} arm of a field. A nil When always applies.
type Rule struct {
	When  *Conditions
	Value string
	// Literal holds the typed value of an unquoted non-string YAML scalar
	// (true, 42, 1.5), so `flag: true` yields a bool rather than the string
	// "true". Nil for templates and string literals.
	Literal any
}

// UnmarshalYAML decodes a fields mapping preserving document order and
// desugaring bare strings into a single unconditional rule.
func (f *Fields) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: expected a mapping of field names", node.Line)
	}
	seen := make(map[string]bool, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		keyNode, valNode := node.Content[i], node.Content[i+1]
		// The mapping is walked by hand, so yaml.v3's duplicate-key check
		// does not apply here.
		if seen[keyNode.Value] {
			return fmt.Errorf("line %d: duplicate field %q", keyNode.Line, keyNode.Value)
		}
		seen[keyNode.Value] = true
		field := Field{Name: keyNode.Value}
		switch valNode.Kind {
		case yaml.ScalarNode:
			rule, err := decodeValue(valNode)
			if err != nil {
				return fmt.Errorf("field %q: %w", field.Name, err)
			}
			field.Rules = []Rule{rule}
		case yaml.SequenceNode:
			for _, ruleNode := range valNode.Content {
				rule, err := decodeRule(ruleNode)
				if err != nil {
					return fmt.Errorf("field %q: %w", field.Name, err)
				}
				field.Rules = append(field.Rules, rule)
			}
		default:
			return fmt.Errorf("field %q: expected a template string or a rule list", field.Name)
		}
		*f = append(*f, field)
	}
	return nil
}

// decodeRule decodes one {when, value} mapping, keeping the strictness the
// custom unmarshaler would otherwise lose: unknown keys are rejected and
// value is required.
func decodeRule(node *yaml.Node) (Rule, error) {
	if node.Kind != yaml.MappingNode {
		return Rule{}, fmt.Errorf("line %d: expected a {when, value} mapping", node.Line)
	}
	var rule Rule
	hasValue := false
	for i := 0; i < len(node.Content); i += 2 {
		keyNode, valNode := node.Content[i], node.Content[i+1]
		switch keyNode.Value {
		case "when":
			rule.When = &Conditions{}
			if err := valNode.Decode(rule.When); err != nil {
				return Rule{}, err
			}
		case "value":
			v, err := decodeValue(valNode)
			if err != nil {
				return Rule{}, err
			}
			rule.Value, rule.Literal = v.Value, v.Literal
			hasValue = true
		default:
			return Rule{}, fmt.Errorf("line %d: unknown key %q in rule", keyNode.Line, keyNode.Value)
		}
	}
	if !hasValue {
		return Rule{}, fmt.Errorf("line %d: rule is missing value", node.Line)
	}
	return rule, nil
}

// decodeValue decodes a field value: a template or string literal, or a
// typed scalar literal.
func decodeValue(node *yaml.Node) (Rule, error) {
	if node.Kind != yaml.ScalarNode {
		return Rule{}, fmt.Errorf("line %d: value must be a template string or a scalar", node.Line)
	}
	if err := checkZeroPadded(node); err != nil {
		return Rule{}, err
	}
	switch node.ShortTag() {
	case "!!str":
		return Rule{Value: node.Value}, nil
	case "!!null":
		// Leave Value empty so validation reports it as missing.
		return Rule{}, nil
	}
	var v any
	if err := node.Decode(&v); err != nil {
		return Rule{}, err
	}
	return Rule{Value: node.Value, Literal: v}, nil
}

// UnmarshalYAML decodes an any:/all: block. Custom unmarshalers run outside
// the decoder's KnownFields mode (and `when:` blocks are decoded from a
// node), so unknown keys are rejected here explicitly.
func (c *Conditions) UnmarshalYAML(node *yaml.Node) error {
	if err := checkKeys(node, "any", "all"); err != nil {
		return err
	}
	type plain Conditions
	return node.Decode((*plain)(c))
}

// UnmarshalYAML decodes one condition, rejecting unknown keys and
// zero-padded unquoted numbers in its value.
func (c *Condition) UnmarshalYAML(node *yaml.Node) error {
	if err := checkKeys(node, "key", "operator", "value"); err != nil {
		return err
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == "value" {
			if err := checkZeroPadded(node.Content[i+1]); err != nil {
				return err
			}
		}
	}
	type plain Condition
	return node.Decode((*plain)(c))
}

// checkKeys rejects a mapping key outside allowed.
func checkKeys(node *yaml.Node, allowed ...string) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: expected a mapping with keys %s", node.Line, strings.Join(allowed, ", "))
	}
	for i := 0; i < len(node.Content); i += 2 {
		k := node.Content[i]
		if !slices.Contains(allowed, k.Value) {
			return fmt.Errorf("line %d: unknown key %q (want one of %s)", k.Line, k.Value, strings.Join(allowed, ", "))
		}
	}
	return nil
}

// checkZeroPadded rejects unquoted numbers with a leading zero. YAML reads
// them as numbers — octal when every digit is 0-7 — so an account ID like
// 012345670123 silently becomes 1402433619 and never matches.
func checkZeroPadded(node *yaml.Node) error {
	switch node.Kind {
	case yaml.SequenceNode:
		for _, item := range node.Content {
			if err := checkZeroPadded(item); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		tag := node.ShortTag()
		if node.Style == 0 && (tag == "!!int" || tag == "!!float") {
			digits := strings.TrimLeft(node.Value, "+-")
			if len(digits) > 1 && digits[0] == '0' && digits[1] >= '0' && digits[1] <= '9' {
				return fmt.Errorf("line %d: %s has a leading zero and would be read as a number; quote it (%q)", node.Line, node.Value, node.Value)
			}
		}
	}
	return nil
}

// Parse decodes and structurally validates a FilterPolicy document.
func Parse(data []byte) (*Policy, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parsing policy: %w", err)
	}
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}
	return &p, nil
}

func (p *Policy) validate() error {
	if p.APIVersion != "cca/v1" {
		return fmt.Errorf(`apiVersion must be "cca/v1", got %q`, p.APIVersion)
	}
	if p.Kind != "FilterPolicy" {
		return fmt.Errorf(`kind must be "FilterPolicy", got %q`, p.Kind)
	}
	if len(p.Filters) == 0 {
		return fmt.Errorf("filters: at least one rule is required")
	}

	seen := make(map[string]bool, len(p.Filters)+len(p.Keep))
	checkName := func(kind, name string, i int) error {
		if name == "" {
			return fmt.Errorf("%s[%d]: name is required", kind, i)
		}
		if seen[name] {
			return fmt.Errorf("%s[%d]: duplicate rule name %q", kind, i, name)
		}
		seen[name] = true
		return nil
	}

	for i, r := range p.Keep {
		if err := checkName("keep", r.Name, i); err != nil {
			return err
		}
		if err := r.Match.validate(); err != nil {
			return fmt.Errorf("keep rule %q: match: %w", r.Name, err)
		}
	}
	for i, r := range p.Filters {
		if err := checkName("filters", r.Name, i); err != nil {
			return err
		}
		if r.Action != "skip" {
			return fmt.Errorf("filter rule %q: action must be \"skip\", got %q", r.Name, r.Action)
		}
		if err := r.Match.validate(); err != nil {
			return fmt.Errorf("filter rule %q: match: %w", r.Name, err)
		}
		if r.Exclude != nil {
			if err := r.Exclude.validate(); err != nil {
				return fmt.Errorf("filter rule %q: exclude: %w", r.Name, err)
			}
		}
	}

	for _, f := range p.Preprocess {
		if !isIdentifier(f.Name) {
			return fmt.Errorf("preprocess field %q: name must be an identifier (addressed as preprocess.%s)", f.Name, f.Name)
		}
		if err := f.validate(); err != nil {
			return fmt.Errorf("preprocess field %q: %w", f.Name, err)
		}
	}
	for _, f := range p.Outputs {
		if err := f.validate(); err != nil {
			return fmt.Errorf("output field %q: %w", f.Name, err)
		}
	}
	return nil
}

func (c *Conditions) validate() error {
	if len(c.Any) == 0 && len(c.All) == 0 {
		return fmt.Errorf("needs at least one of any: or all:")
	}
	for _, blk := range []struct {
		name  string
		conds []Condition
	}{{"any", c.Any}, {"all", c.All}} {
		block := blk.name
		for i, cond := range blk.conds {
			if cond.Key == "" {
				return fmt.Errorf("%s[%d]: key is required", block, i)
			}
			if cond.Operator == "" {
				return fmt.Errorf("%s[%d] (key %s): operator is required", block, i, cond.Key)
			}
			if cond.Value == nil {
				return fmt.Errorf("%s[%d] (key %s): value is required", block, i, cond.Key)
			}
		}
	}
	return nil
}

func (f *Field) validate() error {
	if len(f.Rules) == 0 {
		return fmt.Errorf("needs at least one rule")
	}
	for i, r := range f.Rules {
		if r.Value == "" {
			return fmt.Errorf("rule %d: value is required", i)
		}
		if r.When != nil {
			if err := r.When.validate(); err != nil {
				return fmt.Errorf("rule %d: when: %w", i, err)
			}
		}
	}
	return nil
}

func isIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		ok := c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (i > 0 && c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return true
}
