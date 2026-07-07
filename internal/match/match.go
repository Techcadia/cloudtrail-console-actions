// Package match implements the condition operators of a FilterPolicy:
// exact equality, set membership with * and ? wildcards, numeric
// comparisons, and RE2 Matches/NotMatches. Policy values are compiled once
// (wildcards classified, regexes built) so per-record evaluation is cheap and
// cannot fail.
package match

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Operator is a condition operator as written in policy YAML.
type Operator string

const (
	Equals              Operator = "Equals"
	NotEquals           Operator = "NotEquals"
	AnyIn               Operator = "AnyIn"
	AllIn               Operator = "AllIn"
	AnyNotIn            Operator = "AnyNotIn"
	AllNotIn            Operator = "AllNotIn"
	GreaterThan         Operator = "GreaterThan"
	GreaterThanOrEquals Operator = "GreaterThanOrEquals"
	LessThan            Operator = "LessThan"
	LessThanOrEquals    Operator = "LessThanOrEquals"
	Matches             Operator = "Matches"
	NotMatches          Operator = "NotMatches"
)

// Comparison is an operator compiled together with its policy-side value.
// Eval compares a record-side key against it.
type Comparison struct {
	op       Operator
	scalar   any              // Equals / NotEquals
	number   float64          // numeric comparisons
	patterns []wildcard       // set operators
	regexes  []*regexp.Regexp // Matches / NotMatches
}

// Compile validates the (operator, value) pair — mirroring the policy schema:
// set and regex operators take a non-empty list, everything else a scalar —
// and precompiles wildcards and regexes.
func Compile(op Operator, value any) (*Comparison, error) {
	c := &Comparison{op: op}
	switch op {
	case Equals, NotEquals:
		if !isScalar(value) {
			return nil, fmt.Errorf("%s requires a scalar value, got %T", op, value)
		}
		c.scalar = value

	case AnyIn, AllIn, AnyNotIn, AllNotIn:
		items, err := scalarList(op, value)
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			c.patterns = append(c.patterns, compileWildcard(item))
		}

	case GreaterThan, GreaterThanOrEquals, LessThan, LessThanOrEquals:
		n, ok := toNumber(value)
		if !ok {
			return nil, fmt.Errorf("%s requires a numeric value, got %#v", op, value)
		}
		c.number = n

	case Matches, NotMatches:
		items, err := scalarList(op, value)
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			pat, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%s requires string patterns, got %#v", op, item)
			}
			re, err := regexp.Compile(pat)
			if err != nil {
				return nil, fmt.Errorf("%s pattern %q: %w", op, pat, err)
			}
			c.regexes = append(c.regexes, re)
		}

	default:
		return nil, fmt.Errorf("unknown operator %q", op)
	}
	return c, nil
}

// Eval reports whether the record-side key satisfies the comparison.
// A nil key satisfies only the negated operators.
func (c *Comparison) Eval(key any) bool {
	switch c.op {
	case Equals:
		return equalScalar(key, c.scalar)
	case NotEquals:
		return !equalScalar(key, c.scalar)

	case AnyIn, AllIn, AnyNotIn, AllNotIn:
		keys := keyList(key)
		if len(keys) == 0 {
			return c.op == AnyNotIn || c.op == AllNotIn
		}
		switch c.op {
		case AnyIn: // some key is in the set
			for _, k := range keys {
				if c.inSet(k) {
					return true
				}
			}
			return false
		case AllIn: // every key is in the set
			for _, k := range keys {
				if !c.inSet(k) {
					return false
				}
			}
			return true
		case AnyNotIn: // some key is outside the set
			for _, k := range keys {
				if !c.inSet(k) {
					return true
				}
			}
			return false
		default: // AllNotIn: every key is outside the set
			for _, k := range keys {
				if c.inSet(k) {
					return false
				}
			}
			return true
		}

	case GreaterThan, GreaterThanOrEquals, LessThan, LessThanOrEquals:
		n, ok := toNumber(key)
		if !ok {
			return false
		}
		switch c.op {
		case GreaterThan:
			return n > c.number
		case GreaterThanOrEquals:
			return n >= c.number
		case LessThan:
			return n < c.number
		default:
			return n <= c.number
		}

	case Matches, NotMatches:
		s, ok := key.(string)
		matched := false
		if ok {
			for _, re := range c.regexes {
				if re.MatchString(s) {
					matched = true
					break
				}
			}
		}
		if c.op == Matches {
			return matched
		}
		return !matched
	}
	return false
}

func (c *Comparison) inSet(key any) bool {
	for _, p := range c.patterns {
		if p.match(key) {
			return true
		}
	}
	return false
}

// keyList normalizes the record-side key into a set: nil → empty,
// scalar → singleton, array → its elements.
func keyList(key any) []any {
	switch k := key.(type) {
	case nil:
		return nil
	case []any:
		return k
	case []string:
		out := make([]any, len(k))
		for i, s := range k {
			out[i] = s
		}
		return out
	default:
		return []any{key}
	}
}

func isScalar(v any) bool {
	switch v.(type) {
	case string, bool, int, int64, uint64, float64:
		return true
	}
	return false
}

func scalarList(op Operator, value any) ([]any, error) {
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s requires a list value, got %T", op, value)
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("%s requires a non-empty list", op)
	}
	for _, item := range items {
		if !isScalar(item) {
			return nil, fmt.Errorf("%s list items must be scalars, got %#v", op, item)
		}
	}
	return items, nil
}

// equalScalar compares exactly — no wildcards — with numeric cross-type
// coercion (YAML ints vs JSON float64s). nil equals nothing.
func equalScalar(key, value any) bool {
	if key == nil || value == nil {
		return false
	}
	if key == value {
		return true
	}
	kn, kok := toNumber(key)
	vn, vok := toNumber(value)
	return kok && vok && kn == vn
}

// toNumber coerces numeric types and numeric strings; bools are not numbers.
func toNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint64:
		return float64(n), true
	case float64:
		return n, true
	case string:
		f, err := strconv.ParseFloat(n, 64)
		return f, err == nil
	}
	return 0, false
}

// ---- wildcards ----

// wildcard is a set-membership pattern, pre-classified at compile time so the
// common no-wildcard case stays a plain comparison.
type wildcard struct {
	pattern string
	literal any  // non-string or wildcard-free values compare exactly
	glob    bool // pattern contains * or ?
}

func compileWildcard(item any) wildcard {
	s, ok := item.(string)
	if !ok || !strings.ContainsAny(s, "*?") {
		return wildcard{literal: item}
	}
	return wildcard{pattern: s, glob: true}
}

func (w wildcard) match(key any) bool {
	if !w.glob {
		return equalScalar(key, w.literal)
	}
	s, ok := key.(string)
	return ok && wildcardMatch(w.pattern, s)
}

// wildcardMatch reports whether s matches pattern, where * matches any
// (possibly empty) sequence and ? matches exactly one byte. Iterative
// backtracking: linear in practice for the short strings involved.
func wildcardMatch(pattern, s string) bool {
	pi, si := 0, 0
	star, starSi := -1, 0
	for si < len(s) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]):
			pi++
			si++
		case pi < len(pattern) && pattern[pi] == '*':
			star, starSi = pi, si
			pi++
		case star >= 0:
			starSi++
			pi, si = star+1, starSi
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}
