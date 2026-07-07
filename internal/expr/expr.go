// Package expr compiles and evaluates the {{ ... }} template expressions used
// by FilterPolicy documents. The language is a small, JMESPath-shaped subset:
//
//	expr    := chain ("||" chain)*
//	chain   := head ("." ident | "[" int "]")*
//	head    := 'string' | true | false | null | func "(" expr ("," expr)* ")" | ident
//
// Supported functions: trimPrefix(s, prefix), contains(s, substr), split(s, sep).
//
// Evaluation is total: missing fields, type mismatches and out-of-range
// indexes yield nil rather than errors, and "a || b" returns b when a is
// falsy (nil, false, empty string, empty array/map). All syntax errors are
// reported at Compile time so the hot path never fails.
package expr

import (
	"fmt"
	"strings"
)

// Expr is a compiled template. A template is either a literal (no "{{") that
// evaluates to itself, or exactly one "{{ expression }}".
type Expr struct {
	src  string
	node node // nil for literal templates
}

// Compile parses a template string. It returns an error for any malformed
// expression, including text mixed with an expression.
func Compile(template string) (*Expr, error) {
	if !strings.Contains(template, "{{") {
		return &Expr{src: template}, nil
	}

	inner, ok := strings.CutPrefix(strings.TrimSpace(template), "{{")
	if !ok {
		return nil, fmt.Errorf("template %q: text and {{ }} may not be mixed", template)
	}
	inner, ok = strings.CutSuffix(inner, "}}")
	if !ok {
		return nil, fmt.Errorf("template %q: missing closing }}", template)
	}

	p := &parser{input: inner}
	n, err := p.parseExpr()
	if err != nil {
		return nil, fmt.Errorf("template %q: %w", template, err)
	}
	p.skipSpace()
	if p.pos != len(p.input) {
		return nil, fmt.Errorf("template %q: unexpected trailing input %q", template, p.input[p.pos:])
	}
	return &Expr{src: template, node: n}, nil
}

// MustCompile is Compile that panics on error, for statically known templates.
func MustCompile(template string) *Expr {
	e, err := Compile(template)
	if err != nil {
		panic(err)
	}
	return e
}

// Eval resolves the expression against scope. It never fails: unresolvable
// values evaluate to nil.
func (e *Expr) Eval(scope map[string]any) any {
	if e.node == nil {
		return e.src
	}
	return e.node.eval(scope)
}

// String returns the original template source, for use in debug logging.
func (e *Expr) String() string { return e.src }

// IsLiteral reports whether the template contains no expression at all.
func (e *Expr) IsLiteral() bool { return e.node == nil }

// falsy mirrors JMESPath truthiness: nil, false, empty string/array/map.
func falsy(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case bool:
		return !t
	case string:
		return t == ""
	case []any:
		return len(t) == 0
	case []string:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	default:
		return false
	}
}

// ---- AST ----

type node interface {
	eval(scope map[string]any) any
}

type orNode struct{ operands []node }

func (n *orNode) eval(scope map[string]any) any {
	var v any
	for _, op := range n.operands {
		v = op.eval(scope)
		if !falsy(v) {
			return v
		}
	}
	return v
}

type literalNode struct{ value any }

func (n *literalNode) eval(map[string]any) any { return n.value }

type identNode struct{ name string }

func (n *identNode) eval(scope map[string]any) any {
	return scope[n.name]
}

type fieldNode struct {
	base node
	name string
}

func (n *fieldNode) eval(scope map[string]any) any {
	m, _ := n.base.eval(scope).(map[string]any)
	if m == nil {
		return nil
	}
	return m[n.name]
}

type indexNode struct {
	base node
	idx  int
}

func (n *indexNode) eval(scope map[string]any) any {
	switch s := n.base.eval(scope).(type) {
	case []any:
		if n.idx >= 0 && n.idx < len(s) {
			return s[n.idx]
		}
	case []string:
		if n.idx >= 0 && n.idx < len(s) {
			return s[n.idx]
		}
	}
	return nil
}

type callNode struct {
	fn   string
	args []node
}

func (n *callNode) eval(scope map[string]any) any {
	// Arity is checked at compile time; every function takes (string, string).
	s, ok := n.args[0].eval(scope).(string)
	if !ok {
		return nil
	}
	arg, ok := n.args[1].eval(scope).(string)
	if !ok {
		return nil
	}
	switch n.fn {
	case "trimPrefix":
		return strings.TrimPrefix(s, arg)
	case "contains":
		return strings.Contains(s, arg)
	case "split":
		return strings.Split(s, arg)
	}
	return nil
}

// funcs maps supported function names to their arity.
var funcs = map[string]int{
	"trimPrefix": 2,
	"contains":   2,
	"split":      2,
}

// ---- parser ----

type parser struct {
	input string
	pos   int
}

func (p *parser) skipSpace() {
	for p.pos < len(p.input) && (p.input[p.pos] == ' ' || p.input[p.pos] == '\t') {
		p.pos++
	}
}

func (p *parser) peek() byte {
	if p.pos < len(p.input) {
		return p.input[p.pos]
	}
	return 0
}

func (p *parser) parseExpr() (node, error) {
	first, err := p.parseChain()
	if err != nil {
		return nil, err
	}
	operands := []node{first}
	for {
		p.skipSpace()
		if !strings.HasPrefix(p.input[p.pos:], "||") {
			break
		}
		p.pos += 2
		n, err := p.parseChain()
		if err != nil {
			return nil, err
		}
		operands = append(operands, n)
	}
	if len(operands) == 1 {
		return first, nil
	}
	return &orNode{operands: operands}, nil
}

func (p *parser) parseChain() (node, error) {
	n, err := p.parseHead()
	if err != nil {
		return nil, err
	}
	for {
		switch p.peek() {
		case '.':
			p.pos++
			name, err := p.parseIdent()
			if err != nil {
				return nil, err
			}
			n = &fieldNode{base: n, name: name}
		case '[':
			p.pos++
			idx, err := p.parseInt()
			if err != nil {
				return nil, err
			}
			if p.peek() != ']' {
				return nil, fmt.Errorf("expected ] at offset %d", p.pos)
			}
			p.pos++
			n = &indexNode{base: n, idx: idx}
		default:
			return n, nil
		}
	}
}

func (p *parser) parseHead() (node, error) {
	p.skipSpace()
	switch c := p.peek(); {
	case c == '\'':
		return p.parseString()
	case isIdentStart(c):
		name, err := p.parseIdent()
		if err != nil {
			return nil, err
		}
		switch name {
		case "true":
			return &literalNode{value: true}, nil
		case "false":
			return &literalNode{value: false}, nil
		case "null":
			return &literalNode{value: nil}, nil
		}
		if p.peek() == '(' {
			return p.parseCall(name)
		}
		return &identNode{name: name}, nil
	default:
		return nil, fmt.Errorf("unexpected character %q at offset %d", string(c), p.pos)
	}
}

func (p *parser) parseCall(name string) (node, error) {
	arity, ok := funcs[name]
	if !ok {
		return nil, fmt.Errorf("unknown function %q", name)
	}
	p.pos++ // consume '('
	var args []node
	for {
		arg, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		args = append(args, arg)
		p.skipSpace()
		switch p.peek() {
		case ',':
			p.pos++
		case ')':
			p.pos++
			if len(args) != arity {
				return nil, fmt.Errorf("%s takes %d arguments, got %d", name, arity, len(args))
			}
			return &callNode{fn: name, args: args}, nil
		default:
			return nil, fmt.Errorf("expected , or ) in %s(...) at offset %d", name, p.pos)
		}
	}
}

func (p *parser) parseString() (node, error) {
	start := p.pos
	p.pos++ // consume opening quote
	for p.pos < len(p.input) {
		if p.input[p.pos] == '\'' {
			s := p.input[start+1 : p.pos]
			p.pos++
			return &literalNode{value: s}, nil
		}
		p.pos++
	}
	return nil, fmt.Errorf("unterminated string literal at offset %d", start)
}

func (p *parser) parseIdent() (string, error) {
	start := p.pos
	if !isIdentStart(p.peek()) {
		return "", fmt.Errorf("expected identifier at offset %d", p.pos)
	}
	for p.pos < len(p.input) && isIdentPart(p.input[p.pos]) {
		p.pos++
	}
	return p.input[start:p.pos], nil
}

func (p *parser) parseInt() (int, error) {
	start := p.pos
	for p.pos < len(p.input) && p.input[p.pos] >= '0' && p.input[p.pos] <= '9' {
		p.pos++
	}
	if p.pos == start {
		return 0, fmt.Errorf("expected integer index at offset %d", p.pos)
	}
	n := 0
	for _, c := range p.input[start:p.pos] {
		n = n*10 + int(c-'0')
	}
	return n, nil
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}
