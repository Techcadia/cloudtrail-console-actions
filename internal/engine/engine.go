// Package engine compiles a FilterPolicy into an executable form and
// evaluates CloudTrail records against it.
//
// Evaluation per record:
//  1. preprocess fields are computed in document order into preprocess.*
//  2. the record is dropped when any skip rule applies (match ∧ ¬exclude)
//     and no keep rule matches — keep beats skip; the default is emit
//  3. outputs project an emitted record to the log/Slack schema
//
// Compile front-loads every failure mode (template syntax, operator/value
// shapes, regexes), so Evaluate is total and allocation-light. Explain runs
// the same decision with a human-readable account of why every rule matched,
// failed, or was carved out — the debug-logging path.
package engine

import (
	"fmt"
	"maps"
	"strings"

	"github.com/Techcadia/cloudtrail-console-actions/internal/expr"
	"github.com/Techcadia/cloudtrail-console-actions/internal/match"
	"github.com/Techcadia/cloudtrail-console-actions/internal/policy"
)

// Engine is a compiled FilterPolicy, safe for concurrent use.
type Engine struct {
	preprocess []field
	keep       []rule
	filters    []rule
	outputs    []field
}

// Decision is the outcome of evaluating one record.
type Decision struct {
	Emit       bool
	DroppedBy  string         // skip rule that dropped the record, when !Emit
	KeptBy     string         // keep rule that vetoed a skip, when applicable
	Preprocess map[string]any // computed working values (preprocess.*)
	Outputs    map[string]any // projection, only populated when Emit
}

type condition struct {
	key  *expr.Expr
	cmp  *match.Comparison
	repr string // "{{ key }} Operator value" for explanations
}

type conditions struct {
	any []condition
	all []condition
}

type rule struct {
	name    string
	match   conditions
	exclude *conditions
}

type fieldRule struct {
	when  *conditions
	value *expr.Expr
}

type field struct {
	name  string
	rules []fieldRule
}

// Compile validates and compiles every expression, operator and regex in the
// policy. A compiled engine can never fail at evaluation time.
func Compile(p *policy.Policy) (*Engine, error) {
	e := &Engine{}
	var err error

	if e.preprocess, err = compileFields("preprocess", p.Preprocess); err != nil {
		return nil, err
	}
	if e.outputs, err = compileFields("outputs", p.Outputs); err != nil {
		return nil, err
	}
	for _, k := range p.Keep {
		m, err := compileConditions(k.Match)
		if err != nil {
			return nil, fmt.Errorf("keep rule %q: match: %w", k.Name, err)
		}
		e.keep = append(e.keep, rule{name: k.Name, match: m})
	}
	for _, f := range p.Filters {
		r := rule{name: f.Name}
		if r.match, err = compileConditions(f.Match); err != nil {
			return nil, fmt.Errorf("filter rule %q: match: %w", f.Name, err)
		}
		if f.Exclude != nil {
			ex, err := compileConditions(*f.Exclude)
			if err != nil {
				return nil, fmt.Errorf("filter rule %q: exclude: %w", f.Name, err)
			}
			r.exclude = &ex
		}
		e.filters = append(e.filters, r)
	}
	return e, nil
}

func compileFields(section string, fields policy.Fields) ([]field, error) {
	out := make([]field, 0, len(fields))
	for _, f := range fields {
		cf := field{name: f.Name}
		for i, r := range f.Rules {
			fr := fieldRule{}
			var err error
			if fr.value, err = expr.Compile(r.Value); err != nil {
				return nil, fmt.Errorf("%s field %q rule %d: %w", section, f.Name, i, err)
			}
			if r.When != nil {
				when, err := compileConditions(*r.When)
				if err != nil {
					return nil, fmt.Errorf("%s field %q rule %d: when: %w", section, f.Name, i, err)
				}
				fr.when = &when
			}
			cf.rules = append(cf.rules, fr)
		}
		out = append(out, cf)
	}
	return out, nil
}

func compileConditions(c policy.Conditions) (conditions, error) {
	compileList := func(conds []policy.Condition) ([]condition, error) {
		out := make([]condition, 0, len(conds))
		for _, pc := range conds {
			key, err := expr.Compile(pc.Key)
			if err != nil {
				return nil, err
			}
			cmp, err := match.Compile(match.Operator(pc.Operator), pc.Value)
			if err != nil {
				return nil, fmt.Errorf("key %s: %w", pc.Key, err)
			}
			out = append(out, condition{
				key:  key,
				cmp:  cmp,
				repr: fmt.Sprintf("%s %s %v", pc.Key, pc.Operator, pc.Value),
			})
		}
		return out, nil
	}

	var out conditions
	var err error
	if out.any, err = compileList(c.Any); err != nil {
		return out, err
	}
	if out.all, err = compileList(c.All); err != nil {
		return out, err
	}
	return out, nil
}

// Evaluate decides one CloudTrail record. The input record is not mutated.
func (e *Engine) Evaluate(record map[string]any) Decision {
	return e.evaluate(record, nil)
}

// Explain evaluates like Evaluate and additionally returns one line per rule
// describing why it matched, failed, or was carved out. Intended for debug
// logging; it allocates freely.
func (e *Engine) Explain(record map[string]any) (Decision, []string) {
	tr := &tracer{}
	d := e.evaluate(record, tr)
	return d, tr.lines
}

func (e *Engine) evaluate(record map[string]any, tr *tracer) Decision {
	// The scope is a shallow clone so preprocess.* never leaks into the
	// caller's record.
	scope := maps.Clone(record)
	pp := make(map[string]any, len(e.preprocess))
	scope["preprocess"] = pp
	for i := range e.preprocess {
		f := &e.preprocess[i]
		pp[f.name] = f.eval(scope)
	}

	d := Decision{Preprocess: pp}

	// Skip rules combine as a union: the first applicable rule decides, but
	// under Explain every rule reports its outcome.
	for i := range e.filters {
		r := &e.filters[i]
		if d.DroppedBy != "" && tr == nil {
			break
		}
		matched, why := r.match.eval(scope, tr != nil)
		if !matched {
			tr.logf("skip rule %q did not match: %s", r.name, why)
			continue
		}
		if r.exclude != nil {
			if excluded, exWhy := r.exclude.eval(scope, tr != nil); excluded {
				tr.logf("skip rule %q matched (%s) but was carved out by exclude: %s", r.name, why, exWhy)
				continue
			}
		}
		tr.logf("skip rule %q matched: %s", r.name, why)
		if d.DroppedBy == "" {
			d.DroppedBy = r.name
		}
	}

	// A keep veto is only relevant when something would drop the record.
	if d.DroppedBy != "" {
		for i := range e.keep {
			r := &e.keep[i]
			matched, why := r.match.eval(scope, tr != nil)
			if matched {
				tr.logf("keep rule %q matched: %s — veto, record emitted despite %q", r.name, why, d.DroppedBy)
				d.KeptBy = r.name
				break
			}
			tr.logf("keep rule %q did not match: %s", r.name, why)
		}
	}

	d.Emit = d.DroppedBy == "" || d.KeptBy != ""
	if d.Emit {
		d.Outputs = make(map[string]any, len(e.outputs))
		for i := range e.outputs {
			f := &e.outputs[i]
			d.Outputs[f.name] = f.eval(scope)
		}
		tr.logf("decision: EMIT")
	} else {
		tr.logf("decision: DROP by rule %q", d.DroppedBy)
	}
	return d
}

// eval resolves a field: the first rule whose guard matches wins.
func (f *field) eval(scope map[string]any) any {
	for i := range f.rules {
		r := &f.rules[i]
		if r.when != nil {
			if matched, _ := r.when.eval(scope, false); !matched {
				continue
			}
		}
		return r.value.Eval(scope)
	}
	return nil
}

// eval reports whether the block matches: every all-condition and, when an
// any-block is present, at least one any-condition. With explain it also
// returns a human-readable reason.
func (c *conditions) eval(scope map[string]any, explain bool) (bool, string) {
	for i := range c.all {
		cond := &c.all[i]
		got := cond.key.Eval(scope)
		if !cond.cmp.Eval(got) {
			if explain {
				return false, fmt.Sprintf("condition [%s] not satisfied (got %s)", cond.repr, formatValue(got))
			}
			return false, ""
		}
	}
	anyOK := len(c.any) == 0
	for i := range c.any {
		cond := &c.any[i]
		if cond.cmp.Eval(cond.key.Eval(scope)) {
			anyOK = true
			break
		}
	}
	if !anyOK {
		if explain {
			reprs := make([]string, len(c.any))
			for i := range c.any {
				reprs[i] = c.any[i].repr
			}
			return false, fmt.Sprintf("no any-condition satisfied: [%s]", strings.Join(reprs, " | "))
		}
		return false, ""
	}
	if explain {
		return true, c.describeMatch(scope)
	}
	return true, ""
}

// describeMatch renders every satisfied condition with the value it saw.
func (c *conditions) describeMatch(scope map[string]any) string {
	var parts []string
	for i := range c.all {
		cond := &c.all[i]
		parts = append(parts, fmt.Sprintf("[%s] (got %s)", cond.repr, formatValue(cond.key.Eval(scope))))
	}
	for i := range c.any {
		cond := &c.any[i]
		if got := cond.key.Eval(scope); cond.cmp.Eval(got) {
			parts = append(parts, fmt.Sprintf("[%s] (got %s)", cond.repr, formatValue(got)))
		}
	}
	return strings.Join(parts, " and ")
}

func formatValue(v any) string {
	if v == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%#v", v)
}

// tracer accumulates explanation lines; a nil tracer discards everything.
type tracer struct {
	lines []string
}

func (t *tracer) logf(format string, args ...any) {
	if t == nil {
		return
	}
	t.lines = append(t.lines, fmt.Sprintf(format, args...))
}
