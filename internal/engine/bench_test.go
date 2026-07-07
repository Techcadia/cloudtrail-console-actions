package engine_test

import (
	"testing"
	"time"

	"github.com/Techcadia/cloudtrail-console-actions/internal/engine"
	"github.com/Techcadia/cloudtrail-console-actions/internal/policy"
)

// Benchmark records exercising the three characteristic paths.
var (
	// benchEmit runs the full rule ladder and the outputs projection.
	benchEmit = buildRecord(
		pair{"iam.amazonaws.com", "PutRolePolicy"},
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
		identities[0], extras[0], "")

	// benchDropEarly is caught by the first filter rule.
	benchDropEarly = buildRecord(
		pair{"ec2.amazonaws.com", "RunInstances"},
		"Coral/Netty4",
		identities[6], extras[0], "") // invokedBy: AWS Internal

	// benchDropLate walks every rule before the user-agent gate drops it.
	benchDropLate = buildRecord(
		pair{"ec2.amazonaws.com", "RunInstances"},
		"aws-cli/2.13.0 Python/3.11.4",
		identities[0], extras[0], "")
)

func benchEngine(b *testing.B) *engine.Engine {
	b.Helper()
	eng, err := engine.Compile(policy.Default())
	if err != nil {
		b.Fatal(err)
	}
	return eng
}

func BenchmarkCompile(b *testing.B) {
	p := policy.Default()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := engine.Compile(p); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEvaluateEmit(b *testing.B) {
	eng := benchEngine(b)
	b.ReportAllocs()
	for b.Loop() {
		if d := eng.Evaluate(benchEmit); !d.Emit {
			b.Fatalf("dropped by %s", d.DroppedBy)
		}
	}
}

func BenchmarkEvaluateDropEarly(b *testing.B) {
	eng := benchEngine(b)
	b.ReportAllocs()
	for b.Loop() {
		if d := eng.Evaluate(benchDropEarly); d.Emit {
			b.Fatal("emitted")
		}
	}
}

func BenchmarkEvaluateDropLate(b *testing.B) {
	eng := benchEngine(b)
	b.ReportAllocs()
	for b.Loop() {
		if d := eng.Evaluate(benchDropLate); d.Emit {
			b.Fatal("emitted")
		}
	}
}

func BenchmarkExplain(b *testing.B) {
	eng := benchEngine(b)
	b.ReportAllocs()
	for b.Loop() {
		eng.Explain(benchDropLate)
	}
}

// BenchmarkV1Reference is the ported v1 decision logic on the same record,
// for an apples-to-apples baseline.
func BenchmarkV1Reference(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if emit, _ := v1Decision(benchDropLate); emit {
			b.Fatal("emitted")
		}
	}
}

// TestPerformanceBudget is a coarse regression gate: a mixed batch the size
// of a large CloudTrail file must evaluate in a few milliseconds. The budget
// is 100x the expected cost so it only trips on order-of-magnitude
// regressions, not noisy CI.
func TestPerformanceBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	eng := compileDefault(t)

	records := []map[string]any{benchEmit, benchDropEarly, benchDropLate}
	const n = 10_000

	start := time.Now()
	for i := 0; i < n; i++ {
		eng.Evaluate(records[i%len(records)])
	}
	elapsed := time.Since(start)

	perRecord := elapsed / n
	t.Logf("evaluated %d records in %v (%v/record)", n, elapsed, perRecord)
	if budget := 100 * time.Microsecond; perRecord > budget {
		t.Errorf("evaluation cost %v/record exceeds budget %v", perRecord, budget)
	}
}

// TestAllocationBudget guards the per-record allocation count, which the
// time-based budget above (100x headroom) is far too coarse to catch. The
// emit path settles around ~11 allocs/op; a regression that reintroduces
// per-comparison ParseFloat or disabled-tracer boxing pushes it back toward
// the hundreds. The ceiling has ~3x headroom so it isn't noisy.
func TestAllocationBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	eng := compileDefault(t)

	for _, tc := range []struct {
		name    string
		record  map[string]any
		ceiling float64
	}{
		{"emit", benchEmit, 32},
		{"drop-early", benchDropEarly, 32},
		{"drop-late", benchDropLate, 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := testing.AllocsPerRun(200, func() { eng.Evaluate(tc.record) })
			if got > tc.ceiling {
				t.Errorf("%s: %.0f allocs/record exceeds ceiling %.0f", tc.name, got, tc.ceiling)
			}
		})
	}
}
