package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/Techcadia/cloudtrail-console-actions/v2/internal/collector"
	"github.com/Techcadia/cloudtrail-console-actions/v2/internal/engine"
	"github.com/Techcadia/cloudtrail-console-actions/v2/internal/event"
	"github.com/Techcadia/cloudtrail-console-actions/v2/internal/policy"
	"github.com/Techcadia/cloudtrail-console-actions/v2/internal/trail"
)

// App processes Lambda invocations: fetch each referenced CloudTrail file,
// run every record through the policy engine, collect the emitted ones, and
// flush alerts.
type App struct {
	Engine *engine.Engine
	Logger *slog.Logger
	Dedupe bool
	// NewObjectGetter returns an S3 client for the region a log file
	// lives in.
	NewObjectGetter func(region string) trail.ObjectGetter
	// Alert receives every flushed group, with the invocation's context so
	// sinks honour the Lambda deadline.
	Alert func(context.Context, *collector.Group)
}

// Alerts are grouped, timed and linked by these policy fields, so every
// policy must define them.
var (
	requiredPreprocess = []string{"eventName", "userName"}
	requiredOutputs    = []string{"account_id", "event_source", "error_code", "event_id", "event_time"}
)

// CheckPolicy reports the fields the alert pipeline reads that p does not
// define.
func CheckPolicy(p *policy.Policy) error {
	has := func(fields policy.Fields, name string) bool {
		return slices.ContainsFunc(fields, func(f policy.Field) bool { return f.Name == name })
	}
	var missing []string
	for _, name := range requiredPreprocess {
		if !has(p.Preprocess, name) {
			missing = append(missing, "preprocess."+name)
		}
	}
	for _, name := range requiredOutputs {
		if !has(p.Outputs, name) {
			missing = append(missing, "outputs."+name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("policy must define the fields alerts are grouped by: %s", strings.Join(missing, ", "))
	}
	return nil
}

// Handle is the Lambda entrypoint.
func (a *App) Handle(ctx context.Context, ev event.Event) error {
	col := collector.New(func(g *collector.Group) { a.Alert(ctx, g) }, a.Dedupe)
	for _, src := range ev.Records {
		if err := a.processObject(ctx, src, col); err != nil {
			return err
		}
	}
	col.Flush()
	return nil
}

func (a *App) processObject(ctx context.Context, src event.Record, col *collector.Collector) error {
	bucket, key := src.S3.Bucket.Name, src.ObjectKey()
	a.Logger.LogAttrs(ctx, slog.LevelDebug, "reading log file",
		slog.String("bucket", bucket), slog.String("key", key))

	file, err := trail.Fetch(ctx, a.NewObjectGetter(src.AWSRegion), bucket, key)
	if err != nil {
		// A poison object (not a CloudTrail log file) must not fail the whole
		// invocation, because async retries would reprocess it forever. Log and skip;
		// only genuine fetch errors (S3/network) propagate.
		if errors.Is(err, trail.ErrMalformed) {
			a.Logger.LogAttrs(ctx, slog.LevelError, "skipping unparseable object",
				slog.String("bucket", bucket), slog.String("key", key),
				slog.String("error", err.Error()))
			return nil
		}
		return err
	}
	if file == nil { // housekeeping object (digest/config)
		return nil
	}
	if file.Skipped > 0 {
		a.Logger.LogAttrs(ctx, slog.LevelError, "skipping undecodable records",
			slog.String("bucket", bucket), slog.String("key", key),
			slog.Int("skipped", file.Skipped))
	}

	debug := a.Logger.Enabled(ctx, slog.LevelDebug)
	for _, record := range file.Records {
		a.processRecord(ctx, record, src, col, debug)
	}
	return nil
}

func (a *App) processRecord(ctx context.Context, record map[string]any, src event.Record, col *collector.Collector, debug bool) {
	var d engine.Decision
	if debug {
		var lines []string
		d, lines = a.Engine.Explain(record)
		msg, rule := "record emitted", d.DroppedBy
		if !d.Emit {
			msg = "record dropped"
		}
		a.Logger.LogAttrs(ctx, slog.LevelDebug, msg,
			slog.Any("event_source", record["eventSource"]),
			slog.Any("event_name", record["eventName"]),
			slog.Any("event_id", record["eventID"]),
			slog.String("dropped_by", rule),
			slog.String("kept_by", d.KeptBy),
			slog.Any("trace", lines),
		)
	} else {
		d = a.Engine.Evaluate(record)
	}
	if !d.Emit {
		return
	}

	e := collector.Entry{
		Record:    record,
		Outputs:   d.Outputs,
		UserName:  collector.Text(d.Preprocess["userName"]),
		EventName: collector.Text(d.Preprocess["eventName"]),
		Source:    src,
	}
	e.AccountID = e.Output("account_id")
	e.EventSource = e.Output("event_source")
	e.ErrorCode = e.Output("error_code")
	e.EventID = e.Output("event_id")

	eventTime, err := time.Parse(time.RFC3339, e.Output("event_time"))
	if err != nil {
		a.Logger.LogAttrs(ctx, slog.LevelWarn, "unparseable event_time; using zero time",
			slog.String("event_id", e.EventID),
			slog.String("event_time", e.Output("event_time")))
	}
	e.Time = eventTime
	col.Add(e)
}
