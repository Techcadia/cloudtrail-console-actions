package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/Techcadia/cloudtrail-console-actions/internal/collector"
	"github.com/Techcadia/cloudtrail-console-actions/internal/engine"
	"github.com/Techcadia/cloudtrail-console-actions/internal/event"
	"github.com/Techcadia/cloudtrail-console-actions/internal/trail"
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
		// invocation — async retries would reprocess it forever. Log and skip;
		// only genuine fetch errors (S3/network) propagate.
		if errors.Is(err, trail.ErrMalformed) {
			a.Logger.LogAttrs(ctx, slog.LevelWarn, "skipping unparseable object",
				slog.String("bucket", bucket), slog.String("key", key),
				slog.String("error", err.Error()))
			return nil
		}
		return err
	}
	if file == nil { // housekeeping object (digest/config)
		return nil
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

	eventTime, err := time.Parse(time.RFC3339, str(record["eventTime"]))
	if err != nil {
		a.Logger.LogAttrs(ctx, slog.LevelWarn, "unparseable eventTime; using zero time",
			slog.Any("event_id", record["eventID"]),
			slog.Any("event_time", record["eventTime"]))
	}
	errorCode, _ := record["errorCode"].(string)
	col.Add(collector.Entry{
		Record:      record,
		Outputs:     d.Outputs,
		AccountID:   strOr(d.Outputs["account_id"], record["recipientAccountId"]),
		EventSource: str(record["eventSource"]),
		UserName:    strOr(d.Preprocess["userName"], pathStr(record, "userIdentity", "principalId")),
		EventName:   strOr(d.Preprocess["eventName"], record["eventName"]),
		ErrorCode:   errorCode,
		EventID:     str(record["eventID"]),
		Time:        eventTime,
		Source:      src,
	})
}

// strOr stringifies the first non-nil, non-empty value — custom policies may
// omit the preprocess fields the collector groups by.
func strOr(v, fallback any) string {
	if s := str(v); s != "" {
		return s
	}
	return str(fallback)
}

func str(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func pathStr(record map[string]any, keys ...string) any {
	var v any = record
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}
