// Package notify delivers alerts for collected event groups: a structured
// "Event" log line for CloudWatch, and optionally a Slack message. Both
// sinks render from the policy's outputs: projection, so what notifications
// contain is controlled by the config, not this code.
package notify

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"

	"github.com/Techcadia/cloudtrail-console-actions/internal/collector"
)

// LogSink writes one structured "Event" line per group. The fields are
// exactly the policy's outputs keys (add or change fields in the policy's
// outputs: section), plus count and s3_uri. Existing CloudWatch queries
// (filter msg == "Event") keep working.
type LogSink struct {
	Logger *slog.Logger
}

// Send logs the group's outputs plus count and s3_uri.
func (l *LogSink) Send(ctx context.Context, g *collector.Group) {
	attrs := make([]slog.Attr, 0, len(g.Outputs)+2)
	for _, k := range slices.Sorted(maps.Keys(g.Outputs)) {
		attrs = append(attrs, slog.Any(k, g.Outputs[k]))
	}
	attrs = append(attrs,
		slog.Int("count", g.Count),
		slog.String("s3_uri", s3URI(g)),
	)
	l.Logger.LogAttrs(ctx, slog.LevelInfo, "Event", attrs...)
}

func s3URI(g *collector.Group) string {
	return fmt.Sprintf("s3://%s/%s", g.Source.S3.Bucket.Name, g.Source.ObjectKey())
}
