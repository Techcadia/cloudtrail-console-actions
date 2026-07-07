package notify

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"

	"github.com/Techcadia/cloudtrail-console-actions/internal/collector"
	"github.com/Techcadia/cloudtrail-console-actions/internal/event"
)

// group builds an alert group shaped like the default policy's outputs.
func group(count int) *collector.Group {
	t0 := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	return &collector.Group{
		Entry: collector.Entry{
			Record: map[string]any{"eventID": "abc-123"},
			Outputs: map[string]any{
				"event_source":        "iam.amazonaws.com",
				"event_name":          "PutUserPolicy",
				"event_time":          "2026-07-07T12:00:00Z",
				"event_id":            "abc-123",
				"aws_region":          "us-west-2",
				"user_name":           `jane "the admin" doe`,
				"account_id":          "111111111111",
				"identity_account_id": "111111111111",
				"error_code":          "",
			},
			UserName:  `jane "the admin" doe`,
			EventName: "PutUserPolicy",
			Source: event.Record{
				S3: events.S3Entity{
					Bucket: events.S3Bucket{Name: "trail-bucket"},
					Object: events.S3Object{Key: "AWSLogs/x.json.gz"},
				},
			},
		},
		Count: count,
		First: t0,
		Last:  t0.Add(90 * time.Minute),
	}
}

func TestLogSinkEmitsEventRecord(t *testing.T) {
	var buf bytes.Buffer
	sink := &LogSink{Logger: slog.New(slog.NewJSONHandler(&buf, nil))}
	sink.Send(group(1))

	var fields map[string]any
	if err := json.Unmarshal(buf.Bytes(), &fields); err != nil {
		t.Fatalf("log line is not JSON: %v\n%s", err, buf.String())
	}
	if fields["msg"] != "Event" {
		t.Errorf(`msg = %v, want "Event" (CloudWatch queries filter on it)`, fields["msg"])
	}
	for k, want := range map[string]any{
		"event_source": "iam.amazonaws.com",
		"event_name":   "PutUserPolicy",
		"user_name":    `jane "the admin" doe`,
		"account_id":   "111111111111",
		"aws_region":   "us-west-2",
		"count":        float64(1),
		"s3_uri":       "s3://trail-bucket/AWSLogs/x.json.gz",
	} {
		if fields[k] != want {
			t.Errorf("%s = %#v, want %#v", k, fields[k], want)
		}
	}
}

// The log line must be a pure projection of the policy outputs: a custom
// policy with different fields logs exactly those fields.
func TestLogSinkFollowsCustomOutputs(t *testing.T) {
	var buf bytes.Buffer
	sink := &LogSink{Logger: slog.New(slog.NewJSONHandler(&buf, nil))}

	g := group(1)
	g.Outputs = map[string]any{"who": "jane", "did_what": "PutUserPolicy"}
	sink.Send(g)

	var fields map[string]any
	if err := json.Unmarshal(buf.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	if fields["who"] != "jane" || fields["did_what"] != "PutUserPolicy" {
		t.Errorf("custom outputs not logged: %v", fields)
	}
	if _, ok := fields["event_source"]; ok {
		t.Error("log line contains fields the policy did not project")
	}
}
