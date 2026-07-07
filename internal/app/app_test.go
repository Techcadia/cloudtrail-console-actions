package app

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/Techcadia/cloudtrail-console-actions/internal/collector"
	"github.com/Techcadia/cloudtrail-console-actions/internal/engine"
	"github.com/Techcadia/cloudtrail-console-actions/internal/event"
	"github.com/Techcadia/cloudtrail-console-actions/internal/policy"
	"github.com/Techcadia/cloudtrail-console-actions/internal/trail"
)

const logFileJSON = `{"Records":[
  {"eventSource":"iam.amazonaws.com","eventName":"PutUserPolicy","eventTime":"2026-07-07T12:00:00Z","eventID":"e1","awsRegion":"us-east-1","recipientAccountId":"111111111111","userAgent":"Mozilla/5.0","userIdentity":{"type":"IAMUser","principalId":"AIDAX","userName":"jane.doe","accountId":"111111111111"}},
  {"eventSource":"iam.amazonaws.com","eventName":"PutUserPolicy","eventTime":"2026-07-07T12:05:00Z","eventID":"e2","awsRegion":"us-east-1","recipientAccountId":"111111111111","userAgent":"Mozilla/5.0","userIdentity":{"type":"IAMUser","principalId":"AIDAX","userName":"jane.doe","accountId":"111111111111"}},
  {"eventSource":"s3.amazonaws.com","eventName":"GetObject","eventTime":"2026-07-07T12:06:00Z","eventID":"e3","awsRegion":"us-east-1","recipientAccountId":"111111111111","userAgent":"Mozilla/5.0","userIdentity":{"type":"IAMUser","principalId":"AIDAX","userName":"jane.doe","accountId":"111111111111"}}
]}`

type fakeGetter struct{ body []byte }

func (f *fakeGetter) GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(f.body))}, nil
}

func s3Event() event.Event {
	var ev event.Event
	payload := `{"Records":[{"eventSource":"aws:s3","awsRegion":"us-east-1","s3":{"bucket":{"name":"trail-bucket"},"object":{"key":"AWSLogs/111/CloudTrail/us-east-1/x.json.gz"}}}]}`
	if err := json.Unmarshal([]byte(payload), &ev); err != nil {
		panic(err)
	}
	return ev
}

func newTestApp(t *testing.T, logger *slog.Logger, dedupe bool, alerts *[]*collector.Group) *App {
	t.Helper()
	eng, err := engine.Compile(policy.Default())
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(logFileJSON)); err != nil {
		t.Fatal(err)
	}
	gz.Close()

	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &App{
		Engine: eng,
		Logger: logger,
		Dedupe: dedupe,
		NewObjectGetter: func(region string) trail.ObjectGetter {
			return &fakeGetter{body: buf.Bytes()}
		},
		Alert: func(g *collector.Group) { *alerts = append(*alerts, g) },
	}
}

func TestHandleDedupes(t *testing.T) {
	var alerts []*collector.Group
	a := newTestApp(t, nil, true, &alerts)

	if err := a.Handle(context.Background(), s3Event()); err != nil {
		t.Fatal(err)
	}
	// GetObject is dropped; the two PutUserPolicy records group into one.
	if len(alerts) != 1 {
		t.Fatalf("alerts = %d, want 1", len(alerts))
	}
	g := alerts[0]
	if g.Count != 2 || g.EventName != "PutUserPolicy" || g.UserName != "jane.doe" {
		t.Errorf("group = count %d, %s by %s", g.Count, g.EventName, g.UserName)
	}
	if g.First.IsZero() || g.Last.Before(g.First) {
		t.Errorf("window = %v..%v", g.First, g.Last)
	}
	if g.Outputs["account_id"] != "111111111111" {
		t.Errorf("outputs = %v", g.Outputs)
	}
}

func TestHandleDedupeDisabled(t *testing.T) {
	var alerts []*collector.Group
	a := newTestApp(t, nil, false, &alerts)

	if err := a.Handle(context.Background(), s3Event()); err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 2 {
		t.Fatalf("alerts = %d, want 2 (one per record)", len(alerts))
	}
}

func TestHandleDebugTracesDrops(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var alerts []*collector.Group
	a := newTestApp(t, logger, true, &alerts)
	if err := a.Handle(context.Background(), s3Event()); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	// The dropped GetObject record must say which rule dropped it and why.
	if !strings.Contains(out, "drop-read-prefixes-title") {
		t.Errorf("debug output does not name the dropping rule:\n%s", out)
	}
	if !strings.Contains(out, "GetObject") {
		t.Errorf("debug output does not identify the record:\n%s", out)
	}
	if !strings.Contains(out, "did not match") {
		t.Errorf("debug output does not explain skipped rules:\n%s", out)
	}
}

func TestHandleNoDebugCostWhenInfo(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	var alerts []*collector.Group
	a := newTestApp(t, logger, true, &alerts)
	if err := a.Handle(context.Background(), s3Event()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "drop-read-prefixes-title") {
		t.Error("trace lines leaked into info-level logs")
	}
}
