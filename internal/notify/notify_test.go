package notify

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"

	"github.com/Techcadia/cloudtrail-console-actions/internal/collector"
	"github.com/Techcadia/cloudtrail-console-actions/internal/event"
)

func group(count int) *collector.Group {
	t0 := time.Date(2026, 7, 7, 12, 0, 0, 0, time.UTC)
	return &collector.Group{
		Entry: collector.Entry{
			Record: map[string]any{
				"awsRegion": "us-west-2",
				"eventID":   "abc-123",
				"userIdentity": map[string]any{
					"accountId": "111111111111",
				},
			},
			Outputs: map[string]any{
				"event_source": "iam.amazonaws.com",
				"event_name":   "PutUserPolicy",
				"event_time":   "2026-07-07T12:00:00Z",
				"event_id":     "abc-123",
				"user_name":    `jane "the admin" doe`,
				"account_id":   "111111111111",
				"error_code":   "",
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
		"count":        float64(1),
		"s3_uri":       "s3://trail-bucket/AWSLogs/x.json.gz",
	} {
		if fields[k] != want {
			t.Errorf("%s = %#v, want %#v", k, fields[k], want)
		}
	}
}

func slackServer(t *testing.T, response string) (*httptest.Server, *[][]byte) {
	t.Helper()
	var bodies [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, body)
		io.WriteString(w, response)
	}))
	t.Cleanup(srv.Close)
	return srv, &bodies
}

func decodePayload(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("slack payload is not valid JSON: %v\n%s", err, body)
	}
	return payload
}

func TestSlackSingleEvent(t *testing.T) {
	srv, bodies := slackServer(t, "ok")
	s := &Slack{
		WebhookURL: srv.URL,
		Channel:    "#cloudtrail",
		HTTPClient: srv.Client(),
		LookupEnv:  func(string) (string, bool) { return "", false },
	}
	if err := s.Send(group(1)); err != nil {
		t.Fatalf("Send: %v", err)
	}

	payload := decodePayload(t, (*bodies)[0])
	if payload["channel"] != "#cloudtrail" {
		t.Errorf("channel = %v", payload["channel"])
	}
	text := payload["text"].(string)
	// Without SLACK_NAME* config the account id is the display name.
	if !strings.Contains(text, "111111111111") || !strings.Contains(text, "*PutUserPolicy*") {
		t.Errorf("text = %q", text)
	}
	raw := string((*bodies)[0])
	if !strings.Contains(raw, "EventId=abc-123") {
		t.Errorf("single event must deep-link by EventId:\n%s", raw)
	}
	if !strings.Contains(raw, "region=us-west-2") {
		t.Errorf("cloudwatch url must carry the record region:\n%s", raw)
	}
}

func TestSlackGroupedEvent(t *testing.T) {
	srv, bodies := slackServer(t, "ok")
	s := &Slack{
		WebhookURL: srv.URL,
		Channel:    "#cloudtrail",
		HTTPClient: srv.Client(),
		LookupEnv:  func(string) (string, bool) { return "", false },
	}
	if err := s.Send(group(3)); err != nil {
		t.Fatalf("Send: %v", err)
	}

	raw := string((*bodies)[0])
	payload := decodePayload(t, (*bodies)[0])
	if !strings.Contains(payload["text"].(string), "3x *PutUserPolicy*") {
		t.Errorf("grouped display missing count: %q", payload["text"])
	}
	if !strings.Contains(raw, "Username=") {
		t.Errorf("grouped event must link a Username search:\n%s", raw)
	}
	// Same-day window renders start ... short end time.
	if !strings.Contains(raw, "2026-07-07 12:00:00 ... 13:30:00") {
		t.Errorf("time window display wrong:\n%s", raw)
	}
}

func TestSlackNameLookup(t *testing.T) {
	srv, bodies := slackServer(t, "ok")
	env := map[string]string{
		"SLACK_NAME_111111111111": ":lock: security",
		"SLACK_NAME":              "default-name",
	}
	s := &Slack{
		WebhookURL: srv.URL,
		HTTPClient: srv.Client(),
		LookupEnv:  func(k string) (string, bool) { v, ok := env[k]; return v, ok },
	}
	if err := s.Send(group(1)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.Contains(string((*bodies)[0]), ":lock: security") {
		t.Errorf("account-specific SLACK_NAME_* not applied:\n%s", (*bodies)[0])
	}
}

func TestSlackNonOKResponse(t *testing.T) {
	srv, _ := slackServer(t, "invalid_payload")
	s := &Slack{
		WebhookURL: srv.URL,
		HTTPClient: srv.Client(),
		LookupEnv:  func(string) (string, bool) { return "", false },
	}
	err := s.Send(group(1))
	if err == nil || !strings.Contains(err.Error(), "invalid_payload") {
		t.Fatalf("err = %v, want non-ok response error", err)
	}
}

func TestSlackErrorCodeDisplay(t *testing.T) {
	srv, bodies := slackServer(t, "ok")
	s := &Slack{
		WebhookURL: srv.URL,
		HTTPClient: srv.Client(),
		LookupEnv:  func(string) (string, bool) { return "", false },
	}
	g := group(1)
	g.ErrorCode = "AccessDenied"
	if err := s.Send(g); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.Contains(string((*bodies)[0]), "`AccessDenied`") {
		t.Errorf("error code missing from section text:\n%s", (*bodies)[0])
	}
}
