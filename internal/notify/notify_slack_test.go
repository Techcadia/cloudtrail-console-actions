package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
	// aws_region comes from the outputs projection.
	if !strings.Contains(raw, "region=us-west-2") {
		t.Errorf("cloudwatch url must carry the aws_region output:\n%s", raw)
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

func TestSlackNameLookupUsesIdentityAccountOutput(t *testing.T) {
	srv, bodies := slackServer(t, "ok")
	env := map[string]string{
		"SLACK_NAME_999999999999": ":lock: security",
		"SLACK_NAME":              "default-name",
	}
	s := &Slack{
		WebhookURL: srv.URL,
		HTTPClient: srv.Client(),
		LookupEnv:  func(k string) (string, bool) { v, ok := env[k]; return v, ok },
	}
	g := group(1)
	g.Outputs["identity_account_id"] = "999999999999"
	if err := s.Send(g); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.Contains(string((*bodies)[0]), ":lock: security") {
		t.Errorf("SLACK_NAME_<identity_account_id> not applied:\n%s", (*bodies)[0])
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
	g.Outputs["error_code"] = "AccessDenied"
	if err := s.Send(g); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.Contains(string((*bodies)[0]), "`AccessDenied`") {
		t.Errorf("error code missing from section text:\n%s", (*bodies)[0])
	}
}

// Custom policies may omit slack-facing outputs; the sink degrades instead
// of panicking.
func TestSlackToleratesMissingOutputs(t *testing.T) {
	srv, _ := slackServer(t, "ok")
	s := &Slack{
		WebhookURL: srv.URL,
		HTTPClient: srv.Client(),
		LookupEnv:  func(string) (string, bool) { return "", false },
	}
	g := group(1)
	g.Outputs = map[string]any{}
	if err := s.Send(g); err != nil {
		t.Fatalf("Send with empty outputs: %v", err)
	}
}
