package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	if err := s.Send(context.Background(), group(1)); err != nil {
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
	if err := s.Send(context.Background(), group(3)); err != nil {
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

func TestSlackNameLookupUsesAccountOutput(t *testing.T) {
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
	// v0.4.0 keys the lookup on the recipient account, not the identity's.
	g := group(1)
	g.Outputs["account_id"] = "999999999999"
	g.Outputs["identity_account_id"] = "111111111111"
	if err := s.Send(context.Background(), g); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.Contains(string((*bodies)[0]), ":lock: security") {
		t.Errorf("SLACK_NAME_<account_id> not applied:\n%s", (*bodies)[0])
	}
}

func TestSlackNonOKResponse(t *testing.T) {
	srv, _ := slackServer(t, "invalid_payload")
	s := &Slack{
		WebhookURL: srv.URL,
		HTTPClient: srv.Client(),
		LookupEnv:  func(string) (string, bool) { return "", false },
	}
	err := s.Send(context.Background(), group(1))
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
	if err := s.Send(context.Background(), g); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.Contains(string((*bodies)[0]), "`AccessDenied`") {
		t.Errorf("error code missing from section text:\n%s", (*bodies)[0])
	}
}

func TestSlackEncodesURLParams(t *testing.T) {
	srv, bodies := slackServer(t, "ok")
	s := &Slack{
		WebhookURL: srv.URL,
		HTTPClient: srv.Client(),
		LookupEnv:  func(string) (string, bool) { return "", false },
	}
	// Assumed-role / SSO principals carry ':' and '@', which must be escaped
	// or the console deep link breaks.
	g := group(3)
	g.Outputs["user_name"] = "AROAEXAMPLE:jane@example.com"
	if err := s.Send(context.Background(), g); err != nil {
		t.Fatalf("Send: %v", err)
	}

	raw := string((*bodies)[0])
	if !strings.Contains(raw, "Username=AROAEXAMPLE%3Ajane%40example.com") {
		t.Errorf("username not URL-encoded in deep link:\n%s", raw)
	}
	if strings.Contains(raw, "Username=AROAEXAMPLE:jane@example.com") {
		t.Errorf("raw unescaped username leaked into deep link:\n%s", raw)
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
	if err := s.Send(context.Background(), g); err != nil {
		t.Fatalf("Send with empty outputs: %v", err)
	}
}

// The webhook URL is the credential: transport errors must not echo it into
// the logs.
func TestSlackErrorsOmitWebhookURL(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	webhook := srv.URL + "/services/T000/B000/SECRETTOKEN"
	srv.Close() // connection refused from here on

	s := &Slack{
		WebhookURL: webhook,
		HTTPClient: &http.Client{Timeout: time.Second},
		LookupEnv:  func(string) (string, bool) { return "", false },
	}
	err := s.Send(context.Background(), group(1))
	if err == nil {
		t.Fatal("Send to a closed server succeeded")
	}
	if strings.Contains(err.Error(), "SECRETTOKEN") {
		t.Errorf("error leaks the webhook URL: %v", err)
	}

	s.WebhookURL = "https://hooks.slack.com/services/SECRETTOKEN\x7f"
	if err := s.Send(context.Background(), group(1)); err == nil || strings.Contains(err.Error(), "SECRETTOKEN") {
		t.Errorf("invalid-URL error = %v, want one without the URL", err)
	}
}

func TestSlackRetriesRateLimit(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			io.WriteString(w, "rate_limited")
			return
		}
		io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)

	s := &Slack{
		WebhookURL: srv.URL,
		HTTPClient: srv.Client(),
		LookupEnv:  func(string) (string, bool) { return "", false },
	}
	if err := s.Send(context.Background(), group(1)); err != nil {
		t.Fatalf("Send after one 429: %v", err)
	}
	if calls != 2 {
		t.Errorf("calls = %d, want 2", calls)
	}
}

func TestSlackGivesUpAfterMaxAttempts(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	s := &Slack{
		WebhookURL: srv.URL,
		HTTPClient: srv.Client(),
		LookupEnv:  func(string) (string, bool) { return "", false },
	}
	if err := s.Send(context.Background(), group(1)); err == nil {
		t.Fatal("Send succeeded against a failing server")
	}
	if calls != maxAttempts {
		t.Errorf("calls = %d, want %d", calls, maxAttempts)
	}
}

func TestSlackEscapesMrkdwn(t *testing.T) {
	srv, bodies := slackServer(t, "ok")
	s := &Slack{
		WebhookURL: srv.URL,
		HTTPClient: srv.Client(),
		LookupEnv:  func(string) (string, bool) { return "", false },
	}
	g := group(1)
	g.Outputs["user_name"] = "<!channel> & <https://evil.example|click>"
	if err := s.Send(context.Background(), g); err != nil {
		t.Fatalf("Send: %v", err)
	}
	payload := decodePayload(t, (*bodies)[0])
	text := payload["text"].(string)
	if strings.Contains(text, "<!channel>") || !strings.Contains(text, "&lt;!channel&gt; &amp;") {
		t.Errorf("user name not mrkdwn-escaped: %q", text)
	}
}

// Same day-of-month in different months is not the same day.
func TestSlackTimeWindowAcrossMonths(t *testing.T) {
	srv, bodies := slackServer(t, "ok")
	s := &Slack{
		WebhookURL: srv.URL,
		HTTPClient: srv.Client(),
		LookupEnv:  func(string) (string, bool) { return "", false },
	}
	g := group(2)
	g.First = time.Date(2026, 1, 5, 23, 59, 0, 0, time.UTC)
	g.Last = time.Date(2026, 2, 5, 0, 1, 0, 0, time.UTC)
	if err := s.Send(context.Background(), g); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !strings.Contains(string((*bodies)[0]), "2026-01-05 23:59:00 ... 2026-02-05 00:01:00") {
		t.Errorf("cross-month window must show both dates:\n%s", (*bodies)[0])
	}
}
