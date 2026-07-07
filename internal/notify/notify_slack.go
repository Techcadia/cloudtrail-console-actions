package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Techcadia/cloudtrail-console-actions/internal/collector"
)

// Slack posts one message per group to an incoming webhook.
//
// The message renders entirely from the policy's outputs: projection — the
// documented keys are event_source, user_name, account_id,
// identity_account_id, error_code, event_id and aws_region — plus the group
// metadata (count, time window, and the preprocess-derived user/event names
// used for grouping). Override those output fields in the policy to change
// what Slack shows.
type Slack struct {
	WebhookURL string
	Channel    string
	HTTPClient *http.Client
	// LookupEnv resolves SLACK_NAME / SLACK_NAME_<accountId>; injectable
	// for tests. Typically os.LookupEnv.
	LookupEnv func(string) (string, bool)
}

type payload struct {
	Channel string  `json:"channel"`
	Text    string  `json:"text"`
	Blocks  []block `json:"blocks"`
}

type block struct {
	Type     string   `json:"type"`
	Text     *mrkdwn  `json:"text,omitempty"`
	Elements []mrkdwn `json:"elements,omitempty"`
}

type mrkdwn struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Send builds and posts the Slack message. The payload is marshalled, not
// string-interpolated, so user-controlled values (userName, error codes)
// cannot break the JSON.
func (s *Slack) Send(g *collector.Group) error {
	name := s.displayName(g)
	userName := outputStr(g, "user_name", g.UserName)
	eventName := fmt.Sprintf("*%s*", g.EventName)
	timeDisplay := g.First.Format("2006-01-02 15:04:05")
	region := url.QueryEscape(outputStr(g, "aws_region", ""))
	// userName and the timestamps carry ':' '@' '+' and spaces (assumed-role
	// and SSO principals especially), which must be escaped or the console
	// deep link breaks.
	link := fmt.Sprintf(
		"https://us-east-1.console.aws.amazon.com/cloudtrailv2/home?region=%s#/events?EventId=%s",
		region, url.QueryEscape(outputStr(g, "event_id", "")))

	if g.Count > 1 {
		eventName = fmt.Sprintf("%dx *%s*", g.Count, g.EventName)
		if g.First.Day() == g.Last.Day() {
			timeDisplay = fmt.Sprintf("%s ... %s", timeDisplay, g.Last.Format("15:04:05"))
		} else {
			timeDisplay = fmt.Sprintf("%s ... %s", timeDisplay, g.Last.Format("2006-01-02 15:04:05"))
		}
		link = fmt.Sprintf(
			"https://us-east-1.console.aws.amazon.com/cloudtrailv2/home?region=%s#/events?Username=%s&StartTime=%s&EndTime=%s",
			region, url.QueryEscape(userName),
			url.QueryEscape(g.First.Format(time.RFC3339)), url.QueryEscape(g.Last.Format(time.RFC3339)))
	}

	errorCode := ""
	if ec := outputStr(g, "error_code", ""); ec != "" {
		errorCode = fmt.Sprintf(" - `%s`", ec)
	}

	msg := payload{
		Channel: s.Channel,
		Text:    fmt.Sprintf("%s | %s | %s", name, eventName, userName),
		Blocks: []block{
			{
				Type: "section",
				Text: &mrkdwn{
					Type: "mrkdwn",
					Text: fmt.Sprintf("%s - %s%s", eventName, outputStr(g, "event_source", ""), errorCode),
				},
			},
			{
				Type: "context",
				Elements: []mrkdwn{
					{Type: "mrkdwn", Text: name},
					{Type: "mrkdwn", Text: userName},
					{Type: "mrkdwn", Text: fmt.Sprintf("<%s|%s>", link, timeDisplay)},
				},
			},
		},
	}

	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshalling slack payload: %w", err)
	}
	return s.post(body)
}

// displayName resolves the account label: SLACK_NAME_<identity_account_id>
// beats SLACK_NAME beats the account_id output.
func (s *Slack) displayName(g *collector.Group) string {
	if v, ok := s.LookupEnv("SLACK_NAME_" + outputStr(g, "identity_account_id", "")); ok && v != "" {
		return v
	}
	if v, ok := s.LookupEnv("SLACK_NAME"); ok && v != "" {
		return v
	}
	return outputStr(g, "account_id", "")
}

// outputStr reads one projection field, tolerating custom policies that omit
// it.
func outputStr(g *collector.Group, key, fallback string) string {
	if v, ok := g.Outputs[key]; ok && v != nil {
		return fmt.Sprintf("%v", v)
	}
	return fallback
}

func (s *Slack) post(body []byte) error {
	req, err := http.NewRequest(http.MethodPost, s.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	reply, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return err
	}
	if string(reply) != "ok" {
		return fmt.Errorf("non-ok response from Slack: %s", reply)
	}
	return nil
}
