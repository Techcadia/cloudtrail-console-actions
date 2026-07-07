// Package notify delivers alerts for collected event groups: a structured
// "Event" log line for CloudWatch, and optionally a Slack message.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"time"

	"github.com/Techcadia/cloudtrail-console-actions/internal/collector"
)

// LogSink writes one structured "Event" line per group. Field names are the
// policy's outputs keys, so existing CloudWatch queries
// (filter msg == "Event") keep working.
type LogSink struct {
	Logger *slog.Logger
}

// Send logs the group's outputs plus count and s3_uri.
func (l *LogSink) Send(g *collector.Group) {
	attrs := make([]slog.Attr, 0, len(g.Outputs)+2)
	for _, k := range slices.Sorted(maps.Keys(g.Outputs)) {
		attrs = append(attrs, slog.Any(k, g.Outputs[k]))
	}
	attrs = append(attrs,
		slog.Int("count", g.Count),
		slog.String("s3_uri", s3URI(g)),
	)
	l.Logger.LogAttrs(context.Background(), slog.LevelInfo, "Event", attrs...)
}

func s3URI(g *collector.Group) string {
	return fmt.Sprintf("s3://%s/%s", g.Source.S3.Bucket.Name, g.Source.S3.Object.Key)
}

// Slack posts one message per group to an incoming webhook.
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
	Type     string  `json:"type"`
	Text     *mrkdwn `json:"text,omitempty"`
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
	eventName := fmt.Sprintf("*%s*", g.EventName)
	timeDisplay := g.First.Format("2006-01-02 15:04:05")
	url := fmt.Sprintf(
		"https://us-east-1.console.aws.amazon.com/cloudtrailv2/home?region=%v#/events?EventId=%v",
		g.Record["awsRegion"], g.Record["eventID"])

	if g.Count > 1 {
		eventName = fmt.Sprintf("%dx *%s*", g.Count, g.EventName)
		if g.First.Day() == g.Last.Day() {
			timeDisplay = fmt.Sprintf("%s ... %s", timeDisplay, g.Last.Format("15:04:05"))
		} else {
			timeDisplay = fmt.Sprintf("%s ... %s", timeDisplay, g.Last.Format("2006-01-02 15:04:05"))
		}
		url = fmt.Sprintf(
			"https://us-east-1.console.aws.amazon.com/cloudtrailv2/home?region=%v#/events?Username=%v&StartTime=%s&EndTime=%s",
			g.Record["awsRegion"], g.UserName,
			g.First.Format(time.RFC3339), g.Last.Format(time.RFC3339))
	}

	errorCode := ""
	if g.ErrorCode != "" {
		errorCode = fmt.Sprintf(" - `%s`", g.ErrorCode)
	}

	msg := payload{
		Channel: s.Channel,
		Text:    fmt.Sprintf("%s | %s | %s", name, eventName, g.UserName),
		Blocks: []block{
			{
				Type: "section",
				Text: &mrkdwn{
					Type: "mrkdwn",
					Text: fmt.Sprintf("%s - %v%s", eventName, g.Outputs["event_source"], errorCode),
				},
			},
			{
				Type: "context",
				Elements: []mrkdwn{
					{Type: "mrkdwn", Text: name},
					{Type: "mrkdwn", Text: g.UserName},
					{Type: "mrkdwn", Text: fmt.Sprintf("<%s|%s>", url, timeDisplay)},
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

// displayName resolves the account label: SLACK_NAME_<accountId> beats
// SLACK_NAME beats the raw account id from the outputs.
func (s *Slack) displayName(g *collector.Group) string {
	fallback := fmt.Sprintf("%v", g.Outputs["account_id"])
	identityAccount := ""
	if ui, ok := g.Record["userIdentity"].(map[string]any); ok {
		identityAccount, _ = ui["accountId"].(string)
	}
	if v, ok := s.LookupEnv("SLACK_NAME_" + identityAccount); ok && v != "" {
		return v
	}
	if v, ok := s.LookupEnv("SLACK_NAME"); ok && v != "" {
		return v
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
