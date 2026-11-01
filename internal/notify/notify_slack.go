package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Techcadia/cloudtrail-console-actions/internal/collector"
)

// Slack posts one message per group to an incoming webhook.
//
// The message renders from the policy's outputs: projection (the keys read
// are event_source, user_name, account_id, error_code, event_id and
// aws_region) plus the group metadata: count, time window, and the
// preprocess-derived event name used for grouping (preprocess.eventName, not
// the event_name output). Override those output fields in the policy to
// change what Slack shows.
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
// cannot break the JSON, and record-derived text is mrkdwn-escaped so it
// cannot inject links or mentions. ctx bounds the post and any retries.
func (s *Slack) Send(ctx context.Context, g *collector.Group) error {
	name := s.displayName(g)
	userName := outputStr(g, "user_name", g.UserName)
	eventName := fmt.Sprintf("*%s*", escapeMrkdwn(g.EventName))
	timeDisplay := g.First.Format("2006-01-02 15:04:05")
	region := url.QueryEscape(outputStr(g, "aws_region", ""))
	// userName and the timestamps carry ':' '@' '+' and spaces (assumed-role
	// and SSO principals especially), which must be escaped or the console
	// deep link breaks.
	link := fmt.Sprintf(
		"https://us-east-1.console.aws.amazon.com/cloudtrailv2/home?region=%s#/events?EventId=%s",
		region, url.QueryEscape(outputStr(g, "event_id", "")))

	if g.Count > 1 {
		eventName = fmt.Sprintf("%dx *%s*", g.Count, escapeMrkdwn(g.EventName))
		if g.First.Format(time.DateOnly) == g.Last.Format(time.DateOnly) {
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
		errorCode = fmt.Sprintf(" - `%s`", escapeMrkdwn(ec))
	}

	msg := payload{
		Channel: s.Channel,
		Text:    fmt.Sprintf("%s | %s | %s", name, eventName, escapeMrkdwn(userName)),
		Blocks: []block{
			{
				Type: "section",
				Text: &mrkdwn{
					Type: "mrkdwn",
					Text: fmt.Sprintf("%s - %s%s", eventName, escapeMrkdwn(outputStr(g, "event_source", "")), errorCode),
				},
			},
			{
				Type: "context",
				Elements: []mrkdwn{
					{Type: "mrkdwn", Text: name},
					{Type: "mrkdwn", Text: escapeMrkdwn(userName)},
					{Type: "mrkdwn", Text: fmt.Sprintf("<%s|%s>", link, timeDisplay)},
				},
			},
		},
	}

	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshalling slack payload: %w", err)
	}
	return s.post(ctx, body)
}

// displayName resolves the account label: SLACK_NAME_<account_id> beats
// SLACK_NAME beats the account_id output itself. Keying on account_id (the
// recipient account) matches v1 v0.4.0.
func (s *Slack) displayName(g *collector.Group) string {
	if v, ok := s.LookupEnv("SLACK_NAME_" + outputStr(g, "account_id", "")); ok && v != "" {
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

// mrkdwnEscaper escapes the three characters Slack's mrkdwn treats as
// control syntax (links, mentions); everything else renders literally.
var mrkdwnEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

func escapeMrkdwn(s string) string { return mrkdwnEscaper.Replace(s) }

// maxAttempts bounds delivery: Slack webhooks rate-limit at roughly one
// message per second, so a burst of groups can hit 429s.
const maxAttempts = 3

// maxRetryWait caps a server-requested Retry-After so one message cannot
// consume the invocation's whole timeout.
const maxRetryWait = 5 * time.Second

// errRetryable marks a response worth retrying (429 or 5xx).
var errRetryable = errors.New("retryable slack response")

func (s *Slack) post(ctx context.Context, body []byte) error {
	var err error
	for attempt := 1; ; attempt++ {
		var wait time.Duration
		wait, err = s.postOnce(ctx, body)
		if !errors.Is(err, errRetryable) || attempt == maxAttempts {
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w (giving up: %w)", err, ctx.Err())
		case <-time.After(wait):
		}
	}
}

// postOnce sends one request. On a retryable response it also returns how
// long to wait before the next attempt.
func (s *Slack) postOnce(ctx context.Context, body []byte) (time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.WebhookURL, bytes.NewReader(body))
	if err != nil {
		// The parse error quotes the URL, and the webhook URL is the secret.
		return 0, errors.New("building slack request: invalid SLACK_WEBHOOK URL")
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		// *url.Error embeds the full request URL; log only the cause so the
		// webhook credential never reaches CloudWatch.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return 0, fmt.Errorf("posting to slack webhook: %w", err)
	}
	defer resp.Body.Close()

	reply, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return 0, fmt.Errorf("reading slack response: %w", err)
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return retryAfter(resp.Header.Get("Retry-After")),
			fmt.Errorf("%w: HTTP %d: %s", errRetryable, resp.StatusCode, reply)
	}
	if string(reply) != "ok" {
		return 0, fmt.Errorf("non-ok response from Slack: %s", reply)
	}
	return 0, nil
}

// retryAfter parses a Retry-After header in seconds, defaulting to one
// second and capping at maxRetryWait.
func retryAfter(header string) time.Duration {
	wait := time.Second
	if secs, err := strconv.Atoi(header); err == nil && secs >= 0 {
		wait = time.Duration(secs) * time.Second
	}
	return min(wait, maxRetryWait)
}
