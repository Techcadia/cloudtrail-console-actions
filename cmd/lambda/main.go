// Command lambda is the CloudTrail Console Actions entrypoint: it filters
// CloudTrail log files through a declarative policy and alerts on the events
// a human performed.
//
// Configuration (flags beat env):
//
//	--config-file / CCA_POLICY_FILE   policy YAML overriding the embedded default
//	--dedupe      / CCA_DEDUPE        group identical events (default true)
//	--log-level   / LOG_LEVEL         debug logs explain every rule decision
//	--validate-only                   validate the policy and exit
//	--dump-default-policy             print the embedded policy and exit
//	SLACK_WEBHOOK, SLACK_CHANNEL, SLACK_NAME, SLACK_NAME_<accountId>
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/Techcadia/cloudtrail-console-actions/internal/app"
	"github.com/Techcadia/cloudtrail-console-actions/internal/collector"
	"github.com/Techcadia/cloudtrail-console-actions/internal/engine"
	"github.com/Techcadia/cloudtrail-console-actions/internal/notify"
	"github.com/Techcadia/cloudtrail-console-actions/internal/policy"
	"github.com/Techcadia/cloudtrail-console-actions/internal/trail"
)

// version is stamped at build time (make build sets -X main.version).
var version = "2.0.0-dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	opts, err := app.ParseOptions(os.Args[1:], os.LookupEnv)
	if err != nil {
		return err
	}

	if opts.DumpDefaultPolicy {
		_, err := os.Stdout.Write(policy.DefaultSource())
		return err
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: opts.LogLevel}))
	slog.SetDefault(logger)

	pol, source := policy.Default(), "embedded default"
	if opts.PolicyFile != "" {
		if pol, err = policy.LoadFile(opts.PolicyFile); err != nil {
			return err
		}
		source = opts.PolicyFile
	}
	eng, err := engine.Compile(pol)
	if err != nil {
		return fmt.Errorf("compiling policy (%s): %w", source, err)
	}

	if opts.ValidateOnly {
		fmt.Printf("policy %s is valid: %d filter, %d keep rules\n", source, len(pol.Filters), len(pol.Keep))
		return nil
	}

	ctx := context.Background()
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("loading AWS config: %w", err)
	}

	// One S3 client per log-file region, reused across invocations. A plain
	// map is enough: the Lambda runtime runs one invocation at a time per
	// process.
	clients := map[string]*s3.Client{}
	newObjectGetter := func(region string) trail.ObjectGetter {
		c, ok := clients[region]
		if !ok {
			c = s3.NewFromConfig(awsCfg, func(o *s3.Options) { o.Region = region })
			clients[region] = c
		}
		return c
	}

	a := &app.App{
		Engine:          eng,
		Logger:          logger,
		Dedupe:          opts.Dedupe,
		NewObjectGetter: newObjectGetter,
		Alert:           buildAlert(logger),
	}

	logger.Info("starting cloudtrail-console-actions",
		"version", version,
		"policy", source,
		"dedupe", opts.Dedupe,
		"filter_rules", len(pol.Filters),
		"keep_rules", len(pol.Keep),
	)
	lambda.Start(a.Handle)
	return nil
}

// buildAlert composes the sinks: the Event log line always, Slack when a
// webhook is configured. Slack failures are logged, not fatal — the log line
// has already preserved the event.
func buildAlert(logger *slog.Logger) func(context.Context, *collector.Group) {
	logSink := &notify.LogSink{Logger: logger}

	webhook, hasWebhook := os.LookupEnv("SLACK_WEBHOOK")
	var slack *notify.Slack
	if hasWebhook && webhook != "" {
		slack = &notify.Slack{
			WebhookURL: webhook,
			Channel:    os.Getenv("SLACK_CHANNEL"),
			HTTPClient: &http.Client{Timeout: 10 * time.Second},
			LookupEnv:  os.LookupEnv,
		}
	}

	return func(ctx context.Context, g *collector.Group) {
		logSink.Send(ctx, g)
		if slack == nil {
			return
		}
		if err := slack.Send(ctx, g); err != nil {
			logger.Error("sending slack notification",
				"error", err,
				"event_name", g.EventName,
				"user_name", g.UserName,
			)
		}
	}
}
