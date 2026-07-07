// Package event decodes the Lambda invocation envelope. CloudTrail delivery
// notifications arrive as S3 events directly, or wrapped in SNS or SQS; all
// three unwrap to the S3 objects to fetch.
package event

import (
	"encoding/json"
	"fmt"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

// Event is the normalized invocation payload.
type Event struct {
	Records []Record
}

// Record points at one CloudTrail log object in S3, retaining the transport
// entities for diagnostics.
type Record struct {
	EventSource    string
	EventSourceArn string
	AWSRegion      string
	S3             events.S3Entity
	SQS            events.SQSMessage
	SNS            events.SNSEntity
}

// UnmarshalJSON sniffs the envelope type from the first record's eventSource
// and decodes accordingly.
func (event *Event) UnmarshalJSON(data []byte) error {
	switch source := sniffEventSource(data); source {
	case "aws:s3":
		var s3Event events.S3Event
		if err := json.Unmarshal(data, &s3Event); err != nil {
			return fmt.Errorf("decoding s3 event: %w", err)
		}
		return event.mapS3EventRecords(&s3Event)

	case "aws:sns":
		var snsEvent events.SNSEvent
		if err := json.Unmarshal(data, &snsEvent); err != nil {
			return fmt.Errorf("decoding sns event: %w", err)
		}
		return event.mapSNSEventRecords(&snsEvent)

	case "aws:sqs":
		var sqsEvent events.SQSEvent
		if err := json.Unmarshal(data, &sqsEvent); err != nil {
			return fmt.Errorf("decoding sqs event: %w", err)
		}
		return event.mapSQSEventRecords(&sqsEvent)

	default:
		return fmt.Errorf("unrecognized event envelope (eventSource %q)", source)
	}
}

// sniffEventSource peeks at Records[0].{EventSource,eventSource} without
// committing to a full envelope shape.
func sniffEventSource(data []byte) string {
	var probe struct {
		Records []struct {
			EventSourceUpper string `json:"EventSource"`
			EventSourceLower string `json:"eventSource"`
		} `json:"Records"`
	}
	if err := json.Unmarshal(data, &probe); err != nil || len(probe.Records) == 0 {
		return ""
	}
	if probe.Records[0].EventSourceUpper != "" {
		return probe.Records[0].EventSourceUpper
	}
	return probe.Records[0].EventSourceLower
}

func (event *Event) mapS3EventRecords(s3Event *events.S3Event) error {
	for _, s3Record := range s3Event.Records {
		event.Records = append(event.Records, Record{
			EventSource:    s3Record.EventSource,
			EventSourceArn: s3Record.S3.Bucket.Arn,
			AWSRegion:      s3Record.AWSRegion,
			S3:             s3Record.S3,
		})
	}
	return nil
}

func (event *Event) mapSNSEventRecords(snsEvent *events.SNSEvent) error {
	for _, snsRecord := range snsEvent.Records {
		var s3Event events.S3Event
		if err := json.Unmarshal([]byte(snsRecord.SNS.Message), &s3Event); err != nil {
			return fmt.Errorf("decoding sns message as an s3 event: %w", err)
		}
		if len(s3Event.Records) == 0 {
			return fmt.Errorf("sns message contains no s3 records")
		}

		topicArn, err := arn.Parse(snsRecord.SNS.TopicArn)
		if err != nil {
			return fmt.Errorf("parsing sns topic arn %q: %w", snsRecord.SNS.TopicArn, err)
		}

		for _, s3Record := range s3Event.Records {
			event.Records = append(event.Records, Record{
				EventSource:    snsRecord.EventSource,
				EventSourceArn: snsRecord.SNS.TopicArn,
				AWSRegion:      topicArn.Region,
				SNS:            snsRecord.SNS,
				S3:             s3Record.S3,
			})
		}
	}
	return nil
}

func (event *Event) mapSQSEventRecords(sqsEvent *events.SQSEvent) error {
	for _, sqsRecord := range sqsEvent.Records {
		var s3Event events.S3Event
		if err := json.Unmarshal([]byte(sqsRecord.Body), &s3Event); err != nil {
			return fmt.Errorf("decoding sqs body as an s3 event: %w", err)
		}
		if len(s3Event.Records) == 0 {
			return fmt.Errorf("sqs body contains no s3 records")
		}

		for _, s3Record := range s3Event.Records {
			event.Records = append(event.Records, Record{
				EventSource:    sqsRecord.EventSource,
				EventSourceArn: sqsRecord.EventSourceARN,
				AWSRegion:      sqsRecord.AWSRegion,
				SQS:            sqsRecord,
				S3:             s3Record.S3,
			})
		}
	}
	return nil
}
