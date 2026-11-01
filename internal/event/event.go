// Package event decodes the Lambda invocation envelope. CloudTrail delivery
// notifications arrive as S3 events directly, or wrapped in SNS or SQS; all
// three unwrap to the S3 objects to fetch.
package event

import (
	"cmp"
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

// ObjectKey is the S3 object key. S3 event notifications URL-encode keys
// (spaces as '+', '=' as %3D); this returns the decoded form, falling back
// to the raw key for hand-built events that lack it.
func (r Record) ObjectKey() string {
	if r.S3.Object.URLDecodedKey != "" {
		return r.S3.Object.URLDecodedKey
	}
	return r.S3.Object.Key
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
		s3Event, err := decodeS3Notification(snsRecord.SNS.Message)
		if err != nil {
			return fmt.Errorf("sns message: %w", err)
		}

		topicArn, err := arn.Parse(snsRecord.SNS.TopicArn)
		if err != nil {
			return fmt.Errorf("parsing sns topic arn %q: %w", snsRecord.SNS.TopicArn, err)
		}

		for _, s3Record := range s3Event.Records {
			event.Records = append(event.Records, Record{
				EventSource:    snsRecord.EventSource,
				EventSourceArn: snsRecord.SNS.TopicArn,
				AWSRegion:      cmp.Or(s3Record.AWSRegion, topicArn.Region),
				SNS:            snsRecord.SNS,
				S3:             s3Record.S3,
			})
		}
	}
	return nil
}

func (event *Event) mapSQSEventRecords(sqsEvent *events.SQSEvent) error {
	for _, sqsRecord := range sqsEvent.Records {
		s3Event, err := decodeS3Notification(sqsRecord.Body)
		if err != nil {
			return fmt.Errorf("sqs body: %w", err)
		}

		for _, s3Record := range s3Event.Records {
			event.Records = append(event.Records, Record{
				EventSource:    sqsRecord.EventSource,
				EventSourceArn: sqsRecord.EventSourceARN,
				AWSRegion:      cmp.Or(s3Record.AWSRegion, sqsRecord.AWSRegion),
				SQS:            sqsRecord,
				S3:             s3Record.S3,
			})
		}
	}
	return nil
}

// decodeS3Notification decodes an S3 event notification wrapped in an SNS
// message or SQS body. The s3:TestEvent S3 sends when a notification is
// first configured carries no records and decodes to an empty event rather
// than failing the batch it arrives in.
func decodeS3Notification(body string) (*events.S3Event, error) {
	var s3Event events.S3Event
	if err := json.Unmarshal([]byte(body), &s3Event); err != nil {
		return nil, fmt.Errorf("decoding as an s3 event: %w", err)
	}
	if len(s3Event.Records) > 0 {
		return &s3Event, nil
	}
	var probe struct {
		Event string `json:"Event"`
	}
	if json.Unmarshal([]byte(body), &probe) == nil && probe.Event == "s3:TestEvent" {
		return &s3Event, nil
	}
	return nil, fmt.Errorf("contains no s3 records")
}
