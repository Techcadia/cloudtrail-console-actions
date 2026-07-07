package event

import (
	"encoding/json"
	"strings"
	"testing"
)

const s3Records = `{"Records":[{"eventVersion":"2.1","eventSource":"aws:s3","awsRegion":"eu-west-1","eventTime":"2020-04-05T19:37:27.192Z","eventName":"ObjectCreated:Put","userIdentity":{"principalId":"AWS:AIDAINPONIXQXHT3IKHL2"},"requestParameters":{"sourceIPAddress":"205.255.255.255"},"responseElements":{"x-amz-request-id":"D82B88E5F771F645","x-amz-id-2":"vlR7PnpV2Ce81l0PRw6jlUpck7Jo5ZsQjryTjKlc5aLWGVHPZLj5NeC6qMa0emYBDXOo6QBU0Wo="},"s3":{"s3SchemaVersion":"1.0","configurationId":"828aa6fc-f7b5-4305-8584-487c791949c1","bucket":{"name":"lambda-artifacts-deafc19498e3f2df","ownerIdentity":{"principalId":"A3I5XTEXAMAI3E"},"arn":"arn:aws:s3:::lambda-artifacts-deafc19498e3f2df"},"object":{"key":"b21b84d653bb07b05b1e6b33684dc11b","size":1305107,"eTag":"b21b84d653bb07b05b1e6b33684dc11b","sequencer":"0C0F6F405D6ED209E1"}}}]}`

func TestUnmarshalS3Event(t *testing.T) {
	var e Event
	if err := json.Unmarshal([]byte(s3Records), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(e.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(e.Records))
	}
	r := e.Records[0]
	if r.S3.Bucket.Name != "lambda-artifacts-deafc19498e3f2df" {
		t.Errorf("bucket = %q", r.S3.Bucket.Name)
	}
	if r.S3.Object.Key != "b21b84d653bb07b05b1e6b33684dc11b" {
		t.Errorf("key = %q", r.S3.Object.Key)
	}
	if r.AWSRegion != "eu-west-1" {
		t.Errorf("region = %q", r.AWSRegion)
	}
}

func TestUnmarshalSNSEvent(t *testing.T) {
	message, _ := json.Marshal(s3Records)
	snsEvent := `{"Records":[{"EventVersion":"1.0","EventSource":"aws:sns","EventSubscriptionArn":"arn:aws:sns:us-east-2:123456789012:sns-lambda:sub","Sns":{"Type":"Notification","MessageId":"95df01b4-ee98-5cb9-9903-4c221d41eb5e","TopicArn":"arn:aws:sns:eu-west-2:123456789012:sns-lambda","Message":` + string(message) + `}}]}`

	var e Event
	if err := json.Unmarshal([]byte(snsEvent), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(e.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(e.Records))
	}
	r := e.Records[0]
	if r.S3.Bucket.Name != "lambda-artifacts-deafc19498e3f2df" {
		t.Errorf("bucket = %q", r.S3.Bucket.Name)
	}
	// Region comes from the topic ARN, not the inner S3 record.
	if r.AWSRegion != "eu-west-2" {
		t.Errorf("region = %q, want eu-west-2 (from topic arn)", r.AWSRegion)
	}
}

func TestUnmarshalSQSEvent(t *testing.T) {
	body, _ := json.Marshal(s3Records)
	sqsEvent := `{"Records":[{"messageId":"059f36b4-87a3-44ab-83d2-661975830a7d","eventSource":"aws:sqs","eventSourceARN":"arn:aws:sqs:eu-west-1:123456789012:my-queue","awsRegion":"eu-west-1","body":` + string(body) + `}]}`

	var e Event
	if err := json.Unmarshal([]byte(sqsEvent), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(e.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(e.Records))
	}
	if e.Records[0].S3.Bucket.Name != "lambda-artifacts-deafc19498e3f2df" {
		t.Errorf("bucket = %q", e.Records[0].S3.Bucket.Name)
	}
}

func TestUnmarshalErrors(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		wantErr string
	}{
		{"empty records", `{"Records":[]}`, "unrecognized"},
		{"no records key", `{}`, "unrecognized"},
		{"unknown source", `{"Records":[{"eventSource":"aws:kinesis"}]}`, "aws:kinesis"},
		{"sns without s3 records", `{"Records":[{"EventSource":"aws:sns","Sns":{"TopicArn":"arn:aws:sns:eu-west-2:1:t","Message":"{\"Records\":[]}"}}]}`, "no s3 records"},
		{"sqs with garbage body", `{"Records":[{"eventSource":"aws:sqs","body":"not-json"}]}`, "sqs body"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var e Event
			err := json.Unmarshal([]byte(tt.payload), &e)
			if err == nil {
				t.Fatalf("unmarshal succeeded, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not mention %q", err, tt.wantErr)
			}
		})
	}
}
