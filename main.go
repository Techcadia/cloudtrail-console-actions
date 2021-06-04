package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	log "github.com/sirupsen/logrus"
)

type CloudTrailFile struct {
	Records []map[string]interface{} `json:"Records"`
}

func init() {
}

func main() {
	log.SetFormatter(&log.JSONFormatter{})
	log.Info("Starting v0.1.4")
	lambda.Start(S3Handler)
}

func S3Handler(ctx context.Context, s3Event events.S3Event) error {
	log.Infof("S3 event: %v", s3Event)

	for _, s3Record := range s3Event.Records {
		err := Stream(
			s3Record.AWSRegion,
			s3Record.S3.Bucket.Name,
			s3Record.S3.Object.Key,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

func FilterRecords(logFile *CloudTrailFile) error {
	for _, record := range logFile.Records {
		userIdentity, _ := record["userIdentity"].(map[string]interface{})

		if userIdentity["invokedBy"] == "AWS Internal" {
			continue
		}

		switch en := record["eventName"].(string); {
		// Some events don't match AWS defined standards
		// So we have to convert the input to Title
		case strings.HasPrefix(strings.Title(en), "Get"):
			continue
		// Some events don't match AWS defined standards
		// So we have to convert the input to Title
		case strings.HasPrefix(strings.Title(en), "List"):
			continue
		case strings.HasPrefix(en, "Head"):
			continue
		case strings.HasPrefix(en, "Describe"):
			continue
		case strings.HasPrefix(en, "Test"):
			continue
		case strings.HasPrefix(en, "Download"):
			continue
		case en == "ConsoleLogin":
			continue
		case strings.HasSuffix(en, "VirtualMFADevice"):
			continue
		case en == "CheckMfa":
			continue
		case en == "CheckDomainAvailability":
			continue
		case en == "LookupEvents":
			continue
		case en == "listDnssec":
			continue
		case en == "Decrypt":
			continue
		case en == "BatchGetQueryExecution":
			continue
		case en == "QueryObjects":
			continue
		case strings.HasPrefix(en, "StartQuery"):
			continue
		case strings.HasPrefix(en, "StopQuery"):
			continue
		case strings.HasPrefix(en, "CancelQuery"):
			continue
		case strings.HasPrefix(en, "BatchGet"):
			continue
		case strings.HasPrefix(en, "Search"):
			continue
		case en == "GenerateServiceLastAccessedDetails":
			continue
		case en == "REST.GET.OBJECT_LOCK_CONFIGURATION":
			continue
		case en == "AssumeRoleWithWebIdentity":
			continue
		case en == "PutQueryDefinition":
			if record["eventSource"] == "logs.amazonaws.com" {
				continue
			}
		case en == "AssumeRole":
			if record["userAgent"] == "Coral/Netty4" {
				switch userIdentity["invokedBy"] {
				case
					"ecs-tasks.amazonaws.com",
					"ec2.amazonaws.com",
					"monitoring.rds.amazonaws.com",
					"lambda.amazonaws.com":
					continue
				}
			}
		}

		if usa, ok := record["userAgent"]; ok {
			switch ua := usa.(string); {
			case ua == "console.amazonaws.com":
				break
			case ua == "signin.amazonaws.com":
				break
			case ua == "Coral/Jakarta":
				break
			case ua == "Coral/Netty4":
				break
			case ua == "AWS CloudWatch Console":
				break
			case strings.HasPrefix(ua, "S3Console/"):
				break
			case strings.HasPrefix(ua, "[S3Console"):
				break
			case strings.HasPrefix(ua, "Mozilla/"):
				break
			case matchString("console.*.amazonaws.com", ua):
				break
			case matchString("signin.*.amazonaws.com", ua):
				break
			case matchString("aws-internal*", ua):
				break
			default:
				continue
			}
		}

		userName := fmt.Sprintf("%s", userIdentity["principalId"])
		if strings.Contains(userName, ":") {
			userName = strings.Split(userName, ":")[1]
		}
		if userIdentity["userName"] != nil {
			userName = fmt.Sprintf("%s", userIdentity["userName"])
		}

		log.WithFields(log.Fields{
			"user_agent":   record["userAgent"],
			"event_time":   record["eventTime"],
			"principal":    userIdentity["principalId"],
			"user_name":    userName,
			"event_source": record["eventSource"],
			"event_name":   record["eventName"],
			"account_id":   userIdentity["accountId"],
			"event_id":     record["eventID"],
		}).Info("Event")

		if webhookUrl, ok := os.LookupEnv("SLACK_WEBHOOK"); ok {
			slackBody := fmt.Sprintf(`
{
  "channel": "%s",
  "text": "Not Used",
  "blocks": [
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*%s* - %s"
      }
    },
    {
      "type": "context",
      "elements": [
        {
          "type": "mrkdwn",
          "text": "%s"
        },
        {
          "type": "mrkdwn",
          "text": "%s"
        },
        {
          "type": "mrkdwn",
          "text": "<https://console.aws.amazon.com/cloudtrail/home?region=%s#/events?EventId=%s|%s>"
        }
      ]
    }
  ]
}
`,
				os.Getenv("SLACK_CHANNEL"),
				record["eventName"],
				record["eventSource"],
				getEnv(
					fmt.Sprintf("SLACK_NAME_%s", userIdentity["accountId"]),
					getEnv("SLACK_NAME", fmt.Sprintf("%s", userIdentity["accountId"]))),
				userName,
				record["awsRegion"],
				record["eventID"],
				record["eventTime"])

			err := SendSlackNotification(webhookUrl, []byte(slackBody))
			if err != nil {
				log.Debugln(slackBody)
				log.Debug(err)
			}
		}
	}
	// log.Infof("Scanned %d records", len(logFile.Records))
	return nil
}

func Stream(awsRegion string, bucket string, objectKey string) error {
	s3ClientConfig := aws.NewConfig().WithRegion(awsRegion)
	s3Client := s3.New(session.Must(session.NewSession()), s3ClientConfig)

	log.Debugf("Reading %s from %s with client config of %+v", objectKey, bucket, s3Client.Config)

	object, err := fetchLogFromS3(s3Client, bucket, objectKey)
	if err != nil {
		return fmt.Errorf("%v: %v", objectKey, err)
	}
	if object == nil {
		return nil
	}

	logFile, err := readLogFile(object)
	if err != nil {
		return fmt.Errorf("%v: %v", objectKey, err)
	}

	err = FilterRecords(logFile)
	if err != nil {
		return fmt.Errorf("%v: %v", objectKey, err)
	}

	return nil
}

func fetchLogFromS3(s3Client *s3.S3, bucket string, objectKey string) (*s3.GetObjectOutput, error) {
	logInput := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectKey),
	}

	if strings.Contains(objectKey, "/CloudTrail-Digest/") || strings.Contains(objectKey, "/Config/") {
		return nil, nil
	}

	object, err := s3Client.GetObject(logInput)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			return nil, fmt.Errorf("AWS Error: %v", aerr)
		}
		return nil, fmt.Errorf("Error getting S3 Object: %v", err)
	}

	return object, nil
}

func readLogFile(object *s3.GetObjectOutput) (*CloudTrailFile, error) {
	defer object.Body.Close()

	var logFileBlob io.ReadCloser
	var err error
	if object.ContentType != nil && *object.ContentType == "application/x-gzip" {
		logFileBlob, err = gzip.NewReader(object.Body)
		if err != nil {
			return nil, fmt.Errorf("extracting json.gz file: %v", err)
		}
		defer logFileBlob.Close()
	} else {
		logFileBlob = object.Body
	}

	blobBuf := new(bytes.Buffer)
	_, err = blobBuf.ReadFrom(logFileBlob)
	if err != nil {
		return nil, fmt.Errorf("Error reading from logFileBlob: %v", err)
	}

	var logFile CloudTrailFile
	err = json.Unmarshal(blobBuf.Bytes(), &logFile)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling s3 object to CloudTrailFile: %v", err)
	}

	return &logFile, nil
}

func matchString(m, s string) bool {
	v, _ := regexp.MatchString(m, s)
	return v
}

func prettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "  ")
	return string(s)
}

func SendSlackNotification(webhookUrl string, slackBody []byte) error {

	req, err := http.NewRequest(http.MethodPost, webhookUrl, bytes.NewBuffer(slackBody))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	if buf.String() != "ok" {
		return errors.New(fmt.Sprintf("Non-ok response returned from Slack: %s", buf.String()))
	}
	return nil
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		if value == "" {
			return fallback
		}
		return value
	}
	return fallback
}
