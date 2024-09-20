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

	"github.com/Techcadia/cloudtrail-console-actions/pkg/handler"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type CloudTrailFile struct {
	Records []map[string]interface{} `json:"Records"`
}

func init() {
}

func main() {
	log.SetFormatter(&log.JSONFormatter{})
	log.Info("Starting v0.1.18")
	lambda.Start(Handler)
}

func Title(s string) string {
	return cases.Title(language.Und, cases.NoLower).String(s)
}

func Handler(ctx context.Context, event handler.Event) error {
	log.Infof("S3 event: %v", event)

	for _, record := range event.Records {
		err := Stream(record)
		if err != nil {
			return err
		}
	}

	return nil
}

func FilterRecords(logFile *CloudTrailFile, eventRecord handler.Record) error {
	for _, record := range logFile.Records {
		userIdentity, _ := record["userIdentity"].(map[string]interface{})

		if userIdentity["invokedBy"] == "AWS Internal" {
			continue
		}

		userName := fmt.Sprintf("%s", userIdentity["principalId"])
		if strings.Contains(userName, ":") {
			userName = strings.Split(userName, ":")[1]
		}
		if userIdentity["userName"] != nil {
			userName = fmt.Sprintf("%s", userIdentity["userName"])
		}

		eventName := record["eventName"].(string)

		if record["eventSource"] == "ssm.amazonaws.com" {
			if eventName == "OpenDataChannel" {
				if rps, ok := record["requestParameters"].(map[string]interface{}); ok {
					if k, ok := rps["sessionId"].(string); ok {
						userName = k
					}
				}
			}
		}

		// codecommit.amazonaws.com
		if record["eventSource"] == "codecommit.amazonaws.com" {
			continue
		}

		// billingconsole.amazonaws.com
		if record["eventSource"] == "billingconsole.amazonaws.com" {
			eventName = strings.TrimPrefix(eventName, "AWSPaymentPortalService.")
		}

		// q.amazonaws.com
		if record["eventSource"] == "q.amazonaws.com" {
			if ec, ok := record["errorCode"].(string); ok {
				if ec == "AccessDenied" || ec == "ThrottlingException" {
					if eventName == "StartConversation" {
						continue
					}
					if eventName == "SendMessage" {
						continue
					}
				}
			}
		}

		switch en := eventName; {
		// Some events don't match AWS defined standards
		// So we have to convert the input to Title
		case strings.HasPrefix(Title(en), "Get"):
			continue
		// Some events don't match AWS defined standards
		// So we have to convert the input to Title
		case strings.HasPrefix(Title(en), "List"):
			continue
		// Some events don't match AWS defined standards
		// So we have to convert the input to Title
		case strings.HasPrefix(Title(en), "View"):
			continue
		case strings.HasPrefix(en, "Head"):
			continue
		case strings.HasPrefix(en, "Describe"):
			continue
		case strings.HasPrefix(en, "Test"):
			continue
		case strings.HasPrefix(en, "Download"):
			continue
		case strings.HasPrefix(en, "Report"):
			continue
		case strings.HasPrefix(en, "Refresh"):
			continue
		case strings.HasPrefix(en, "Poll"):
			continue
		case strings.HasPrefix(en, "Verify"):
			continue
		case strings.HasPrefix(en, "Skip"):
			continue
		case strings.HasPrefix(en, "Select"):
			continue
		case strings.HasPrefix(en, "Count"):
			continue
		case strings.HasPrefix(en, "Detect"):
			continue
		case strings.HasPrefix(en, "Lookup"):
			continue

		case strings.HasPrefix(en, "AdminList"):
			if record["eventSource"] == "cognito-idp.amazonaws.com" {
				continue
			}
		case strings.HasSuffix(strings.ToLower(en), "get"):
			if record["eventSource"] == "cognito-idp.amazonaws.com" {
				continue
			}
		case en == "ConsoleLogin":
			continue
		case strings.HasSuffix(en, "VirtualMFADevice"):
			continue
		case en == "CheckMfa":
			continue
		case en == "InitiateAuth":
			// cognito-idp.amazonaws.com - Refresh Token
			if userIdentity["principalId"] == "Anonymous" {
				continue
			}
		case en == "CheckDomainAvailability":
			continue
		case en == "AccessKubernetesApi":
			// eks.amazonaws.com
			if record["readOnly"] == true {
				// TODO: Validate that this command only does readOnly events
				continue
			}
		case en == "Decrypt":
			continue
		case en == "SetTaskStatus":
			continue
		case en == "BatchGetQueryExecution":
			continue
		case en == "QueryObjects":
			continue
		case en == "ValidatePolicy":
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

		//cloudwatch.amazonaws.com
		case strings.HasPrefix(en, "CreateLog"):
			if rps, ok := record["requestParameters"].(map[string]interface{}); ok {
				if k, ok := rps["logGroupName"].(string); ok {
					if k == "RDSOSMetrics" {
						continue
					}
				}
			}

		//ec2.amazonaws.com
		case strings.HasPrefix(en, "CreateNetworkInterface"):
			if rps, ok := record["requestParameters"].(map[string]interface{}); ok {
				if k, ok := rps["description"].(string); ok {
					if strings.HasPrefix(k, "AWS Lambda VPC ENI-") {
						continue
					}
				}
			}

		// elasticfilesystem.amazonaws.com
		case en == "NewClientConnection":
			if record["eventSource"] == "elasticfilesystem.amazonaws.com" {
				if userName != "" {
					// still post if anonymous/no user
					continue
				}
			}

		// quicksight.amazonaws
		case en == "QueryDatabase":
			if record["eventSource"] == "quicksight.amazonaws.com" {
				continue
			}

		case en == "Federate":
			if record["eventSource"] == "sso.amazonaws.com" {
				continue
			}
		case en == "Authenticate":
			if record["eventSource"] == "sso.amazonaws.com" {
				continue
			}
		case en == "Logout":
			if record["eventSource"] == "sso.amazonaws.com" {
				continue
			}

		//signin.amazonaws.com
		case en == "UserAuthentication":
			if record["eventSource"] == "signin.amazonaws.com" {
				if aed, ok := record["additionalEventData"].(map[string]interface{}); ok {
					if k, ok := aed["CredentialType"].(string); ok {
						if k == "EXTERNAL_IDP" {
							continue
						}
					}
				}
			}

		//cloudshell.amazonaws.com
		case en == "SendHeartBeat":
			continue
		//cloudshell.amazonaws.com
		case en == "CreateEnvironment":
			continue
		//cloudshell.amazonaws.com
		case en == "CreateSession":
			continue
		//cloudshell.amazonaws.com
		case en == "DeleteEnvironment":
			continue
		//cloudshell.amazonaws.com
		case en == "RedeemCode":
			continue
		//cloudshell.amazonaws.com
		case en == "startEnvironment":
			continue
		//cloudshell.amazonaws.com
		case en == "stopEnvironment":
			continue
		//cloudshell.amazonaws.com
		case en == "PutCredentials":
			continue

		//ssm.amazonaws.com
		case strings.HasSuffix(en, "Session"):
			// ssm:StartSession
			// ssm:ResumeSession
			// ssm:TerminateSession
			if record["eventSource"] == "ssm.amazonaws.com" {
				continue
			}

		// "logs.amazonaws.com"
		case en == "FilterLogEvents":
			if record["eventSource"] == "logs.amazonaws.com" {
				continue
			}
		case en == "PutQueryDefinition":
			if record["eventSource"] == "logs.amazonaws.com" {
				continue
			}

		// s3.amazonaws.com
		case en == "PutObject":
			// Fingerprinting on KeyPath for LB Logs
			// Objects are originating outside our account with these account ids.
			// https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/enable-access-logs.html
			if userIdentity["type"] == "AWSAccount" {
				if rps, ok := record["requestParameters"].(map[string]interface{}); ok {
					if k, ok := rps["key"].(string); ok {
						if strings.Contains(k, "/AWSLogs/") && strings.Contains(k, "/elasticloadbalancing/") {
							continue
						}
					}
				}
			}

		// iam.amazonaws.com
		case strings.HasPrefix(en, "AssumeRole"):
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
			if userIdentity["type"] == "SAMLUser" {
				continue
			}
			if userIdentity["type"] == "AWSAccount" {
				continue
			}

		// batch.amazonaws.com
		case en == "SubmitJob":
			// Fingerprinting on userName, Length and Contents
			// When called from AWS Step Functions the UA appears too similar to console actions
			if len(userName) == 32 {
				matched, _ := regexp.MatchString(`^[a-zA-Z]+$`, userName)
				if matched {
					continue
				}
			}

		if usa, ok := record["userAgent"]; ok {
			// This switch case is backwards from all the others.
			// We are targeting specific UserAgents that are considered
			// Console Actions
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
			case strings.HasPrefix(ua, "AWS Signin"):
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

			// fsx.amazonaws.com uses AWS Internal
			// Not sure if we need to filter for just that
			// or if this is trapping more than it should.
			// AWS Internal, aws-internal, aws-sdk-ruby aws-internal (...)
			case matchString("(?i)aws[\\s-]internal", ua):
				if matchString("^aws-vpc-flow-logs", ua) {
					continue
				}
				break
			default:
				// If we can't determine the UserAgent
				// we consider it most likely a CLI or IaC Tool.
				continue
			}
		}

		var errorCode string
		if ec, ok := record["errorCode"].(string); ok {
			errorCode = fmt.Sprintf(" - `%s`", ec)
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
			"s3_uri":       fmt.Sprintf("s3://%s/%s", eventRecord.S3.Bucket.Name, eventRecord.S3.Object.Key),
		}).Info("Event")

		// Not all records include the accountId in the userIdentity field.
		// This was originally identified in cognito-idp:RespondToAuthChallenge
		// It makes finding the event difficult, so this falls back to another place
		// where accountId might be listed, making investigation easier
		var recordAccount string
		if accountId, ok := userIdentity["accountId"].(string); ok {
			recordAccount = accountId
		} else if recipientAccountId, ok := record["recipientAccountId"].(string); ok {
			recordAccount = fmt.Sprintf("Fallback: %s", recipientAccountId)
		} else {
			recordAccount = "Unknown"
		}

		if webhookUrl, ok := os.LookupEnv("SLACK_WEBHOOK"); ok {
			slackName := getEnv(
				fmt.Sprintf("SLACK_NAME_%s", userIdentity["accountId"]),
				getEnv("SLACK_NAME", fmt.Sprintf("%s", recordAccount)),
			)
			slackBody := fmt.Sprintf(`
{
  "channel": "%s",
  "text": "%s | %s | %s",
  "blocks": [
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*%s* - %s%s"
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
				slackName,
				record["eventName"],
				userName,
				record["eventName"],
				record["eventSource"],
				errorCode,
				slackName,
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

func Stream(eventRecord handler.Record) error {
	s3ClientConfig := aws.NewConfig().WithRegion(eventRecord.AWSRegion)
	s3Client := s3.New(session.Must(session.NewSession()), s3ClientConfig)
	s3Bucket := eventRecord.S3.Bucket.Name
	s3Object := eventRecord.S3.Object.Key

	log.Debugf("Reading %s from %s with client config of %+v", s3Object, s3Bucket, s3Client.Config)

	obj, err := fetchLogFromS3(s3Client, s3Bucket, s3Object)
	if err != nil {
		return fmt.Errorf("%v: %v", s3Object, err)
	}
	if obj == nil {
		return nil
	}

	logFile, err := readLogFile(obj)
	if err != nil {
		return fmt.Errorf("%v: %v", s3Object, err)
	}

	err = FilterRecords(logFile, eventRecord)
	if err != nil {
		return fmt.Errorf("%v: %v", s3Object, err)
	}

	return nil
}

func fetchLogFromS3(s3Client *s3.S3, s3Bucket string, s3Object string) (*s3.GetObjectOutput, error) {
	logInput := &s3.GetObjectInput{
		Bucket: aws.String(s3Bucket),
		Key:    aws.String(s3Object),
	}

	if strings.Contains(s3Object, "/CloudTrail-Digest/") || strings.Contains(s3Object, "/Config/") {
		return nil, nil
	}

	obj, err := s3Client.GetObject(logInput)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			return nil, fmt.Errorf("AWS Error: %v", aerr)
		}
		return nil, fmt.Errorf("Error getting S3 Object: %v", err)
	}

	return obj, nil
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
