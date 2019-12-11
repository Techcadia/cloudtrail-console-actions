package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"regexp"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
)

type CloudTrailFile struct {
	Records []map[string]interface{} `json:"Records"`
}

func init() {
}

func main() {
	log.Info("Startup")
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
		switch en := record["eventName"].(string); {
		case strings.HasPrefix(en, "Get"):
			continue
		case strings.HasPrefix(en, "List"):
			continue
		case strings.HasPrefix(en, "Describe"):
			continue
		case en == "ConsoleLogin":
			continue
		case en == "DownloadDBLogFilePortion":
			continue
		case en == "TestScheduleExpression":
			continue
		case en == "TestEventPattern":
			continue
		case en == "LookupEvents":
			continue
		case en == "listDnssec":
			continue
		case en == "Decrypt":
			continue
		case en == "REST.GET.OBJECT_LOCK_CONFIGURATION":
			continue

		}

		userIdentity, _ := record["userIdentity"].(map[string]interface{})
		if userIdentity["invokedBy"] == "AWS Internal" {
			continue
		}

		if record["eventName"] == "AssumeRole" &&
			record["userAgent"] == "Coral/Netty4" {
			switch userIdentity["invokedBy"] {
			case
				"ecs-tasks.amazonaws.com",
				"ec2.amazonaws.com",
				"monitoring.rds.amazonaws.com",
				"lambda.amazonaws.com":
				continue
			}
		}

		switch ua := record["userAgent"].(string); {
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
		case matchString("aws-internal*AWSLambdaConsole/*", ua):
			break
		default:
			continue
		}
		// log.Infof("Event Name: %s", record["eventName"])
		// log.Infof("User Agent: %s", record["userAgent"])
		log.Infof("Event Time: %s", record["eventTime"])
		log.Infof("Principal: %s", userIdentity["userName"])
		log.Infof("Event Source: %s", record["eventSource"])
		log.Infof("Event Name: %s", record["eventName"])
		log.Infof("Account ID: %s", userIdentity["accountId"])
		// requestParameters, _ := record["requestParameters"].(map[string]interface{})
		// if len(requestParameters) < 3 {
		// 	log.Infof("Request Parameters: %s", prettyPrint(requestParameters))
		// } else {
		log.Infof("Event ID: [%s](https://console.aws.amazon.com/cloudtrail/home?region=%s#/events?EventId=%s)", record["eventID"], record["awsRegion"], record["eventID"])
		// }

		log.Infoln("----------------------")

		log.Info(spew.Sdump(record))
	}
	return nil
}

func Stream(awsRegion string, bucket string, objectKey string) error {
	s3ClientConfig := aws.NewConfig().WithRegion(awsRegion)
	s3Client := s3.New(session.Must(session.NewSession()), s3ClientConfig)

	log.Debugf("Reading %s from %s with client config of %+v", objectKey, bucket, s3Client.Config)

	object, err := fetchLogFromS3(s3Client, bucket, objectKey)
	if err != nil {
		return err
	}

	logFile, err := readLogFile(object)
	if err != nil {
		return err
	}

	err = FilterRecords(logFile)
	if err != nil {
		return err
	}

	return nil
}

func fetchLogFromS3(s3Client *s3.S3, bucket string, objectKey string) (*s3.GetObjectOutput, error) {
	logInput := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectKey),
	}

	object, err := s3Client.GetObject(logInput)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			log.Errorf("AWS Error: %s", aerr)
			return nil, aerr
		}
		log.Errorf("Error getting S3 object: %s", err)
		return nil, err
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
			log.Errorf("extracting json.gz file: %s", err)
			return nil, err
		}
		defer logFileBlob.Close()
	} else {
		logFileBlob = object.Body
	}

	blobBuf := new(bytes.Buffer)
	_, err = blobBuf.ReadFrom(logFileBlob)
	if err != nil {
		log.Errorf("Error reading from logFileBlob: %s", err)
		return nil, err
	}

	var logFile CloudTrailFile
	err = json.Unmarshal(blobBuf.Bytes(), &logFile)
	if err != nil {
		log.Errorf("unmarshalling s3 object to CloudTrailFile: %s", err)
		return nil, err
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
