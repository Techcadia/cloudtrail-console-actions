package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"log"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/s3"
)

func TestReadExamples(t *testing.T) {
	dir := "examples"

	files, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		path := fmt.Sprintf("%s/%s", dir, f.Name())
		log.Printf("Test File: %s", path)
		content, err := ioutil.ReadFile(path)
		if err != nil {
			log.Fatal(err)
		}

		err = testReadLogFile(t, []byte(content), path)
		if err != nil {
			t.Fatal(fmt.Errorf("%s: %v", path, err))
		}
	}
}

type BufferCloser struct {
	*bytes.Buffer
}

func (bc BufferCloser) Close() error {
	return nil
}

func testReadLogFile(t *testing.T, testData []byte, path string) error {
	buf := BufferCloser{&bytes.Buffer{}}
	gzip := gzip.NewWriter(&buf)
	_, err := gzip.Write(testData)
	if err != nil {
		return err
	}
	gzip.Close()

	cntType := "application/x-gzip"
	obj := &s3.GetObjectOutput{Body: buf, ContentType: &cntType}

	logFile, err := readLogFile(obj)
	if err != nil {
		return err
	}

	FilterRecords(logFile, events.S3EventRecord{
		AWSRegion: "us-east-1",
		S3: events.S3Entity{
			Bucket: events.S3Bucket{
				Name: "test-harness",
			},
			Object: events.S3Object{
				Key: path,
			},
		},
	})
	if err != nil {
		return err
	}

	return nil
}
