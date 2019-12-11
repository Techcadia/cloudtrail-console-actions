package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"log"
	"testing"

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
		content, err := ioutil.ReadFile(path)
		if err != nil {
			log.Fatal(err)
		}

		testReadLogFile(t, []byte(content))
	}
}

type BufferCloser struct {
	*bytes.Buffer
}

func (bc BufferCloser) Close() error {
	return nil
}

func testReadLogFile(t *testing.T, testData []byte) {
	buf := BufferCloser{&bytes.Buffer{}}
	gzip := gzip.NewWriter(&buf)
	_, err := gzip.Write(testData)
	if err != nil {
		t.Fatal(err)
	}
	gzip.Close()

	cntType := "application/x-gzip"
	obj := &s3.GetObjectOutput{Body: buf, ContentType: &cntType}

	logFile, err := readLogFile(obj)
	if err != nil {
		t.Fatal(err)
	}

	FilterRecords(logFile)
	if err != nil {
		t.Fatal(err)
	}

}
