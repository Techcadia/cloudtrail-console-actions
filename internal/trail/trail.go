// Package trail reads CloudTrail log files: fetch from S3, transparently
// gunzip, and decode the {"Records": [...]} document.
package trail

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// ErrMalformed marks an object whose bytes could not be gunzipped or decoded
// as a CloudTrail log file — a poison object the caller should log and skip
// rather than fail the whole invocation on (which would retry indefinitely).
var ErrMalformed = errors.New("malformed log file")

// File is a decoded CloudTrail log file.
type File struct {
	Records []map[string]any `json:"Records"`
}

// ObjectGetter is the slice of the S3 client the fetcher needs; satisfied by
// *s3.Client.
type ObjectGetter interface {
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// IsIgnoredKey reports whether the object key is CloudTrail housekeeping
// (digests, Config snapshots) rather than a log file.
func IsIgnoredKey(key string) bool {
	return strings.Contains(key, "/CloudTrail-Digest/") || strings.Contains(key, "/Config/")
}

// Fetch downloads and decodes one CloudTrail log object. Ignored keys return
// (nil, nil).
func Fetch(ctx context.Context, client ObjectGetter, bucket, key string) (*File, error) {
	if IsIgnoredKey(key) {
		return nil, nil
	}

	obj, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("getting s3://%s/%s: %w", bucket, key, err)
	}
	defer obj.Body.Close()

	file, err := Decode(obj.Body)
	if err != nil {
		return nil, fmt.Errorf("s3://%s/%s: %w", bucket, key, err)
	}
	return file, nil
}

// Decode reads a CloudTrail log file, gunzipping when the stream carries the
// gzip magic bytes — more reliable than trusting the object's Content-Type.
func Decode(r io.Reader) (*File, error) {
	buffered := bufio.NewReader(r)

	magic, err := buffered.Peek(2)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("reading log file: %w", err)
	}

	var body io.Reader = buffered
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(buffered)
		if err != nil {
			return nil, fmt.Errorf("extracting gzipped log file: %w: %w", ErrMalformed, err)
		}
		defer gz.Close()
		body = gz
	}

	var file File
	if err := json.NewDecoder(body).Decode(&file); err != nil {
		return nil, fmt.Errorf("decoding CloudTrail log file: %w: %w", ErrMalformed, err)
	}
	return &file, nil
}
