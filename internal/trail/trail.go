// Package trail reads CloudTrail log files: fetch from S3, transparently
// gunzip, and decode the {"Records": [...]} document.
package trail

import (
	"bufio"
	"bytes"
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
// as a CloudTrail log file: a poison object the caller should log and skip
// rather than fail the whole invocation on (which would retry indefinitely).
var ErrMalformed = errors.New("malformed log file")

// File is a decoded CloudTrail log file.
type File struct {
	Records []map[string]any
	// Skipped counts entries in the Records array that could not be decoded
	// as a JSON object (including null). The rest of the file is still
	// processed.
	Skipped int
}

// ObjectGetter is the slice of the S3 client the fetcher needs; satisfied by
// *s3.Client.
type ObjectGetter interface {
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// IsIgnoredKey reports whether the object key is not a management-event log
// file: CloudTrail digests, Config snapshots, or CloudTrail Insights files
// (anomaly summaries with no acting user to alert on).
func IsIgnoredKey(key string) bool {
	return strings.Contains(key, "/CloudTrail-Digest/") ||
		strings.Contains(key, "/CloudTrail-Insight/") ||
		strings.Contains(key, "/Config/")
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
// gzip magic bytes, which is more reliable than trusting the object's
// Content-Type.
//
// Only bad bytes are ErrMalformed. A failure reading the stream itself (a
// connection reset mid-body) is returned unwrapped so the invocation fails
// and the object is retried rather than silently skipped.
func Decode(r io.Reader) (*File, error) {
	src := &readErrRecorder{r: r}
	buffered := bufio.NewReader(src)

	magic, err := buffered.Peek(2)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("reading log file: %w", err)
	}

	var body io.Reader = buffered
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(buffered)
		if err != nil {
			if src.err != nil {
				return nil, fmt.Errorf("reading log file: %w", src.err)
			}
			return nil, fmt.Errorf("extracting gzipped log file: %w: %w", ErrMalformed, err)
		}
		defer gz.Close()
		body = gz
	}

	// Records are decoded one at a time so a single bad record cannot take
	// the rest of the file down with it.
	var doc struct {
		Records []json.RawMessage `json:"Records"`
	}
	if err := json.NewDecoder(body).Decode(&doc); err != nil {
		if src.err != nil {
			return nil, fmt.Errorf("reading log file: %w", src.err)
		}
		return nil, fmt.Errorf("decoding CloudTrail log file: %w: %w", ErrMalformed, err)
	}

	file := &File{Records: make([]map[string]any, 0, len(doc.Records))}
	for _, raw := range doc.Records {
		if record := decodeRecord(raw); record != nil {
			file.Records = append(file.Records, record)
		} else {
			file.Skipped++
		}
	}
	return file, nil
}

// decodeRecord decodes one CloudTrail record, or returns nil when it is not
// a JSON object. Numbers default to float64; a record holding a number
// outside float64 range is decoded again with json.Number instead of being
// dropped.
func decodeRecord(raw json.RawMessage) map[string]any {
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err == nil {
		return record
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	record = nil
	if err := dec.Decode(&record); err != nil {
		return nil
	}
	return record
}

// readErrRecorder remembers the first non-EOF error from the underlying
// stream, so decode failures can be told apart from transport failures.
type readErrRecorder struct {
	r   io.Reader
	err error
}

func (rr *readErrRecorder) Read(p []byte) (int, error) {
	n, err := rr.r.Read(p)
	if err != nil && err != io.EOF && rr.err == nil {
		rr.err = err
	}
	return n, err
}
