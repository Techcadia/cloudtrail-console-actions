package trail

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const logFile = `{"Records":[{"eventName":"RunInstances","eventSource":"ec2.amazonaws.com"},{"eventName":"GetObject","eventSource":"s3.amazonaws.com"}]}`

func gzipped(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestDecodePlain(t *testing.T) {
	file, err := Decode(strings.NewReader(logFile))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(file.Records) != 2 {
		t.Fatalf("records = %d, want 2", len(file.Records))
	}
	if file.Records[0]["eventName"] != "RunInstances" {
		t.Errorf("first record = %v", file.Records[0])
	}
}

func TestDecodeErrors(t *testing.T) {
	// Content errors must wrap ErrMalformed so the caller can skip poison
	// objects instead of failing (and endlessly retrying) the invocation.
	if _, err := Decode(strings.NewReader("not json")); err == nil || !errors.Is(err, ErrMalformed) {
		t.Errorf("plain garbage: want ErrMalformed, got %v", err)
	}
	if _, err := Decode(bytes.NewReader([]byte{0x1f, 0x8b, 0x00})); err == nil || !errors.Is(err, ErrMalformed) {
		t.Errorf("truncated gzip: want ErrMalformed, got %v", err)
	}
	if _, err := Decode(strings.NewReader("")); err == nil || !errors.Is(err, ErrMalformed) {
		t.Errorf("empty input: want ErrMalformed, got %v", err)
	}
}

// failingReader yields prefix, then fails like a connection reset mid-body.
type failingReader struct {
	prefix []byte
	done   bool
}

func (f *failingReader) Read(p []byte) (int, error) {
	if !f.done {
		f.done = true
		return copy(p, f.prefix), nil
	}
	return 0, errors.New("connection reset by peer")
}

func TestDecodeTransportErrorIsNotMalformed(t *testing.T) {
	// A transport failure must propagate so the invocation is retried; only
	// bad bytes are poison.
	for name, prefix := range map[string][]byte{
		"plain": []byte(logFile[:40]),
		"gzip":  gzipped(t, logFile)[:30],
	} {
		_, err := Decode(&failingReader{prefix: prefix})
		if err == nil || errors.Is(err, ErrMalformed) {
			t.Errorf("%s: want a non-ErrMalformed error, got %v", name, err)
		}
		if err != nil && !strings.Contains(err.Error(), "connection reset") {
			t.Errorf("%s: error should carry the cause, got %v", name, err)
		}
	}
}

func TestIsIgnoredKey(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"AWSLogs/111/CloudTrail-Digest/us-east-1/2026/07/07/x.json.gz", true},
		{"AWSLogs/111/Config/us-east-1/2026/07/07/x.json.gz", true},
		{"AWSLogs/111/CloudTrail-Insight/us-east-1/2026/07/07/x.json.gz", true},
		{"AWSLogs/111/CloudTrail/us-east-1/2026/07/07/x.json.gz", false},
	}
	for _, tt := range tests {
		if got := IsIgnoredKey(tt.key); got != tt.want {
			t.Errorf("IsIgnoredKey(%q) = %v, want %v", tt.key, got, tt.want)
		}
	}
}

type fakeGetter struct {
	body []byte
	err  error
	keys []string
}

func (f *fakeGetter) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.keys = append(f.keys, *in.Key)
	if f.err != nil {
		return nil, f.err
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(f.body))}, nil
}

func TestFetch(t *testing.T) {
	getter := &fakeGetter{body: gzipped(t, logFile)}
	file, err := Fetch(context.Background(), getter, "bucket", "AWSLogs/111/CloudTrail/us-east-1/x.json.gz")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(file.Records) != 2 {
		t.Errorf("records = %d, want 2", len(file.Records))
	}
}

func TestFetchSkipsIgnoredKeys(t *testing.T) {
	getter := &fakeGetter{}
	file, err := Fetch(context.Background(), getter, "bucket", "AWSLogs/111/CloudTrail-Digest/x.json.gz")
	if err != nil || file != nil {
		t.Fatalf("Fetch = (%v, %v), want (nil, nil)", file, err)
	}
	if len(getter.keys) != 0 {
		t.Error("ignored key still fetched from S3")
	}
}

func TestFetchError(t *testing.T) {
	getter := &fakeGetter{err: errors.New("boom")}
	_, err := Fetch(context.Background(), getter, "bucket", "AWSLogs/111/CloudTrail/x.json.gz")
	if err == nil || !strings.Contains(err.Error(), "s3://bucket/") {
		t.Fatalf("err = %v, want s3 uri context", err)
	}
}
