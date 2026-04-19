package zeeklog

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"strings"
	"testing"
)

func makeGzip(t *testing.T, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte(content)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

type nopCloser struct{ io.Reader }

func (nopCloser) Close() error { return nil }

func TestOpenMaybeGzip_plain(t *testing.T) {
	content := "hello world"
	rc := nopCloser{strings.NewReader(content)}
	out, err := openMaybeGzip(rc, "file.log")
	if err != nil {
		t.Fatalf("openMaybeGzip plain: %v", err)
	}
	defer out.Close()
	got, err := io.ReadAll(out)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != content {
		t.Errorf("got %q, want %q", got, content)
	}
}

func TestOpenMaybeGzip_compressed(t *testing.T) {
	content := "compressed content"
	data := makeGzip(t, content)
	rc := nopCloser{bytes.NewReader(data)}
	out, err := openMaybeGzip(rc, "file.log.gz")
	if err != nil {
		t.Fatalf("openMaybeGzip gz: %v", err)
	}
	defer out.Close()
	got, err := io.ReadAll(out)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != content {
		t.Errorf("got %q, want %q", got, content)
	}
}

func TestOpenMaybeGzip_sizeCap(t *testing.T) {
	// Build a gzip stream that will exceed the 100 MB cap.
	// We override the constant via a local limitedReadCloser with a tiny cap.
	// Simulate by creating a limitedReadCloser with limit=5, reading 10 bytes.
	bigContent := strings.Repeat("A", 10)
	data := makeGzip(t, bigContent)

	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	lrc := &limitedReadCloser{
		Reader: io.LimitReader(gz, 6),
		inner:  gz,
		outer:  io.NopCloser(bytes.NewReader(nil)),
		limit:  5, // cap at 5 bytes
		path:   "test.log.gz",
	}
	buf := make([]byte, 10)
	_, err = io.ReadFull(lrc, buf)
	if err == nil {
		t.Error("expected size cap error, got nil")
	}
	if !strings.Contains(fmt.Sprintf("%v", err), "exceeds") {
		t.Errorf("error message should mention 'exceeds': %v", err)
	}
}
