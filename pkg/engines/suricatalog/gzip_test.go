package suricatalog

import (
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestReadGzipEveJSON(t *testing.T) {
	// Create a temp .gz version of the golden fixture.
	src, err := os.ReadFile("testdata/eve_mixed.json")
	if err != nil {
		t.Fatalf("read golden fixture: %v", err)
	}

	tmp := filepath.Join(t.TempDir(), "eve.json.gz")
	f, err := os.Create(tmp)
	if err != nil {
		t.Fatalf("create temp gz: %v", err)
	}
	gz := gzip.NewWriter(f)
	if _, err := gz.Write(src); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	gz.Close()
	f.Close()

	recs, err := readEveJSON(context.Background(), tmp)
	if err != nil {
		t.Fatalf("readEveJSON gzip: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("got %d records from gzip, want 3", len(recs))
	}
}

func TestSizeCap(t *testing.T) {
	// Write a file that is just over the cap to verify the error fires.
	tmp := filepath.Join(t.TempDir(), "huge.json")
	f, err := os.Create(tmp)
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	// Write maxDecompressedBytes+2 worth of data (non-JSON; scanner will skip them
	// but the cap should fire first).
	chunk := make([]byte, 65536)
	written := int64(0)
	for written <= maxDecompressedBytes {
		n, werr := f.Write(chunk)
		written += int64(n)
		if werr != nil {
			break
		}
	}
	f.Close()

	_, err = readEveJSON(context.Background(), tmp)
	if err == nil {
		t.Fatal("expected size-cap error for huge file")
	}
}
