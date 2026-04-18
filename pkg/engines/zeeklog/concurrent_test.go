package zeeklog

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

// TestConcurrent_ParseSSLLog runs parseSSLLog from many goroutines simultaneously.
// Verifies no data race (run with -race) and consistent results.
func TestConcurrent_ParseSSLLog(t *testing.T) {
	const goroutines = 50
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	counts := make(chan int, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			recs, err := parseSSLLog(strings.NewReader(sslTSVGolden))
			if err != nil {
				errs <- err
				return
			}
			counts <- len(recs)
		}()
	}
	wg.Wait()
	close(errs)
	close(counts)

	for err := range errs {
		t.Errorf("concurrent parse error: %v", err)
	}
	// All goroutines should agree on the record count.
	var first int
	n := 0
	for c := range counts {
		if n == 0 {
			first = c
		} else if c != first {
			t.Errorf("inconsistent record count: goroutine 0 got %d, another got %d", first, c)
		}
		n++
	}
}

// TestConcurrent_ParseX509Log runs parseX509Log concurrently.
func TestConcurrent_ParseX509Log(t *testing.T) {
	const goroutines = 50
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := parseX509Log(strings.NewReader(x509TSVGolden))
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent x509 parse error: %v", err)
	}
}

// TestConcurrent_EngineScan verifies that Engine.Scan can be called concurrently
// on the same Engine instance without races. Each call uses its own log file
// (the testdata fixtures are read-only on disk).
func TestConcurrent_EngineScan(t *testing.T) {
	const goroutines = 10
	e := New()
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.Scan(context.Background(), engines.ScanOptions{
				ZeekSSLPath:  "testdata/ssl_tsv.log",
				ZeekX509Path: "testdata/x509_tsv.log",
			})
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent engine scan error: %v", err)
	}
}

// TestConcurrent_DedupPerCall verifies that deduplication state is per-call,
// not shared across concurrent invocations. Each call to parseSSLLog creates
// its own `seen` map; there must be no cross-call contamination.
func TestConcurrent_DedupPerCall(t *testing.T) {
	// Two distinct inputs with disjoint dedup keys.
	inputA := "#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\testablished\n" +
		"1704067200\tCa\t10.0.0.1\t9999\t1.2.3.4\t443\tTLSv13\tTLS_AES_256_GCM_SHA384\tX25519MLKEM768\talpha.example.com\tT\n"
	inputB := "#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\testablished\n" +
		"1704067200\tCb\t10.0.0.2\t9998\t5.6.7.8\t443\tTLSv13\tTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\tsecp256r1\tbeta.example.com\tT\n"

	const goroutines = 20
	var wg sync.WaitGroup
	results := make(chan int, goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			var input string
			if i%2 == 0 {
				input = inputA
			} else {
				input = inputB
			}
			recs, _ := parseSSLLog(strings.NewReader(input))
			results <- len(recs)
		}()
	}
	wg.Wait()
	close(results)

	for count := range results {
		if count != 1 {
			t.Errorf("dedup per-call: expected 1 record per call, got %d (possible state leak)", count)
		}
	}
}
