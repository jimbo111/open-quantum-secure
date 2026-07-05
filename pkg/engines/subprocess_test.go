package engines

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeFakeBin(t *testing.T, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake binary not portable to Windows")
	}
	bin := filepath.Join(t.TempDir(), "fake")
	if err := os.WriteFile(bin, []byte(script), 0755); err != nil {
		t.Fatalf("write fake bin: %v", err)
	}
	return bin
}

func TestRunSubprocess_CapturesStdout(t *testing.T) {
	bin := writeFakeBin(t, "#!/bin/sh\nprintf 'hello'\n")
	out, stderr, err := RunSubprocess(context.Background(), bin)
	if err != nil || string(out) != "hello" || stderr != "" {
		t.Errorf("got out=%q stderr=%q err=%v; want hello/empty/nil", out, stderr, err)
	}
}

func TestRunSubprocess_RedactsStderr(t *testing.T) {
	bin := writeFakeBin(t, "#!/bin/sh\necho 'API_KEY=supersecret123' >&2\n")
	_, stderr, _ := RunSubprocess(context.Background(), bin)
	if strings.Contains(stderr, "supersecret123") {
		t.Errorf("stderr not redacted: %q", stderr)
	}
	if stderr == "" {
		t.Error("stderr dropped entirely; want redacted placeholder present")
	}
}

func TestRunSubprocess_NonZeroExitReturnsErrAndStderr(t *testing.T) {
	bin := writeFakeBin(t, "#!/bin/sh\necho 'boom' >&2\nexit 3\n")
	_, stderr, err := RunSubprocess(context.Background(), bin)
	if err == nil {
		t.Fatal("want non-nil runErr for exit 3")
	}
	if !strings.Contains(stderr, "boom") {
		t.Errorf("stderr = %q; want it to contain 'boom'", stderr)
	}
}

func TestRunSubprocess_ContextCancel(t *testing.T) {
	bin := writeFakeBin(t, "#!/bin/sh\nsleep 30\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := RunSubprocess(ctx, bin); err == nil {
		t.Fatal("want error for pre-cancelled context")
	}
}

func TestRunSubprocessNoStdout_RedactsStderr(t *testing.T) {
	bin := writeFakeBin(t, "#!/bin/sh\necho 'API_KEY=supersecret123' >&2\n")
	stderr, err := RunSubprocessNoStdout(context.Background(), bin)
	if err != nil {
		t.Errorf("got err=%v; want nil", err)
	}
	if strings.Contains(stderr, "supersecret123") {
		t.Errorf("stderr not redacted: %q", stderr)
	}
	if stderr == "" {
		t.Error("stderr dropped entirely; want redacted placeholder present")
	}
}

func TestRunSubprocessNoStdout_NonZeroExitReturnsErrAndStderr(t *testing.T) {
	bin := writeFakeBin(t, "#!/bin/sh\necho 'boom' >&2\nexit 3\n")
	stderr, err := RunSubprocessNoStdout(context.Background(), bin)
	if err == nil {
		t.Fatal("want non-nil runErr for exit 3")
	}
	if !strings.Contains(stderr, "boom") {
		t.Errorf("stderr = %q; want it to contain 'boom'", stderr)
	}
}
