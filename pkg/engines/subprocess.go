package engines

import (
	"bytes"
	"context"
	"os/exec"
	"time"
)

// RunSubprocess executes binary with args under ctx, applying the two
// mandatory subprocess-safety conventions so individual engines cannot
// forget them:
//   - cmd.WaitDelay = 2s bounds ctx-cancel cleanup (a grand-child holding
//     the pipe open would otherwise block cmd.Wait() past SIGKILL).
//   - stderr is captured and returned already passed through RedactStderr,
//     safe to embed in error messages.
// Exit-code policy, empty-output policy, and error wording stay with the
// caller: stdout bytes and the raw run error are returned untouched.
func RunSubprocess(ctx context.Context, binary string, args ...string) ([]byte, string, error) {
	var stderrBuf bytes.Buffer
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stderr = &stderrBuf
	cmd.WaitDelay = 2 * time.Second
	stdout, runErr := cmd.Output()
	return stdout, RedactStderr(stderrBuf.String()), runErr
}

// RunSubprocessNoStdout is RunSubprocess for engines that never read child
// stdout: cmd.Stdout stays nil so the child writes directly to the OS null
// device — no pipe, no in-memory buffering, and no WaitDelay I/O hazard from
// a grand-child inheriting the stdout pipe. Matches pre-runner behavior of
// the cmd.Run() engines.
func RunSubprocessNoStdout(ctx context.Context, binary string, args ...string) (redactedStderr string, runErr error) {
	var stderrBuf bytes.Buffer
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stderr = &stderrBuf
	cmd.WaitDelay = 2 * time.Second
	runErr = cmd.Run()
	return RedactStderr(stderrBuf.String()), runErr
}
