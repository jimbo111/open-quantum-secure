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
