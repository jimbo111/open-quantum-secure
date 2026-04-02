package auth

import (
	"fmt"
	"net/url"
	"os/exec"
	"runtime"
)

// OpenBrowser attempts to open rawURL in the system default browser.
// It returns an error if the command fails, which commonly indicates a
// headless environment (e.g., a CI server or SSH session).
// Only http:// and https:// URLs are accepted (prevents file:// injection).
func OpenBrowser(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("auth: invalid verification URI: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("auth: refusing to open non-HTTP URI scheme %q", u.Scheme)
	}

	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", rawURL)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL)
	default:
		// Linux and other POSIX systems.
		cmd = exec.Command("xdg-open", rawURL)
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("auth: open browser: %w", err)
	}
	return nil
}
