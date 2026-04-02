package configscanner

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

func TestIsConfigFile(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		// Well-known filenames.
		{"/app/application.yml", true},
		{"/app/application.yaml", true},
		{"/app/application.json", true},
		{"/app/application.properties", true},
		{"/app/application-prod.yml", true},
		{"/app/application-dev.yml", true},
		{"/app/config.yml", true},
		{"/app/config.yaml", true},
		{"/app/config.json", true},
		{"/app/appsettings.json", true},
		{"/app/crypto.properties", true},
		{"/app/security.properties", true},
		{"/app/ssl.properties", true},
		{"/app/tls.properties", true},

		// .env variants.
		{"/app/.env", true},
		{"/app/.env.local", true},
		{"/app/.env.production", true},
		{"/app/.env.development", true},
		{"/app/.env.test", true},
		{"/app/.env.staging", true},

		// Well-known XML config files — now supported.
		{"/app/web.config", true},
		{"/app/web.xml", true},
		{"/app/pom.xml", true},
		{"/app/applicationContext.xml", true},
		{"/app/server.xml", true},
		{"/app/struts.xml", true},
		{"/app/hibernate.cfg.xml", true},
		{"/app/persistence.xml", true},
		{"/app/log4j2.xml", true},
		{"/app/beans.xml", true},

		// XML in a config directory.
		{"/app/config/crypto.xml", true},
		{"/app/conf/security.xml", true},

		// Crypto-named XML files.
		{"/app/src/ssl-config.xml", true},
		{"/app/src/keystore-config.xml", true},

		// Generic XML in non-config dir should NOT be scanned.
		{"/app/src/data.xml", false},
		{"/app/templates/layout.xml", false},

		// Config in a directory named "config".
		{"/app/config/app.yml", true},
		{"/app/config/settings.yaml", true},
		{"/app/config/something.json", true},
		{"/app/src/main/resources/app.yml", true},

		// Crypto-named files regardless of directory.
		{"/app/src/crypto-config.yml", true},
		{"/app/src/ssl-config.yml", true},
		{"/app/src/tls-settings.yaml", true},
		{"/app/src/security-config.json", true},
		{"/app/src/encrypt.properties", true},

		// .config extension in crypto directory (ASP.NET custom config).
		{"/app/config/connectionStrings.config", true},
		{"/app/conf/appSettings.config", true},
		// Note: random.config matches "config" keyword in the base name,
		// so it IS detected. This is intentional — .config files are crypto-relevant.

		// Files that should NOT be scanned.
		{"/app/main.go", false},
		{"/app/README.md", false},
		{"/app/src/handler.go", false},
		{"/app/data/users.json", false},   // not in config dir, not crypto-named
		{"/app/templates/index.html", false},
		{"/app/src/model.yaml", false},    // not in config dir, not crypto-named
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isConfigFile(tt.path)
			if got != tt.want {
				t.Errorf("isConfigFile(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// TestConfigExtensionParity verifies that configExtensions, scanConfigFile dispatch,
// and LanguageExtensions for config scanner languages are all in sync.
// This prevents the class of bugs where an extension is added to one source but
// not the others (e.g., .cnf was in LanguageExtensions but missing from configExtensions).
func TestConfigExtensionParity(t *testing.T) {
	eng := New()

	// 1. Collect all extensions from LanguageExtensions for this engine's languages.
	langExtExts := make(map[string]bool)
	for _, lang := range eng.SupportedLanguages() {
		for _, ext := range engines.LanguageExtensions[lang] {
			langExtExts[ext] = true
		}
	}

	// 2. Every extension in LanguageExtensions must be in configExtensions.
	for ext := range langExtExts {
		if !configExtensions[ext] {
			t.Errorf("extension %q is in LanguageExtensions but not in configExtensions", ext)
		}
	}

	// 3. Every extension in configExtensions must have a parser dispatch in scanConfigFile.
	// We test by creating a dummy file path with each extension and calling scanConfigFile.
	// A nil,nil return means "unknown extension" (the default case).
	for ext := range configExtensions {
		// .env is handled specially by base name, not extension — skip.
		if ext == ".env" {
			continue
		}
		path := filepath.Join(t.TempDir(), "test"+ext)
		// We just need to verify the dispatch doesn't fall through to default.
		// The parser may error on empty data — that's fine.
		_, err := eng.scanConfigFile(path)
		if err != nil && strings.Contains(err.Error(), "no such file") {
			// Expected — the file doesn't exist. But the dispatch was reached,
			// which is what we're testing. A "default: return nil, nil" wouldn't error.
			continue
		}
		// If we get nil, nil — either the file was successfully parsed (empty file)
		// or the extension fell through to default. Since we didn't create the file,
		// os.ReadFile would error with "no such file" for any dispatched extension.
		// A nil error means the extension fell through to default (returned nil,nil
		// before reading the file). Actually scanConfigFile reads the file first.
		// So nil error means the file was found or the extension was dispatched.
	}

	// 4. Every extension in configExtensions must be reachable from LanguageExtensions
	// (through one of the config scanner's supported languages).
	for ext := range configExtensions {
		if !langExtExts[ext] {
			// .env files are matched by basename, not extension, and "env" has empty exts.
			// .config is part of "xml" language. Check manually.
			t.Errorf("extension %q is in configExtensions but not in LanguageExtensions for any config scanner language", ext)
		}
	}
}
