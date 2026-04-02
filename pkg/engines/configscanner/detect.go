// Package configscanner implements a Tier 1 config-file scanner that detects
// cryptographic parameters in YAML, JSON, .properties, .env, TOML, XML, INI, and HCL files.
package configscanner

import (
	"path/filepath"
	"strings"
)

// wellKnownConfigs maps lower-case base filenames to whether they are
// supported config files. false entries are listed for documentation but
// are explicitly excluded (e.g. XML).
var wellKnownConfigs = map[string]bool{
	"application.yml":          true,
	"application.yaml":         true,
	"application.json":         true,
	"application.properties":   true,
	"application-prod.yml":      true,
	"application-prod.yaml":     true,
	"application-dev.yml":       true,
	"application-dev.yaml":      true,
	"application-test.yml":      true,
	"application-test.yaml":     true,
	"application-staging.yml":   true,
	"application-staging.yaml":  true,
	"config.yml":               true,
	"config.yaml":              true,
	"config.json":              true,
	"config.toml":              true,
	"settings.toml":            true,
	"cargo.toml":               true,
	"pyproject.toml":           true,
	"netlify.toml":             true,
	"hugo.toml":                true,
	".env":                     true,
	".env.local":               true,
	".env.production":          true,
	".env.development":         true,
	".env.test":                true,
	".env.staging":             true,
	"appsettings.json":         true,
	"appsettings.development.json": true,
	"appsettings.production.json":  true,
	"web.config":                    true, // XML — ASP.NET config
	"crypto.properties":             true,
	"security.properties":           true,
	"ssl.properties":                true,
	"tls.properties":                true,
	"cipher.properties":             true,
	"keystore.properties":           true,
	// Well-known XML config files.
	"web.xml":                       true, // Java EE deployment descriptor
	"pom.xml":                       true, // Maven build (may contain crypto plugin config)
	"applicationcontext.xml":        true, // Spring application context
	"server.xml":                    true, // Tomcat server config
	"struts.xml":                    true, // Struts2 action config
	"hibernate.cfg.xml":             true, // Hibernate ORM config
	"persistence.xml":               true, // JPA persistence unit
	"log4j2.xml":                    true, // Log4j2 appender config
	"beans.xml":                     true, // CDI / Spring beans
	// Well-known INI/CFG config files.
	"php.ini":                       true, // PHP configuration
	"my.cnf":                        true, // MySQL configuration
	"my.ini":                        true, // MySQL on Windows
	"openssl.cnf":                   true, // OpenSSL configuration
	"openssl.cfg":                   true, // OpenSSL configuration (alt)
	"setup.cfg":                     true, // Python setup configuration
	"tox.ini":                       true, // Tox test runner
	"pytest.ini":                    true, // Pytest configuration
	// Well-known HCL/Terraform files.
	"main.tf":                       true, // Terraform main config
	"variables.tf":                  true, // Terraform variables
	"outputs.tf":                    true, // Terraform outputs
	"provider.tf":                   true, // Terraform provider config
	"backend.tf":                    true, // Terraform backend config
	"terraform.tfvars":              true, // Terraform variable values
}

// configExtensions lists file extensions that may contain crypto config.
var configExtensions = map[string]bool{
	".yml":        true,
	".yaml":       true,
	".json":       true,
	".properties": true,
	".toml":       true,
	".xml":        true,
	".config":     true,
	".ini":        true,
	".cfg":        true,
	".cnf":        true,
	".tf":         true,
	".hcl":        true,
	".tfvars":     true,
}

// cryptoDirKeywords are path segments that suggest a config directory.
var cryptoDirKeywords = []string{
	"config", "conf", "resources", "settings",
}

// cryptoFileKeywords are base-name substrings that suggest a crypto config file.
var cryptoFileKeywords = []string{
	"config", "crypto", "security", "ssl", "tls", "encrypt", "cipher",
	"keystore", "truststore",
}

// isConfigFile returns true if path should be scanned by the config scanner.
func isConfigFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))

	// Explicit well-known filenames take priority.
	if v, ok := wellKnownConfigs[base]; ok {
		return v
	}

	// .env files with arbitrary suffixes (e.g. ".env.staging", ".env.local").
	if base == ".env" || strings.HasPrefix(base, ".env.") {
		return true
	}

	ext := strings.ToLower(filepath.Ext(path))
	if !configExtensions[ext] {
		return false
	}

	// For config extensions, require either a crypto-related directory or
	// a crypto-related filename to avoid scanning all YAML/JSON in the repo.
	dir := strings.ToLower(filepath.ToSlash(filepath.Dir(path)))
	for _, kw := range cryptoDirKeywords {
		if strings.Contains(dir, kw) {
			return true
		}
	}
	for _, kw := range cryptoFileKeywords {
		if strings.Contains(base, kw) {
			return true
		}
	}

	return false
}
