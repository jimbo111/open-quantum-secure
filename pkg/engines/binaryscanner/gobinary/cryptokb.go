// Package gobinary inspects compiled Go binaries for cryptographic module usage
// by reading the embedded build information and cross-referencing against a
// curated knowledge base of cryptographic Go modules.
package gobinary

import (
	_ "embed"
	"encoding/json"
	"sync"
)

//go:embed cryptokb.json
var cryptoKBData []byte

// KBEntry describes a single cryptographic module entry in the knowledge base.
type KBEntry struct {
	// Module is the fully-qualified Go module or package import path.
	Module string `json:"module"`
	// Algorithms lists the cryptographic algorithms provided by this module.
	Algorithms []string `json:"algorithms"`
	// Primitive is the broad cryptographic primitive category
	// (e.g., "symmetric", "asymmetric", "hash", "signature", "kdf", "mac", "kem", "rng", "protocol").
	Primitive string `json:"primitive"`
	// PQCSafe indicates whether the module provides post-quantum-safe algorithms.
	PQCSafe bool `json:"pqcSafe"`
	// Notes is a human-readable description of the module's cryptographic role.
	Notes string `json:"notes"`
}

var (
	kbOnce    sync.Once
	kbEntries []KBEntry
	// kbIndex maps module import path to the corresponding KBEntry pointer.
	kbIndex map[string]*KBEntry
)

// loadCryptoKB initialises the knowledge base exactly once. It unmarshals the
// embedded JSON and builds a fast lookup index keyed on module path. Errors
// during unmarshal are silently ignored — an empty KB is still functional and
// prevents a hard startup failure for embedded data that cannot be changed at
// runtime.
func loadCryptoKB() {
	kbOnce.Do(func() {
		if err := json.Unmarshal(cryptoKBData, &kbEntries); err != nil {
			// Unreachable in production: embedded data is generated at compile time.
			kbEntries = nil
		}
		kbIndex = make(map[string]*KBEntry, len(kbEntries))
		for i := range kbEntries {
			kbIndex[kbEntries[i].Module] = &kbEntries[i]
		}
	})
}

// LookupModule returns the KBEntry for the given module import path, or nil if
// the path is not in the knowledge base. The first call triggers a one-time
// load of the embedded JSON data.
func LookupModule(module string) *KBEntry {
	loadCryptoKB()
	return kbIndex[module]
}

// Entries returns a copy of all knowledge-base entries. Useful for enumeration
// in tests and diagnostics. The first call triggers a one-time load.
func Entries() []KBEntry {
	loadCryptoKB()
	out := make([]KBEntry, len(kbEntries))
	copy(out, kbEntries)
	return out
}
