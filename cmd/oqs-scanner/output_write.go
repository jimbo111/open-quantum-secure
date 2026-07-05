// output_write.go writes scan results to stdout/file in the requested format.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/jimbo111/open-quantum-secure/pkg/cbomutil"
	"github.com/jimbo111/open-quantum-secure/pkg/output"
)

// writeOutput writes the scan result in the specified format to the given destination.
// When signCBOM is true and format is "cbom"/"cyclonedx", the CBOM is signed with an
// ephemeral Ed25519 key pair and the SignedCBOM envelope is written instead of raw CBOM.
func writeOutput(_ *cobra.Command, format, outputFile string, scanResult output.ScanResult, signCBOM bool) error {
	// Validate format before creating the file to avoid truncating existing output.
	if _, ok := output.LookupWriter(format); !ok {
		return fmt.Errorf("unknown format: %s (supported: %v)", format, output.SupportedFormats())
	}

	var w io.Writer = os.Stdout
	var f *os.File
	if outputFile != "" {
		var err error
		f, err = os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		w = f
	}

	var writeErr error
	if signCBOM && (format == "cbom" || format == "cyclonedx") {
		writeErr = writeSignedCBOM(w, scanResult)
	} else {
		writeErr = output.WriteFormat(format, w, scanResult)
	}

	if writeErr != nil {
		if f != nil {
			f.Close() // best-effort cleanup; original writeErr is more relevant
		}
		return writeErr
	}

	// fsync THEN close. Without Sync(), the most recent buffered writes
	// can be lost if the host loses power between Close() and the kernel
	// flushing its page cache. Close() alone gives no guarantee the bytes
	// reached disk. saveLocalCBOM (line ~1933) follows the same
	// Sync→Close pattern; mirror it here for any --output writer.
	if f != nil {
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return fmt.Errorf("sync output file: %w", err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("close output file: %w", err)
		}
	}

	return nil
}

// writeSignedCBOM generates an ephemeral Ed25519 key pair, signs the CBOM, and
// writes the SignedCBOM JSON envelope to w. The public key is embedded in the
// envelope so consumers can verify provenance without a separate key store.
func writeSignedCBOM(w io.Writer, scanResult output.ScanResult) error {
	// Render the raw CBOM into a buffer first.
	var buf bytes.Buffer
	if err := output.WriteCBOM(&buf, scanResult); err != nil {
		return fmt.Errorf("generate CBOM for signing: %w", err)
	}

	// Generate a fresh ephemeral key pair for this scan.
	_, priv, err := cbomutil.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate signing key: %w", err)
	}

	// Sign the CBOM bytes.
	envelope, err := cbomutil.Sign(buf.Bytes(), priv)
	if err != nil {
		return fmt.Errorf("sign CBOM: %w", err)
	}

	// Write the SignedCBOM envelope as indented JSON.
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(envelope); err != nil {
		return fmt.Errorf("encode signed CBOM: %w", err)
	}

	fmt.Fprintf(os.Stderr, "CBOM signed with ephemeral Ed25519 key (public key: %s)\n", envelope.PublicKey)
	return nil
}
