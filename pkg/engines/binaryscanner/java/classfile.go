// Package java implements Java binary artifact scanning for the OQS PQC scanner.
// It parses Java class file constant pools and JAR/WAR/EAR archives to detect
// cryptographic API usage and algorithm strings.
package java

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// Java class-file constant pool tag values (JVMS §4.4).
const (
	tagUtf8               = 1
	tagInteger            = 3
	tagFloat              = 4
	tagLong               = 5
	tagDouble             = 6
	tagClass              = 7
	tagString             = 8
	tagFieldref           = 9
	tagMethodref          = 10
	tagInterfaceMethodref = 11
	tagNameAndType        = 12
	tagMethodHandle       = 15
	tagMethodType         = 16
	tagDynamic            = 17
	tagInvokeDynamic      = 18
	tagModule             = 19
	tagPackage            = 20
)

// javaMagic is the class-file magic number (CAFEBABE).
const javaMagic uint32 = 0xCAFEBABE

// cpEntry holds the data extracted from a single constant-pool entry that is
// relevant to crypto detection. Tags not listed here are parsed but not stored
// in detail.
type cpEntry struct {
	tag              byte
	utf8             string // valid when tag == tagUtf8
	classIndex       uint16 // valid when tag == tagClass
	nameAndTypeIndex uint16 // valid when tag == tagNameAndType (or ref types)
}

// AlgorithmRef records an algorithm string found in the constant pool together
// with a description of where it was found.
type AlgorithmRef struct {
	Value  string
	Source string
}

// CryptoEvidence summarises the crypto-related data found in a single class file.
type CryptoEvidence struct {
	// APIsDetected lists JVM internal class names (slash-separated) that match
	// known cryptographic API packages.
	APIsDetected []string

	// AlgorithmStrings holds Utf8 constant pool entries that classify as
	// known algorithm identifier strings.
	AlgorithmStrings []AlgorithmRef

	// JavaVersion is the major class-file version number (e.g. 61 = Java 17).
	JavaVersion int
}

// cryptoAPIPackages is the set of JVM internal class-name prefixes (or exact
// names) that indicate use of a cryptographic API.
var cryptoAPIPackages = []string{
	"javax/crypto/Cipher",
	"javax/crypto/KeyGenerator",
	"javax/crypto/Mac",
	"javax/crypto/KeyAgreement",
	"javax/crypto/SecretKeyFactory",
	"javax/crypto/spec/",
	"javax/crypto/",
	"java/security/MessageDigest",
	"java/security/Signature",
	"java/security/KeyPairGenerator",
	"java/security/KeyFactory",
	"javax/net/ssl/SSLContext",
	"org/bouncycastle/",
	"com/google/crypto/tink/",
	"software/amazon/cryptography/",
}

// ParseClassFile reads a Java class file from r, parses the constant pool, and
// returns a CryptoEvidence summary. It returns an error when the data is not a
// valid Java class file.
func ParseClassFile(r io.Reader) (*CryptoEvidence, error) {
	// --- Magic number ---
	var magic uint32
	if err := binary.Read(r, binary.BigEndian, &magic); err != nil {
		return nil, fmt.Errorf("read magic: %w", err)
	}
	if magic != javaMagic {
		return nil, fmt.Errorf("not a Java class file: bad magic 0x%08X", magic)
	}

	// --- Minor / Major version ---
	var minorVersion, majorVersion uint16
	if err := binary.Read(r, binary.BigEndian, &minorVersion); err != nil {
		return nil, fmt.Errorf("read minor version: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &majorVersion); err != nil {
		return nil, fmt.Errorf("read major version: %w", err)
	}

	// --- Constant pool count (1-based) ---
	var cpCount uint16
	if err := binary.Read(r, binary.BigEndian, &cpCount); err != nil {
		return nil, fmt.Errorf("read constant pool count: %w", err)
	}
	// cpCount is 1-based; there are (cpCount-1) actual entries.
	// Note: cpCount is uint16 (max 65535) per JVM spec §4.1.
	entries := make([]cpEntry, int(cpCount))

	// i starts at 1 because slot 0 is unused by the spec.
	for i := 1; i < int(cpCount); i++ {
		var tag byte
		if err := binary.Read(r, binary.BigEndian, &tag); err != nil {
			return nil, fmt.Errorf("constant pool entry %d tag: %w", i, err)
		}

		entry, skip, err := readCPEntry(r, tag)
		if err != nil {
			return nil, fmt.Errorf("constant pool entry %d (tag %d): %w", i, tag, err)
		}
		entries[i] = entry

		if skip {
			// Long (5) and Double (6) consume two constant pool slots.
			i++
			// Leave the phantom slot as a zero cpEntry.
		}
	}

	ev := &CryptoEvidence{
		JavaVersion: int(majorVersion),
	}

	// --- Scan entries for crypto evidence ---
	for i := 1; i < int(cpCount); i++ {
		e := &entries[i]
		switch e.tag {
		case tagClass:
			// Resolve the class name from the Utf8 entry pointed to by classIndex.
			if int(e.classIndex) < int(cpCount) {
				nameEntry := &entries[e.classIndex]
				if nameEntry.tag == tagUtf8 {
					if isCryptoAPI(nameEntry.utf8) {
						ev.APIsDetected = append(ev.APIsDetected, nameEntry.utf8)
					}
				}
			}
		case tagUtf8:
			// Scan Utf8 constants for algorithm identifier strings.
			if ca := classifyAlgorithmString(e.utf8); ca != nil {
				ev.AlgorithmStrings = append(ev.AlgorithmStrings, AlgorithmRef{
					Value:  e.utf8,
					Source: "constant-pool-utf8",
				})
			}
		}
	}

	return ev, nil
}

// readCPEntry reads a single constant-pool entry body (after the tag byte has
// been read). It returns the cpEntry, whether the next slot should be skipped
// (Long/Double), and any read error.
func readCPEntry(r io.Reader, tag byte) (cpEntry, bool, error) {
	e := cpEntry{tag: tag}

	switch tag {
	case tagUtf8:
		var length uint16
		if err := binary.Read(r, binary.BigEndian, &length); err != nil {
			return e, false, fmt.Errorf("utf8 length: %w", err)
		}
		buf := make([]byte, length)
		if _, err := io.ReadFull(r, buf); err != nil {
			return e, false, fmt.Errorf("utf8 bytes: %w", err)
		}
		e.utf8 = string(buf)

	case tagInteger, tagFloat:
		// 4 bytes — discard.
		if _, err := io.ReadFull(r, make([]byte, 4)); err != nil {
			return e, false, fmt.Errorf("integer/float bytes: %w", err)
		}

	case tagLong, tagDouble:
		// 8 bytes — discard; the next cp slot is also consumed.
		if _, err := io.ReadFull(r, make([]byte, 8)); err != nil {
			return e, false, fmt.Errorf("long/double bytes: %w", err)
		}
		return e, true, nil // signal caller to skip next slot

	case tagClass:
		var idx uint16
		if err := binary.Read(r, binary.BigEndian, &idx); err != nil {
			return e, false, fmt.Errorf("class name index: %w", err)
		}
		e.classIndex = idx

	case tagString:
		// 2-byte index into constant pool — discard.
		if _, err := io.ReadFull(r, make([]byte, 2)); err != nil {
			return e, false, fmt.Errorf("string index bytes: %w", err)
		}

	case tagFieldref, tagMethodref, tagInterfaceMethodref:
		// class_index (u2) + name_and_type_index (u2).
		var classIdx, natIdx uint16
		if err := binary.Read(r, binary.BigEndian, &classIdx); err != nil {
			return e, false, fmt.Errorf("ref class index: %w", err)
		}
		if err := binary.Read(r, binary.BigEndian, &natIdx); err != nil {
			return e, false, fmt.Errorf("ref name_and_type index: %w", err)
		}
		e.classIndex = classIdx
		e.nameAndTypeIndex = natIdx

	case tagNameAndType:
		// name_index (u2) + descriptor_index (u2).
		if _, err := io.ReadFull(r, make([]byte, 4)); err != nil {
			return e, false, fmt.Errorf("name_and_type bytes: %w", err)
		}

	case tagMethodHandle:
		// reference_kind (u1) + reference_index (u2).
		if _, err := io.ReadFull(r, make([]byte, 3)); err != nil {
			return e, false, fmt.Errorf("method handle bytes: %w", err)
		}

	case tagMethodType:
		// descriptor_index (u2).
		if _, err := io.ReadFull(r, make([]byte, 2)); err != nil {
			return e, false, fmt.Errorf("method type bytes: %w", err)
		}

	case tagDynamic, tagInvokeDynamic:
		// bootstrap_method_attr_index (u2) + name_and_type_index (u2).
		if _, err := io.ReadFull(r, make([]byte, 4)); err != nil {
			return e, false, fmt.Errorf("dynamic/invokedynamic bytes: %w", err)
		}

	case tagModule, tagPackage:
		// name_index (u2).
		if _, err := io.ReadFull(r, make([]byte, 2)); err != nil {
			return e, false, fmt.Errorf("module/package bytes: %w", err)
		}

	default:
		return e, false, fmt.Errorf("unknown constant pool tag %d", tag)
	}

	return e, false, nil
}

// isCryptoAPI reports whether the JVM internal class name (slash-separated)
// matches a known cryptographic API class or package prefix.
func isCryptoAPI(className string) bool {
	for _, prefix := range cryptoAPIPackages {
		if strings.HasPrefix(className, prefix) || className == strings.TrimSuffix(prefix, "/") {
			return true
		}
	}
	return false
}
