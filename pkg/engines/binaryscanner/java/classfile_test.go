package java

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// classFileBuilder is a helper to construct minimal valid Java class file bytes.
type classFileBuilder struct {
	buf bytes.Buffer
}

func (b *classFileBuilder) writeU32(v uint32) {
	_ = binary.Write(&b.buf, binary.BigEndian, v)
}
func (b *classFileBuilder) writeU16(v uint16) {
	_ = binary.Write(&b.buf, binary.BigEndian, v)
}
func (b *classFileBuilder) writeU8(v uint8) {
	b.buf.WriteByte(v)
}

// writeMagicAndVersion writes the standard header (magic + minor + major).
func (b *classFileBuilder) writeMagicAndVersion(major uint16) {
	b.writeU32(0xCAFEBABE)
	b.writeU16(0)     // minor version
	b.writeU16(major) // major version
}

// writeUtf8 writes a CONSTANT_Utf8 entry.
func (b *classFileBuilder) writeUtf8(s string) {
	b.writeU8(tagUtf8)
	b.writeU16(uint16(len(s)))
	b.buf.WriteString(s)
}

// writeClass writes a CONSTANT_Class entry referencing utf8 slot idx.
func (b *classFileBuilder) writeClass(nameIdx uint16) {
	b.writeU8(tagClass)
	b.writeU16(nameIdx)
}

// writeLong writes a CONSTANT_Long entry (consumes 2 cp slots).
func (b *classFileBuilder) writeLong(hi, lo uint32) {
	b.writeU8(tagLong)
	b.writeU32(hi)
	b.writeU32(lo)
}

// writeDouble writes a CONSTANT_Double entry (consumes 2 cp slots).
func (b *classFileBuilder) writeDouble(hi, lo uint32) {
	b.writeU8(tagDouble)
	b.writeU32(hi)
	b.writeU32(lo)
}

// writeInteger writes a CONSTANT_Integer entry.
func (b *classFileBuilder) writeInteger(v uint32) {
	b.writeU8(tagInteger)
	b.writeU32(v)
}

// writeMethodref writes a CONSTANT_Methodref entry.
func (b *classFileBuilder) writeMethodref(classIdx, natIdx uint16) {
	b.writeU8(tagMethodref)
	b.writeU16(classIdx)
	b.writeU16(natIdx)
}

// writeNameAndType writes a CONSTANT_NameAndType entry.
func (b *classFileBuilder) writeNameAndType(nameIdx, descIdx uint16) {
	b.writeU8(tagNameAndType)
	b.writeU16(nameIdx)
	b.writeU16(descIdx)
}

// buildMinimalClass creates a valid empty class file with the given constant pool entries
// pre-constructed.  cpCount must be (1 + number of actual entries + phantom slots).
func buildMinimalClass(major uint16, cpCount uint16, writeEntries func(*classFileBuilder)) []byte {
	b := &classFileBuilder{}
	b.writeMagicAndVersion(major)
	b.writeU16(cpCount)
	writeEntries(b)
	return b.buf.Bytes()
}

// ---- Tests ----

func TestParseClassFile_ValidWithCryptoAPI(t *testing.T) {
	// Build a class file whose constant pool contains:
	//  slot 1: Utf8 "javax/crypto/Cipher"
	//  slot 2: Class → slot 1
	// cpCount = 3 (slots 0, 1, 2)
	data := buildMinimalClass(61, 3, func(b *classFileBuilder) {
		b.writeUtf8("javax/crypto/Cipher")
		b.writeClass(1) // references slot 1
	})

	ev, err := ParseClassFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ParseClassFile error: %v", err)
	}
	if len(ev.APIsDetected) == 0 {
		t.Error("expected APIsDetected to contain javax/crypto/Cipher, got none")
	} else if ev.APIsDetected[0] != "javax/crypto/Cipher" {
		t.Errorf("APIsDetected[0] = %q, want %q", ev.APIsDetected[0], "javax/crypto/Cipher")
	}
	if ev.JavaVersion != 61 {
		t.Errorf("JavaVersion = %d, want 61", ev.JavaVersion)
	}
}

func TestParseClassFile_InvalidMagic(t *testing.T) {
	b := &classFileBuilder{}
	b.writeU32(0xDEADBEEF) // wrong magic
	b.writeU16(0)
	b.writeU16(61)
	b.writeU16(1) // empty cp

	_, err := ParseClassFile(bytes.NewReader(b.buf.Bytes()))
	if err == nil {
		t.Fatal("expected error for bad magic, got nil")
	}
}

func TestParseClassFile_TruncatedConstantPool(t *testing.T) {
	b := &classFileBuilder{}
	b.writeMagicAndVersion(61)
	b.writeU16(3) // claims 2 entries (slots 1, 2) but we only write 1
	b.writeUtf8("hello")
	// slot 2 is missing → truncated

	_, err := ParseClassFile(bytes.NewReader(b.buf.Bytes()))
	if err == nil {
		t.Fatal("expected error for truncated constant pool, got nil")
	}
}

func TestParseClassFile_LongDoubleSlotSkip(t *testing.T) {
	// Build: slot1=Long (consumes slots 1 & 2), slot3=Utf8("AES/GCM/NoPadding")
	// cpCount = 5 → slots 1,2 (Long phantom), 3 (Utf8), 4 (unused, we stop there)
	// Actually cpCount=4: slot1=Long→phantom at 2, slot3=Utf8("AES/GCM/NoPadding")
	data := buildMinimalClass(61, 4, func(b *classFileBuilder) {
		b.writeLong(0, 42) // slots 1 & 2
		b.writeUtf8("AES/GCM/NoPadding") // slot 3
	})

	ev, err := ParseClassFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ParseClassFile error: %v", err)
	}
	if len(ev.AlgorithmStrings) == 0 {
		t.Error("expected AlgorithmStrings to contain AES/GCM/NoPadding")
	}
}

func TestParseClassFile_DoubleSlotSkip(t *testing.T) {
	// slot1=Double, phantom slot2, slot3=Utf8("HmacSHA256")
	data := buildMinimalClass(61, 4, func(b *classFileBuilder) {
		b.writeDouble(0, 0) // slots 1 & 2
		b.writeUtf8("HmacSHA256") // slot 3
	})

	ev, err := ParseClassFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ParseClassFile error: %v", err)
	}
	found := false
	for _, a := range ev.AlgorithmStrings {
		if a.Value == "HmacSHA256" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected AlgorithmStrings to contain HmacSHA256, got %v", ev.AlgorithmStrings)
	}
}

func TestParseClassFile_CryptoAPIDetection(t *testing.T) {
	tests := []struct {
		name      string
		className string
	}{
		{"javax/crypto/Cipher", "javax/crypto/Cipher"},
		{"javax/crypto/KeyGenerator", "javax/crypto/KeyGenerator"},
		{"javax/crypto/Mac", "javax/crypto/Mac"},
		{"javax/crypto/KeyAgreement", "javax/crypto/KeyAgreement"},
		{"java/security/MessageDigest", "java/security/MessageDigest"},
		{"java/security/Signature", "java/security/Signature"},
		{"java/security/KeyPairGenerator", "java/security/KeyPairGenerator"},
		{"java/security/KeyFactory", "java/security/KeyFactory"},
		{"javax/crypto/SecretKeyFactory", "javax/crypto/SecretKeyFactory"},
		{"javax/net/ssl/SSLContext", "javax/net/ssl/SSLContext"},
		{"javax/crypto/spec/GCMParameterSpec", "javax/crypto/spec/GCMParameterSpec"},
		{"org/bouncycastle/crypto/CryptoEngine", "org/bouncycastle/crypto/CryptoEngine"},
		{"com/google/crypto/tink/Aead", "com/google/crypto/tink/Aead"},
		{"software/amazon/cryptography/Foo", "software/amazon/cryptography/Foo"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// slot1=Utf8(className), slot2=Class→1; cpCount=3
			data := buildMinimalClass(61, 3, func(b *classFileBuilder) {
				b.writeUtf8(tc.className)
				b.writeClass(1)
			})
			ev, err := ParseClassFile(bytes.NewReader(data))
			if err != nil {
				t.Fatalf("ParseClassFile error: %v", err)
			}
			found := false
			for _, api := range ev.APIsDetected {
				if api == tc.className {
					found = true
				}
			}
			if !found {
				t.Errorf("expected %q in APIsDetected, got %v", tc.className, ev.APIsDetected)
			}
		})
	}
}

func TestParseClassFile_AlgorithmStringExtraction(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"AES/GCM/NoPadding", "AES/GCM/NoPadding"},
		{"HmacSHA256", "HmacSHA256"},
		{"SHA-256", "SHA-256"},
		{"RSA/ECB/PKCS1Padding", "RSA/ECB/PKCS1Padding"},
		{"TLSv1.3", "TLSv1.3"},
		{"PBKDF2WithHmacSHA256", "PBKDF2WithHmacSHA256"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// slot1=Utf8(value); cpCount=2
			data := buildMinimalClass(61, 2, func(b *classFileBuilder) {
				b.writeUtf8(tc.value)
			})
			ev, err := ParseClassFile(bytes.NewReader(data))
			if err != nil {
				t.Fatalf("ParseClassFile error: %v", err)
			}
			found := false
			for _, a := range ev.AlgorithmStrings {
				if a.Value == tc.value {
					found = true
				}
			}
			if !found {
				t.Errorf("expected AlgorithmStrings to contain %q, got %v", tc.value, ev.AlgorithmStrings)
			}
		})
	}
}

func TestParseClassFile_UnknownTag(t *testing.T) {
	b := &classFileBuilder{}
	b.writeMagicAndVersion(61)
	b.writeU16(2) // 1 entry
	b.writeU8(99) // unknown tag

	_, err := ParseClassFile(bytes.NewReader(b.buf.Bytes()))
	if err == nil {
		t.Fatal("expected error for unknown tag, got nil")
	}
}

func TestParseClassFile_EmptyConstantPool(t *testing.T) {
	// cpCount=1 means 0 actual entries.
	data := buildMinimalClass(61, 1, func(b *classFileBuilder) {})

	ev, err := ParseClassFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ParseClassFile error: %v", err)
	}
	if len(ev.APIsDetected) != 0 {
		t.Errorf("expected no APIsDetected, got %v", ev.APIsDetected)
	}
	if len(ev.AlgorithmStrings) != 0 {
		t.Errorf("expected no AlgorithmStrings, got %v", ev.AlgorithmStrings)
	}
}

func TestParseClassFile_IntegerAndMethodref(t *testing.T) {
	// slot1=Utf8("getInstance"), slot2=Utf8("(Ljava/lang/String;)Ljavax/crypto/Cipher;"),
	// slot3=Utf8("javax/crypto/Cipher"), slot4=Class→3,
	// slot5=NameAndType(1,2), slot6=Methodref(4,5), slot7=Integer(42)
	// cpCount=8
	data := buildMinimalClass(61, 8, func(b *classFileBuilder) {
		b.writeUtf8("getInstance")                             // 1
		b.writeUtf8("(Ljava/lang/String;)Ljavax/crypto/Cipher;") // 2
		b.writeUtf8("javax/crypto/Cipher")                    // 3
		b.writeClass(3)                                        // 4 → slot3
		b.writeNameAndType(1, 2)                               // 5
		b.writeMethodref(4, 5)                                 // 6
		b.writeInteger(42)                                     // 7
	})

	ev, err := ParseClassFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ParseClassFile error: %v", err)
	}
	found := false
	for _, api := range ev.APIsDetected {
		if api == "javax/crypto/Cipher" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected javax/crypto/Cipher in APIsDetected, got %v", ev.APIsDetected)
	}
}

func TestParseClassFile_NonCryptoStringsNotExtracted(t *testing.T) {
	// Non-crypto Utf8 strings should NOT appear in AlgorithmStrings.
	data := buildMinimalClass(61, 4, func(b *classFileBuilder) {
		b.writeUtf8("UTF-8")   // 1 — encoding, not crypto
		b.writeUtf8("main")    // 2 — too short / non-crypto
		b.writeUtf8("java/lang/Object") // 3 — class path
	})

	ev, err := ParseClassFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ParseClassFile error: %v", err)
	}
	if len(ev.AlgorithmStrings) != 0 {
		t.Errorf("expected no AlgorithmStrings for non-crypto constants, got %v", ev.AlgorithmStrings)
	}
}
