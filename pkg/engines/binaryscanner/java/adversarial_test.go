package java

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Adversarial fixture tests for the Java classfile parser. These tests
// hand-craft malformed class file byte slices that target specific known or
// suspected failure modes: constant pool OOB indices, cyclic Utf8 references,
// integer overflow in attribute/length fields, and negative-int casts.
//
// The primary invariant is that ParseClassFile MUST NOT panic on any input.
// Each test here documents a specific adversarial byte pattern and asserts
// the parser either rejects it with an error or returns a safe summary.

// helperWriteHeader writes the minimal class-file prelude (magic + version)
// to b, defaulting to Java 17 (major=61).
func helperWriteHeader(b *classFileBuilder) {
	b.writeMagicAndVersion(61)
}

// ---------------------------------------------------------------------------
// A1: cpCount=0 edge case. cpCount is 1-based; 0 is invalid but the parser
// currently tolerates it by iterating `for i := 1; i < 0` (never). Must not
// panic — but also must not misrepresent data.
// ---------------------------------------------------------------------------

func TestAdversarial_CpCountZero(t *testing.T) {
	b := &classFileBuilder{}
	helperWriteHeader(b)
	b.writeU16(0) // cpCount=0 — spec violation (must be >= 1)

	// Parser should not panic. It may either error or return an empty summary.
	// Today it returns an empty summary silently — document as low-severity.
	_, err := ParseClassFile(bytes.NewReader(b.buf.Bytes()))
	_ = err // accept either outcome — focus is non-panic
}

// ---------------------------------------------------------------------------
// A2: CP entry's Class.classIndex points into a Long/Double PHANTOM slot.
// The phantom slot is initialised to a zero cpEntry (tag=0), so the lookup
// check `nameEntry.tag == tagUtf8` filters it out. Must not panic.
// ---------------------------------------------------------------------------

func TestAdversarial_ClassIndexIntoPhantomSlot(t *testing.T) {
	// cpCount=4: slot1=Long(phantom slot2), slot3=Class(index=2)
	data := buildMinimalClass(61, 4, func(b *classFileBuilder) {
		b.writeLong(0, 0)   // occupies slot 1 (phantom slot 2 is zero)
		b.writeClass(2)     // slot 3: points at phantom slot 2
	})

	ev, err := ParseClassFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(ev.APIsDetected) != 0 {
		t.Errorf("phantom slot lookup must not produce an API match, got %v", ev.APIsDetected)
	}
}

// ---------------------------------------------------------------------------
// A3: CP entry's Class.classIndex points OUT OF BOUNDS (>= cpCount).
// Code path: `if int(e.classIndex) < int(cpCount)` — properly gated.
// ---------------------------------------------------------------------------

func TestAdversarial_ClassIndexOutOfBounds(t *testing.T) {
	// cpCount=2: slot1=Class(index=9999). Index 9999 >> cpCount.
	data := buildMinimalClass(61, 2, func(b *classFileBuilder) {
		b.writeClass(9999)
	})

	ev, err := ParseClassFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(ev.APIsDetected) != 0 {
		t.Errorf("OOB classIndex must not match, got %v", ev.APIsDetected)
	}
}

// ---------------------------------------------------------------------------
// A4: CP entry's Class.classIndex points at index 0 (reserved/unused per JVMS).
// The reserved slot has tag=0 so the tagUtf8 guard filters it out. Must not panic.
// ---------------------------------------------------------------------------

func TestAdversarial_ClassIndexZero(t *testing.T) {
	// cpCount=2: slot1=Class(index=0). Slot 0 is reserved zero entry.
	data := buildMinimalClass(61, 2, func(b *classFileBuilder) {
		b.writeClass(0)
	})

	ev, err := ParseClassFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(ev.APIsDetected) != 0 {
		t.Errorf("classIndex=0 must not match, got %v", ev.APIsDetected)
	}
}

// ---------------------------------------------------------------------------
// A5: Maximum cpCount (0xFFFF) with truncated pool. Parser should return an
// io error when it runs out of input, not allocate 64K stubs and panic.
// ---------------------------------------------------------------------------

func TestAdversarial_MaxCpCountTruncated(t *testing.T) {
	b := &classFileBuilder{}
	helperWriteHeader(b)
	b.writeU16(0xFFFF) // cpCount=65535 — near max
	// Write a single Utf8 entry then stop. Parser must error, not panic.
	b.writeU8(tagUtf8)
	b.writeU16(3)
	b.buf.WriteString("AES")

	_, err := ParseClassFile(bytes.NewReader(b.buf.Bytes()))
	if err == nil {
		t.Fatal("expected truncation error, got nil")
	}
}

// ---------------------------------------------------------------------------
// A6: Utf8 length = 0xFFFF (max). Parser must tolerate a 64KB allocation.
// ---------------------------------------------------------------------------

func TestAdversarial_MaxLengthUtf8(t *testing.T) {
	b := &classFileBuilder{}
	helperWriteHeader(b)
	b.writeU16(2) // cpCount=2 (one entry)
	b.writeU8(tagUtf8)
	b.writeU16(0xFFFF) // length = 65535
	payload := make([]byte, 0xFFFF)
	for i := range payload {
		payload[i] = 'A'
	}
	b.buf.Write(payload)

	ev, err := ParseClassFile(bytes.NewReader(b.buf.Bytes()))
	if err != nil {
		t.Fatalf("parse error on max Utf8 length: %v", err)
	}
	_ = ev
}

// ---------------------------------------------------------------------------
// A7: Utf8 length declared larger than remaining bytes (io.ErrUnexpectedEOF).
// ---------------------------------------------------------------------------

func TestAdversarial_Utf8LengthTooLarge(t *testing.T) {
	b := &classFileBuilder{}
	helperWriteHeader(b)
	b.writeU16(2) // cpCount=2
	b.writeU8(tagUtf8)
	b.writeU16(1000) // claims 1000 bytes
	b.buf.WriteString("AES") // but only 3 available

	_, err := ParseClassFile(bytes.NewReader(b.buf.Bytes()))
	if err == nil {
		t.Fatal("expected truncation error for oversized utf8 length")
	}
}

// ---------------------------------------------------------------------------
// A8: Unknown/reserved CP tag value returns a parse error (not a panic).
// Covers all unused tag bytes in the spec (2, 13, 14, 21..255).
// ---------------------------------------------------------------------------

func TestAdversarial_UnknownTags(t *testing.T) {
	unknownTags := []byte{2, 13, 14, 21, 100, 200, 255}
	for _, tag := range unknownTags {
		b := &classFileBuilder{}
		helperWriteHeader(b)
		b.writeU16(2) // cpCount=2
		b.writeU8(tag)
		_, err := ParseClassFile(bytes.NewReader(b.buf.Bytes()))
		if err == nil {
			t.Errorf("tag %d: expected parse error, got nil", tag)
		}
	}
}

// ---------------------------------------------------------------------------
// A9: Back-to-back Long/Double entries (each consumes 2 slots). Verify the
// `i++` skip advances correctly when several long/double entries abut.
// ---------------------------------------------------------------------------

func TestAdversarial_AdjacentLongDouble(t *testing.T) {
	// cpCount=7: long(1,2), double(3,4), long(5,6), Utf8 at 7? Too many slots.
	// Layout: slot1=Long(phantom 2), slot3=Double(phantom 4), slot5=Long(phantom 6)
	// cpCount=7 (indices 0..6).
	data := buildMinimalClass(61, 7, func(b *classFileBuilder) {
		b.writeLong(0, 1)
		b.writeDouble(0, 2)
		b.writeLong(0, 3)
	})

	ev, err := ParseClassFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(ev.APIsDetected) != 0 || len(ev.AlgorithmStrings) != 0 {
		t.Errorf("expected empty evidence, got APIs=%v strings=%v",
			ev.APIsDetected, ev.AlgorithmStrings)
	}
}

// ---------------------------------------------------------------------------
// A10: Final slot is a Long, which declares a phantom slot that does not fit
// within cpCount. The parser's `i++` will bump `i` past cpCount-1 but the
// for-loop condition `i < cpCount` terminates the loop. Must not panic.
// ---------------------------------------------------------------------------

func TestAdversarial_LongAtLastSlot(t *testing.T) {
	// cpCount=2: slot1=Long (declares phantom slot 2 that equals cpCount).
	// Spec violation but must not panic.
	data := buildMinimalClass(61, 2, func(b *classFileBuilder) {
		b.writeLong(0, 0)
	})

	_, err := ParseClassFile(bytes.NewReader(data))
	_ = err // accept error or success; primary invariant is non-panic
}

// ---------------------------------------------------------------------------
// A11: Pathological case — cyclic Class → Utf8 chains. The code does NOT
// recursively dereference; it only reads one level (Class → Utf8). But we
// want to confirm there's no unexpected recursion path.
// ---------------------------------------------------------------------------

func TestAdversarial_ClassSelfReference(t *testing.T) {
	// slot1=Class(index=1) — points to itself.
	// slot 1's tag is tagClass, not tagUtf8, so no match.
	data := buildMinimalClass(61, 2, func(b *classFileBuilder) {
		b.writeClass(1) // self-reference
	})

	ev, err := ParseClassFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(ev.APIsDetected) != 0 {
		t.Errorf("self-referential class must not match, got %v", ev.APIsDetected)
	}
}

// ---------------------------------------------------------------------------
// A12: Deeply nested Class→Class→Utf8 — the parser only follows one level, so
// a Class whose classIndex points at another Class (not Utf8) must not match.
// ---------------------------------------------------------------------------

func TestAdversarial_ClassChain(t *testing.T) {
	// slot1=Class(index=2), slot2=Class(index=3), slot3=Utf8("javax/crypto/Cipher")
	// The code checks `nameEntry.tag == tagUtf8` — slot 2 is Class, so the chain
	// breaks at slot1 and no API is detected.
	data := buildMinimalClass(61, 4, func(b *classFileBuilder) {
		b.writeClass(2)
		b.writeClass(3)
		b.writeUtf8("javax/crypto/Cipher")
	})

	ev, err := ParseClassFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	// slot3 Utf8 has no classifying algorithm string so AlgorithmStrings=[].
	// slot1 Class→slot2 is a Class, not Utf8, so APIsDetected=[].
	// But slot2 Class→slot3 IS a Utf8 "javax/crypto/Cipher" — detected!
	foundViaSlot2 := false
	for _, api := range ev.APIsDetected {
		if api == "javax/crypto/Cipher" {
			foundViaSlot2 = true
		}
	}
	if !foundViaSlot2 {
		t.Errorf("expected slot2->slot3 chain to detect Cipher, got %v", ev.APIsDetected)
	}
}

// ---------------------------------------------------------------------------
// A13: Magic number immediately EOF. Already covered in classfile_test.go but
// added here explicitly for the adversarial inventory.
// ---------------------------------------------------------------------------

func TestAdversarial_OnlyMagic(t *testing.T) {
	data := []byte{0xCA, 0xFE, 0xBA, 0xBE}
	_, err := ParseClassFile(bytes.NewReader(data))
	if err == nil {
		t.Fatal("expected truncation error after magic, got nil")
	}
}

// ---------------------------------------------------------------------------
// A14: Utf8 entry containing embedded NUL bytes — Go strings tolerate this but
// downstream classifiers must not mis-handle them.
// ---------------------------------------------------------------------------

func TestAdversarial_Utf8WithNULBytes(t *testing.T) {
	data := []byte{
		0xCA, 0xFE, 0xBA, 0xBE, // magic
		0x00, 0x00, 0x00, 0x3D, // minor=0 major=61
		0x00, 0x02, // cpCount=2
		tagUtf8,
		0x00, 0x05, // length=5
		'A', 'E', 0x00, 'S', 0x00, // "AE\0S\0"
	}
	_, err := ParseClassFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse error on NUL-embedded utf8: %v", err)
	}
}

// ---------------------------------------------------------------------------
// A15: cpCount claims 1 entry but provides trailing garbage. Current code
// stops at the last valid entry so the garbage is ignored.
// ---------------------------------------------------------------------------

func TestAdversarial_TrailingGarbage(t *testing.T) {
	b := &classFileBuilder{}
	helperWriteHeader(b)
	b.writeU16(2) // cpCount=2
	b.writeUtf8("AES")
	// Append garbage — should be ignored.
	for i := 0; i < 100; i++ {
		b.writeU8(0xFF)
	}
	_, err := ParseClassFile(bytes.NewReader(b.buf.Bytes()))
	if err != nil {
		t.Errorf("unexpected parse error on trailing garbage: %v", err)
	}
}

// ---------------------------------------------------------------------------
// A16: The "integer overflow on attribute_length / negative-int cast from u4"
// threat from the audit focus list. The classfile parser currently does not
// read attribute tables — it only reads the constant pool and returns.
// Document this gap: attributes are not parsed, so no overflow path exists
// here. Adding a marker test makes the assertion explicit.
// ---------------------------------------------------------------------------

func TestAdversarial_AttributeOverflowNotApplicable(t *testing.T) {
	// Build a minimal class that would have attribute data after the CP.
	// The parser returns after the CP, so the attribute bytes are simply left
	// in the reader. Any u4 attribute_length would therefore be ignored.
	data := buildMinimalClass(61, 2, func(b *classFileBuilder) {
		b.writeUtf8("AES")
	})
	// Append what would be a spec u4 with value 0xFFFFFFFF.
	data = append(data, 0xFF, 0xFF, 0xFF, 0xFF)
	_, err := ParseClassFile(bytes.NewReader(data))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// A17: Sanity helper — cpCount=1 with no entries is valid per spec.
// ---------------------------------------------------------------------------

func TestAdversarial_CpCountOneEmpty(t *testing.T) {
	data := buildMinimalClass(61, 1, func(b *classFileBuilder) {})
	ev, err := ParseClassFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if ev.JavaVersion != 61 {
		t.Errorf("JavaVersion = %d, want 61", ev.JavaVersion)
	}
}

// ---------------------------------------------------------------------------
// Helpers — ensure encoding/binary.Write import is used.
// ---------------------------------------------------------------------------

var _ = binary.BigEndian
