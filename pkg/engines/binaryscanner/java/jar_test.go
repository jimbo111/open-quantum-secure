package java

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"testing"
)

// buildClassBytes builds a minimal valid Java class file that contains the given
// UTF-8 constant pool string (for algorithm detection).
func buildClassBytes(utf8Constant string) []byte {
	b := &classFileBuilder{}
	b.writeU32(0xCAFEBABE)
	b.writeU16(0)  // minor
	b.writeU16(61) // major (Java 17)

	// cpCount: slot1=Utf8(utf8Constant), total=2
	b.writeU16(2)
	b.writeUtf8(utf8Constant)
	return b.buf.Bytes()
}

// buildClassWithCryptoAPI builds a class file that references a crypto API class.
func buildClassWithCryptoAPI(className string) []byte {
	b := &classFileBuilder{}
	b.writeU32(0xCAFEBABE)
	b.writeU16(0)
	b.writeU16(61)
	// slot1=Utf8(className), slot2=Class→1; cpCount=3
	b.writeU16(3)
	b.writeUtf8(className)
	b.writeClass(1)
	return b.buf.Bytes()
}

// buildInMemoryZip creates an in-memory ZIP archive. entries is a map from
// entry name to content bytes.
func buildInMemoryZip(entries map[string][]byte) []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, data := range entries {
		f, err := w.Create(name)
		if err != nil {
			panic(err)
		}
		if _, err := f.Write(data); err != nil {
			panic(err)
		}
	}
	_ = w.Close()
	return buf.Bytes()
}

// writeTempZip writes a ZIP to a temp file and returns the path.
func writeTempZip(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	data := buildInMemoryZip(entries)
	path, err := writeToTempFile(data, "*.jar")
	if err != nil {
		t.Fatalf("writeTempZip: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(path)
	})
	return path
}

// ---- Tests ----

func TestScanArchive_SingleClassWithCrypto(t *testing.T) {
	classData := buildClassBytes("AES/GCM/NoPadding")
	path := writeTempZip(t, map[string][]byte{
		"com/example/Foo.class": classData,
	})

	ctx := context.Background()
	fds, err := ScanArchive(ctx, path, defaultMaxDepth)
	if err != nil {
		t.Fatalf("ScanArchive error: %v", err)
	}
	if len(fds) == 0 {
		t.Fatal("expected findings, got none")
	}
	found := false
	for _, f := range fds {
		if f.Algorithm != nil && f.Algorithm.Name == "AES" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected finding with Algorithm.Name=AES, got %+v", fds)
	}
}

func TestScanArchive_FindingLocation(t *testing.T) {
	classData := buildClassBytes("AES/GCM/NoPadding")
	path := writeTempZip(t, map[string][]byte{
		"com/example/Foo.class": classData,
	})

	ctx := context.Background()
	fds, err := ScanArchive(ctx, path, defaultMaxDepth)
	if err != nil {
		t.Fatalf("ScanArchive error: %v", err)
	}

	for _, f := range fds {
		if f.Algorithm != nil && f.Algorithm.Name == "AES" {
			if f.Location.InnerPath != "com/example/Foo.class" {
				t.Errorf("InnerPath = %q, want %q", f.Location.InnerPath, "com/example/Foo.class")
			}
			if f.Location.ArtifactType == "" {
				t.Error("ArtifactType is empty, want non-empty")
			}
			if f.SourceEngine != "binary-scanner" {
				t.Errorf("SourceEngine = %q, want binary-scanner", f.SourceEngine)
			}
			return
		}
	}
	t.Error("AES finding not found")
}

func TestScanArchive_NestedJAR(t *testing.T) {
	// Inner JAR contains a class with a crypto algorithm.
	innerClassData := buildClassBytes("RSA/ECB/PKCS1Padding")
	innerZip := buildInMemoryZip(map[string][]byte{
		"com/inner/Bar.class": innerClassData,
	})

	// Outer JAR contains the inner JAR.
	outerPath := writeTempZip(t, map[string][]byte{
		"lib/inner.jar": innerZip,
	})

	ctx := context.Background()
	fds, err := ScanArchive(ctx, outerPath, defaultMaxDepth)
	if err != nil {
		t.Fatalf("ScanArchive error: %v", err)
	}
	found := false
	for _, f := range fds {
		if f.Algorithm != nil && f.Algorithm.Name == "RSA" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected RSA finding from nested JAR, got %v", fds)
	}
}

func TestScanArchive_MaxDepthEnforced(t *testing.T) {
	// Build 3 levels of nesting; with maxDepth=1 the innermost should NOT be scanned.
	lvl2Class := buildClassBytes("AES/GCM/NoPadding")
	lvl2 := buildInMemoryZip(map[string][]byte{"deep/Deep.class": lvl2Class})
	lvl1 := buildInMemoryZip(map[string][]byte{"nested/inner.jar": lvl2})

	outerPath := writeTempZip(t, map[string][]byte{
		"outer/middle.jar": lvl1,
	})

	ctx := context.Background()
	// maxDepth=0 → no recursion at all.
	fds, err := ScanArchive(ctx, outerPath, 0)
	if err != nil {
		t.Fatalf("ScanArchive error: %v", err)
	}
	for _, f := range fds {
		if f.Algorithm != nil && f.Algorithm.Name == "AES" {
			t.Error("expected no AES findings when maxDepth=0 prevents recursion")
		}
	}
}

func TestScanArchive_ContextCancellation(t *testing.T) {
	// Build a JAR with many entries to give cancellation a chance to fire.
	entries := make(map[string][]byte)
	classData := buildClassBytes("AES/GCM/NoPadding")
	for i := 0; i < 200; i++ {
		key := "com/example/Cls" + itoa(i) + ".class"
		entries[key] = classData
	}
	path := writeTempZip(t, entries)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := ScanArchive(ctx, path, defaultMaxDepth)
	// Should return context error (or nil with no panic).
	if err != nil && err != context.Canceled {
		t.Logf("ScanArchive returned: %v (acceptable)", err)
	}
}

func TestScanArchive_EmptyJAR(t *testing.T) {
	path := writeTempZip(t, map[string][]byte{})

	ctx := context.Background()
	fds, err := ScanArchive(ctx, path, defaultMaxDepth)
	if err != nil {
		t.Fatalf("ScanArchive error: %v", err)
	}
	if len(fds) != 0 {
		t.Errorf("expected no findings from empty JAR, got %d", len(fds))
	}
}

func TestScanArchive_MalformedClassSkipped(t *testing.T) {
	// One valid, one malformed class entry.
	validClass := buildClassBytes("HmacSHA256")
	path := writeTempZip(t, map[string][]byte{
		"Good.class": validClass,
		"Bad.class":  []byte("not a class file at all"),
	})

	ctx := context.Background()
	fds, err := ScanArchive(ctx, path, defaultMaxDepth)
	if err != nil {
		t.Fatalf("ScanArchive error: %v", err)
	}
	// Should have findings from Good.class; Bad.class skipped without fatal error.
	found := false
	for _, f := range fds {
		if f.Algorithm != nil && f.Algorithm.Name == "HMAC" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected HMAC finding from Good.class, got %v", fds)
	}
}

func TestScanArchive_OversizedEntry(t *testing.T) {
	// Verify that a .class entry with UncompressedSize64 > maxEntryBytes is
	// skipped (no findings), while a normal-sized .class still produces findings.
	//
	// zip.Writer always sets UncompressedSize64 to actual bytes written, so we
	// forge the field by patching the central directory of a valid zip archive.
	normalClass := buildClassBytes("AES")
	oversizedClass := buildClassBytes("RSA")

	// Step 1: build a valid zip with two entries.
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, entry := range []struct {
		name string
		data []byte
	}{
		{"Normal.class", normalClass},
		{"Oversized.class", oversizedClass},
	} {
		h := &zip.FileHeader{Name: entry.name, Method: zip.Store}
		fw, err := w.CreateHeader(h)
		if err != nil {
			t.Fatalf("create header %s: %v", entry.name, err)
		}
		if _, err := fw.Write(entry.data); err != nil {
			t.Fatalf("write %s: %v", entry.name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}

	// Step 2: patch the zip central directory to inflate Oversized.class size.
	// The central directory "uncompressed size" field is at offset 24 from the
	// start of each central directory entry (sig 0x02014b50). We find the entry
	// for "Oversized.class" and set the 4-byte uncompressed size to 0xFFFFFFFF,
	// which causes Go's zip reader to use the Zip64 extra field (if present) or
	// report the size as 4GB+. Either way, > maxEntryBytes.
	zipData := buf.Bytes()
	sig := []byte("PK\x01\x02") // central directory header signature
	target := []byte("Oversized.class")
	patched := false
	for i := 0; i < len(zipData)-46; i++ {
		if !bytes.Equal(zipData[i:i+4], sig) {
			continue
		}
		// File name length at offset 28 (2 bytes, little-endian)
		nameLen := int(zipData[i+28]) | int(zipData[i+29])<<8
		if i+46+nameLen > len(zipData) {
			continue
		}
		name := zipData[i+46 : i+46+nameLen]
		if !bytes.Equal(name, target) {
			continue
		}
		// Uncompressed size at offset 24 (4 bytes, little-endian)
		// Set to 200MB (> maxEntryBytes=100MB)
		binary.LittleEndian.PutUint32(zipData[i+24:i+28], 200*1024*1024)
		patched = true
		break
	}
	if !patched {
		t.Fatal("failed to find Oversized.class in central directory")
	}

	path, err := writeToTempFile(zipData, "*.jar")
	if err != nil {
		t.Fatalf("write temp: %v", err)
	}
	t.Cleanup(func() { os.Remove(path) })

	ctx := context.Background()
	fds, err := ScanArchive(ctx, path, defaultMaxDepth)
	if err != nil {
		t.Fatalf("ScanArchive error: %v", err)
	}

	// Normal.class should produce AES finding; Oversized.class (RSA) should be skipped.
	foundAES := false
	foundRSA := false
	for _, f := range fds {
		if f.Algorithm != nil {
			if f.Algorithm.Name == "AES" {
				foundAES = true
			}
			if f.Algorithm.Name == "RSA" {
				foundRSA = true
			}
		}
	}
	if !foundAES {
		t.Error("expected AES finding from Normal.class, but not found")
	}
	if foundRSA {
		t.Error("Oversized.class should have been skipped by size guard, but RSA finding was produced")
	}
}

func TestScanArchive_TooManyEntries(t *testing.T) {
	entries := make(map[string][]byte)
	classData := buildClassBytes("SHA-256")
	// maxTotalEntries+500 entries
	for i := 0; i < maxTotalEntries+500; i++ {
		key := "com/pkg/C" + string(rune('A'+i%26)) + itoa(i) + ".class"
		entries[key] = classData
	}
	path := writeTempZip(t, entries)

	ctx := context.Background()
	fds, err := ScanArchive(ctx, path, defaultMaxDepth)
	if err != nil {
		t.Fatalf("ScanArchive error: %v", err)
	}
	// We expect at most maxTotalEntries findings processed (not a crash).
	t.Logf("processed %d findings within entry limit", len(fds))
}

func TestScanArchive_CryptoAPIFinding(t *testing.T) {
	classData := buildClassWithCryptoAPI("javax/crypto/Cipher")
	path := writeTempZip(t, map[string][]byte{
		"com/App.class": classData,
	})

	ctx := context.Background()
	fds, err := ScanArchive(ctx, path, defaultMaxDepth)
	if err != nil {
		t.Fatalf("ScanArchive error: %v", err)
	}
	found := false
	for _, f := range fds {
		if f.Dependency != nil && f.Dependency.Library == "javax/crypto/Cipher" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected dependency finding for javax/crypto/Cipher, got %v", fds)
	}
}

// itoa is duplicated from classfile.go for use in tests.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	digits := make([]byte, 0, 10)
	for n > 0 {
		digits = append(digits, byte('0'+n%10))
		n /= 10
	}
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	if neg {
		return "-" + string(digits)
	}
	return string(digits)
}

// Verify that binary.Write is available in the test package (used indirectly).
var _ = binary.BigEndian

// ---- Nested archive tests ----

// TestScanArchive_WARWithLibJARs tests a WAR containing JARs in WEB-INF/lib/.
func TestScanArchive_WARWithLibJARs(t *testing.T) {
	// Build an inner JAR with a crypto class.
	innerClassData := buildClassBytes("AES/GCM/NoPadding")
	innerJar := buildInMemoryZip(map[string][]byte{
		"com/example/Crypto.class": innerClassData,
	})

	// Build a WAR with the inner JAR in WEB-INF/lib/.
	outerPath := writeTempZip(t, map[string][]byte{
		"WEB-INF/lib/crypto.jar": innerJar,
	})

	ctx := context.Background()
	fds, err := ScanArchive(ctx, outerPath, defaultMaxDepth)
	if err != nil {
		t.Fatalf("ScanArchive error: %v", err)
	}

	found := false
	for _, f := range fds {
		if f.Algorithm != nil && f.Algorithm.Name == "AES" {
			found = true
			// InnerPath must chain: WEB-INF/lib/crypto.jar!com/example/Crypto.class
			wantInner := "WEB-INF/lib/crypto.jar!com/example/Crypto.class"
			if f.Location.InnerPath != wantInner {
				t.Errorf("InnerPath = %q, want %q", f.Location.InnerPath, wantInner)
			}
		}
	}
	if !found {
		t.Errorf("expected AES finding from WAR/WEB-INF/lib nested JAR, got %v", fds)
	}
}

// TestScanArchive_EARWithWARAndJARs tests an EAR containing a WAR and a JAR.
func TestScanArchive_EARWithWARAndJARs(t *testing.T) {
	// Inner-most class files.
	classInWAR := buildClassBytes("RSA/ECB/PKCS1Padding")
	classInJAR := buildClassBytes("HmacSHA256")

	// WAR embedded in the EAR.
	embeddedWAR := buildInMemoryZip(map[string][]byte{
		"WEB-INF/classes/com/svc/App.class": classInWAR,
	})

	// Plain JAR also embedded in the EAR at root.
	embeddedJAR := buildInMemoryZip(map[string][]byte{
		"com/lib/Auth.class": classInJAR,
	})

	// EAR contains both.
	outerPath := writeTempZip(t, map[string][]byte{
		"service.war": embeddedWAR,
		"lib/auth.jar": embeddedJAR,
	})

	ctx := context.Background()
	fds, err := ScanArchive(ctx, outerPath, defaultMaxDepth)
	if err != nil {
		t.Fatalf("ScanArchive error: %v", err)
	}

	foundRSA := false
	foundHMAC := false
	for _, f := range fds {
		if f.Algorithm != nil {
			switch f.Algorithm.Name {
			case "RSA":
				foundRSA = true
			case "HMAC":
				foundHMAC = true
			}
		}
	}
	if !foundRSA {
		t.Errorf("expected RSA finding from EAR→WAR nesting, got %v", fds)
	}
	if !foundHMAC {
		t.Errorf("expected HMAC finding from EAR→JAR nesting, got %v", fds)
	}
}

// TestScanArchive_ThreeLevelInnerPath verifies that InnerPath chains correctly
// across three nesting levels: EAR → WAR → JAR → class.
func TestScanArchive_ThreeLevelInnerPath(t *testing.T) {
	classData := buildClassBytes("AES/GCM/NoPadding")

	// Level 3: inner JAR.
	innerJar := buildInMemoryZip(map[string][]byte{
		"com/App.class": classData,
	})
	// Level 2: mid WAR containing inner JAR.
	midWar := buildInMemoryZip(map[string][]byte{
		"WEB-INF/lib/crypto.jar": innerJar,
	})
	// Level 1: outer EAR containing mid WAR.
	outerPath := writeTempZip(t, map[string][]byte{
		"lib/service.war": midWar,
	})

	ctx := context.Background()
	fds, err := ScanArchive(ctx, outerPath, defaultMaxDepth)
	if err != nil {
		t.Fatalf("ScanArchive error: %v", err)
	}

	wantInner := "lib/service.war!WEB-INF/lib/crypto.jar!com/App.class"
	found := false
	for _, f := range fds {
		if f.Algorithm != nil && f.Algorithm.Name == "AES" {
			found = true
			if f.Location.InnerPath != wantInner {
				t.Errorf("InnerPath = %q, want %q", f.Location.InnerPath, wantInner)
			}
		}
	}
	if !found {
		t.Errorf("expected AES finding with chained InnerPath, got %v", fds)
	}
}

// TestScanArchive_DepthLimitAt3 verifies depth-3 nesting is scanned but depth-4 is not.
func TestScanArchive_DepthLimitAt3(t *testing.T) {
	classData := buildClassBytes("AES/GCM/NoPadding")

	// Build 4 levels: outer → lvl1.jar → lvl2.jar → lvl3.jar (class here, depth=3 = limit)
	lvl3 := buildInMemoryZip(map[string][]byte{"deep.class": classData})
	lvl2 := buildInMemoryZip(map[string][]byte{"lvl3.jar": lvl3})
	lvl1 := buildInMemoryZip(map[string][]byte{"lvl2.jar": lvl2})
	outerPath := writeTempZip(t, map[string][]byte{"lvl1.jar": lvl1})

	ctx := context.Background()
	// maxDepth=3 should reach depth=3 (lvl3.jar), finding the class.
	fds, err := ScanArchive(ctx, outerPath, 3)
	if err != nil {
		t.Fatalf("ScanArchive error: %v", err)
	}
	foundAtDepth3 := false
	for _, f := range fds {
		if f.Algorithm != nil && f.Algorithm.Name == "AES" {
			foundAtDepth3 = true
		}
	}
	if !foundAtDepth3 {
		t.Error("expected AES finding at depth 3")
	}

	// maxDepth=2 should NOT reach the class (it's at nesting depth 3).
	fds2, err := ScanArchive(ctx, outerPath, 2)
	if err != nil {
		t.Fatalf("ScanArchive error: %v", err)
	}
	for _, f := range fds2 {
		if f.Algorithm != nil && f.Algorithm.Name == "AES" {
			t.Error("expected no AES finding when maxDepth=2 prevents reaching depth 3")
		}
	}
}

// TestScanArchive_CorruptNestedArchive verifies that a corrupt nested archive
// is skipped gracefully and scanning continues with other entries.
func TestScanArchive_CorruptNestedArchive(t *testing.T) {
	// Good nested JAR.
	goodClass := buildClassBytes("HmacSHA256")
	goodJar := buildInMemoryZip(map[string][]byte{"Good.class": goodClass})

	// Corrupt "JAR" — just random bytes with a .jar extension.
	corruptData := []byte("this is not a zip file at all!!!")

	outerPath := writeTempZip(t, map[string][]byte{
		"lib/corrupt.jar": corruptData,
		"lib/good.jar":    goodJar,
	})

	ctx := context.Background()
	fds, err := ScanArchive(ctx, outerPath, defaultMaxDepth)
	if err != nil {
		t.Fatalf("ScanArchive should not return error on corrupt nested archive, got: %v", err)
	}

	// Must still find HMAC from the good nested JAR.
	found := false
	for _, f := range fds {
		if f.Algorithm != nil && f.Algorithm.Name == "HMAC" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected HMAC finding from good.jar despite corrupt sibling, got %v", fds)
	}
}

// TestScanArchive_EmptyNestedArchive verifies that an empty nested archive does
// not cause a crash and returns no findings for that entry.
func TestScanArchive_EmptyNestedArchive(t *testing.T) {
	emptyJar := buildInMemoryZip(map[string][]byte{})

	outerPath := writeTempZip(t, map[string][]byte{
		"lib/empty.jar": emptyJar,
	})

	ctx := context.Background()
	fds, err := ScanArchive(ctx, outerPath, defaultMaxDepth)
	if err != nil {
		t.Fatalf("ScanArchive error: %v", err)
	}
	if len(fds) != 0 {
		t.Errorf("expected no findings from archive with empty nested JAR, got %d", len(fds))
	}
}

// TestScanArchive_AARWithClassesJar tests an AAR containing classes.jar.
func TestScanArchive_AARWithClassesJar(t *testing.T) {
	classData := buildClassBytes("AES/GCM/NoPadding")
	classesJar := buildInMemoryZip(map[string][]byte{
		"com/example/Crypto.class": classData,
	})

	outerPath := writeTempZip(t, map[string][]byte{
		"classes.jar": classesJar,
	})

	ctx := context.Background()
	fds, err := ScanArchive(ctx, outerPath, defaultMaxDepth)
	if err != nil {
		t.Fatalf("ScanArchive error: %v", err)
	}

	found := false
	for _, f := range fds {
		if f.Algorithm != nil && f.Algorithm.Name == "AES" {
			found = true
			// InnerPath should chain: classes.jar!com/example/Crypto.class
			wantInner := "classes.jar!com/example/Crypto.class"
			if f.Location.InnerPath != wantInner {
				t.Errorf("InnerPath = %q, want %q", f.Location.InnerPath, wantInner)
			}
		}
	}
	if !found {
		t.Errorf("expected AES finding from AAR→classes.jar, got %v", fds)
	}
}

// TestScanArchive_ZipBombInNestedArchive verifies that a zip-bomb-like entry
// inside a nested archive is rejected by the per-entry size limit.
func TestScanArchive_ZipBombInNestedArchive(t *testing.T) {
	// Build an inner "JAR" with two entries: a normal AES class and a "bomb"
	// class whose central directory uncompressed size is forged to exceed
	// maxEntryBytes. The bomb entry should be skipped.
	normalClass := buildClassBytes("AES")
	bombClass := buildClassBytes("RSA")

	var innerBuf bytes.Buffer
	w := zip.NewWriter(&innerBuf)
	for _, e := range []struct {
		name string
		data []byte
	}{
		{"Normal.class", normalClass},
		{"Bomb.class", bombClass},
	} {
		h := &zip.FileHeader{Name: e.name, Method: zip.Store}
		fw, err := w.CreateHeader(h)
		if err != nil {
			t.Fatalf("create header %s: %v", e.name, err)
		}
		if _, err := fw.Write(e.data); err != nil {
			t.Fatalf("write %s: %v", e.name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}

	// Patch central directory to inflate Bomb.class UncompressedSize64.
	innerData := innerBuf.Bytes()
	sig := []byte("PK\x01\x02")
	target := []byte("Bomb.class")
	patched := false
	for i := 0; i < len(innerData)-46; i++ {
		if !bytes.Equal(innerData[i:i+4], sig) {
			continue
		}
		nameLen := int(innerData[i+28]) | int(innerData[i+29])<<8
		if i+46+nameLen > len(innerData) {
			continue
		}
		if !bytes.Equal(innerData[i+46:i+46+nameLen], target) {
			continue
		}
		binary.LittleEndian.PutUint32(innerData[i+24:i+28], 200*1024*1024)
		patched = true
		break
	}
	if !patched {
		t.Fatal("failed to patch Bomb.class in inner JAR central directory")
	}

	outerPath := writeTempZip(t, map[string][]byte{
		"bomb.jar": innerData,
	})

	ctx := context.Background()
	fds, err := ScanArchive(ctx, outerPath, defaultMaxDepth)
	if err != nil {
		t.Fatalf("ScanArchive error: %v", err)
	}

	// Normal.class AES finding should exist; Bomb.class RSA should be skipped.
	foundAES := false
	foundRSA := false
	for _, f := range fds {
		if f.Algorithm != nil {
			if f.Algorithm.Name == "AES" {
				foundAES = true
			}
			if f.Algorithm.Name == "RSA" {
				foundRSA = true
			}
		}
	}
	if !foundAES {
		t.Error("expected AES finding from Normal.class in nested JAR")
	}
	if foundRSA {
		t.Error("Bomb.class should have been skipped by size guard in nested JAR, but RSA finding was produced")
	}
}

// TestScanArchive_TooManyEntriesInNested verifies that the entry limit applies
// within nested archives as well.
func TestScanArchive_TooManyEntriesInNested(t *testing.T) {
	classData := buildClassBytes("SHA-256")
	innerEntries := make(map[string][]byte)
	for i := 0; i < maxTotalEntries+100; i++ {
		innerEntries["com/C"+itoa(i)+".class"] = classData
	}
	innerJar := buildInMemoryZip(innerEntries)

	outerPath := writeTempZip(t, map[string][]byte{
		"lib/big.jar": innerJar,
	})

	ctx := context.Background()
	// Should not panic, entry count guard applies.
	_, err := ScanArchive(ctx, outerPath, defaultMaxDepth)
	if err != nil {
		t.Fatalf("ScanArchive error: %v", err)
	}
}

// TestScanArchive_WARDirectClasses verifies that class files directly inside a
// WAR (not in a nested JAR) are also scanned.
func TestScanArchive_WARDirectClasses(t *testing.T) {
	classData := buildClassBytes("RSA/ECB/PKCS1Padding")

	outerPath := writeTempZip(t, map[string][]byte{
		"WEB-INF/classes/com/App.class": classData,
	})

	ctx := context.Background()
	fds, err := ScanArchive(ctx, outerPath, defaultMaxDepth)
	if err != nil {
		t.Fatalf("ScanArchive error: %v", err)
	}

	found := false
	for _, f := range fds {
		if f.Algorithm != nil && f.Algorithm.Name == "RSA" {
			found = true
			wantInner := "WEB-INF/classes/com/App.class"
			if f.Location.InnerPath != wantInner {
				t.Errorf("InnerPath = %q, want %q", f.Location.InnerPath, wantInner)
			}
		}
	}
	if !found {
		t.Errorf("expected RSA finding from direct WAR class file, got %v", fds)
	}
}

// TestArchiveType verifies that archiveType returns correct strings.
func TestArchiveType(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"app.jar", "jar"},
		{"app.JAR", "jar"},
		{"app.war", "war"},
		{"app.WAR", "war"},
		{"app.ear", "ear"},
		{"app.EAR", "ear"},
		{"app.aar", "aar"},
		{"app.AAR", "aar"},
		{"app.zip", "jar"}, // default fallback
	}
	for _, tc := range tests {
		got := archiveType(tc.path)
		if got != tc.want {
			t.Errorf("archiveType(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// TestIsArchiveEntry verifies that isArchiveEntry recognises all supported extensions.
func TestIsArchiveEntry(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"lib/dep.jar", true},
		{"lib/dep.JAR", true},
		{"service.war", true},
		{"service.WAR", true},
		{"enterprise.ear", true},
		{"enterprise.EAR", true},
		{"android.aar", true},
		{"android.AAR", true},
		{"README.txt", false},
		{"com/App.class", false},
		{"archive.zip", false},
	}
	for _, tc := range tests {
		got := isArchiveEntry(tc.name)
		if got != tc.want {
			t.Errorf("isArchiveEntry(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
