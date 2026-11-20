package elfx

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// goLinux builds a tiny Linux program with the Go toolchain: a real ELF produced by someone else, used as the reference.
func goLinux(t *testing.T, goarch string, extra ...string) []byte {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte("package main\nimport \"fmt\"\nfunc main(){ fmt.Println(\"x\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "prog")
	args := append([]string{"build", "-o", out}, extra...)
	cmd := exec.Command("go", append(args, src)...)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot build fixture: %v\n%s", err, b)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestMatchesStdlibOnRealBinaries(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64", "386"} {
		data := goLinux(t, arch)
		mine, err := Parse(data)
		if err != nil {
			t.Fatalf("%s: %v", arch, err)
		}
		ref, err := elf.NewFile(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		if mine.Entry != ref.Entry || uint16(ref.Machine) != mine.Machine || uint16(ref.Type) != mine.Type {
			t.Errorf("%s: header mismatch: %+v vs %+v", arch, mine.Entry, ref.Entry)
		}
		if mine.Is64 != (ref.Class == elf.ELFCLASS64) {
			t.Errorf("%s: class mismatch", arch)
		}
		if len(mine.Segments) != len(ref.Progs) {
			t.Fatalf("%s: segments %d vs %d", arch, len(mine.Segments), len(ref.Progs))
		}
		for i, p := range ref.Progs {
			s := mine.Segments[i]
			if uint32(p.Type) != s.Type || uint32(p.Flags) != s.Flags || p.Off != s.Offset || p.Vaddr != s.VAddr || p.Filesz != s.FileSize || p.Memsz != s.MemSize {
				t.Errorf("%s: segment %d differs", arch, i)
			}
		}
		if len(mine.Sections) != len(ref.Sections) {
			t.Fatalf("%s: sections %d vs %d", arch, len(mine.Sections), len(ref.Sections))
		}
		for i, sec := range ref.Sections {
			m := mine.Sections[i]
			sizeOK := sec.Size == m.Size || (m.Compressed && sec.Flags&elf.SHF_COMPRESSED != 0) // stdlib reports the decompressed size
			if sec.Name != m.Name || uint32(sec.Type) != m.Type || sec.Addr != m.Addr || sec.Offset != m.Offset || !sizeOK {
				t.Errorf("%s: section %d (%s) differs: %+v", arch, i, sec.Name, m)
			}
		}
		syms, _ := ref.Symbols()
		var mineSyms int
		for _, s := range mine.Symbols {
			if !s.Dynamic {
				mineSyms++
			}
		}
		if mineSyms != len(syms)+1 { // debug/elf skips the mandatory null symbol, we keep it
			t.Errorf("%s: symbols %d vs %d", arch, mineSyms, len(syms)+1)
		}
	}
}

func TestStaticGoBinaryHardening(t *testing.T) {
	f, _ := Parse(goLinux(t, "amd64"))
	h := f.Hardening()
	if !h.Static || h.PIE || !h.NX || h.RELRO != "none" || h.Canary {
		t.Errorf("unexpected hardening %+v", h)
	}
}

func TestPIEAndStrippedGoBinary(t *testing.T) {
	f, err := Parse(goLinux(t, "amd64", "-buildmode=pie", "-ldflags=-s -w"))
	if err != nil {
		t.Fatal(err)
	}
	h := f.Hardening()
	if f.Type != ET_DYN || !h.Stripped {
		t.Errorf("want ET_DYN and stripped, got type %d %+v", f.Type, h)
	}
}

// minimalELF64 builds a tiny hand-made executable with the given program headers.
func minimalELF64(segs [][4]uint32) []byte {
	var b bytes.Buffer
	hdr := make([]byte, 64)
	copy(hdr, "\x7fELF\x02\x01\x01")
	binary.LittleEndian.PutUint16(hdr[16:], ET_EXEC)
	binary.LittleEndian.PutUint16(hdr[18:], 62)
	binary.LittleEndian.PutUint64(hdr[32:], 64)
	binary.LittleEndian.PutUint16(hdr[52:], 64)
	binary.LittleEndian.PutUint16(hdr[54:], 56)
	binary.LittleEndian.PutUint16(hdr[56:], uint16(len(segs)))
	b.Write(hdr)
	for _, s := range segs { // s = type, flags, offset, size
		ph := make([]byte, 56)
		binary.LittleEndian.PutUint32(ph[0:], s[0])
		binary.LittleEndian.PutUint32(ph[4:], s[1])
		binary.LittleEndian.PutUint64(ph[8:], uint64(s[2]))
		binary.LittleEndian.PutUint64(ph[16:], 0x400000+uint64(s[2]))
		binary.LittleEndian.PutUint64(ph[32:], uint64(s[3]))
		binary.LittleEndian.PutUint64(ph[40:], uint64(s[3]))
		b.Write(ph)
	}
	return b.Bytes()
}

func TestNXRWXAndMissingGnuStack(t *testing.T) {
	f, _ := Parse(minimalELF64([][4]uint32{{PT_LOAD, 7, 0, 64}, {PT_GNU_STACK, 6, 0, 0}}))
	h := f.Hardening()
	if !h.NX || len(h.RWX) != 1 {
		t.Errorf("NX stack with RWX load: %+v", h)
	}
	f, _ = Parse(minimalELF64([][4]uint32{{PT_LOAD, 5, 0, 64}}))
	h = f.Hardening()
	if h.NX || len(h.Notes) == 0 {
		t.Errorf("missing PT_GNU_STACK must mean executable stack: %+v", h)
	}
	f, _ = Parse(minimalELF64([][4]uint32{{PT_LOAD, 5, 0, 64}, {PT_GNU_STACK, 7, 0, 0}}))
	if f.Hardening().NX {
		t.Error("RWX stack must not be NX")
	}
}

func TestRejectsNonELFAndBigEndian(t *testing.T) {
	if _, err := Parse([]byte("MZ not an elf")); err != ErrNotELF {
		t.Errorf("got %v", err)
	}
	be := minimalELF64(nil)
	be[5] = 2
	if _, err := Parse(be); err == nil {
		t.Error("big-endian must be rejected")
	}
}

// Truncating or corrupting a real file must never panic or hang.
func TestTruncatedAndCorruptedInputNeverPanics(t *testing.T) {
	data := goLinux(t, "amd64")
	for cut := 0; cut < len(data) && cut < 4096; cut += 3 {
		_, _ = Parse(data[:cut])
	}
	for cut := 4096; cut < len(data); cut += len(data) / 40 {
		_, _ = Parse(data[:cut])
	}
	for i := 0; i < 400; i++ {
		mut := append([]byte(nil), data[:8192]...)
		for k := 0; k < 8; k++ {
			mut[(i*131+k*977)%len(mut)] ^= byte(i + k*37 + 1)
		}
		_, _ = Parse(mut)
	}
}

func TestEntropy(t *testing.T) {
	if Entropy(bytes.Repeat([]byte{7}, 1000)) != 0 {
		t.Error("constant data must have zero entropy")
	}
	all := make([]byte, 0, 256*4)
	for i := 0; i < 1024; i++ {
		all = append(all, byte(i))
	}
	if e := Entropy(all); e < 7.99 || e > 8.0001 {
		t.Errorf("uniform data entropy %f", e)
	}
}
