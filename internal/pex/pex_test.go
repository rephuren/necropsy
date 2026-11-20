package pex

import (
	"bytes"
	"debug/pe"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func goWindows(t *testing.T, goarch string) []byte {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	_ = os.WriteFile(src, []byte("package main\nimport \"fmt\"\nfunc main(){ fmt.Println(\"x\") }\n"), 0o644)
	out := filepath.Join(dir, "prog.exe")
	cmd := exec.Command("go", "build", "-o", out, src)
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH="+goarch, "CGO_ENABLED=0")
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
	for _, arch := range []string{"amd64", "386", "arm64"} {
		data := goWindows(t, arch)
		mine, err := Parse(data)
		if err != nil {
			t.Fatalf("%s: %v", arch, err)
		}
		ref, err := pe.NewFile(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		if uint16(ref.Machine) != mine.Machine || ref.TimeDateStamp != mine.Timestamp {
			t.Errorf("%s: header mismatch", arch)
		}
		if len(ref.Sections) != len(mine.Sections) {
			t.Fatalf("%s: sections %d vs %d", arch, len(ref.Sections), len(mine.Sections))
		}
		for i, s := range ref.Sections {
			m := mine.Sections[i]
			if s.Name != m.Name || s.VirtualAddress != m.RVA || s.VirtualSize != m.VirtualSize || s.Size != m.RawSize || s.Offset != m.RawOffset || s.Characteristics != m.Characteristics {
				t.Errorf("%s: section %d (%s) differs", arch, i, s.Name)
			}
		}
		switch oh := ref.OptionalHeader.(type) {
		case *pe.OptionalHeader64:
			if !mine.Is64 || oh.AddressOfEntryPoint != mine.EntryRVA || oh.ImageBase != mine.ImageBase || oh.DllCharacteristics != mine.DllCharacteristics || oh.Subsystem != mine.Subsystem {
				t.Errorf("%s: optional header differs", arch)
			}
		case *pe.OptionalHeader32:
			if mine.Is64 || oh.AddressOfEntryPoint != mine.EntryRVA || uint64(oh.ImageBase) != mine.ImageBase || oh.DllCharacteristics != mine.DllCharacteristics || oh.Subsystem != mine.Subsystem {
				t.Errorf("%s: optional header differs", arch)
			}
		}
		refImports, _ := ref.ImportedSymbols() // entries look like "Name:dll.dll"
		var got []string
		for _, imp := range mine.Imports {
			for _, fn := range imp.Functions {
				got = append(got, fn+":"+imp.DLL)
			}
		}
		sort.Strings(refImports)
		sort.Strings(got)
		if strings.Join(refImports, "|") != strings.Join(got, "|") {
			t.Errorf("%s: imports differ: %d vs %d", arch, len(refImports), len(got))
		}
	}
}

func TestHardeningOfGoBinary(t *testing.T) {
	f, _ := Parse(goWindows(t, "amd64"))
	h := f.Hardening()
	if !h.ASLR || !h.DEP || h.Signed {
		t.Errorf("unexpected hardening %+v", h)
	}
	if f.EntrySection() != ".text" {
		t.Errorf("entry section %q", f.EntrySection())
	}
}

func TestRejectsNonPE(t *testing.T) {
	for _, in := range [][]byte{[]byte("hello"), []byte("MZ" + strings.Repeat("\x00", 100)), nil} {
		if _, err := Parse(in); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

func TestTruncatedAndCorruptedInputNeverPanics(t *testing.T) {
	data := goWindows(t, "amd64")
	for cut := 0; cut < len(data) && cut < 4096; cut += 3 {
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
