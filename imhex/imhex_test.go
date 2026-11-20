package imhex

import (
	"os"
	"strings"
	"testing"
)

// The patterns are not run in ImHex here, so this only checks what can be checked as text.
func TestPatternsAreStructurallySane(t *testing.T) {
	want := map[string][]string{
		"elf64.hexpat": {"struct Header", "struct ProgramHeader", "struct SectionHeader", "@ header.phoff", "@ header.shoff"},
		"pe.hexpat":    {"struct DosHeader", "struct CoffHeader", "struct OptionalHeader64", "struct OptionalHeader32", "struct SectionHeader", "0x20B"},
	}
	for file, needles := range want {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		for _, n := range needles {
			if !strings.Contains(src, n) {
				t.Errorf("%s: missing %q", file, n)
			}
		}
		if strings.Count(src, "{") != strings.Count(src, "}") {
			t.Errorf("%s: unbalanced braces", file)
		}
		if !strings.Contains(src, "#pragma endian little") || !strings.Contains(src, "#pragma magic") {
			t.Errorf("%s: missing pragmas", file)
		}
	}
}
