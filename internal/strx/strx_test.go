package strx

import (
	"bytes"
	"strings"
	"testing"
)

func utf16le(s string) []byte {
	var b []byte
	for _, c := range []byte(s) {
		b = append(b, c, 0)
	}
	return b
}

func TestExtractsAsciiAndUTF16WithOffsets(t *testing.T) {
	var data []byte
	data = append(data, 0, 1, 2)
	data = append(data, []byte("hello-world")...)
	data = append(data, 0, 0xff)
	data = append(data, utf16le("wide string")...)
	data = append(data, 0, 0)
	items := Extract(data, 5)
	got := map[string]Item{}
	for _, it := range items {
		got[it.Text] = it
	}
	if it, ok := got["hello-world"]; !ok || it.Offset != 3 || it.Encoding != "ascii" {
		t.Errorf("ascii string: %+v", items)
	}
	if it, ok := got["wide string"]; !ok || it.Encoding != "utf16le" || it.Offset != 3+11+2 {
		t.Errorf("utf16 string: %+v", items)
	}
}

func TestMinLengthIsRespected(t *testing.T) {
	if n := len(Extract([]byte("\x00abcd\x00abcdef\x00"), 5)); n != 1 {
		t.Errorf("want 1 string of >=5 chars, got %d", n)
	}
}

func TestClassification(t *testing.T) {
	cases := map[string]Class{
		"http://example.test/a.sh":            URL,
		"connect to 203.0.113.7 now":          IP,
		"admin@corp.test":                     Email,
		"/etc/passwd":                         Path,
		`C:\Windows\System32\cmd.exe`:         Path,
		`HKLM\Software\Microsoft\Windows\Run`: Registry,
		"-----BEGIN OPENSSH PRIVATE KEY-----": KeyBlock,
		"VirtualAlloc":                        API,
		"execve":                              API,
		strings.Repeat("QUJD", 15):            Base64,
		"just some text":                      Plain,
		"999.999.999.999":                     Plain,
	}
	for in, want := range cases {
		if got := Classify(in); got != want {
			t.Errorf("Classify(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestVeryLongRunIsCut(t *testing.T) {
	items := Extract(bytes.Repeat([]byte("A"), 50000), 4)
	if len(items) != 1 || len(items[0].Text) != maxLen {
		t.Errorf("long run not cut: %d items", len(items))
	}
}

func TestSummaryLeavesOutPlain(t *testing.T) {
	m := Summary([]Item{{Class: URL}, {Class: URL}, {Class: Plain}, {Class: API}})
	if m[URL] != 2 || m[API] != 1 || len(m) != 2 {
		t.Errorf("summary %v", m)
	}
}
