package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func linuxBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	_ = os.WriteFile(src, []byte("package main\nfunc main(){}\n"), 0o644)
	out := filepath.Join(dir, "prog")
	cmd := exec.Command("go", "build", "-o", out, src)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot build fixture: %v\n%s", err, b)
	}
	return out
}

func TestInspectTextAndJSON(t *testing.T) {
	path := linuxBinary(t)
	var out, errb bytes.Buffer
	if code := run([]string{"inspect", path}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "ELF 64-bit x86-64") || !strings.Contains(out.String(), "hardening:") {
		t.Errorf("unexpected text output:\n%s", out.String())
	}
	out.Reset()
	if code := run([]string{"inspect", "--json", path}, &out, &errb); code != 0 {
		t.Fatal("json exit", code)
	}
	var rep map[string]any
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil || rep["format"] != "ELF" {
		t.Errorf("bad json: %v %s", err, out.String())
	}
}

func TestInspectErrors(t *testing.T) {
	var out, errb bytes.Buffer
	if run(nil, &out, &errb) != 2 || run([]string{"inspect"}, &out, &errb) != 2 {
		t.Error("usage errors must exit 2")
	}
	if run([]string{"inspect", filepath.Join(t.TempDir(), "missing")}, &out, &errb) != 1 {
		t.Error("missing file must exit 1")
	}
	txt := filepath.Join(t.TempDir(), "a.txt")
	_ = os.WriteFile(txt, []byte("hello"), 0o644)
	if run([]string{"inspect", txt}, &out, &errb) != 1 || !strings.Contains(errb.String(), "not an ELF") {
		t.Error("non-ELF must exit 1 with a clear message")
	}
}
