// Command necropsy dissects binaries: ELF and PE.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/rephuren/necropsy/internal/elfx"
	"github.com/rephuren/necropsy/internal/pex"
)

const maxFile = 256 << 20 // refuse to load more than 256 MiB

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: necropsy inspect [--json] FILE")
}

func run(args []string, out, errw io.Writer) int {
	if len(args) == 0 || args[0] != "inspect" {
		usage(errw)
		return 2
	}
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(errw)
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		usage(errw)
		return 2
	}
	data, err := readFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		return 1
	}
	var rep report
	switch {
	case bytes.HasPrefix(data, []byte("\x7fELF")):
		f, err := elfx.Parse(data)
		if err != nil {
			fmt.Fprintln(errw, "error:", err)
			return 1
		}
		rep = summarize(fs.Arg(0), f)
	case bytes.HasPrefix(data, []byte("MZ")):
		f, err := pex.Parse(data)
		if err != nil {
			fmt.Fprintln(errw, "error:", err)
			return 1
		}
		rep = summarizePE(fs.Arg(0), f)
	default:
		fmt.Fprintln(errw, "error: not an ELF or PE file")
		return 1
	}
	if *asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return 0
	}
	rep.Text(out)
	return 0
}

func readFile(path string) ([]byte, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > maxFile {
		return nil, errors.New("file too large")
	}
	return io.ReadAll(io.LimitReader(fh, maxFile))
}
