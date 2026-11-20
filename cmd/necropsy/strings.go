package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/rephuren/necropsy/internal/strx"
)

func runStrings(args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("strings", flag.ContinueOnError)
	fs.SetOutput(errw)
	min := fs.Int("min", 6, "minimum string length")
	all := fs.Bool("all", false, "include plain strings (by default only classified ones)")
	classes := fs.String("class", "", "comma-separated classes to show (url,ip,email,path,registry,private-key,base64,api)")
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil {
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
	want := map[strx.Class]bool{}
	for _, c := range strings.Split(*classes, ",") {
		if c = strings.TrimSpace(c); c != "" {
			want[strx.Class(c)] = true
		}
	}
	items := strx.Extract(data, *min)
	summary := strx.Summary(items)
	var shown []strx.Item
	for _, it := range items {
		if len(want) > 0 && !want[it.Class] {
			continue
		}
		if len(want) == 0 && !*all && it.Class == strx.Plain {
			continue
		}
		shown = append(shown, it)
	}
	if *asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"file": fs.Arg(0), "summary": summary, "strings": shown})
		return 0
	}
	for _, it := range shown {
		text := it.Text
		if len(text) > 160 {
			text = text[:160] + "..."
		}
		fmt.Fprintf(out, "%08x  %-11s %-7s %s\n", it.Offset, it.Class, it.Encoding, text)
	}
	var keys []string
	for c, n := range summary {
		keys = append(keys, fmt.Sprintf("%s %d", c, n))
	}
	sort.Strings(keys)
	fmt.Fprintf(out, "summary: %s\n", strings.Join(keys, " · "))
	return 0
}
