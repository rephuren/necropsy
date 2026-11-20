// Package strx extracts printable strings from binaries and classifies them for triage.
package strx

import (
	"regexp"
	"sort"
	"strings"
)

type Class string

const (
	URL      Class = "url"
	IP       Class = "ip"
	Email    Class = "email"
	Path     Class = "path"
	Registry Class = "registry"
	KeyBlock Class = "private-key"
	Base64   Class = "base64"
	API      Class = "api"
	Plain    Class = "plain"
)

type Item struct {
	Offset   int    `json:"offset"`
	Encoding string `json:"encoding"` // ascii | utf16le
	Text     string `json:"text"`
	Class    Class  `json:"class"`
}

const maxLen = 4096 // a single "string" longer than this is cut: do not let one blob dominate the report

func printable(b byte) bool { return b == '\t' || (b >= 0x20 && b < 0x7f) }

// Extract returns ASCII and UTF-16LE strings of at least min characters, ordered by offset.
func Extract(data []byte, min int) []Item {
	if min < 3 {
		min = 3
	}
	var out []Item
	start := -1
	for i := 0; i <= len(data); i++ {
		if i < len(data) && printable(data[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= min {
			end := i
			if end-start > maxLen {
				end = start + maxLen
			}
			out = append(out, Item{Offset: start, Encoding: "ascii", Text: string(data[start:end])})
		}
		start = -1
	}
	// UTF-16LE: printable byte followed by 0x00, repeated
	var buf []byte
	begin := -1
	for i := 0; i+1 < len(data); i += 1 {
		if printable(data[i]) && data[i+1] == 0 {
			if begin < 0 {
				begin = i
			}
			buf = append(buf, data[i])
			i++
			continue
		}
		if len(buf) >= min {
			out = append(out, Item{Offset: begin, Encoding: "utf16le", Text: trim(buf)})
		}
		buf, begin = buf[:0], -1
	}
	if len(buf) >= min {
		out = append(out, Item{Offset: begin, Encoding: "utf16le", Text: trim(buf)})
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Offset < out[b].Offset })
	for i := range out {
		out[i].Class = Classify(out[i].Text)
	}
	return out
}

func trim(b []byte) string {
	if len(b) > maxLen {
		b = b[:maxLen]
	}
	return string(b)
}

var (
	reURL    = regexp.MustCompile(`(?i)\b(?:https?|ftp|ws|wss)://[^\s"'<>]{3,}`)
	reIP     = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	reEmail  = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
	rePath   = regexp.MustCompile(`(?:^|[\s"'=])(?:/(?:etc|usr|var|tmp|home|bin|proc|dev|root)/[^\s"']*|[A-Za-z]:\\[^\s"']+|\\\\[^\s"']+)`)
	reReg    = regexp.MustCompile(`(?i)\b(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[^\s"']+`)
	reKey    = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)
	reBase64 = regexp.MustCompile(`^[A-Za-z0-9+/]{40,}={0,2}$`)
)

// apis are imported or called names that are common in malware triage. Presence alone is not proof of anything:
// legitimate programs use all of them.
var apis = map[string]bool{
	"VirtualAlloc": true, "VirtualProtect": true, "WriteProcessMemory": true, "CreateRemoteThread": true, "OpenProcess": true,
	"LoadLibraryA": true, "LoadLibraryW": true, "GetProcAddress": true, "WinExec": true, "ShellExecuteA": true, "ShellExecuteW": true,
	"URLDownloadToFileA": true, "InternetOpenA": true, "InternetOpenUrlA": true, "RegSetValueExA": true, "RegSetValueExW": true,
	"IsDebuggerPresent": true, "CheckRemoteDebuggerPresent": true, "CryptEncrypt": true,
	"ptrace": true, "execve": true, "execl": true, "system": true, "popen": true, "dlopen": true, "dlsym": true, "mprotect": true,
	"fork": true, "socket": true, "connect": true, "bind": true, "listen": true, "setuid": true,
}

func Classify(s string) Class {
	switch {
	case reKey.MatchString(s):
		return KeyBlock
	case reURL.MatchString(s):
		return URL
	case reEmail.MatchString(s):
		return Email
	case reIP.MatchString(s):
		return IP
	case reReg.MatchString(s):
		return Registry
	case rePath.MatchString(s):
		return Path
	case apis[strings.TrimSpace(s)]:
		return API
	case reBase64.MatchString(s):
		return Base64
	}
	return Plain
}

// Summary counts items per class, leaving out plain text.
func Summary(items []Item) map[Class]int {
	m := map[Class]int{}
	for _, it := range items {
		if it.Class != Plain {
			m[it.Class]++
		}
	}
	return m
}
