package elfx

import "strings"

// Hardening is a checksec-style summary. Values are conservative: when a property cannot be established it is reported as unknown/absent.
type Hardening struct {
	PIE      bool     `json:"pie"`
	NX       bool     `json:"nx"`
	RELRO    string   `json:"relro"` // none | partial | full
	Canary   bool     `json:"canary"`
	Fortify  bool     `json:"fortify"`
	Stripped bool     `json:"stripped"`
	Static   bool     `json:"static"`
	RWX      []string `json:"rwx_segments,omitempty"`
	RunPath  string   `json:"runpath,omitempty"`
	Notes    []string `json:"notes,omitempty"`
}

func (f *File) Hardening() Hardening {
	h := Hardening{RELRO: "none", Static: !f.HasDynamic && f.Interp == ""}
	h.PIE = f.Type == ET_DYN && (f.PIEFlag || f.Interp != "")
	stack := false
	relro := false
	for i, s := range f.Segments {
		switch s.Type {
		case PT_GNU_STACK:
			stack = true
			h.NX = !s.Executable()
		case PT_GNU_RELRO:
			relro = true
		}
		if s.Type == PT_LOAD && s.Writable() && s.Executable() {
			h.RWX = append(h.RWX, segName(i))
		}
	}
	if !stack {
		h.NX = false // no PT_GNU_STACK: the loader assumes an executable stack
		h.Notes = append(h.Notes, "no PT_GNU_STACK: stack treated as executable")
	}
	if relro {
		h.RELRO = "partial"
		if f.BindNow {
			h.RELRO = "full"
		}
	}
	h.Stripped = true
	for _, s := range f.Symbols {
		if !s.Dynamic {
			h.Stripped = false
		}
		if strings.HasPrefix(s.Name, "__stack_chk_") {
			h.Canary = true
		}
		if strings.HasSuffix(s.Name, "_chk") && strings.HasPrefix(s.Name, "__") {
			h.Fortify = true
		}
	}
	h.RunPath = f.RunPath
	return h
}

func segName(i int) string { return "LOAD#" + itoa(i) }

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}
