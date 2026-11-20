package main

import (
	"fmt"
	"io"

	"github.com/rephuren/necropsy/internal/elfx"
	"github.com/rephuren/necropsy/internal/pex"
)

type sectionOut struct {
	Name    string  `json:"name"`
	Type    uint32  `json:"type"`
	Addr    uint64  `json:"addr"`
	Size    uint64  `json:"size"`
	Entropy float64 `json:"entropy"`
	Flags   string  `json:"flags"`
}

type report struct {
	File      string         `json:"file"`
	Format    string         `json:"format"`
	Bits      int            `json:"bits"`
	Machine   string         `json:"machine"`
	Kind      string         `json:"kind"`
	Entry     uint64         `json:"entry"`
	Interp    string         `json:"interpreter,omitempty"`
	Needed    []string       `json:"needed,omitempty"`
	Hardening elfx.Hardening `json:"hardening,omitempty"`
	PE        *pex.Hardening `json:"pe_hardening,omitempty"`
	Imports   []pex.Import   `json:"imports,omitempty"`
	Sections  []sectionOut   `json:"sections"`
	Warnings  []string       `json:"warnings,omitempty"`
}

var machines = map[uint16]string{3: "x86", 8: "mips", 40: "arm", 62: "x86-64", 183: "aarch64", 243: "riscv"}
var kinds = map[uint16]string{1: "relocatable", 2: "executable", 3: "shared object / PIE", 4: "core"}

func flagStr(f uint64) string {
	s := ""
	for _, p := range []struct {
		bit uint64
		c   string
	}{{2, "A"}, {1, "W"}, {4, "X"}} {
		if f&p.bit != 0 {
			s += p.c
		}
	}
	return s
}

func summarize(path string, f *elfx.File) report {
	r := report{File: path, Format: "ELF", Bits: 32, Entry: f.Entry, Interp: f.Interp, Needed: f.Needed, Hardening: f.Hardening()}
	if f.Is64 {
		r.Bits = 64
	}
	if m, ok := machines[f.Machine]; ok {
		r.Machine = m
	} else {
		r.Machine = fmt.Sprintf("0x%x", f.Machine)
	}
	if k, ok := kinds[f.Type]; ok {
		r.Kind = k
	} else {
		r.Kind = fmt.Sprintf("0x%x", f.Type)
	}
	for _, s := range f.Sections {
		if s.Name == "" && s.Size == 0 {
			continue
		}
		r.Sections = append(r.Sections, sectionOut{s.Name, s.Type, s.Addr, s.Size, s.Entropy, flagStr(s.Flags)})
		if s.Entropy > 7.2 && s.Size >= 512 && !s.Compressed { // compressed debug sections are always high-entropy
			r.Warnings = append(r.Warnings, fmt.Sprintf("section %q has entropy %.2f: packed or encrypted data?", s.Name, s.Entropy))
		}
	}
	h := r.Hardening
	if len(h.RWX) > 0 {
		r.Warnings = append(r.Warnings, fmt.Sprintf("writable and executable segments: %v", h.RWX))
	}
	if !h.NX {
		r.Warnings = append(r.Warnings, "stack is executable (no NX)")
	}
	if h.RunPath != "" {
		r.Warnings = append(r.Warnings, "RUNPATH/RPATH set: "+h.RunPath)
	}
	return r
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func (r report) Text(w io.Writer) {
	fmt.Fprintf(w, "%s: %s %d-bit %s, %s, entry 0x%x\n", r.File, r.Format, r.Bits, r.Machine, r.Kind, r.Entry)
	if r.Interp != "" {
		fmt.Fprintf(w, "interpreter: %s\n", r.Interp)
	}
	if len(r.Needed) > 0 {
		fmt.Fprintf(w, "needed: %v\n", r.Needed)
	}
	if r.PE != nil {
		r.peText(w)
		return
	}
	h := r.Hardening
	fmt.Fprintf(w, "hardening: PIE %s · NX %s · RELRO %s · canary %s · fortify %s · stripped %s · static %s\n",
		yn(h.PIE), yn(h.NX), h.RELRO, yn(h.Canary), yn(h.Fortify), yn(h.Stripped), yn(h.Static))
	fmt.Fprintln(w, "sections:")
	for _, s := range r.Sections {
		fmt.Fprintf(w, "  %-18s %-4s addr 0x%-10x size %-8d entropy %.2f\n", s.Name, s.Flags, s.Addr, s.Size, s.Entropy)
	}
	for _, x := range h.Notes {
		fmt.Fprintln(w, "note:", x)
	}
	for _, x := range r.Warnings {
		fmt.Fprintln(w, "warning:", x)
	}
}

var peMachines = map[uint16]string{0x14c: "x86", 0x8664: "x86-64", 0x1c0: "arm", 0xaa64: "aarch64"}

func summarizePE(path string, f *pex.File) report {
	r := report{File: path, Format: "PE", Bits: 32, Entry: uint64(f.EntryRVA)}
	if f.Is64 {
		r.Bits = 64
	}
	if m, ok := peMachines[f.Machine]; ok {
		r.Machine = m
	} else {
		r.Machine = fmt.Sprintf("0x%x", f.Machine)
	}
	r.Kind = "executable"
	if f.FileCharacteristics&0x2000 != 0 {
		r.Kind = "DLL"
	}
	h := f.Hardening()
	r.PE = &h
	r.Imports = f.Imports
	for _, s := range f.Sections {
		fl := ""
		for _, p := range []struct {
			bit uint32
			c   string
		}{{pex.SecRead, "R"}, {pex.SecWrite, "W"}, {pex.SecExec, "X"}} {
			if s.Characteristics&p.bit != 0 {
				fl += p.c
			}
		}
		r.Sections = append(r.Sections, sectionOut{s.Name, s.Characteristics, uint64(s.RVA), uint64(s.VirtualSize), s.Entropy, fl})
		if s.Entropy > 7.2 && s.RawSize >= 512 {
			r.Warnings = append(r.Warnings, fmt.Sprintf("section %q has entropy %.2f: packed or encrypted data?", s.Name, s.Entropy))
		}
	}
	if len(h.RWX) > 0 {
		r.Warnings = append(r.Warnings, fmt.Sprintf("writable and executable sections: %v", h.RWX))
	}
	if !h.ASLR {
		r.Warnings = append(r.Warnings, "ASLR is not enabled (no DYNAMIC_BASE)")
	}
	if !h.DEP {
		r.Warnings = append(r.Warnings, "DEP is not enabled (no NX_COMPAT)")
	}
	if es := f.EntrySection(); es == "" {
		r.Warnings = append(r.Warnings, "entry point lies outside every section")
	} else if es != ".text" && es != "CODE" {
		r.Warnings = append(r.Warnings, fmt.Sprintf("entry point is in section %q, not .text", es))
	}
	return r
}

func (r report) peText(w io.Writer) {
	h := r.PE
	fmt.Fprintf(w, "hardening: ASLR %s · high-entropy VA %s · DEP %s · CFG %s · no SEH %s · signed %s\n",
		yn(h.ASLR), yn(h.HighEntropy), yn(h.DEP), yn(h.CFG), yn(h.NoSEH), yn(h.Signed))
	fmt.Fprintln(w, "sections:")
	for _, s := range r.Sections {
		fmt.Fprintf(w, "  %-10s %-3s rva 0x%-8x vsize %-8d entropy %.2f\n", s.Name, s.Flags, s.Addr, s.Size, s.Entropy)
	}
	for _, imp := range r.Imports {
		fmt.Fprintf(w, "imports %s: %d functions\n", imp.DLL, len(imp.Functions))
	}
	for _, x := range r.Warnings {
		fmt.Fprintln(w, "warning:", x)
	}
}
