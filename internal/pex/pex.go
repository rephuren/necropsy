// Package pex is a small, dependency-free PE32/PE32+ reader. Every read is bounds-checked: input is untrusted.
package pex

import (
	"encoding/binary"
	"errors"
	"math"
)

const (
	DLLHighEntropyVA  = 0x0020
	DLLDynamicBase    = 0x0040
	DLLForceIntegrity = 0x0080
	DLLNXCompat       = 0x0100
	DLLNoSEH          = 0x0400
	DLLGuardCF        = 0x4000

	SecExec  = 0x20000000
	SecRead  = 0x40000000
	SecWrite = 0x80000000

	dirImport   = 1
	dirSecurity = 4
	dirLoadCfg  = 10

	maxItems = 65536
)

var ErrNotPE = errors.New("not a PE file")

type Section struct {
	Name            string
	VirtualSize     uint32
	RVA             uint32
	RawSize         uint32
	RawOffset       uint32
	Characteristics uint32
	Entropy         float64
}

type Import struct {
	DLL       string
	Functions []string
}

type File struct {
	Is64                bool
	Machine             uint16
	Timestamp           uint32
	FileCharacteristics uint16
	EntryRVA            uint32
	ImageBase           uint64
	Subsystem           uint16
	DllCharacteristics  uint16
	Sections            []Section
	Imports             []Import
	HasSignature        bool
	HasLoadConfig       bool
	data                []byte
}

type reader struct{ b []byte }

func (r reader) in(off, n uint64) bool { return n <= uint64(len(r.b)) && off <= uint64(len(r.b))-n }
func (r reader) u16(off uint64) (uint16, bool) {
	if !r.in(off, 2) {
		return 0, false
	}
	return binary.LittleEndian.Uint16(r.b[off:]), true
}
func (r reader) u32(off uint64) (uint32, bool) {
	if !r.in(off, 4) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(r.b[off:]), true
}
func (r reader) u64(off uint64) (uint64, bool) {
	if !r.in(off, 8) {
		return 0, false
	}
	return binary.LittleEndian.Uint64(r.b[off:]), true
}
func (r reader) cstr(off uint64) string {
	if off >= uint64(len(r.b)) {
		return ""
	}
	end := off
	for end < uint64(len(r.b)) && r.b[end] != 0 && end-off < 4096 {
		end++
	}
	return string(r.b[off:end])
}

func Parse(data []byte) (*File, error) {
	r := reader{data}
	if len(data) < 64 || data[0] != 'M' || data[1] != 'Z' {
		return nil, ErrNotPE
	}
	lfanew, _ := r.u32(0x3c)
	sig, ok := r.u32(uint64(lfanew))
	if !ok || sig != 0x00004550 {
		return nil, ErrNotPE
	}
	co := uint64(lfanew) + 4
	f := &File{data: data}
	f.Machine, ok = r.u16(co)
	nsec, _ := r.u16(co + 2)
	f.Timestamp, _ = r.u32(co + 4)
	symPtr, _ := r.u32(co + 8)
	symCount, _ := r.u32(co + 12)
	optSize, _ := r.u16(co + 16)
	f.FileCharacteristics, _ = r.u16(co + 18)
	if !ok {
		return nil, errors.New("truncated COFF header")
	}
	oh := co + 20
	magic, ok := r.u16(oh)
	if !ok {
		return nil, errors.New("truncated optional header")
	}
	var dirOff uint64
	var ndirs uint32
	switch magic {
	case 0x10b:
		f.EntryRVA, _ = r.u32(oh + 16)
		ib, _ := r.u32(oh + 28)
		f.ImageBase = uint64(ib)
		f.Subsystem, _ = r.u16(oh + 68)
		f.DllCharacteristics, _ = r.u16(oh + 70)
		ndirs, _ = r.u32(oh + 92)
		dirOff = oh + 96
	case 0x20b:
		f.Is64 = true
		f.EntryRVA, _ = r.u32(oh + 16)
		f.ImageBase, _ = r.u64(oh + 24)
		f.Subsystem, _ = r.u16(oh + 68)
		f.DllCharacteristics, _ = r.u16(oh + 70)
		ndirs, _ = r.u32(oh + 108)
		dirOff = oh + 112
	default:
		return nil, errors.New("unknown optional header magic")
	}
	if ndirs > 16 {
		ndirs = 16
	}
	dir := func(i uint32) (rva, size uint32) {
		if i >= ndirs {
			return 0, 0
		}
		rva, _ = r.u32(dirOff + uint64(i)*8)
		size, _ = r.u32(dirOff + uint64(i)*8 + 4)
		return
	}
	so := oh + uint64(optSize)
	for i := uint64(0); i < uint64(nsec) && i < maxItems; i++ {
		p := so + i*40
		if !r.in(p, 40) {
			break
		}
		var s Section
		s.Name = trimNUL(data[p : p+8])
		if len(s.Name) > 1 && s.Name[0] == '/' { // long name: "/123" is an offset into the COFF string table that follows the symbol table
			if n, ok := atoi(s.Name[1:]); ok && symPtr != 0 {
				s.Name = r.cstr(uint64(symPtr) + uint64(symCount)*18 + n)
			}
		}
		s.VirtualSize, _ = r.u32(p + 8)
		s.RVA, _ = r.u32(p + 12)
		s.RawSize, _ = r.u32(p + 16)
		s.RawOffset, _ = r.u32(p + 20)
		s.Characteristics, _ = r.u32(p + 36)
		if s.RawSize > 0 && r.in(uint64(s.RawOffset), uint64(s.RawSize)) {
			s.Entropy = Entropy(data[s.RawOffset : uint64(s.RawOffset)+uint64(s.RawSize)])
		}
		f.Sections = append(f.Sections, s)
	}
	if rva, size := dir(dirSecurity); rva != 0 && size != 0 { // for the security directory "rva" is a file offset
		f.HasSignature = true
	}
	if rva, _ := dir(dirLoadCfg); rva != 0 {
		f.HasLoadConfig = true
	}
	if rva, _ := dir(dirImport); rva != 0 {
		f.readImports(r, rva)
	}
	return f, nil
}

func trimNUL(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// rvaToOff maps a relative virtual address to a file offset through the section table.
func (f *File) rvaToOff(rva uint32) (uint64, bool) {
	for _, s := range f.Sections {
		size := s.VirtualSize
		if s.RawSize > size {
			size = s.RawSize
		}
		if rva >= s.RVA && rva-s.RVA < size {
			d := uint64(rva - s.RVA)
			if d >= uint64(s.RawSize) {
				return 0, false // uninitialised tail: not backed by the file
			}
			return uint64(s.RawOffset) + d, true
		}
	}
	return 0, false
}

func (f *File) readImports(r reader, rva uint32) {
	off, ok := f.rvaToOff(rva)
	if !ok {
		return
	}
	step := uint64(4)
	if f.Is64 {
		step = 8
	}
	for n := 0; n < maxItems; n++ {
		p := off + uint64(n)*20
		oft, ok1 := r.u32(p)
		nameRVA, ok2 := r.u32(p + 12)
		ft, ok3 := r.u32(p + 16)
		if !ok1 || !ok2 || !ok3 || (oft == 0 && nameRVA == 0 && ft == 0) {
			return
		}
		var imp Import
		if no, ok := f.rvaToOff(nameRVA); ok {
			imp.DLL = r.cstr(no)
		}
		thunk := oft
		if thunk == 0 {
			thunk = ft
		}
		if to, ok := f.rvaToOff(thunk); ok {
			for k := 0; k < maxItems; k++ {
				var v uint64
				var ok bool
				if f.Is64 {
					v, ok = r.u64(to + uint64(k)*step)
				} else {
					var v32 uint32
					v32, ok = r.u32(to + uint64(k)*step)
					v = uint64(v32)
				}
				if !ok || v == 0 {
					break
				}
				ordinalFlag := uint64(1) << 31
				if f.Is64 {
					ordinalFlag = 1 << 63
				}
				if v&ordinalFlag != 0 {
					imp.Functions = append(imp.Functions, "#"+utoa(v&0xffff))
					continue
				}
				if no, ok := f.rvaToOff(uint32(v)); ok { // skip the 2-byte hint
					imp.Functions = append(imp.Functions, r.cstr(no+2))
				}
			}
		}
		f.Imports = append(f.Imports, imp)
	}
}

func atoi(s string) (uint64, bool) {
	var v uint64
	for _, c := range []byte(s) {
		if c < '0' || c > '9' || v > 1<<40 {
			return 0, false
		}
		v = v*10 + uint64(c-'0')
	}
	return v, len(s) > 0
}

func utoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	n := len(b)
	for v > 0 {
		n--
		b[n] = byte('0' + v%10)
		v /= 10
	}
	return string(b[n:])
}

// Entropy returns the Shannon entropy of b in bits per byte (0..8).
func Entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var cnt [256]float64
	for _, c := range b {
		cnt[c]++
	}
	n := float64(len(b))
	h := 0.0
	for _, c := range cnt {
		if c > 0 {
			p := c / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// Hardening is a summary of the mitigations a PE image opts in to.
type Hardening struct {
	ASLR        bool     `json:"aslr"`
	HighEntropy bool     `json:"high_entropy_va"`
	DEP         bool     `json:"dep"`
	CFG         bool     `json:"cfg"`
	NoSEH       bool     `json:"no_seh"`
	Signed      bool     `json:"signed"`
	RWX         []string `json:"rwx_sections,omitempty"`
}

func (f *File) Hardening() Hardening {
	d := f.DllCharacteristics
	h := Hardening{
		ASLR: d&DLLDynamicBase != 0, HighEntropy: d&DLLHighEntropyVA != 0, DEP: d&DLLNXCompat != 0,
		CFG: d&DLLGuardCF != 0, NoSEH: d&DLLNoSEH != 0, Signed: f.HasSignature,
	}
	for _, s := range f.Sections {
		if s.Characteristics&SecWrite != 0 && s.Characteristics&SecExec != 0 {
			h.RWX = append(h.RWX, s.Name)
		}
	}
	return h
}

// EntrySection returns the name of the section containing the entry point, or "" when it lies outside all sections.
func (f *File) EntrySection() string {
	for _, s := range f.Sections {
		size := s.VirtualSize
		if s.RawSize > size {
			size = s.RawSize
		}
		if f.EntryRVA >= s.RVA && f.EntryRVA-s.RVA < size {
			return s.Name
		}
	}
	return ""
}
