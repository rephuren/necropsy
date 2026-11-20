// Package elfx is a small, dependency-free ELF reader (32/64-bit, little-endian).
// Every read is bounds-checked: input files are untrusted and may be truncated or forged.
package elfx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

const (
	PT_LOAD      = 1
	PT_DYNAMIC   = 2
	PT_INTERP    = 3
	PT_GNU_STACK = 0x6474e551
	PT_GNU_RELRO = 0x6474e552

	SHT_SYMTAB  = 2
	SHT_STRTAB  = 3
	SHT_DYNAMIC = 6
	SHT_NOBITS  = 8
	SHT_DYNSYM  = 11

	DT_NULL     = 0
	DT_NEEDED   = 1
	DT_STRTAB   = 5
	DT_RPATH    = 15
	DT_BIND_NOW = 24
	DT_RUNPATH  = 29
	DT_FLAGS    = 30
	DT_FLAGS_1  = 0x6ffffffb

	DF_BIND_NOW = 0x8
	DF_1_NOW    = 0x1
	DF_1_PIE    = 0x08000000

	ET_EXEC = 2
	ET_DYN  = 3

	maxItems = 65536 // cap on counts read from headers: a forged file must not make us allocate gigabytes
)

var ErrNotELF = errors.New("not an ELF file")

type Segment struct {
	Type, Flags                      uint32
	Offset, VAddr, FileSize, MemSize uint64
}

func (s Segment) Readable() bool   { return s.Flags&4 != 0 }
func (s Segment) Writable() bool   { return s.Flags&2 != 0 }
func (s Segment) Executable() bool { return s.Flags&1 != 0 }

type Section struct {
	Name         string
	Type         uint32
	Flags        uint64
	Addr, Offset uint64
	Size         uint64
	Link         uint32
	Compressed   bool    // SHF_COMPRESSED: Size is the size in the file, not the decompressed size
	Entropy      float64 // Shannon entropy, bits per byte; 0 for NOBITS and empty sections
}

type Symbol struct {
	Name    string
	Value   uint64
	Size    uint64
	Info    uint8
	Section uint16
	Dynamic bool
}

type File struct {
	Is64       bool
	OSABI      uint8
	Type       uint16
	Machine    uint16
	Entry      uint64
	Segments   []Segment
	Sections   []Section
	Symbols    []Symbol
	Interp     string
	Needed     []string
	RunPath    string
	BindNow    bool
	PIEFlag    bool
	HasDynamic bool
	data       []byte
}

type reader struct{ b []byte }

func (r reader) in(off, n uint64) bool { return n <= uint64(len(r.b)) && off <= uint64(len(r.b))-n }

func (r reader) u8(off uint64) (uint8, bool) {
	if !r.in(off, 1) {
		return 0, false
	}
	return r.b[off], true
}
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

// cstr reads a NUL-terminated string at off, capped at 4096 bytes.
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

// word reads a native-size word (4 or 8 bytes) as uint64.
func (r reader) word(off uint64, is64 bool) (uint64, bool) {
	if is64 {
		return r.u64(off)
	}
	v, ok := r.u32(off)
	return uint64(v), ok
}

func Parse(data []byte) (*File, error) {
	r := reader{data}
	if len(data) < 16 || string(data[:4]) != "\x7fELF" {
		return nil, ErrNotELF
	}
	f := &File{data: data}
	switch data[4] {
	case 1:
	case 2:
		f.Is64 = true
	default:
		return nil, fmt.Errorf("unknown ELF class %d", data[4])
	}
	if data[5] != 1 {
		return nil, errors.New("only little-endian ELF is supported")
	}
	f.OSABI = data[7]
	f.Type, _ = r.u16(16)
	f.Machine, _ = r.u16(18)
	var phoff, shoff uint64
	var phentsize, phnum, shentsize, shnum, shstrndx uint16
	var ok bool
	if f.Is64 {
		f.Entry, ok = r.u64(24)
		phoff, _ = r.u64(32)
		shoff, _ = r.u64(40)
		phentsize, _ = r.u16(54)
		phnum, _ = r.u16(56)
		shentsize, _ = r.u16(58)
		shnum, _ = r.u16(60)
		shstrndx, _ = r.u16(62)
	} else {
		var e, po, so uint32
		e, ok = r.u32(24)
		po, _ = r.u32(28)
		so, _ = r.u32(32)
		f.Entry, phoff, shoff = uint64(e), uint64(po), uint64(so)
		phentsize, _ = r.u16(42)
		phnum, _ = r.u16(44)
		shentsize, _ = r.u16(46)
		shnum, _ = r.u16(48)
		shstrndx, _ = r.u16(50)
	}
	if !ok {
		return nil, errors.New("truncated ELF header")
	}
	f.readSegments(r, phoff, phentsize, phnum)
	f.readSections(r, shoff, shentsize, shnum, shstrndx)
	f.readDynamic(r)
	f.readSymbols(r)
	return f, nil
}

func (f *File) readSegments(r reader, off uint64, entsize, num uint16) {
	min := uint64(32)
	if f.Is64 {
		min = 56
	}
	if uint64(entsize) < min || num == 0 {
		return
	}
	for i := uint64(0); i < uint64(num) && i < maxItems; i++ {
		p := off + i*uint64(entsize)
		var s Segment
		var ok bool
		if f.Is64 {
			s.Type, ok = r.u32(p)
			s.Flags, _ = r.u32(p + 4)
			s.Offset, _ = r.u64(p + 8)
			s.VAddr, _ = r.u64(p + 16)
			s.FileSize, _ = r.u64(p + 32)
			s.MemSize, _ = r.u64(p + 40)
		} else {
			s.Type, ok = r.u32(p)
			var a, b, c, d uint32
			a, _ = r.u32(p + 4)
			b, _ = r.u32(p + 8)
			c, _ = r.u32(p + 16)
			d, _ = r.u32(p + 20)
			s.Flags, _ = r.u32(p + 24)
			s.Offset, s.VAddr, s.FileSize, s.MemSize = uint64(a), uint64(b), uint64(c), uint64(d)
		}
		if !ok {
			return
		}
		f.Segments = append(f.Segments, s)
		if s.Type == PT_INTERP && r.in(s.Offset, s.FileSize) {
			f.Interp = r.cstr(s.Offset)
		}
	}
}

func (f *File) readSections(r reader, off uint64, entsize, num, strndx uint16) {
	min := uint64(40)
	if f.Is64 {
		min = 64
	}
	if uint64(entsize) < min || num == 0 {
		return
	}
	names := make([]uint32, 0, num)
	for i := uint64(0); i < uint64(num) && i < maxItems; i++ {
		p := off + i*uint64(entsize)
		var s Section
		var nm uint32
		var ok bool
		nm, ok = r.u32(p)
		if !ok {
			break
		}
		s.Type, _ = r.u32(p + 4)
		if f.Is64 {
			s.Flags, _ = r.u64(p + 8)
			s.Addr, _ = r.u64(p + 16)
			s.Offset, _ = r.u64(p + 24)
			s.Size, _ = r.u64(p + 32)
			s.Link, _ = r.u32(p + 40)
		} else {
			fl, _ := r.u32(p + 8)
			a, _ := r.u32(p + 12)
			o, _ := r.u32(p + 16)
			sz, _ := r.u32(p + 20)
			s.Flags, s.Addr, s.Offset, s.Size = uint64(fl), uint64(a), uint64(o), uint64(sz)
			s.Link, _ = r.u32(p + 24)
		}
		s.Compressed = s.Flags&0x800 != 0
		if s.Type != SHT_NOBITS && s.Size > 0 && r.in(s.Offset, s.Size) {
			s.Entropy = Entropy(r.b[s.Offset : s.Offset+s.Size])
		}
		f.Sections = append(f.Sections, s)
		names = append(names, nm)
	}
	if int(strndx) < len(f.Sections) {
		st := f.Sections[strndx]
		if r.in(st.Offset, st.Size) {
			for i := range f.Sections {
				f.Sections[i].Name = r.cstr(st.Offset + uint64(names[i]))
			}
		}
	}
}

// vaddrToOff maps a virtual address to a file offset through the PT_LOAD segments.
func (f *File) vaddrToOff(v uint64) (uint64, bool) {
	for _, s := range f.Segments {
		if s.Type == PT_LOAD && v >= s.VAddr && v-s.VAddr < s.FileSize {
			return s.Offset + (v - s.VAddr), true
		}
	}
	return 0, false
}

func (f *File) readDynamic(r reader) {
	var dyn *Segment
	for i := range f.Segments {
		if f.Segments[i].Type == PT_DYNAMIC {
			dyn = &f.Segments[i]
		}
	}
	if dyn == nil || !r.in(dyn.Offset, dyn.FileSize) {
		return
	}
	f.HasDynamic = true
	ent := uint64(8)
	if f.Is64 {
		ent = 16
	}
	type kv struct{ tag, val uint64 }
	var items []kv
	for p := dyn.Offset; p+ent <= dyn.Offset+dyn.FileSize && len(items) < maxItems; p += ent {
		tag, _ := r.word(p, f.Is64)
		val, _ := r.word(p+ent/2, f.Is64)
		if tag == DT_NULL {
			break
		}
		items = append(items, kv{tag, val})
	}
	var strtab uint64
	var haveStr bool
	for _, it := range items {
		switch it.tag {
		case DT_STRTAB:
			strtab, haveStr = f.vaddrToOff(it.val)
		case DT_BIND_NOW:
			f.BindNow = true
		case DT_FLAGS:
			if it.val&DF_BIND_NOW != 0 {
				f.BindNow = true
			}
		case DT_FLAGS_1:
			if it.val&DF_1_NOW != 0 {
				f.BindNow = true
			}
			if it.val&DF_1_PIE != 0 {
				f.PIEFlag = true
			}
		}
	}
	if !haveStr {
		return
	}
	for _, it := range items {
		switch it.tag {
		case DT_NEEDED:
			f.Needed = append(f.Needed, r.cstr(strtab+it.val))
		case DT_RUNPATH, DT_RPATH:
			f.RunPath = r.cstr(strtab + it.val)
		}
	}
}

func (f *File) readSymbols(r reader) {
	for _, sec := range f.Sections {
		if sec.Type != SHT_SYMTAB && sec.Type != SHT_DYNSYM {
			continue
		}
		if int(sec.Link) >= len(f.Sections) || !r.in(sec.Offset, sec.Size) {
			continue
		}
		str := f.Sections[sec.Link]
		ent := uint64(16)
		if f.Is64 {
			ent = 24
		}
		for i := uint64(0); i < sec.Size/ent && i < maxItems; i++ {
			p := sec.Offset + i*ent
			nm, _ := r.u32(p)
			var s Symbol
			if f.Is64 {
				s.Info, _ = r.u8(p + 4)
				s.Section, _ = r.u16(p + 6)
				s.Value, _ = r.u64(p + 8)
				s.Size, _ = r.u64(p + 16)
			} else {
				v, _ := r.u32(p + 4)
				sz, _ := r.u32(p + 8)
				s.Value, s.Size = uint64(v), uint64(sz)
				s.Info, _ = r.u8(p + 12)
				s.Section, _ = r.u16(p + 14)
			}
			s.Dynamic = sec.Type == SHT_DYNSYM
			if r.in(str.Offset, str.Size) && uint64(nm) < str.Size {
				s.Name = r.cstr(str.Offset + uint64(nm))
			}
			f.Symbols = append(f.Symbols, s)
		}
	}
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
