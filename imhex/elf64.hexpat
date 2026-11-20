#pragma author misxnthropy
#pragma description ELF64 (little-endian): header, program headers, section headers
#pragma endian little
#pragma magic [ 7F 45 4C 46 02 01 ] @ 0x00

// Written by hand from the ELF specification. Not generated, and not exhaustive.

enum ObjectType : u16 {
    None = 0,
    Relocatable = 1,
    Executable = 2,
    SharedObject = 3,
    Core = 4
};

enum SegmentType : u32 {
    Null = 0,
    Load = 1,
    Dynamic = 2,
    Interp = 3,
    Note = 4,
    Phdr = 6,
    Tls = 7,
    GnuEhFrame = 0x6474e550,
    GnuStack = 0x6474e551,
    GnuRelro = 0x6474e552
};

struct Ident {
    char magic[4];
    u8 class;
    u8 data;
    u8 version;
    u8 osabi;
    u8 abi_version;
    padding[7];
};

struct Header {
    Ident ident;
    ObjectType type;
    u16 machine;
    u32 version;
    u64 entry;
    u64 phoff;
    u64 shoff;
    u32 flags;
    u16 ehsize;
    u16 phentsize;
    u16 phnum;
    u16 shentsize;
    u16 shnum;
    u16 shstrndx;
};

bitfield SegmentFlags {
    execute : 1;
    write : 1;
    read : 1;
    padding : 29;
};

struct ProgramHeader {
    SegmentType type;
    SegmentFlags flags;
    u64 offset;
    u64 vaddr;
    u64 paddr;
    u64 filesz;
    u64 memsz;
    u64 align;
};

struct SectionHeader {
    u32 name_offset;
    u32 type;
    u64 flags;
    u64 addr;
    u64 offset;
    u64 size;
    u32 link;
    u32 info;
    u64 addralign;
    u64 entsize;
};

Header header @ 0x00;
ProgramHeader program_headers[header.phnum] @ header.phoff;
SectionHeader section_headers[header.shnum] @ header.shoff;
