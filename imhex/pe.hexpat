#pragma author misxnthropy
#pragma description PE32 / PE32+: DOS header, COFF header, optional header, data directories, section table
#pragma endian little
#pragma magic [ 4D 5A ] @ 0x00

// Written by hand from the PE/COFF specification. Not generated, and not exhaustive.

struct DosHeader {
    char magic[2];
    u8 reserved[58];
    u32 pe_offset;
};

struct CoffHeader {
    char signature[4];
    u16 machine;
    u16 number_of_sections;
    u32 timestamp;
    u32 symbol_table_pointer;
    u32 number_of_symbols;
    u16 size_of_optional_header;
    u16 characteristics;
};

struct DataDirectory {
    u32 rva;
    u32 size;
};

struct OptionalHeader32 {
    u16 magic;
    u8 linker_major;
    u8 linker_minor;
    u32 size_of_code;
    u32 size_of_initialized_data;
    u32 size_of_uninitialized_data;
    u32 entry_point_rva;
    u32 base_of_code;
    u32 base_of_data;
    u32 image_base;
    u32 section_alignment;
    u32 file_alignment;
    u16 os_major;
    u16 os_minor;
    u16 image_major;
    u16 image_minor;
    u16 subsystem_major;
    u16 subsystem_minor;
    u32 win32_version;
    u32 size_of_image;
    u32 size_of_headers;
    u32 checksum;
    u16 subsystem;
    u16 dll_characteristics;
    u32 size_of_stack_reserve;
    u32 size_of_stack_commit;
    u32 size_of_heap_reserve;
    u32 size_of_heap_commit;
    u32 loader_flags;
    u32 number_of_rva_and_sizes;
    DataDirectory directories[number_of_rva_and_sizes > 16 ? 16 : number_of_rva_and_sizes];
};

struct OptionalHeader64 {
    u16 magic;
    u8 linker_major;
    u8 linker_minor;
    u32 size_of_code;
    u32 size_of_initialized_data;
    u32 size_of_uninitialized_data;
    u32 entry_point_rva;
    u32 base_of_code;
    u64 image_base;
    u32 section_alignment;
    u32 file_alignment;
    u16 os_major;
    u16 os_minor;
    u16 image_major;
    u16 image_minor;
    u16 subsystem_major;
    u16 subsystem_minor;
    u32 win32_version;
    u32 size_of_image;
    u32 size_of_headers;
    u32 checksum;
    u16 subsystem;
    u16 dll_characteristics;
    u64 size_of_stack_reserve;
    u64 size_of_stack_commit;
    u64 size_of_heap_reserve;
    u64 size_of_heap_commit;
    u32 loader_flags;
    u32 number_of_rva_and_sizes;
    DataDirectory directories[number_of_rva_and_sizes > 16 ? 16 : number_of_rva_and_sizes];
};

struct SectionHeader {
    char name[8];
    u32 virtual_size;
    u32 virtual_address;
    u32 size_of_raw_data;
    u32 pointer_to_raw_data;
    u32 pointer_to_relocations;
    u32 pointer_to_line_numbers;
    u16 number_of_relocations;
    u16 number_of_line_numbers;
    u32 characteristics;
};

DosHeader dos @ 0x00;
CoffHeader coff @ dos.pe_offset;

u16 optional_magic @ dos.pe_offset + 24;
if (optional_magic == 0x20B) {
    OptionalHeader64 optional @ dos.pe_offset + 24;
} else {
    OptionalHeader32 optional @ dos.pe_offset + 24;
}

SectionHeader sections[coff.number_of_sections] @ dos.pe_offset + 24 + coff.size_of_optional_header;
