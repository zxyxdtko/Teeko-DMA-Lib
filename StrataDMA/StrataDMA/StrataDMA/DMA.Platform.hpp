#pragma once

// VMMDLL supplies the basic Win32-compatible integer types and section-header
// layout on Linux. StrataDMA also uses a small set of Windows data definitions
// that are part of the target-memory format rather than the host operating
// system. Keep those definitions here so public code does not depend on the
// Windows SDK when built on Linux.

#if defined(LINUX) && !defined(_WIN32)

#include <cstdint>

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

struct POINT {
    std::int32_t x;
    std::int32_t y;
};

inline constexpr DWORD REG_SZ = 1;
inline constexpr DWORD REG_EXPAND_SZ = 2;
inline constexpr DWORD REG_BINARY = 3;
inline constexpr DWORD REG_DWORD = 4;
inline constexpr DWORD REG_MULTI_SZ = 7;
inline constexpr DWORD REG_QWORD = 11;

inline constexpr WORD IMAGE_DOS_SIGNATURE = 0x5a4d;
inline constexpr DWORD IMAGE_NT_SIGNATURE = 0x00004550;
inline constexpr WORD IMAGE_FILE_MACHINE_AMD64 = 0x8664;
inline constexpr WORD IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b;
inline constexpr WORD IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;
inline constexpr DWORD IMAGE_SCN_MEM_EXECUTE = 0x20000000;
inline constexpr DWORD IMAGE_SCN_MEM_READ = 0x40000000;
inline constexpr DWORD IMAGE_SCN_MEM_WRITE = 0x80000000;
inline constexpr DWORD IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;
inline constexpr DWORD IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11;

struct IMAGE_DOS_HEADER {
    WORD e_magic;
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip;
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovno;
    WORD e_res[4];
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10];
    std::int32_t e_lfanew;
};
using PIMAGE_DOS_HEADER = IMAGE_DOS_HEADER*;

struct IMAGE_FILE_HEADER {
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
};
using PIMAGE_FILE_HEADER = IMAGE_FILE_HEADER*;

struct IMAGE_OPTIONAL_HEADER32 {
    WORD Magic;
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    DWORD BaseOfData;
    DWORD ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    DWORD SizeOfStackReserve;
    DWORD SizeOfStackCommit;
    DWORD SizeOfHeapReserve;
    DWORD SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};
using PIMAGE_OPTIONAL_HEADER32 = IMAGE_OPTIONAL_HEADER32*;

struct IMAGE_OPTIONAL_HEADER64 {
    WORD Magic;
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    QWORD ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    QWORD SizeOfStackReserve;
    QWORD SizeOfStackCommit;
    QWORD SizeOfHeapReserve;
    QWORD SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};
using PIMAGE_OPTIONAL_HEADER64 = IMAGE_OPTIONAL_HEADER64*;

struct IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

inline PIMAGE_SECTION_HEADER ImageFirstSection(IMAGE_NT_HEADERS64* ntHeader)
{
    return reinterpret_cast<PIMAGE_SECTION_HEADER>(
        reinterpret_cast<BYTE*>(&ntHeader->OptionalHeader) +
        ntHeader->FileHeader.SizeOfOptionalHeader);
}

inline const IMAGE_SECTION_HEADER* ImageFirstSection(
    const IMAGE_NT_HEADERS64* ntHeader)
{
    return reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        reinterpret_cast<const BYTE*>(&ntHeader->OptionalHeader) +
        ntHeader->FileHeader.SizeOfOptionalHeader);
}

#define IMAGE_FIRST_SECTION(nt_header) ImageFirstSection(nt_header)

static_assert(sizeof(POINT) == 8);
static_assert(sizeof(IMAGE_DOS_HEADER) == 64);
static_assert(sizeof(IMAGE_FILE_HEADER) == 20);
static_assert(sizeof(IMAGE_OPTIONAL_HEADER32) == 224);
static_assert(sizeof(IMAGE_OPTIONAL_HEADER64) == 240);
static_assert(sizeof(IMAGE_NT_HEADERS64) == 264);

#endif
