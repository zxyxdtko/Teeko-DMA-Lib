#include "MockVmmBackend.hpp"
#include "TestHarness.hpp"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <vector>

namespace {
void StoreValidPe64(MockVmmBackend& backend)
{
    IMAGE_DOS_HEADER dos{};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x80;
    backend.Store(MockVmmBackend::MemoryBase, dos);

    IMAGE_NT_HEADERS64 nt{};
    nt.Signature = IMAGE_NT_SIGNATURE;
    nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt.FileHeader.NumberOfSections = 1;
    nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt.OptionalHeader.SectionAlignment = 0x1000;
    nt.OptionalHeader.FileAlignment = 0x200;
    nt.OptionalHeader.SizeOfImage = 0x8000;
    nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT]
        .VirtualAddress = 0x777;
    backend.Store(MockVmmBackend::MemoryBase + 0x80, nt);

    IMAGE_SECTION_HEADER section{};
    std::memcpy(section.Name, ".text", 5);
    section.Misc.VirtualSize = 0x200;
    section.VirtualAddress = 0x1000;
    section.SizeOfRawData = 0x200;
    section.PointerToRawData = 0x400;
    section.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
    backend.Store(MockVmmBackend::MemoryBase + 0x80 +
        sizeof(IMAGE_NT_HEADERS64), section);
    backend.Fill(MockVmmBackend::MemoryBase + 0x1000, 0x200, 0x90);
}

std::filesystem::path TemporaryFile(const char* name)
{
    return std::filesystem::temp_directory_path() / name;
}

std::vector<uint8_t> ReadFile(const std::filesystem::path& path)
{
    std::ifstream stream(path, std::ios::binary);
    return { std::istreambuf_iterator<char>(stream),
        std::istreambuf_iterator<char>() };
}
}

STRATA_TEST_CASE(module_dump_rebuilds_file_layout_and_import_thunks)
{
    MockDmaFixture fixture;
    fixture.Initialize();
    fixture.Attach();
    StoreValidPe64(*fixture.backend);
    const auto path = TemporaryFile("strata_dma_module_dump_test.bin");

    STRATA_REQUIRE(fixture.dma.DumpModule("test.exe", path.string()));
    const auto bytes = ReadFile(path);
    STRATA_REQUIRE(bytes.size() == fixture.backend->modules[0].imageSize);

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        bytes.data() + 0x80);
    STRATA_REQUIRE(nt->OptionalHeader.FileAlignment == 0x1000);
    STRATA_REQUIRE(nt->OptionalHeader.DataDirectory[
        IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress == 0);
    const auto* section = IMAGE_FIRST_SECTION(nt);
    STRATA_REQUIRE(section->PointerToRawData == section->VirtualAddress);
    STRATA_REQUIRE(section->SizeOfRawData == 0x200);
    uint64_t thunk = 0;
    std::memcpy(&thunk, bytes.data() + 0x300, sizeof(thunk));
    STRATA_REQUIRE(thunk == 0x400);

    std::error_code error;
    std::filesystem::remove(path, error);
    STRATA_REQUIRE(!error);
}

STRATA_TEST_CASE(module_dump_rejects_invalid_or_truncated_headers)
{
    MockDmaFixture fixture;
    fixture.Initialize();
    fixture.Attach();
    const auto path = TemporaryFile("strata_dma_invalid_dump_test.bin");

    fixture.backend->Store<uint16_t>(MockVmmBackend::MemoryBase, 0);
    auto dumped = fixture.dma.DumpModule("test.exe", path.string());
    STRATA_REQUIRE(!dumped);
    STRATA_REQUIRE(dumped.message.find("DOS header") !=
        std::string::npos);

    IMAGE_DOS_HEADER dos{};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x7ff0;
    fixture.backend->Store(MockVmmBackend::MemoryBase, dos);
    dumped = fixture.dma.DumpModule("test.exe", path.string());
    STRATA_REQUIRE(!dumped);
    STRATA_REQUIRE(dumped.message.find("PE header") !=
        std::string::npos);
}

STRATA_TEST_CASE(memory_dump_obeys_pid_and_partial_read_contracts)
{
    MockDmaFixture fixture;
    fixture.Initialize();
    fixture.Attach();
    fixture.backend->Fill(0x1800, 32, 0x5a);
    auto bytes = fixture.dma.DumpMemory(0x1800, 32);
    STRATA_REQUIRE(bytes.size() == 32);
    STRATA_REQUIRE(bytes.front() == 0x5a && bytes.back() == 0x5a);

    fixture.backend->partialReadLimit = 8;
    bytes = fixture.dma.DumpMemory(0x1800, 32);
    STRATA_REQUIRE(bytes.size() == 32);
    STRATA_REQUIRE(bytes[7] == 0x5a && bytes[8] == 0);

    bytes = fixture.dma.DumpMemoryEx(MockVmmBackend::TargetPid, 0x1800, 32);
    STRATA_REQUIRE(bytes.size() == 32);
    bytes = fixture.dma.DumpMemoryEx(MockVmmBackend::TargetPid, 0x1800, 32,
        VMMDLL_FLAG_NOCACHE);
    STRATA_REQUIRE(bytes.size() == 8);
    STRATA_REQUIRE(fixture.backend->lastReadPid == MockVmmBackend::TargetPid);
}

STRATA_TEST_CASE(module_dump_reports_missing_module_and_output_failures)
{
    MockDmaFixture fixture;
    fixture.Initialize();
    fixture.Attach();
    STRATA_REQUIRE(!fixture.dma.DumpModule("missing.dll", "unused.bin"));
    STRATA_REQUIRE(!fixture.dma.DumpModule("test.exe", ""));

    StoreValidPe64(*fixture.backend);
    const auto impossible = TemporaryFile("strata_dma_missing_directory") /
        "dump.bin";
    const auto dumped = fixture.dma.DumpModule("test.exe", impossible.string());
    STRATA_REQUIRE(!dumped);
    STRATA_REQUIRE(dumped.message.find("open") != std::string::npos);
}
