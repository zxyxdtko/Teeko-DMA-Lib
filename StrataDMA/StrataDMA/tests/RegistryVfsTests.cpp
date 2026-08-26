#include "MockVmmBackend.hpp"
#include "TestHarness.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

STRATA_TEST_CASE(registry_value_conversions_handle_supported_types)
{
    DMARegistryValue text;
    text.type = REG_SZ;
    const std::string expected = "value";
    const std::u16string encoded = u"value";
    text.data.resize((encoded.size() + 1) * sizeof(char16_t));
    std::memcpy(text.data.data(), encoded.c_str(), text.data.size());
    STRATA_REQUIRE(text.AsString() == expected);

    DMARegistryValue dword;
    dword.type = REG_DWORD;
    dword.data.resize(sizeof(uint32_t));
    const uint32_t dwordValue = 0x12345678;
    std::memcpy(dword.data.data(), &dwordValue, sizeof(dwordValue));
    STRATA_REQUIRE(dword.AsDword() == dwordValue);

    DMARegistryValue qword;
    qword.type = REG_QWORD;
    qword.data.resize(sizeof(uint64_t));
    const uint64_t qwordValue = 0x1122334455667788ULL;
    std::memcpy(qword.data.data(), &qwordValue, sizeof(qwordValue));
    STRATA_REQUIRE(qword.AsQword() == qwordValue);

    DMARegistryValue invalid;
    invalid.type = REG_BINARY;
    invalid.data = { 1 };
    STRATA_REQUIRE(invalid.AsDword(77) == 77);
    STRATA_REQUIRE(invalid.AsQword(88) == 88);
}

STRATA_TEST_CASE(registry_enumeration_and_query_return_owned_data)
{
    MockDmaFixture fixture;
    fixture.Initialize();
    auto hives = fixture.dma.GetRegistryHives();
    auto keys = fixture.dma.EnumerateRegistryKeys("HKLM\\SYSTEM");
    auto values = fixture.dma.EnumerateRegistryValues("HKLM\\SYSTEM");
    auto answer = fixture.dma.QueryRegistryValue(
        "HKLM\\SOFTWARE\\Answer");
    STRATA_REQUIRE(hives && hives.value.size() == 1);
    STRATA_REQUIRE(hives.value[0].rootPath == "HKLM\\SYSTEM");
    STRATA_REQUIRE(keys && keys.value[0].name == "Child");
    STRATA_REQUIRE(values && values.value[0].AsDword() == 42);
    STRATA_REQUIRE(answer && answer.value.AsDword() == 42);

    auto invalid = fixture.dma.EnumerateRegistryKeys("");
    STRATA_REQUIRE(!invalid);
    STRATA_REQUIRE_STATUS(invalid.operation, DMAStatus::InvalidArgument);
}

STRATA_TEST_CASE(raw_registry_hive_reads_and_writes_report_byte_counts)
{
    MockDmaFixture fixture;
    fixture.Initialize();
    const std::array<uint8_t, 4> expected{ 1, 2, 3, 4 };
    auto written = fixture.dma.WriteRegistryHive(0x1111, 0x20,
        expected.data(), expected.size());
    STRATA_REQUIRE(written);
    STRATA_REQUIRE(written.transferredBytes == expected.size());
    std::array<uint8_t, 4> actual{};
    auto read = fixture.dma.ReadRegistryHive(0x1111, 0x20, actual.data(),
        actual.size());
    STRATA_REQUIRE(read && actual == expected);
    STRATA_REQUIRE(read.requestedBytes == expected.size());
    STRATA_REQUIRE(read.transferredBytes == expected.size());

    STRATA_REQUIRE_STATUS(fixture.dma.ReadRegistryHive(0x1111, 0, nullptr, 0),
        DMAStatus::InvalidArgument);
    STRATA_REQUIRE_STATUS(fixture.dma.WriteRegistryHive(0x1111, 0, nullptr, 0),
        DMAStatus::InvalidArgument);
}

STRATA_TEST_CASE(vfs_listing_full_reads_and_offset_reads_work)
{
    MockDmaFixture fixture;
    fixture.Initialize(true);
    auto entries = fixture.dma.ListVfs("\\");
    STRATA_REQUIRE(entries && entries.value.size() == 2);
    STRATA_REQUIRE(entries.value[0].name == "mock.txt");
    STRATA_REQUIRE(entries.value[1].directory);

    auto file = fixture.dma.ReadVfsFile("\\mock.txt");
    STRATA_REQUIRE(file);
    STRATA_REQUIRE(std::string(file.value.begin(), file.value.end()) == "mock");

    std::array<char, 2> tail{};
    auto read = fixture.dma.ReadVfs("\\mock.txt", 2, tail.data(), tail.size());
    STRATA_REQUIRE(read);
    STRATA_REQUIRE(std::string(tail.data(), tail.size()) == "ck");
    STRATA_REQUIRE(read.address == 2);
    STRATA_REQUIRE(read.transferredBytes == 2);
}

STRATA_TEST_CASE(vfs_size_limits_and_missing_files_are_reported)
{
    MockDmaFixture fixture;
    fixture.Initialize(true);
    fixture.backend->vfsFiles["\\large.bin"] =
        std::vector<uint8_t>(32, 0xaa);
    auto limited = fixture.dma.ReadVfsFile("\\large.bin", 8);
    STRATA_REQUIRE(!limited);
    STRATA_REQUIRE_STATUS(limited.operation, DMAStatus::PartialTransfer);
    STRATA_REQUIRE(limited.value.size() == 8);

    auto missing = fixture.dma.ReadVfsFile("\\missing.bin");
    STRATA_REQUIRE(!missing);
    STRATA_REQUIRE_STATUS(missing.operation, DMAStatus::NotFound);
    STRATA_REQUIRE(!fixture.dma.ReadVfsFile("", 16));
    STRATA_REQUIRE(!fixture.dma.ReadVfsFile("\\mock.txt", 0));
}

STRATA_TEST_CASE(vfs_writes_modify_and_extend_files)
{
    MockDmaFixture fixture;
    fixture.Initialize(true);
    const std::array<uint8_t, 3> replacement{ 'X', 'Y', 'Z' };
    auto written = fixture.dma.WriteVfs("\\mock.txt", 1,
        replacement.data(), replacement.size());
    STRATA_REQUIRE(written);
    STRATA_REQUIRE(written.requestedBytes == replacement.size());
    STRATA_REQUIRE(written.transferredBytes == replacement.size());
    auto updated = fixture.dma.ReadVfsFile("\\mock.txt");
    STRATA_REQUIRE(updated);
    STRATA_REQUIRE(std::string(updated.value.begin(), updated.value.end()) ==
        "mXYZ");

    const uint8_t extra = '!';
    STRATA_REQUIRE(fixture.dma.WriteVfs("\\mock.txt", 6, &extra, 1));
    STRATA_REQUIRE(fixture.backend->vfsFiles["\\mock.txt"].size() == 7);
    STRATA_REQUIRE_STATUS(fixture.dma.WriteVfs("\\mock.txt", 0, nullptr, 0),
        DMAStatus::InvalidArgument);
}

namespace {
class MinimalBackend final : public IVmmBackend {
public:
    DMAOperationResult Initialize(const std::vector<std::string>&) override
    {
        initialized = true;
        return DMAOperationResult::Success();
    }
    void Close() override { initialized = false; }
    bool IsInitialized() const noexcept override { return initialized; }
    bool initialized = false;
};
}

STRATA_TEST_CASE(optional_backend_methods_default_to_unsupported)
{
    MinimalBackend backend;
    std::vector<DMARegistryHiveInfo> hives;
    std::vector<DMAPhysicalMemoryRange> ranges;
    DWORD transferred = 0;
    uint8_t byte = 0;
    STRATA_REQUIRE_STATUS(backend.InitializePlugins(), DMAStatus::Unsupported);
    STRATA_REQUIRE_STATUS(backend.GetRegistryHives(hives),
        DMAStatus::Unsupported);
    STRATA_REQUIRE_STATUS(backend.GetPhysicalMemoryMap(ranges),
        DMAStatus::Unsupported);
    STRATA_REQUIRE_STATUS(backend.ReadVfs("\\file", 0, &byte, 1,
        transferred), DMAStatus::Unsupported);
    STRATA_REQUIRE(!backend.CreateScatter(42, 0));
}
