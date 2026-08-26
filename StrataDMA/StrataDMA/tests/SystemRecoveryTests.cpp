#include "MockVmmBackend.hpp"
#include "TestHarness.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

STRATA_TEST_CASE(native_peb_fields_are_parsed_from_stable_offsets)
{
    MockDmaFixture fixture;
    fixture.Initialize();
    std::array<uint8_t, 0x38> bytes{};
    bytes[0] = 1;
    bytes[2] = 1;
    const uint64_t image = 0x140000000;
    const uint64_t loader = 0x8100;
    const uint64_t parameters = 0x8200;
    const uint64_t heap = 0x8300;
    std::memcpy(bytes.data() + 0x10, &image, sizeof(image));
    std::memcpy(bytes.data() + 0x18, &loader, sizeof(loader));
    std::memcpy(bytes.data() + 0x20, &parameters, sizeof(parameters));
    std::memcpy(bytes.data() + 0x30, &heap, sizeof(heap));
    fixture.backend->StoreBytes(0x8000, bytes.data(), bytes.size());

    auto peb = fixture.dma.GetProcessEnvironmentBlock(
        MockVmmBackend::TargetPid);
    STRATA_REQUIRE(peb);
    STRATA_REQUIRE(!peb.value.is32Bit);
    STRATA_REQUIRE(peb.value.inheritedAddressSpace);
    STRATA_REQUIRE(peb.value.beingDebugged);
    STRATA_REQUIRE(peb.value.imageBaseAddress == image);
    STRATA_REQUIRE(peb.value.loaderDataAddress == loader);
    STRATA_REQUIRE(peb.value.processParametersAddress == parameters);
    STRATA_REQUIRE(peb.value.processHeapAddress == heap);
}

STRATA_TEST_CASE(wow64_peb_selection_and_32bit_pointers_are_supported)
{
    MockDmaFixture fixture;
    fixture.Initialize();
    fixture.backend->processes[0].wow64 = true;
    fixture.backend->processes[0].wow64PebAddress = 0x8500;
    std::array<uint8_t, 0x1c> bytes{};
    bytes[1] = 1;
    const uint32_t image = 0x400000;
    const uint32_t loader = 0x8600;
    const uint32_t parameters = 0x8700;
    const uint32_t heap = 0x8800;
    std::memcpy(bytes.data() + 0x08, &image, sizeof(image));
    std::memcpy(bytes.data() + 0x0c, &loader, sizeof(loader));
    std::memcpy(bytes.data() + 0x10, &parameters, sizeof(parameters));
    std::memcpy(bytes.data() + 0x18, &heap, sizeof(heap));
    fixture.backend->StoreBytes(0x8500, bytes.data(), bytes.size());

    auto wow64 = fixture.dma.GetProcessEnvironmentBlock(
        MockVmmBackend::TargetPid, true);
    STRATA_REQUIRE(wow64 && wow64.value.is32Bit);
    STRATA_REQUIRE(wow64.value.readImageFileExecOptions);
    STRATA_REQUIRE(wow64.value.imageBaseAddress == image);
    STRATA_REQUIRE(wow64.value.processHeapAddress == heap);

    auto native = fixture.dma.GetProcessEnvironmentBlock(
        MockVmmBackend::TargetPid, false);
    STRATA_REQUIRE(native && !native.value.is32Bit);
    STRATA_REQUIRE(native.value.address == 0x8000);
}

STRATA_TEST_CASE(peb_lookup_reports_missing_addresses_and_partial_reads)
{
    MockDmaFixture fixture;
    fixture.Initialize();
    fixture.backend->processes[0].pebAddress = 0;
    auto missing = fixture.dma.GetProcessEnvironmentBlock(
        MockVmmBackend::TargetPid);
    STRATA_REQUIRE(!missing);
    STRATA_REQUIRE_STATUS(missing.operation, DMAStatus::NotFound);

    fixture.backend->processes[0].pebAddress = 0x8000;
    fixture.backend->partialReadLimit = 4;
    auto partial = fixture.dma.GetProcessEnvironmentBlock(
        MockVmmBackend::TargetPid);
    STRATA_REQUIRE(!partial);
    STRATA_REQUIRE_STATUS(partial.operation, DMAStatus::PartialTransfer);
}

STRATA_TEST_CASE(cr3_recovery_short_circuits_when_current_mapping_is_valid)
{
    MockDmaFixture fixture;
    fixture.Initialize();
    auto recovery = fixture.dma.RecoverCR3(MockVmmBackend::TargetPid,
        "test.exe");
    STRATA_REQUIRE(recovery);
    STRATA_REQUIRE(!recovery.value.recoveryNeeded);
    STRATA_REQUIRE(recovery.value.attempts.empty());
    STRATA_REQUIRE(!fixture.backend->pluginsInitialized);
}

STRATA_TEST_CASE(cr3_recovery_tests_candidates_and_returns_diagnostics)
{
    MockDmaFixture fixture;
    fixture.Initialize();
    fixture.backend->requireConfiguredDtb = true;
    fixture.backend->configuredDtb = 0;
    DMACR3RecoveryOptions options;
    options.timeout = std::chrono::milliseconds(20);
    options.pollInterval = std::chrono::milliseconds(1);
    auto recovery = fixture.dma.RecoverCR3(MockVmmBackend::TargetPid,
        "test.exe", options);
    STRATA_REQUIRE(recovery);
    STRATA_REQUIRE(fixture.backend->pluginsInitialized);
    STRATA_REQUIRE(recovery.value.recoveryNeeded);
    STRATA_REQUIRE(recovery.value.recoveredDtb == MockVmmBackend::ValidDtb);
    STRATA_REQUIRE(recovery.value.attempts.size() >= 3);
    STRATA_REQUIRE(recovery.value.attempts.back().operation);
    STRATA_REQUIRE(fixture.backend->configuredDtb == MockVmmBackend::ValidDtb);
}

STRATA_TEST_CASE(cr3_failure_restores_original_dtb)
{
    MockDmaFixture fixture;
    fixture.Initialize();
    fixture.backend->requireConfiguredDtb = true;
    const std::string wrong = "0000 0 0000000000bad000 0 test.exe\n";
    fixture.backend->vfsFiles["\\misc\\procinfo\\dtb.txt"] =
        std::vector<uint8_t>(wrong.begin(), wrong.end());
    DMACR3RecoveryOptions options;
    options.timeout = std::chrono::milliseconds(20);
    options.pollInterval = std::chrono::milliseconds(1);
    auto recovery = fixture.dma.RecoverCR3(MockVmmBackend::TargetPid,
        "test.exe", options);
    STRATA_REQUIRE(!recovery);
    STRATA_REQUIRE_STATUS(recovery.operation, DMAStatus::NotFound);
    STRATA_REQUIRE(recovery.value.restoredOriginalDtb);
    STRATA_REQUIRE(fixture.backend->configuredDtb == 0x111000);
    STRATA_REQUIRE(!recovery.value.attempts.empty());
}

STRATA_TEST_CASE(cr3_plugin_failure_and_timeout_are_bounded)
{
    MockDmaFixture pluginFailure;
    pluginFailure.Initialize();
    pluginFailure.backend->requireConfiguredDtb = true;
    pluginFailure.backend->failPluginInitialization = true;
    auto failed = pluginFailure.dma.RecoverCR3(MockVmmBackend::TargetPid,
        "test.exe");
    STRATA_REQUIRE(!failed);
    STRATA_REQUIRE_STATUS(failed.operation, DMAStatus::BackendError);

    MockDmaFixture timeout;
    timeout.Initialize();
    timeout.backend->requireConfiguredDtb = true;
    timeout.backend->vfsFiles["\\misc\\procinfo\\progress_percent.txt"] =
        { '0' };
    DMACR3RecoveryOptions options;
    options.timeout = std::chrono::milliseconds(2);
    options.pollInterval = std::chrono::milliseconds(1);
    auto timedOut = timeout.dma.RecoverCR3(MockVmmBackend::TargetPid,
        "test.exe", options);
    STRATA_REQUIRE(!timedOut);
    STRATA_REQUIRE_STATUS(timedOut.operation, DMAStatus::Timeout);
}

STRATA_TEST_CASE(attach_with_cr3_recovery_handles_pre_attach_failure)
{
    MockDmaFixture fixture;
    fixture.Initialize();
    fixture.backend->requireConfiguredDtb = true;
    DMACR3RecoveryOptions options;
    options.timeout = std::chrono::milliseconds(20);
    options.pollInterval = std::chrono::milliseconds(1);
    auto attached = fixture.dma.AttachWithCR3Recovery("test.exe", options);
    STRATA_REQUIRE(attached);
    STRATA_REQUIRE(fixture.dma.IsAttached());
    STRATA_REQUIRE(fixture.dma.GetPID() == MockVmmBackend::TargetPid);
    STRATA_REQUIRE(attached.value.recoveredDtb == MockVmmBackend::ValidDtb);
}

STRATA_TEST_CASE(physical_ranges_are_sorted_refreshed_and_exported)
{
    MockDmaFixture fixture;
    fixture.Initialize();
    std::reverse(fixture.backend->physicalRanges.begin(),
        fixture.backend->physicalRanges.end());
    auto ranges = fixture.dma.GetPhysicalMemoryMap(true);
    STRATA_REQUIRE(ranges && ranges.value.size() == 2);
    STRATA_REQUIRE(ranges.value[0].baseAddress == 0x1000);
    STRATA_REQUIRE(ranges.value[0].EndAddress() == 0xa000);
    STRATA_REQUIRE(ranges.value[0].LastAddress() == 0x9fff);
    STRATA_REQUIRE(std::find_if(fixture.backend->configWrites.begin(),
        fixture.backend->configWrites.end(), [](const auto& write) {
            return write.first == VMMDLL_OPT_REFRESH_SPECIFIC_PHYSMEMMAP;
        }) != fixture.backend->configWrites.end());

    const auto path = std::filesystem::temp_directory_path() /
        "strata_dma_physical_map_test.txt";
    auto exported = fixture.dma.ExportPhysicalMemoryMap(path.string());
    STRATA_REQUIRE(exported);
    std::ifstream input(path);
    std::string firstLine;
    std::getline(input, firstLine);
    STRATA_REQUIRE(firstLine == "0000000000001000 0000000000009fff");
    input.close();
    std::error_code error;
    std::filesystem::remove(path, error);
    STRATA_REQUIRE(!error);
}

STRATA_TEST_CASE(physical_map_errors_are_structured)
{
    MockDmaFixture fixture;
    fixture.Initialize();
    fixture.backend->failPhysicalMap = true;
    auto failed = fixture.dma.GetPhysicalMemoryMap();
    STRATA_REQUIRE(!failed);
    STRATA_REQUIRE_STATUS(failed.operation, DMAStatus::BackendError);
    STRATA_REQUIRE_STATUS(fixture.dma.ExportPhysicalMemoryMap(""),
        DMAStatus::InvalidArgument);
}
