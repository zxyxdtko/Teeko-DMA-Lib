#include "MockVmmBackend.hpp"
#include "TestHarness.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace {
bool HasArgument(const std::vector<std::string>& arguments,
    const std::string& requested)
{
    return std::find(arguments.begin(), arguments.end(), requested) !=
        arguments.end();
}
}

STRATA_TEST_CASE(initialization_forwards_options_and_plugins)
{
    MockDmaFixture fixture;
    DMAInitializationOptions options;
    options.device = "mock://device";
    options.useMemoryMap = true;
    options.memoryMapPath = "auto";
    options.debug = true;
    options.waitForInitialization = true;
    options.initializePlugins = true;
    options.extraArguments = { "-norefresh" };

    STRATA_REQUIRE(fixture.dma.Initialize(options));
    STRATA_REQUIRE(fixture.backend->pluginsInitialized);
    STRATA_REQUIRE(!fixture.backend->initializeArguments.empty());
    STRATA_REQUIRE(fixture.backend->initializeArguments.front().empty());
    STRATA_REQUIRE(HasArgument(fixture.backend->initializeArguments,
        "mock://device"));
    STRATA_REQUIRE(HasArgument(fixture.backend->initializeArguments, "-memmap"));
    STRATA_REQUIRE(HasArgument(fixture.backend->initializeArguments, "auto"));
    STRATA_REQUIRE(HasArgument(fixture.backend->initializeArguments, "-v"));
    STRATA_REQUIRE(HasArgument(fixture.backend->initializeArguments,
        "-waitinitialize"));
    STRATA_REQUIRE(HasArgument(fixture.backend->initializeArguments,
        "-norefresh"));
}

STRATA_TEST_CASE(initialization_failures_preserve_diagnostics)
{
    auto backend = std::make_shared<MockVmmBackend>();
    DMA dma(backend);
    DMAInitializationOptions options;
    options.useMemoryMap = false;

    backend->failInitialize = true;
    auto initialized = dma.Initialize(options);
    STRATA_REQUIRE(!initialized);
    STRATA_REQUIRE(initialized.message.find("mock initialization") !=
        std::string::npos);

    backend->failInitialize = false;
    backend->failPluginInitialization = true;
    options.initializePlugins = true;
    initialized = dma.Initialize(options);
    STRATA_REQUIRE(!initialized);
    STRATA_REQUIRE(!backend->initialized);
    STRATA_REQUIRE(initialized.message.find("plugin") != std::string::npos);
}

STRATA_TEST_CASE(attach_detach_and_module_cache_are_consistent)
{
    MockDmaFixture fixture;
    fixture.Initialize();
    STRATA_REQUIRE(!fixture.dma.IsAttached());
    fixture.Attach();
    STRATA_REQUIRE(fixture.dma.GetPID() == MockVmmBackend::TargetPid);
    STRATA_REQUIRE(fixture.dma.GetMainBase() == MockVmmBackend::MemoryBase);

    const size_t calls = fixture.backend->moduleCalls.load();
    STRATA_REQUIRE(fixture.dma.GetModuleBase("TEST.EXE") ==
        MockVmmBackend::MemoryBase);
    STRATA_REQUIRE(fixture.dma.GetModuleSize("test.exe") == 0x8000);
    STRATA_REQUIRE(fixture.backend->moduleCalls.load() == calls);

    STRATA_REQUIRE(fixture.dma.GetModuleBase("helper.dll") == 0x9000);
    const size_t helperCalls = fixture.backend->moduleCalls.load();
    STRATA_REQUIRE(fixture.dma.GetModuleBase("HELPER.DLL") == 0x9000);
    STRATA_REQUIRE(fixture.backend->moduleCalls.load() == helperCalls);

    fixture.dma.Detach();
    STRATA_REQUIRE(!fixture.dma.IsAttached());
    STRATA_REQUIRE(fixture.dma.GetPID() == 0);
    STRATA_REQUIRE(fixture.dma.GetMainBase() == 0);
}

STRATA_TEST_CASE(process_discovery_and_expanded_metadata_are_exposed)
{
    MockDmaFixture fixture;
    fixture.Initialize();
    const auto ids = fixture.dma.FindProcessIds("TEST.EXE");
    STRATA_REQUIRE(ids == std::vector<DWORD>{ MockVmmBackend::TargetPid });

    auto process = fixture.dma.GetProcessInfo(MockVmmBackend::TargetPid);
    STRATA_REQUIRE(process);
    STRATA_REQUIRE(process.value.parentPid == 4);
    STRATA_REQUIRE(process.value.eprocessAddress != 0);
    STRATA_REQUIRE(process.value.pebAddress == 0x8000);
    STRATA_REQUIRE(process.value.sid == "S-1-5-21-mock");
    STRATA_REQUIRE(process.value.integrityLevel ==
        VMMDLL_PROCESS_INTEGRITY_LEVEL_HIGH);

    auto missing = fixture.dma.GetProcessInfo(99);
    STRATA_REQUIRE(!missing);
    STRATA_REQUIRE_STATUS(missing.operation, DMAStatus::NotFound);
}

STRATA_TEST_CASE(structured_reads_and_writes_report_complete_context)
{
    MockDmaFixture fixture;
    fixture.Attach();
    const uint64_t address = 0x1800;
    const uint32_t expected = 0x12345678;
    auto written = fixture.dma.WriteRaw(address, &expected,
        sizeof(expected));
    STRATA_REQUIRE(written);
    STRATA_REQUIRE(written.pid == MockVmmBackend::TargetPid);
    STRATA_REQUIRE(written.address == address);
    STRATA_REQUIRE(written.requestedBytes == sizeof(expected));
    STRATA_REQUIRE(written.transferredBytes == sizeof(expected));

    auto read = fixture.dma.Read<uint32_t>(address,
        VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_NOPAGING);
    STRATA_REQUIRE(read && read.value == expected);
    STRATA_REQUIRE(read.operation.flags ==
        (VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_NOPAGING));
    STRATA_REQUIRE(fixture.backend->lastReadFlags == read.operation.flags);

    fixture.backend->partialReadLimit = 2;
    uint32_t partialValue = 0;
    auto partial = fixture.dma.ReadRaw(address, &partialValue,
        sizeof(partialValue));
    STRATA_REQUIRE(!partial);
    STRATA_REQUIRE_STATUS(partial, DMAStatus::PartialTransfer);
    STRATA_REQUIRE(partial.transferredBytes == 2);

    fixture.backend->partialReadLimit = 0;
    fixture.backend->failWrites = true;
    auto failedWrite = fixture.dma.WriteRaw(address, &expected,
        sizeof(expected));
    STRATA_REQUIRE(!failedWrite);
    STRATA_REQUIRE(failedWrite.message.find("write") != std::string::npos);
}

STRATA_TEST_CASE(invalid_memory_requests_fail_without_touching_backend)
{
    MockDmaFixture fixture;
    fixture.Attach();
    const size_t reads = fixture.backend->readCalls.load();
    uint32_t value = 0;
    auto nullAddress = fixture.dma.ReadRaw(0, &value, sizeof(value));
    auto nullBuffer = fixture.dma.ReadRaw(0x1800, nullptr, sizeof(value));
    auto zeroSize = fixture.dma.ReadRaw(0x1800, &value, 0);
    STRATA_REQUIRE_STATUS(nullAddress, DMAStatus::InvalidArgument);
    STRATA_REQUIRE_STATUS(nullBuffer, DMAStatus::InvalidArgument);
    STRATA_REQUIRE_STATUS(zeroSize, DMAStatus::InvalidArgument);
    STRATA_REQUIRE(fixture.backend->readCalls.load() == reads);
}

STRATA_TEST_CASE(strings_pointer_chains_and_relative_addresses_work)
{
    MockDmaFixture fixture;
    fixture.Attach();
    const char text[] = "hello";
    fixture.backend->StoreBytes(0x3000, text, sizeof(text));
    const char16_t wide[] = u"wide";
    fixture.backend->StoreBytes(0x3100, wide, sizeof(wide));
    STRATA_REQUIRE(fixture.dma.ReadString(0x3000, 32) == "hello");
    STRATA_REQUIRE(fixture.dma.ReadWString(0x3100, 32) == L"wide");

    // ReadChain dereferences first, then applies each offset.
    fixture.backend->Store<uint64_t>(0x3200, 0x3400);
    fixture.backend->Store<uint64_t>(0x3410, 0x35e0);
    const auto chain = fixture.dma.ReadChain(0x3200, { 0x10, 0x20 });
    STRATA_REQUIRE(chain && chain.value == 0x3600);
    const auto emptyChain = fixture.dma.ReadChain(0x3200, {});
    STRATA_REQUIRE(emptyChain && emptyChain.value == 0x3200);

    const int32_t displacement = 0x20;
    fixture.backend->Store(0x3703, displacement);
    STRATA_REQUIRE(fixture.dma.ResolveRelative(0x3700, 3, 7) == 0x3727);
}

STRATA_TEST_CASE(memory_contexts_bind_pid_flags_and_translation)
{
    MockDmaFixture fixture;
    fixture.Attach();
    const uint32_t expected = 99;
    fixture.backend->Store(0x4000, expected);

    auto process = fixture.dma.ProcessContext();
    auto value = process.Read<uint32_t>(0x4000);
    STRATA_REQUIRE(value && value.value == expected);
    STRATA_REQUIRE(fixture.backend->lastReadPid == MockVmmBackend::TargetPid);

    auto kernel = fixture.dma.KernelContext(4, VMMDLL_FLAG_NOPAGING);
    auto kernelValue = kernel.Read<uint32_t>(0x4000);
    STRATA_REQUIRE(kernelValue && kernelValue.value == expected);
    STRATA_REQUIRE(fixture.backend->lastReadPid ==
        (4 | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY));
    STRATA_REQUIRE(fixture.backend->lastReadFlags == VMMDLL_FLAG_NOPAGING);

    const auto physical = fixture.dma.VirtualToPhysical(0x4000);
    STRATA_REQUIRE(physical && physical.value == 0x103000);
    STRATA_REQUIRE(fixture.dma.PrefetchPages({ 0x4000, 0x5000 }));
    STRATA_REQUIRE(fixture.backend->prefetchedPages.size() == 2);
}

STRATA_TEST_CASE(process_monitor_reports_exit_and_reattachment)
{
    MockDmaFixture fixture;
    fixture.Attach();
    std::atomic<size_t> exits{ 0 };
    std::atomic<size_t> reattachments{ 0 };
    STRATA_REQUIRE(fixture.dma.StartProcessMonitor("test.exe", 10, true,
        [&](const DMAProcessEvent& event) {
            if (event.kind == DMAProcessEventKind::Exited)
                ++exits;
            if (event.kind == DMAProcessEventKind::Reattached ||
                event.kind == DMAProcessEventKind::Attached)
                ++reattachments;
        }));

    fixture.backend->processAvailable.store(false);
    for (int attempt = 0; attempt < 50 && exits.load() == 0; ++attempt)
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    fixture.backend->processAvailable.store(true);
    for (int attempt = 0; attempt < 50 && reattachments.load() == 0; ++attempt)
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    fixture.dma.StopProcessMonitor();

    STRATA_REQUIRE(exits.load() >= 1);
    STRATA_REQUIRE(reattachments.load() >= 1);
    STRATA_REQUIRE(fixture.dma.IsAttached());
}
