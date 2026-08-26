#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "StrataDMA/DMA.hpp"

namespace {
bool RunSelfTest()
{
    const std::vector<uint8_t> bytes = {
        0x48, 0x8B, 0x01, 0x90, 0x48, 0x8B, 0xFF, 0x90
    };
    const auto pattern = DMA::CompilePattern("48 8B ? 90");
    const auto invalid = DMA::CompilePattern("48 ZZ");
    if (!pattern || invalid)
        return false;

    const auto all = DMA::ScanBufferAdvanced(bytes, pattern.value, 0x1000);
    DMAScanOptions limitedOptions;
    limitedOptions.maxResults = 1;
    const auto limited = DMA::ScanBufferAdvanced(bytes, pattern.value, 0x1000,
        limitedOptions);

    return all && limited && all.value.size() == 2 &&
        all.value[0].address == 0x1000 && all.value[1].address == 0x1004 &&
        limited.value.size() == 1 && limited.value[0].address == 0x1000;
}

int RunHardwareSmokeTest(const std::string& processName)
{
    DMA dma;
    size_t failures = 0;
    const auto check = [&failures](bool passed, const std::string& name,
        const std::string& detail = {}) {
        std::cout << (passed ? "[PASS] " : "[FAIL] ") << name;
        if (!detail.empty())
            std::cout << ": " << detail;
        std::cout << '\n';
        if (!passed)
            ++failures;
        return passed;
    };
    const auto optional = [](bool passed, const std::string& name,
        const std::string& detail = {}) {
        std::cout << (passed ? "[PASS] " : "[WARN] ") << name;
        if (!detail.empty())
            std::cout << ": " << detail;
        std::cout << '\n';
    };

    std::cout << "StrataDMA read-only hardware smoke test\n"
        << "Target process: " << processName << "\n\n";

    DMAInitializationOptions options;
    options.useMemoryMap = false;
    options.initializePlugins = true;
    options.waitForInitialization = true;
    const auto initialized = dma.Initialize(options);
    if (!check(static_cast<bool>(initialized), "initialize VMMDLL",
            initialized.message))
        return 1;

    const auto version = dma.GetVmmVersion();
    check(version.major != 0, "read VMM version",
        std::to_string(version.major) + '.' + std::to_string(version.minor) +
        '.' + std::to_string(version.revision));
    check(dma.GetWindowsBuild() != 0, "read target Windows build",
        std::to_string(dma.GetWindowsBuild()));

    const auto physical = dma.GetPhysicalMemoryMap(true);
    check(physical && !physical.value.empty(), "read physical-memory map",
        physical ? std::to_string(physical.value.size()) + " ranges"
                 : physical.operation.message);

    auto attachResult = dma.Attach(processName);
    bool attached = static_cast<bool>(attachResult);
    if (!attached) {
        std::cout << "[INFO] Normal attachment failed; trying bounded CR3 "
            "recovery.\n";
        auto recovery = dma.AttachWithCR3Recovery(processName);
        attached = static_cast<bool>(recovery);
        check(attached, "attach with CR3 recovery",
            attached ? std::to_string(recovery.value.attempts.size()) +
                           " candidates tested"
                     : recovery.operation.message);
    }
    else {
        check(true, "attach to process", processName);
    }
    if (!attached) {
        dma.Disconnect();
        return 1;
    }

    const auto process = dma.GetProcessInfo();
    check(static_cast<bool>(process), "read expanded process metadata",
        process ? "PID " + std::to_string(process.value.pid)
                : process.operation.message);

    const uint64_t base = dma.GetMainBase();
    const auto mz = dma.Read<uint16_t>(base);
    check(mz && mz.value == IMAGE_DOS_SIGNATURE, "read main-module MZ header",
        mz ? "base " + std::to_string(base) : mz.operation.message);

    uint16_t scatterMz = 0;
    auto scatter = dma.CreateScatterBatch();
    const auto queued = scatter.AddRead(base, scatterMz);
    const auto executed = queued ? scatter.Execute()
                                 : DMAResult<std::vector<DMAScatterRequestResult>>{
                                       queued, {} };
    check(executed && scatterMz == IMAGE_DOS_SIGNATURE,
        "execute scatter read",
        executed ? std::to_string(executed.value.size()) + " request"
                 : executed.operation.message);

    const auto modules = dma.GetModules(true);
    check(!modules.empty(), "enumerate modules",
        std::to_string(modules.size()) + " modules");
    const auto sections = dma.GetModuleSections(processName);
    check(sections && !sections.value.empty(), "enumerate PE sections",
        sections ? std::to_string(sections.value.size()) + " sections"
                 : sections.operation.message);

    DMAMemoryRegionFilter regionFilter;
    regionFilter.includePte = true;
    const auto regions = dma.GetMemoryRegions(regionFilter);
    check(regions && !regions.value.empty(), "enumerate VAD/PTE regions",
        regions ? std::to_string(regions.value.size()) + " regions"
                : regions.operation.message);

    const auto peb = dma.GetProcessEnvironmentBlock();
    optional(static_cast<bool>(peb), "parse PEB",
        peb ? (peb.value.is32Bit ? "WoW64" : "native")
            : peb.operation.message);
    const auto vfs = dma.ListVfs("\\");
    optional(static_cast<bool>(vfs), "list MemProcFS VFS root",
        vfs ? std::to_string(vfs.value.size()) + " entries"
            : vfs.operation.message);

    dma.Disconnect();
    std::cout << '\n' << (failures == 0 ? "Hardware smoke test passed."
        : "Hardware smoke test failed: " + std::to_string(failures) +
            " required checks failed.") << '\n';
    return failures == 0 ? 0 : 1;
}
}

auto main(int argc, char** argv) -> int
{
    if (argc > 1 && std::string(argv[1]) == "--self-test") {
        const bool passed = RunSelfTest();
        std::cout << (passed ? "[+] Pure self-test passed.\n"
            : "[-] Pure self-test failed.\n");
        return passed ? 0 : 1;
    }
    if (argc > 1 && std::string(argv[1]) == "--hardware-test")
        return RunHardwareSmokeTest(argc > 2 ? argv[2] : "explorer.exe");
    if (argc > 1 && std::string(argv[1]) == "--help") {
        std::cout << "Usage:\n"
            "  strata_dma_example --self-test\n"
            "  strata_dma_example --hardware-test [process.exe]\n"
            "  strata_dma_example  (interactive input demo)\n";
        return 0;
    }

    auto& dma = DMA::Get();

    DMAInitializationOptions options;
    options.debug = true;
    const auto initialized = dma.Initialize(options);
    if (!initialized) {
        std::cout << "[-] Failed to initialize DMA: "
            << initialized.message << '\n';
        return -1;
    }

    const auto attached = dma.Attach("svchost.exe");
    if (!attached) {
        std::cout << "[-] Failed to attach to svchost.exe: "
            << attached.message << '\n';
        return -2;
    }

    const auto keyboard = dma.InitKeyboard(10, true);
    if (!keyboard)
        std::cout << "[-] Failed to initialize keyboard: "
            << keyboard.message << '\n';

    DMAGamepadConfig gamepadConfig;
    gamepadConfig.pollIntervalMs = 4;
    gamepadConfig.debug = true;
    const auto gamepad = dma.InitGamepad(gamepadConfig);
    if (!gamepad)
        std::cout << "[-] Failed to initialize Xbox Gamepad: "
            << gamepad.message << '\n';

    std::cout << "\n[+] Polling started. Only active inputs will be printed.\n\n";
    while (true) {
        if (dma.IsKeyDown('W')) std::cout << "[KEY] W is held\n";
        if (dma.IsKeyDown('A')) std::cout << "[KEY] A is held\n";
        if (dma.IsKeyDown('S')) std::cout << "[KEY] S is held\n";
        if (dma.IsKeyDown('D')) std::cout << "[KEY] D is held\n";

        if (dma.IsGamepadButtonPressed(XINPUT_GAMEPAD_A))
            std::cout << "[GPAD] A pressed\n";
        if (dma.IsGamepadButtonPressed(XINPUT_GAMEPAD_B))
            std::cout << "[GPAD] B pressed\n";
        if (dma.IsGamepadButtonPressed(XINPUT_GAMEPAD_X))
            std::cout << "[GPAD] X pressed\n";
        if (dma.IsGamepadButtonPressed(XINPUT_GAMEPAD_Y))
            std::cout << "[GPAD] Y pressed\n";
        if (dma.IsGamepadButtonPressed(XINPUT_GAMEPAD_LEFT_SHOULDER))
            std::cout << "[GPAD] LB pressed\n";
        if (dma.IsGamepadButtonPressed(XINPUT_GAMEPAD_RIGHT_SHOULDER))
            std::cout << "[GPAD] RB pressed\n";

        const GamepadState state = dma.GetGamepadState();
        if (state.leftTrigger > 10)
            std::cout << "[GPAD] LT Depth: " << static_cast<int>(state.leftTrigger) << '\n';
        if (state.rightTrigger > 10)
            std::cout << "[GPAD] RT Depth: " << static_cast<int>(state.rightTrigger) << '\n';

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}
