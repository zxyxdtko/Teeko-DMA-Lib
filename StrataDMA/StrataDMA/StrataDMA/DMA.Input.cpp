#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "DMA.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>

namespace {
template <typename T>
T LoadUnalignedInput(const uint8_t* source)
{
    T value{};
    std::memcpy(&value, source, sizeof(value));
    return value;
}

uint64_t FindPattern(const std::vector<uint8_t>& buffer, uint64_t baseAddress,
    const std::string& signature)
{
    const auto pattern = DMA::CompilePattern(signature);
    if (!pattern)
        return 0;
    DMAScanOptions options;
    options.maxResults = 1;
    const auto matches = DMA::ScanBufferAdvanced(buffer, pattern.value,
        baseAddress, options);
    return matches && !matches.value.empty() ? matches.value.front().address : 0;
}

DMAOperationResult InputFailure(DMAStatus status, const char* message)
{
    return DMAOperationResult::Failure(status, message);
}
}


/// <summary>
/// Initialize the keyboard state reader.
/// Finds the gafAsyncKeyState export in win32kbase.sys/win32k.sys and starts a background thread to poll it.
/// </summary>
/// <param name="poll_ms">Interval in milliseconds to poll the keyboard state (default: 10ms).</param>
/// <returns>The keyboard initialization result.</returns>
DMAOperationResult DMA::InitKeyboard(int poll_ms, bool debug) {
    if (!IsInitialized()) {
        if (debug) printf("[InitKeyboard] FAIL: DMA is not initialized\n");
        return InputFailure(DMAStatus::NotInitialized,
            "DMA is not initialized.");
    }

    StopKeyboardThread();
    gafAsyncKeyStateExport = 0;
    gptCursorAsyncExport = 0;
    win_logon_pid = 0;
    {
        std::lock_guard<std::mutex> lock(kb_mutex);
        state_bitmap.fill(0);
        pressed_bitmap.fill(0);
        released_bitmap.fill(0);
    }
    const uint32_t Winver = GetWindowsBuild();
    if (Winver == 0) {
        if (debug) printf("[InitKeyboard] FAIL: Could not query the Windows build.\n");
        return InputFailure(DMAStatus::BackendError,
            "Could not query the Windows build.");
    }

    if (debug) printf("[InitKeyboard] Winver=%d (threshold 22000, path=%s)\n",
        Winver, Winver >= 22000 ? "Win11/csrss sig-scan" : "Win10/EAT");

    if (!backend->FindPid("winlogon.exe", win_logon_pid)) {
        if (debug) printf("[InitKeyboard] FAIL: Could not find winlogon.exe pid\n");
        return InputFailure(DMAStatus::NotFound,
            "Could not find winlogon.exe.");
    }
    if (debug) printf("[InitKeyboard] winlogon.exe pid=%u\n", win_logon_pid);

    // ---------------------------------------------------------------
    // Win11+ path: locate gafAsyncKeyState via csrss session sig-scan
    // ---------------------------------------------------------------
    if (Winver >= 22000) {
        std::vector<DMAProcessInfo> processes;
        if (!backend->GetProcesses(processes)) {
            if (debug) printf("[InitKeyboard] FAIL: process enumeration failed\n");
            return InputFailure(DMAStatus::BackendError,
                "Process enumeration failed.");
        }
        if (debug) printf("[InitKeyboard] Total process count: %zu\n", processes.size());

        for (const auto& process : processes) {
            const DWORD pid = process.pid;
            const std::string procName = process.longName.empty()
                ? process.name : process.longName;

            if (NormalizeName(procName).find("csrss.exe") == std::string::npos)
                continue;

            if (debug) printf("[InitKeyboard] Found csrss candidate: pid=%u path=\"%s\"\n",
                pid, procName.c_str());

            auto getModule = [&](const std::string& name) -> std::pair<uint64_t, uint32_t> {
                DMAModuleInfo module;
                if (backend->GetModule(pid, name, module))
                    return { module.baseAddress, module.imageSize };
                return { 0, 0 };
                };

            // --- Locate win32ksgd.sys or win32k.sys ---
            auto [win32k_base, win32k_size] = getModule("win32ksgd.sys");
            if (win32k_base) {
                if (debug) printf("[InitKeyboard] [pid=%u] win32ksgd.sys base=0x%llx size=0x%x\n",
                    pid, win32k_base, win32k_size);
            }
            else {
                if (debug) printf("[InitKeyboard] [pid=%u] win32ksgd.sys not found, trying win32k.sys\n", pid);
                auto res = getModule("win32k.sys");
                win32k_base = res.first;
                win32k_size = res.second;
                if (!win32k_base) {
                    if (debug) printf("[InitKeyboard] [pid=%u] win32k.sys not found either, skipping\n", pid);
                    continue;
                }
                if (debug) printf("[InitKeyboard] [pid=%u] win32k.sys base=0x%llx size=0x%x\n",
                    pid, win32k_base, win32k_size);
            }

            // --- Dump win32k(sgd).sys ---
            std::vector<uint8_t> win32k_dump = DumpMemoryEx(
                pid | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY,
                win32k_base, win32k_size, VMMDLL_FLAG_ZEROPAD_ON_FAIL);
            if (win32k_dump.empty()) {
                if (debug) printf("[InitKeyboard] [pid=%u] FAIL: DumpMemory returned empty for win32k base=0x%llx\n",
                    pid, win32k_base);
                continue;
            }
            if (debug) printf("[InitKeyboard] [pid=%u] Dumped win32k, bytes=%zu\n", pid, win32k_dump.size());

            // --- Sig1: g_session_global_slots ---
            uint64_t g_session_ptr = FindPattern(win32k_dump, win32k_base,
                "48 8B 05 ? ? ? ? 48 8B 04 C8");
            if (g_session_ptr) {
                if (debug) printf("[InitKeyboard] [pid=%u] Sig1 hit at 0x%llx\n", pid, g_session_ptr);
            }
            else {
                if (debug) printf("[InitKeyboard] [pid=%u] Sig1 no match, trying Sig2\n", pid);
                g_session_ptr = FindPattern(win32k_dump, win32k_base,
                    "48 8B 05 ? ? ? ? FF C9");
                if (g_session_ptr) {
                    if (debug) printf("[InitKeyboard] [pid=%u] Sig2 hit at 0x%llx\n", pid, g_session_ptr);
                }
                else {
                    if (debug) printf("[InitKeyboard] [pid=%u] Sig2 no match, skipping this csrss\n", pid);
                    continue;
                }
            }

            const int32_t relative = LoadUnalignedInput<int32_t>(
                &win32k_dump[g_session_ptr - win32k_base + 3]);
            uint64_t g_session_global_slots = g_session_ptr + 7 + relative;
            if (debug) printf("[InitKeyboard] [pid=%u] relative=0x%x g_session_global_slots=0x%llx\n",
                pid, (uint32_t)relative, g_session_global_slots);

            // --- Walk slot table to find user_session_state ---
            // All pointer reads here are kernel addresses, must use kernel-context pid.
            DWORD kpid = pid | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY;
            auto KRead64 = [&](uint64_t addr) -> uint64_t {
                uint64_t val = 0;
                DWORD br = 0;
                return backend->ReadMemory(kpid, addr, &val, sizeof(val),
                    VMMDLL_FLAG_NOCACHE, br) && br == sizeof(val) ? val : 0;
                };

            uint64_t user_session_state = 0;
            for (int i = 0; i < 4; i++) {
                uint64_t ptr1 = KRead64(g_session_global_slots);
                uint64_t ptr2 = KRead64(ptr1 + 8 * i);
                user_session_state = KRead64(ptr2);
                if (debug) printf("[InitKeyboard] [pid=%u] slot[%d]: ptr1=0x%llx ptr2=0x%llx uss=0x%llx\n",
                    pid, i, ptr1, ptr2, user_session_state);
                if (user_session_state > 0x7FFFFFFFFFFF) {
                    if (debug) printf("[InitKeyboard] [pid=%u] user_session_state valid at slot %d\n", pid, i);
                    break;
                }
            }
            if (user_session_state <= 0x7FFFFFFFFFFF) {
                if (debug) printf("[InitKeyboard] [pid=%u] WARN: No valid user_session_state found in any slot (last=0x%llx)\n",
                    pid, user_session_state);
                continue;
            }

            // --- Locate win32kbase.sys ---
            auto [win32kbase_base, win32kbase_size] = getModule("win32kbase.sys");
            if (!win32kbase_base) {
                if (debug) printf("[InitKeyboard] [pid=%u] FAIL: win32kbase.sys not found, skipping\n", pid);
                continue;
            }
            if (debug) printf("[InitKeyboard] [pid=%u] win32kbase.sys base=0x%llx size=0x%x\n",
                pid, win32kbase_base, win32kbase_size);

            // --- Dump win32kbase.sys ---
            std::vector<uint8_t> win32kbase_dump = DumpMemoryEx(
                pid | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY,
                win32kbase_base, win32kbase_size, VMMDLL_FLAG_ZEROPAD_ON_FAIL);
            if (win32kbase_dump.empty()) {
                if (debug) printf("[InitKeyboard] [pid=%u] FAIL: DumpMemory returned empty for win32kbase base=0x%llx\n",
                    pid, win32kbase_base);
                continue;
            }
            if (debug) printf("[InitKeyboard] [pid=%u] Dumped win32kbase, bytes=%zu\n", pid, win32kbase_dump.size());

            // --- Sig3: session_offset for gafAsyncKeyState ---
            uint64_t ptr = FindPattern(win32kbase_dump, win32kbase_base,
                "48 8D 90 ? ? ? ? E8 ? ? ? ? 0F 57 C0");
            if (ptr) {
                uint32_t session_offset = *reinterpret_cast<uint32_t*>(
                    &win32kbase_dump[ptr - win32kbase_base + 3]);
                gafAsyncKeyStateExport = user_session_state + session_offset;
                if (debug) printf("[InitKeyboard] [pid=%u] Sig3 hit=0x%llx session_offset=0x%x gafAsyncKeyStateExport=0x%llx\n",
                    pid, ptr, session_offset, gafAsyncKeyStateExport);
            }
            else {
                if (debug) printf("[InitKeyboard] [pid=%u] Sig3 no match, skipping this csrss\n", pid);
                continue;
            }

            if (gafAsyncKeyStateExport > 0x7FFFFFFFFFFF) {
                if (debug) printf("[InitKeyboard] [pid=%u] gafAsyncKeyStateExport=0x%llx valid, starting kb thread\n",
                    pid, gafAsyncKeyStateExport);
                {
                    std::lock_guard<std::mutex> lock(kb_mutex);
                    state_bitmap.fill(0);
                    pressed_bitmap.fill(0);
                    released_bitmap.fill(0);
                }
                StartKeyboardThread(poll_ms);
                return DMAOperationResult::Success();
            }
            else {
                if (debug) printf("[InitKeyboard] [pid=%u] FAIL: gafAsyncKeyStateExport=0x%llx failed kernel address check\n",
                    pid, gafAsyncKeyStateExport);
            }
        }

        if (debug) printf("[InitKeyboard] FAIL: Exhausted all csrss candidates without success\n");
        return InputFailure(DMAStatus::NotFound,
            "No usable csrss session exposed gafAsyncKeyState.");

    }
    // ---------------------------------------------------------------
    // Win10 path: locate gafAsyncKeyState via EAT, fallback to PDB
    // ---------------------------------------------------------------
    else {
        if (debug) printf("[InitKeyboard] Win10 path: attempting EAT lookup for gafAsyncKeyState in win32kbase.sys\n");

        std::vector<DMAExportInfo> exports;
        if (backend->GetExports(
            win_logon_pid | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY,
            "win32kbase.sys", exports)) {
            for (size_t i = 0; i < exports.size(); ++i) {
                if (exports[i].name == "gafAsyncKeyState") {
                    gafAsyncKeyStateExport = exports[i].address;
                    if (debug) printf("[InitKeyboard] EAT found gafAsyncKeyState at 0x%llx (entry %zu)\n",
                        static_cast<unsigned long long>(gafAsyncKeyStateExport), i);
                    break;
                }
            }
        }
        else {
            if (debug) printf("[InitKeyboard] WARN: VMMDLL_Map_GetEATU failed for win32kbase.sys in winlogon pid=%u\n",
                win_logon_pid);
        }

        // --- PDB fallback if EAT didn't give a valid kernel address ---
        if (gafAsyncKeyStateExport < 0x7FFFFFFFFFFF) {
            if (debug) printf("[InitKeyboard] EAT result 0x%llx not a valid kernel addr, trying PDB fallback\n",
                gafAsyncKeyStateExport);
            DMAModuleInfo module;
            if (backend->GetModule(
                win_logon_pid | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY,
                "win32kbase.sys", module)) {
                if (debug) printf("[InitKeyboard] PDB: win32kbase.sys base=0x%llx\n",
                    static_cast<unsigned long long>(module.baseAddress));
                std::string symbolModule;
                if (backend->LoadSymbols(
                    win_logon_pid | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY,
                    module.baseAddress, symbolModule)) {
                    if (debug) printf("[InitKeyboard] PDB loaded: module name=\"%s\"\n", symbolModule.c_str());
                    uint64_t va = 0;
                    if (backend->ResolveSymbol(symbolModule, "gafAsyncKeyState", va)) {
                        gafAsyncKeyStateExport = va;
                        if (debug) printf("[InitKeyboard] PDB resolved gafAsyncKeyState to 0x%llx\n", va);
                    }
                    else {
                        if (debug) printf("[InitKeyboard] FAIL: PDB symbol lookup for gafAsyncKeyState returned false\n");
                    }
                }
                else {
                    if (debug) printf("[InitKeyboard] FAIL: VMMDLL_PdbLoad returned false for win32kbase.sys\n");
                }
            }
            else {
                if (debug) printf("[InitKeyboard] FAIL: Could not find win32kbase.sys module entry in winlogon pid=%u\n",
                    win_logon_pid);
            }
        }

        bool valid = gafAsyncKeyStateExport > 0x7FFFFFFFFFFF;
        if (debug) printf("[InitKeyboard] Final gafAsyncKeyStateExport=0x%llx valid=%s\n",
            gafAsyncKeyStateExport, valid ? "YES" : "NO");

        if (valid) {
            if (debug) printf("[InitKeyboard] Starting keyboard thread poll_ms=%d\n", poll_ms);
            StartKeyboardThread(poll_ms);
        }

        return valid ? DMAOperationResult::Success()
            : InputFailure(DMAStatus::NotFound,
                "Could not locate gafAsyncKeyState.");
    }
}

void DMA::StopKeyboard()
{
    StopKeyboardThread();
    std::lock_guard<std::mutex> lock(kb_mutex);
    state_bitmap.fill(0);
    pressed_bitmap.fill(0);
    released_bitmap.fill(0);
}

/// <summary>
/// Initializes the Xbox Gamepad reader by locating xboxgip.sys, scanning for the
/// static context array, and finding the active controller slot.
/// </summary>
DMAOperationResult DMA::InitGamepad(const DMAGamepadConfig& config) {
    if (!IsInitialized() || config.slotCount == 0 || config.slotStride == 0 ||
        config.stateSize < 15) {
        return InputFailure(!IsInitialized() ? DMAStatus::NotInitialized
            : DMAStatus::InvalidArgument,
            !IsInitialized() ? "DMA is not initialized."
            : "Gamepad configuration is invalid.");
    }

    gamepadConfig = config;
    const bool debug = config.debug;

    StopGamepadThread();
    active_controller_address = 0;
    gamepadArrayStart = 0;
    {
        std::lock_guard<std::mutex> lock(gamepad_mutex);
        currentGamepadState = {};
    }
    const int poll_ms = std::max(1, config.pollIntervalMs);

    DWORD sysPid = 4 | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY;

    DMAModuleInfo module;
    if (!backend->GetModule(sysPid, config.moduleName, module)) {
        if (debug) printf("[InitGamepad] FAIL: Could not find xboxgip.sys\n");
        return InputFailure(DMAStatus::NotFound,
            "Could not find the configured gamepad module.");
    }

    const uint64_t base = module.baseAddress;
    const uint32_t size = module.imageSize;

    std::vector<uint8_t> moduleDump = DumpMemoryEx(sysPid, base, size);
    if (moduleDump.empty())
        return InputFailure(DMAStatus::BackendError,
            "Could not read the gamepad module.");

    // Signature #2: 48 8D 05 ? ? ? ? 33 D2
    uint64_t hitAddress = FindPattern(moduleDump, base,
        config.slotArraySignature);

    if (!hitAddress) {
        if (debug) printf("[InitGamepad] FAIL: Signature not found.\n");
        return InputFailure(DMAStatus::NotFound,
            "The gamepad slot-array signature was not found.");
    }

    // Resolve RIP-relative offset from local buffer
    int32_t relativeOffset = LoadUnalignedInput<int32_t>(
        &moduleDump[hitAddress - base + 3]);
    uint64_t arrayStart = hitAddress + 7 + relativeOffset;
    gamepadArrayStart = arrayStart;

    // Find the active slot
    for (size_t i = 0; i < config.slotCount; i++) {
        uint64_t slotAddress = arrayStart + (i * config.slotStride);

        uint8_t isActive = 0;
        DWORD br = 0;
        if (!backend->ReadMemory(sysPid, slotAddress + config.activeOffset,
            &isActive, 1, VMMDLL_FLAG_NOCACHE, br) || br != 1) {
            continue;
        }

        if (isActive == 1) {
            if (debug) printf("[InitGamepad] SUCCESS: Found active controller at 0x%llx\n",
                static_cast<unsigned long long>(slotAddress));
            active_controller_address = slotAddress;

            // Start the background thread
            gamepad_running = true;
            gamepad_thread = std::thread(&DMA::GamepadThread, this, poll_ms);
            return DMAOperationResult::Success();
        }
    }

    if (debug) printf("[InitGamepad] FAIL: No active controllers found.\n");
    return InputFailure(DMAStatus::NotFound,
        "No active gamepad controller was found.");
}

void DMA::StopGamepad()
{
    StopGamepadThread();
    active_controller_address = 0;
    gamepadArrayStart = 0;
    std::lock_guard<std::mutex> lock(gamepad_mutex);
    currentGamepadState = {};
    previousGamepadButtons = 0;
    pressedGamepadButtons = 0;
    releasedGamepadButtons = 0;
}

/// <summary>
/// Returns a thread-safe copy of the current Gamepad State.
/// </summary>
GamepadState DMA::GetGamepadState() const {
    std::lock_guard<std::mutex> lock(gamepad_mutex);
    return currentGamepadState;
}

/// <summary>
/// Checks if a specific XInput button bitmask is currently pressed.
/// Example: dma.IsGamepadButtonPressed(0x1000) // Checks 'A' button
/// </summary>
bool DMA::IsGamepadButtonPressed(uint16_t buttonMask) const {
    std::lock_guard<std::mutex> lock(gamepad_mutex);
    return (currentGamepadState.buttons & buttonMask) != 0;
}

bool DMA::IsGamepadButtonJustPressed(uint16_t buttonMask) {
    std::lock_guard<std::mutex> lock(gamepad_mutex);
    const bool pressed = (pressedGamepadButtons & buttonMask) != 0;
    pressedGamepadButtons &= static_cast<uint16_t>(~buttonMask);
    return pressed;
}

bool DMA::IsGamepadButtonJustReleased(uint16_t buttonMask) {
    std::lock_guard<std::mutex> lock(gamepad_mutex);
    const bool released = (releasedGamepadButtons & buttonMask) != 0;
    releasedGamepadButtons &= static_cast<uint16_t>(~buttonMask);
    return released;
}

DMANormalizedGamepadState DMA::GetNormalizedGamepadState() const {
    std::lock_guard<std::mutex> lock(gamepad_mutex);
    const auto normalizeStick = [](int16_t value, int16_t deadZone) {
        const float magnitude = static_cast<float>(std::abs(static_cast<int>(value)));
        if (magnitude <= deadZone)
            return 0.0f;
        const float normalized = (magnitude - deadZone) / (32767.0f - deadZone);
        return std::copysign(std::min(1.0f, normalized), static_cast<float>(value));
    };
    DMANormalizedGamepadState result;
    result.buttons = currentGamepadState.buttons;
    result.leftTrigger = currentGamepadState.leftTrigger < gamepadConfig.triggerThreshold
        ? 0.0f : currentGamepadState.leftTrigger / 255.0f;
    result.rightTrigger = currentGamepadState.rightTrigger < gamepadConfig.triggerThreshold
        ? 0.0f : currentGamepadState.rightTrigger / 255.0f;
    result.thumbLX = normalizeStick(currentGamepadState.thumbLX,
        gamepadConfig.leftStickDeadZone);
    result.thumbLY = normalizeStick(currentGamepadState.thumbLY,
        gamepadConfig.leftStickDeadZone);
    result.thumbRX = normalizeStick(currentGamepadState.thumbRX,
        gamepadConfig.rightStickDeadZone);
    result.thumbRY = normalizeStick(currentGamepadState.thumbRY,
        gamepadConfig.rightStickDeadZone);
    result.connected = currentGamepadState.connected;
    return result;
}

/// <summary>
/// Check if a key is currently held down.
/// </summary>
/// <param name="vk">Virtual Key code to check.</param>
/// <returns>True if the key is down, false otherwise.</returns>
bool DMA::IsKeyDown(uint32_t vk) const {
    if (vk > 0xFF)
        return false;
    std::lock_guard<std::mutex> lock(kb_mutex);
    return (state_bitmap[(vk * 2 / 8)] & (1 << (vk % 4 * 2))) != 0;
}

// Was the key just pressed this poll (down now, not down before)
/// <summary>
/// Check if a key was just pressed since the last poll (rising edge).
/// </summary>
/// <param name="vk">Virtual Key code to check.</param>
/// <returns>True if the key was just pressed, false otherwise.</returns>
bool DMA::IsKeyPressed(uint32_t vk) {
    if (vk > 0xFF)
        return false;
    std::lock_guard<std::mutex> lock(kb_mutex);
    int byte = vk * 2 / 8;
    int bit = 1 << (vk % 4 * 2);
    if (pressed_bitmap[byte] & bit) {
        pressed_bitmap[byte] &= ~bit; // clear on read
        return true;
    }
    return false;
}

// Was the key just released this poll
/// <summary>
/// Check if a key was just released since the last poll (falling edge).
/// </summary>
/// <param name="vk">Virtual Key code to check.</param>
/// <returns>True if the key was just released, false otherwise.</returns>
bool DMA::IsKeyReleased(uint32_t vk) {
    if (vk > 0xFF)
        return false;
    std::lock_guard<std::mutex> lock(kb_mutex);
    int byte = vk * 2 / 8;
    int bit = 1 << (vk % 4 * 2);
    if (released_bitmap[byte] & bit) {
        released_bitmap[byte] &= ~bit; // clear on read
        return true;
    }
    return false;
}

/// <summary>
    /// Reads the global mouse cursor position from win32kbase.sys
    /// Note: win_logon_pid must be initialized first (e.g., by calling InitKeyboard).
    /// </summary>
POINT DMA::GetCursorPosition(bool debug) {
    POINT pt = { 0, 0 };

    if (!IsInitialized() || win_logon_pid == 0) {
        if (debug) printf("[CursorPos] FAIL: initialized=%d win_logon_pid=%u\n",
            IsInitialized() ? 1 : 0, win_logon_pid);
        return pt;
    }

    if (gptCursorAsyncExport == 0) {
        if (debug) printf("[CursorPos] Attempting to resolve gptCursorAsync via sig scan...\n");

        DMAModuleInfo module;
        if (!backend->GetModule(
            win_logon_pid | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY,
            "win32kbase.sys", module)) {
            if (debug) printf("[CursorPos] FAIL: Could not find win32kbase.sys in pid=%u\n", win_logon_pid);
            return pt;
        }

        const uint64_t base = module.baseAddress;
        const uint32_t size = module.imageSize;

        if (debug) printf("[CursorPos] win32kbase.sys found, vaBase=0x%llx size=0x%x\n", base, size);

        // Dump using win_logon_pid kernel context, NOT targetPID
        std::vector<uint8_t> dump(size);
        DWORD bytesRead = 0;
        if (!backend->ReadMemory(
            win_logon_pid | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY,
            base, dump.data(), size, VMMDLL_FLAG_ZEROPAD_ON_FAIL, bytesRead)) {
            if (debug) printf("[CursorPos] FAIL: Could not dump win32kbase.sys bytesRead=%u\n", bytesRead);
            return pt;
        }

        if (debug) printf("[CursorPos] Dumped win32kbase.sys bytesRead=%u\n", bytesRead);

        struct SigEntry { const char* name; const char* pattern; };
        SigEntry sigs[] = {
            { "Sig2", "4C 8B 0D ? ? ? ? 48 8D 55" },
            { "Sig3", "48 8B 05 ? ? ? ? 49 89 86" },
            { "Sig4", "48 8B 0D ? ? ? ? 48 89 0D" },
            { "Sig5", "4C 8B 0D ? ? ? ? 4C 8B C5" },
        };

        for (auto& sig : sigs) {
            uint64_t hit = FindPattern(dump, base, sig.pattern);
            if (!hit) {
                if (debug) printf("[CursorPos] %s: no match\n", sig.name);
                continue;
            }

            int32_t rel = LoadUnalignedInput<int32_t>(&dump[hit - base + 3]);
            uint64_t va = hit + 7 + rel;

            if (debug) printf("[CursorPos] %s hit=0x%llx rel=0x%x resolved va=0x%llx\n", sig.name, hit, rel, va);

            if (va > 0x7FFFFFFFFFFF) {
                gptCursorAsyncExport = va;
                if (debug) printf("[CursorPos] gptCursorAsync resolved to 0x%llx via %s\n", va, sig.name);
                break;
            }

            if (debug) printf("[CursorPos] %s resolved va 0x%llx failed kernel address check\n", sig.name, va);
        }

        if (gptCursorAsyncExport == 0) {
            if (debug) printf("[CursorPos] FAIL: All sigs failed to resolve gptCursorAsync\n");
            return pt;
        }
    }

    DWORD bytesRead = 0;
    if (!backend->ReadMemory(
        win_logon_pid | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY,
        gptCursorAsyncExport, &pt, sizeof(POINT),
        VMMDLL_FLAG_NOCACHE, bytesRead) || bytesRead != sizeof(POINT)) {
        if (debug) printf("[CursorPos] FAIL: MemReadEx failed at 0x%llx bytesRead=%u\n", gptCursorAsyncExport, bytesRead);
        pt = { 0, 0 };
        return pt;
    }

    if (debug) printf("[CursorPos] OK: x=%ld y=%ld\n", pt.x, pt.y);
    return pt;
}

/// <summary>
    /// Locates the xboxgip.sys static array (caches it), finds the active controller slot,
    /// and returns the live 24-byte hardware state buffer for real-time diffing.
    /// </summary>
std::vector<uint8_t> DMA::GetLiveGamepadBuffer(bool debug) {
    std::vector<uint8_t> buffer(gamepadConfig.stateSize, 0);
    if (!IsInitialized()) return buffer;

    DWORD sysPid = 4 | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY;

    // 1. Check if we already found the controller. If not, do the heavy sig-scan.
    if (active_controller_address == 0) {
        DMAModuleInfo module;
        if (!backend->GetModule(sysPid, gamepadConfig.moduleName, module)) {
            if (debug) printf("[GamepadDump] FAIL: Could not find xboxgip.sys\n");
            return buffer;
        }

        const uint64_t base = module.baseAddress;
        const uint32_t size = module.imageSize;

        std::vector<uint8_t> moduleDump = DumpMemoryEx(sysPid, base, size);
        if (moduleDump.empty()) return buffer;

        uint64_t hitAddress = FindPattern(moduleDump, base,
            gamepadConfig.slotArraySignature);

        if (!hitAddress) {
            if (debug) printf("[GamepadDump] FAIL: Signature not found.\n");
            return buffer;
        }

        const int32_t relativeOffset = LoadUnalignedInput<int32_t>(
            &moduleDump[hitAddress - base + 3]);
        uint64_t arrayStart = hitAddress + 7 + relativeOffset;
        gamepadArrayStart = arrayStart;

        if (debug) printf("[GamepadDump] Array Base resolved to: 0x%llx\n", arrayStart);

        for (size_t i = 0; i < gamepadConfig.slotCount; i++) {
            uint64_t slotAddress = arrayStart + (i * gamepadConfig.slotStride);

            uint8_t isActive = 0;
            DWORD br = 0;
            if (!backend->ReadMemory(sysPid,
                slotAddress + gamepadConfig.activeOffset, &isActive,
                1, VMMDLL_FLAG_NOCACHE, br) || br != 1) {
                continue;
            }

            if (isActive == 1) {
                if (debug) printf("[GamepadDump] Found active controller at slot %zu (0x%llx)\n",
                    i, static_cast<unsigned long long>(slotAddress));
                // Cache the address so we never have to sig-scan again!
                active_controller_address = slotAddress;
                break;
            }
        }
    }

    // 2. We have the address! Read the 24 bytes starting at the button offset.
    if (active_controller_address != 0) {
        DWORD br = 0;
        if (!backend->ReadMemory(sysPid,
            active_controller_address + gamepadConfig.stateOffset, buffer.data(),
            static_cast<DWORD>(buffer.size()), VMMDLL_FLAG_NOCACHE, br) ||
            br != buffer.size()) {
            buffer.assign(buffer.size(), 0);
        }
    }
    else {
        if (debug) printf("[GamepadDump] FAIL: No active controllers found in slots 0-7.\n");
    }

    return buffer;
}
