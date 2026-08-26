
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "DMA.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <limits>
#include <utility>

namespace {
template <typename T>
T LoadUnaligned(const uint8_t* source)
{
    T value{};
    std::memcpy(&value, source, sizeof(value));
    return value;
}

}

std::string DMA::NormalizeName(const std::string& name)
{
    std::string normalized = name;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
        [](unsigned char value) { return static_cast<char>(std::tolower(value)); });
    return normalized;
}

void DMA::StartKeyboardThread(int pollMs)
{
    StopKeyboardThread();
    kb_running.store(true);
    kb_thread = std::thread(&DMA::KeyboardThread, this, std::max(1, pollMs));
}

void DMA::StopKeyboardThread()
{
    kb_running.store(false);
    if (kb_thread.joinable())
        kb_thread.join();
}

void DMA::StopGamepadThread()
{
    gamepad_running.store(false);
    if (gamepad_thread.joinable())
        gamepad_thread.join();
}

void DMA::KeyboardThread(int poll_ms) {
    while (kb_running.load()) {
        if (IsInitialized() && gafAsyncKeyStateExport) {
            uint8_t tmp[64] = { 0 };
            DWORD bytesRead = 0;
            if (backend->ReadMemory(
                win_logon_pid | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY,
                gafAsyncKeyStateExport,
                tmp, 64, VMMDLL_FLAG_NOCACHE, bytesRead) && bytesRead == 64) {
                std::lock_guard<std::mutex> lock(kb_mutex);
                for (int i = 0; i < 64; i++) {
                    uint8_t became_set = tmp[i] & ~state_bitmap[i]; // bits that turned on
                    uint8_t became_clear = state_bitmap[i] & ~tmp[i]; // bits that turned off
                    pressed_bitmap[i] |= became_set;
                    released_bitmap[i] |= became_clear;
                }
                std::memcpy(state_bitmap.data(), tmp, state_bitmap.size());
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(poll_ms));
    }
}

void DMA::GamepadThread(int poll_ms) {
    DWORD sysPid = 4 | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY;

    while (gamepad_running.load()) {
        if (IsInitialized() && active_controller_address) {
            std::vector<uint8_t> buffer(std::max<size_t>(16,
                gamepadConfig.stateSize), 0);
            DWORD br = 0;

            if (backend->ReadMemory(sysPid,
                active_controller_address + gamepadConfig.stateOffset,
                buffer.data(), static_cast<DWORD>(buffer.size()),
                VMMDLL_FLAG_NOCACHE, br) && br == buffer.size()) {

                uint16_t xinput_buttons = 0;
                uint8_t b1 = buffer[1];
                uint8_t b2 = buffer[2];

                // --- Translate Byte 1 (Face Buttons & System) ---
                if (b1 & 0x04) xinput_buttons |= XINPUT_GAMEPAD_START;
                if (b1 & 0x08) xinput_buttons |= XINPUT_GAMEPAD_BACK;
                if (b1 & 0x10) xinput_buttons |= XINPUT_GAMEPAD_A;
                if (b1 & 0x20) xinput_buttons |= XINPUT_GAMEPAD_B;
                if (b1 & 0x40) xinput_buttons |= XINPUT_GAMEPAD_X;
                if (b1 & 0x80) xinput_buttons |= XINPUT_GAMEPAD_Y;

                // --- Translate Byte 2 (D-Pad & Bumpers & Clicks) ---
                if (b2 & 0x01) xinput_buttons |= XINPUT_GAMEPAD_DPAD_UP;
                if (b2 & 0x02) xinput_buttons |= XINPUT_GAMEPAD_DPAD_DOWN;
                if (b2 & 0x04) xinput_buttons |= XINPUT_GAMEPAD_DPAD_LEFT;
                if (b2 & 0x08) xinput_buttons |= XINPUT_GAMEPAD_DPAD_RIGHT;
                if (b2 & 0x10) xinput_buttons |= XINPUT_GAMEPAD_LEFT_SHOULDER;
                if (b2 & 0x20) xinput_buttons |= XINPUT_GAMEPAD_RIGHT_SHOULDER;
                if (b2 & 0x40) xinput_buttons |= XINPUT_GAMEPAD_LEFT_THUMB;
                if (b2 & 0x80) xinput_buttons |= XINPUT_GAMEPAD_RIGHT_THUMB;

                // --- Translate 10-bit Triggers to 8-bit (0-255) ---
                // Read 2 bytes, mask off garbage bits, and divide by 4 (shift right by 2)
                const uint16_t rawLT = LoadUnaligned<uint16_t>(&buffer[3]) & 0x03FF;
                const uint16_t rawRT = LoadUnaligned<uint16_t>(&buffer[5]) & 0x03FF;

                std::lock_guard<std::mutex> lock(gamepad_mutex);

                pressedGamepadButtons |= static_cast<uint16_t>(
                    xinput_buttons & ~previousGamepadButtons);
                releasedGamepadButtons |= static_cast<uint16_t>(
                    previousGamepadButtons & ~xinput_buttons);
                previousGamepadButtons = xinput_buttons;
                currentGamepadState.buttons = xinput_buttons;
                currentGamepadState.leftTrigger = static_cast<uint8_t>(rawLT / 4);
                currentGamepadState.rightTrigger = static_cast<uint8_t>(rawRT / 4);

                // --- Map the 16-bit Thumbsticks ---
                currentGamepadState.thumbLX = LoadUnaligned<int16_t>(&buffer[7]);
                currentGamepadState.thumbLY = LoadUnaligned<int16_t>(&buffer[9]);
                currentGamepadState.thumbRX = LoadUnaligned<int16_t>(&buffer[11]);
                currentGamepadState.thumbRY = LoadUnaligned<int16_t>(&buffer[13]);
                currentGamepadState.connected = true;
                ++currentGamepadState.packetNumber;
            }
            else {
                std::lock_guard<std::mutex> lock(gamepad_mutex);
                currentGamepadState.connected = false;
                active_controller_address = 0;
            }
        }
        else if (IsInitialized() && gamepadArrayStart != 0) {
            for (size_t slot = 0; slot < gamepadConfig.slotCount; ++slot) {
                const uint64_t address = gamepadArrayStart +
                    slot * gamepadConfig.slotStride;
                uint8_t active = 0;
                DWORD transferred = 0;
                if (backend->ReadMemory(sysPid,
                    address + gamepadConfig.activeOffset, &active, 1,
                    VMMDLL_FLAG_NOCACHE, transferred) && transferred == 1 &&
                    active == 1) {
                    active_controller_address = address;
                    break;
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(poll_ms));
    }
}

bool DMA::CacheModule(const std::string& moduleName) {
    if (!IsAttached())
        return false;
    DMAModuleInfo module;
    if (backend->GetModule(targetPID, moduleName, module)) {
        moduleCache[NormalizeName(moduleName)] = { module.baseAddress,
                                   module.imageSize };
        return true;
    }
    return false;
}

DMA::DMA(std::shared_ptr<IVmmBackend> customBackend)
    : backend(customBackend ? std::move(customBackend) : CreateVmmdllBackend())
{
}

DMA::~DMA() { Disconnect(); }

DMAOperationResult DMA::Initialize(const DMAInitializationOptions& options)
{
    Disconnect();

    if (options.device.empty())
        return DMAOperationResult::Failure(DMAStatus::InvalidArgument,
            "The MemProcFS device URI cannot be empty.");

    std::string memoryMapPath = options.memoryMapPath;
    if (options.useMemoryMap && memoryMapPath.empty()) {
        try {
            memoryMapPath = (std::filesystem::temp_directory_path() / "mmap.txt").string();
        }
        catch (const std::exception& exception) {
            if (!options.fallbackWithoutMemoryMap) {
                return DMAOperationResult::Failure(DMAStatus::IoError,
                    std::string("Unable to resolve the temporary memory-map path: ") +
                    exception.what());
            }
        }
    }

    bool memoryMapAvailable = options.useMemoryMap && memoryMapPath == "auto";
    if (options.useMemoryMap && !memoryMapPath.empty() && memoryMapPath != "auto") {
        std::error_code error;
        memoryMapAvailable = std::filesystem::exists(memoryMapPath, error) && !error;
    }
    if (options.useMemoryMap && !memoryMapAvailable &&
        !options.fallbackWithoutMemoryMap) {
        return DMAOperationResult::Failure(DMAStatus::NotFound,
            "The requested memory-map file does not exist: " + memoryMapPath);
    }

    auto attemptInitialize = [&](bool includeMemoryMap) {
        std::vector<std::string> arguments = {
            "", "-device", options.device
        };
        if (options.debug) {
            arguments.push_back("-v");
            arguments.push_back("-printf");
        }
        if (options.waitForInitialization)
            arguments.push_back("-waitinitialize");
        if (includeMemoryMap) {
            arguments.push_back("-memmap");
            arguments.push_back(memoryMapPath);
        }
        arguments.insert(arguments.end(), options.extraArguments.begin(),
            options.extraArguments.end());

        const auto result = backend->Initialize(arguments);
        hVMM = backend->NativeHandle();
        if (!result)
            return result;
        if (options.initializePlugins) {
            const auto plugins = backend->InitializePlugins();
            if (!plugins) {
                backend->Close();
                hVMM = nullptr;
                return plugins;
            }
        }
        return DMAOperationResult::Success();
    };

    if (memoryMapAvailable) {
        auto initialized = attemptInitialize(true);
        if (initialized || !options.fallbackWithoutMemoryMap)
            return initialized;
        backend->Close();
        hVMM = nullptr;
    }

    return !options.useMemoryMap || options.fallbackWithoutMemoryMap
        ? attemptInitialize(false)
        : DMAOperationResult::Failure(DMAStatus::NotFound,
            "The requested memory-map file is unavailable.");
}

/// <summary>
/// Closes all active VMMDLL handles and cleans up resources.
/// </summary>
void DMA::Disconnect() {
    StopProcessMonitor();
    StopKeyboardThread();
    StopGamepadThread();
    ResetAttachmentState();
    if (backend)
        backend->Close();
    hVMM = nullptr;
}

void DMA::ResetAttachmentState()
{
    targetPID = 0;
    mainModuleBase = 0;
    attachedMainModuleName.clear();
    moduleCache.clear();
    gafAsyncKeyStateExport = 0;
    gptCursorAsyncExport = 0;
    win_logon_pid = 0;
    active_controller_address = 0;
    gamepadArrayStart = 0;
    {
        std::lock_guard<std::mutex> lock(kb_mutex);
        state_bitmap.fill(0);
        pressed_bitmap.fill(0);
        released_bitmap.fill(0);
    }
    {
        std::lock_guard<std::mutex> lock(gamepad_mutex);
        currentGamepadState = {};
    }
}

void DMA::Detach()
{
    StopKeyboardThread();
    StopGamepadThread();
    ResetAttachmentState();
}

/// <summary>
/// Attempts to find and attach to a target process by name.
/// </summary>
/// <param name="processName">Name of the process (e.g., "game.exe").</param>
/// <returns>The attachment result, including backend diagnostics on failure.</returns>
DMAOperationResult DMA::Attach(const std::string& processName) {
    if (!IsInitialized())
        return DMAOperationResult::Failure(DMAStatus::NotInitialized,
            "Initialize DMA before attaching to a process.");
    if (processName.empty())
        return DMAOperationResult::Failure(DMAStatus::InvalidArgument,
            "A process name is required.");
    DWORD pid = 0;
    auto result = backend->FindPid(processName, pid);
    if (!result) {
        if (result.message.empty())
            result.message = "Process not found: " + processName;
        return result;
    }
    return Attach(pid, processName);
}

DMAOperationResult DMA::Attach(DWORD pid, const std::string& mainModuleName)
{
    if (!IsInitialized())
        return DMAOperationResult::Failure(DMAStatus::NotInitialized,
            "DMA is not initialized.");
    if (pid == 0)
        return DMAOperationResult::Failure(DMAStatus::InvalidArgument,
            "A non-zero PID is required.");

    Detach();
    targetPID = pid;

    DMAModuleInfo module;
    auto moduleResult = backend->GetModule(targetPID, mainModuleName, module);
    if (!moduleResult) {
        ResetAttachmentState();
        if (moduleResult.message.empty())
            moduleResult.message = "Unable to resolve the process main module.";
        moduleResult.pid = pid;
        return moduleResult;
    }

    mainModuleBase = module.baseAddress;
    const std::string resolvedName = module.name.empty() ? mainModuleName : module.name;
    attachedMainModuleName = resolvedName;
    moduleCache[NormalizeName(resolvedName)] = { module.baseAddress, module.imageSize };
    if (!mainModuleName.empty())
        moduleCache[NormalizeName(mainModuleName)] = { module.baseAddress, module.imageSize };

    auto result = DMAOperationResult::Success();
    result.pid = pid;
    result.address = module.baseAddress;
    return result;
}

DMAVersionInfo DMA::GetVmmVersion() const
{
    DMAVersionInfo version;
    if (!IsInitialized())
        return version;
    backend->ConfigGet(VMMDLL_OPT_CONFIG_VMM_VERSION_MAJOR, version.major);
    backend->ConfigGet(VMMDLL_OPT_CONFIG_VMM_VERSION_MINOR, version.minor);
    backend->ConfigGet(VMMDLL_OPT_CONFIG_VMM_VERSION_REVISION, version.revision);
    return version;
}

uint32_t DMA::GetWindowsBuild() const
{
    uint64_t build = 0;
    if (!IsInitialized() || !backend->ConfigGet(VMMDLL_OPT_WIN_VERSION_BUILD, build))
        return 0;
    return static_cast<uint32_t>(build);
}

std::vector<DMAProcessInfo> DMA::GetProcesses() const
{
    std::vector<DMAProcessInfo> result;
    if (!IsInitialized())
        return result;
    backend->GetProcesses(result);
    return result;
}

std::vector<DWORD> DMA::FindProcessIds(const std::string& processName) const
{
    std::vector<DWORD> result;
    const std::string requested = NormalizeName(processName);
    if (requested.empty())
        return result;
    for (const auto& process : GetProcesses()) {
        if (NormalizeName(process.name) == requested ||
            NormalizeName(process.longName) == requested) {
            result.push_back(process.pid);
        }
    }
    return result;
}

DMAOperationResult DMA::RefreshProcess()
{
    if (!IsAttached())
        return DMAOperationResult::Failure(DMAStatus::NotAttached,
            "DMA is not attached to a process.");
    auto result = backend->ConfigSet(
        VMMDLL_OPT_REFRESH_SPECIFIC_PROCESS | targetPID, 1);
    result.pid = targetPID;
    if (result)
        moduleCache.clear();
    else if (result.message.empty())
        result.message = "MemProcFS failed to refresh the attached process.";
    return result;
}

/// <summary>
/// Verifies if the current Directory Table Base (DTB/CR3) is valid.
/// Checks for the "MZ" header at the main module base.
/// </summary>
/// <returns>True if the DTB is valid.</returns>
bool DMA::IsCR3Valid() {
    if (!IsAttached() || mainModuleBase == 0)
        return false;

    // Use NOCACHE to ensure we are querying the physical memory state right now
    const auto magic = Read<uint16_t>(mainModuleBase);
    return magic && magic.value == 0x5A4D; // 0x5A4D is 'MZ'
}

/// <summary>
/// Manually sets the process Directory Table Base (DTB/CR3).
/// Useful for bypassing anti-cheats that scramble the DTB.
/// </summary>
/// <param name="dtb">The new Directory Table Base.</param>
bool DMA::SetCR3(uint64_t dtb) {
    if (!IsAttached())
        return false;

    // VMMDLL_OPT_PROCESS_DTB expects the PID in the lower DWORD
    uint64_t option = VMMDLL_OPT_PROCESS_DTB | targetPID;
    return static_cast<bool>(backend->ConfigSet(option, dtb));
}

/// <summary>
/// Flushes the internal VMMDLL Transport Lookaside Buffer (TLB) and memory
/// cache. Use this if memory reads fail due to anti-cheat memory swapping.
/// </summary>
bool DMA::ClearCache() {
    if (!IsInitialized())
        return false;
    const bool tlb = static_cast<bool>(backend->ConfigSet(VMMDLL_OPT_REFRESH_FREQ_TLB, 1));
    const bool mem = static_cast<bool>(backend->ConfigSet(VMMDLL_OPT_REFRESH_FREQ_MEM, 1));
    return tlb && mem;
}

/// <summary>
/// Retrieves the base address of a module in the target process.
/// Caches the result to minimize VMMDLL calls.
/// </summary>
/// <param name="moduleName">Name of the module (e.g.,
/// "kernel32.dll").</param> <returns>Base address of the module, or 0 if not
/// found.</returns>
uint64_t DMA::GetModuleBase(const std::string& moduleName) {
    const auto key = NormalizeName(moduleName);
    if (moduleCache.find(key) == moduleCache.end())
        if (!CacheModule(moduleName))
            return 0;
    return moduleCache.at(key).baseAddress;
}

/// <summary>
/// Retrieves the size of a module in bytes.
/// </summary>
/// <param name="moduleName">Name of the module.</param>
/// <returns>Size of the module, or 0 if not found.</returns>
uint32_t DMA::GetModuleSize(const std::string& moduleName) {
    const auto key = NormalizeName(moduleName);
    if (moduleCache.find(key) == moduleCache.end())
        if (!CacheModule(moduleName))
            return 0;
    return moduleCache.at(key).size;
}

void DMA::ClearModuleCache()
{
    moduleCache.clear();
}

std::vector<DMAModuleInfo> DMA::GetModules(bool refresh)
{
    std::vector<DMAModuleInfo> result;
    if (!IsAttached())
        return result;
    if (refresh)
        RefreshProcess();

    if (!backend->GetModules(targetPID, result))
        return result;
    for (const auto& info : result)
        moduleCache[NormalizeName(info.name)] = { info.baseAddress, info.imageSize };
    return result;
}

/// <summary>
/// Follows a pointer chain to retrieve the final address.
/// </summary>
/// <param name="base">Base address to start from.</param>
/// <param name="offsets">List of offsets to apply sequentially.</param>
/// <returns>The final address and operation status.</returns>
DMAResult<uint64_t> DMA::ReadChain(uint64_t base,
    const std::vector<uint64_t>& offsets) {
    DMAResult<uint64_t> result;
    if (base == 0) {
        result.operation = DMAOperationResult::Failure(
            DMAStatus::InvalidArgument, "Pointer-chain base cannot be zero.");
        return result;
    }

    uint64_t currentAddress = base;
    for (const auto& offset : offsets) {
        const auto read = Read<uint64_t>(currentAddress);
        if (!read) {
            result.operation = read.operation;
            return result;
        }
        if (read.value == 0) {
            result.operation = DMAOperationResult::Failure(
                DMAStatus::NotFound, "Pointer chain contains a null pointer.");
            result.operation.address = currentAddress;
            result.operation.pid = targetPID;
            return result;
        }
        if (offset > std::numeric_limits<uint64_t>::max() - read.value) {
            result.operation = DMAOperationResult::Failure(
                DMAStatus::InvalidArgument, "Pointer-chain address overflow.");
            result.operation.address = currentAddress;
            result.operation.pid = targetPID;
            return result;
        }
        currentAddress = read.value + offset;
    }
    result.value = currentAddress;
    result.operation = DMAOperationResult::Success(sizeof(uint64_t));
    result.operation.address = currentAddress;
    result.operation.pid = targetPID;
    return result;
}

/// <summary>
/// Reads an ASCII string from the target process.
/// </summary>
/// <param name="address">Target virtual address.</param>
/// <param name="maxLength">Maximum characters to read.</param>
/// <returns>The read string, truncated at the first null
/// terminator.</returns>
std::string DMA::ReadString(uint64_t address, size_t maxLength) {
    if (address == 0 || maxLength == 0)
        return "";
    std::string result;
    result.resize(maxLength);
    if (ReadRaw(address, result.data(), maxLength)) {
        size_t nullTerminator = result.find('\0');
        if (nullTerminator != std::string::npos) {
            result.resize(nullTerminator);
        }
        return result;
    }
    return "";
}

/// <summary>
/// Reads a Unicode (wide) string from the target process.
/// </summary>
/// <param name="address">Target virtual address.</param>
/// <param name="maxLength">Maximum characters to read.</param>
/// <returns>The read string, truncated at the first null
/// terminator.</returns>
std::wstring DMA::ReadWString(uint64_t address, size_t maxLength) {
    if (address == 0 || maxLength == 0 ||
        maxLength > std::numeric_limits<size_t>::max() / sizeof(char16_t))
        return L"";
    std::vector<char16_t> encoded(maxLength);
    if (!ReadRaw(address, encoded.data(), encoded.size() * sizeof(char16_t)))
        return L"";
    std::wstring result;
    result.reserve(maxLength);
    for (char16_t value : encoded) {
        if (value == u'\0')
            break;
        result.push_back(static_cast<wchar_t>(value));
    }
    return result;
}

/// <summary>
/// Resolves a relative memory address (common in x64 instructions like
/// RIP-relative addressing).
/// </summary>
/// <param name="instructionAddress">Address of the instruction.</param>
/// <param name="offsetOffset">Offset to the displacement value within the
/// instruction.</param> <param name="instructionSize">Total size of the
/// instruction.</param> <returns>The absolute address resolved from the
/// relative offset.</returns>
uint64_t DMA::ResolveRelative(uint64_t instructionAddress,
    uint32_t offsetOffset,
    uint32_t instructionSize) {
    if (instructionAddress == 0)
        return 0;
    if (offsetOffset > std::numeric_limits<uint64_t>::max() - instructionAddress)
        return 0;
    const auto relative = Read<int32_t>(instructionAddress + offsetOffset);
    if (!relative)
        return 0;
    const int32_t relativeOffset = relative.value;
    if (instructionSize > std::numeric_limits<uint64_t>::max() - instructionAddress)
        return 0;
    const uint64_t nextInstruction = instructionAddress + instructionSize;
    if (relativeOffset >= 0) {
        const auto positiveOffset = static_cast<uint64_t>(relativeOffset);
        if (positiveOffset > std::numeric_limits<uint64_t>::max() - nextInstruction)
            return 0;
        return nextInstruction + positiveOffset;
    }
    const auto magnitude = static_cast<uint64_t>(-static_cast<int64_t>(relativeOffset));
    return magnitude > nextInstruction ? 0 : nextInstruction - magnitude;
}

DMAResult<uint64_t> DMA::VirtualToPhysical(uint64_t virtualAddress) const
{
    DMAResult<uint64_t> result;
    if (!IsAttached()) {
        result.operation = DMAOperationResult::Failure(
            DMAStatus::NotAttached, "DMA is not attached to a process.");
        return result;
    }
    if (virtualAddress == 0) {
        result.operation = DMAOperationResult::Failure(
            DMAStatus::InvalidArgument, "Virtual address cannot be zero.");
        return result;
    }
    result.operation = backend->VirtualToPhysical(targetPID, virtualAddress,
        result.value);
    result.operation.pid = targetPID;
    result.operation.address = virtualAddress;
    return result;
}

DMAOperationResult DMA::PrefetchPages(
    const std::vector<uint64_t>& addresses) const
{
    if (!IsAttached())
        return DMAOperationResult::Failure(DMAStatus::NotAttached,
            "DMA is not attached to a process.");
    if (addresses.empty() ||
        addresses.size() > std::numeric_limits<DWORD>::max()) {
        return DMAOperationResult::Failure(DMAStatus::InvalidArgument,
            "Prefetch requires a non-empty address list within DWORD limits.");
    }
    auto result = backend->PrefetchPages(targetPID, addresses);
    result.pid = targetPID;
    return result;
}

/// <summary>
/// Reads a block of memory from the target process.
/// </summary>
std::vector<uint8_t> DMA::DumpMemory(uint64_t address, size_t size,
    ULONG64 flags) {
    return DumpMemoryEx(targetPID, address, size, flags);
}

/// <summary>
/// Reads a block of memory using an explicit PID (e.g. a csrss/winlogon pid
/// ORed with VMMDLL_PID_PROCESS_WITH_KERNELMEMORY for kernel module dumps).
/// Use this instead of DumpMemory whenever the target address lives in kernel
/// space (win32k.sys, win32kbase.sys, win32ksgd.sys, etc.).
/// </summary>
std::vector<uint8_t> DMA::DumpMemoryEx(DWORD pid, uint64_t address, size_t size,
    ULONG64 flags) {
    if (!IsInitialized() || address == 0 || size == 0 ||
        size - 1 > std::numeric_limits<uint64_t>::max() - address) {
        return {};
    }

    std::vector<uint8_t> buffer(size, 0);
    constexpr size_t maxReadSize = 0x40000000; // VMMDLL documents a 1 GiB maximum.
    size_t offset = 0;
    while (offset < size) {
        const DWORD chunkSize = static_cast<DWORD>(
            std::min(maxReadSize, size - offset));
        DWORD bytesRead = 0;
        const auto result = backend->ReadMemory(pid, address + offset,
            buffer.data() + offset, chunkSize, flags, bytesRead);
        if (!result && result.status != DMAStatus::PartialTransfer) {
            buffer.clear();
            return buffer;
        }
        if (bytesRead != chunkSize &&
            !(flags & VMMDLL_FLAG_ZEROPAD_ON_FAIL)) {
            buffer.resize(offset + bytesRead);
            return buffer;
        }
        offset += chunkSize;
    }
    return buffer;
}
