#pragma once

#include "DMA.Backend.hpp"
#include "DMA.Context.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <vector>

// Keep the familiar XInput names available without conflicting with Xinput.h.
#ifndef XINPUT_GAMEPAD_DPAD_UP
#define XINPUT_GAMEPAD_DPAD_UP          0x0001
#define XINPUT_GAMEPAD_DPAD_DOWN        0x0002
#define XINPUT_GAMEPAD_DPAD_LEFT        0x0004
#define XINPUT_GAMEPAD_DPAD_RIGHT       0x0008
#define XINPUT_GAMEPAD_START            0x0010
#define XINPUT_GAMEPAD_BACK             0x0020
#define XINPUT_GAMEPAD_LEFT_THUMB       0x0040
#define XINPUT_GAMEPAD_RIGHT_THUMB      0x0080
#define XINPUT_GAMEPAD_LEFT_SHOULDER    0x0100
#define XINPUT_GAMEPAD_RIGHT_SHOULDER   0x0200
#define XINPUT_GAMEPAD_A                0x1000
#define XINPUT_GAMEPAD_B                0x2000
#define XINPUT_GAMEPAD_X                0x4000
#define XINPUT_GAMEPAD_Y                0x8000
#endif

class DMA {
private:
    struct ModuleData {
        uint64_t baseAddress = 0;
        uint32_t size = 0;
    };

    std::shared_ptr<IVmmBackend> backend;
    VMM_HANDLE hVMM = nullptr;
    DWORD targetPID = 0;
    uint64_t mainModuleBase = 0;
    std::string attachedMainModuleName;
    std::unordered_map<std::string, ModuleData> moduleCache;

    uint64_t gafAsyncKeyStateExport = 0;
    uint64_t gptCursorAsyncExport = 0;
    DWORD win_logon_pid = 0;
    std::array<uint8_t, 64> state_bitmap{};
    std::array<uint8_t, 64> pressed_bitmap{};
    std::array<uint8_t, 64> released_bitmap{};
    std::atomic<bool> kb_running{ false };
    std::thread kb_thread;
    mutable std::mutex kb_mutex;

    uint64_t active_controller_address = 0;
    uint64_t gamepadArrayStart = 0;
    GamepadState currentGamepadState{};
    std::atomic<bool> gamepad_running{ false };
    std::thread gamepad_thread;
    mutable std::mutex gamepad_mutex;
    DMAGamepadConfig gamepadConfig{};
    uint16_t previousGamepadButtons = 0;
    uint16_t pressedGamepadButtons = 0;
    uint16_t releasedGamepadButtons = 0;

    std::atomic<bool> processMonitorRunning{ false };
    std::thread processMonitorThread;
    std::string monitoredProcessName;
    std::string monitoredMainModuleName;
    std::function<void(const DMAProcessEvent&)> processMonitorCallback;
    bool processMonitorAutoReattach = true;
    int processMonitorPollMs = 500;

    void ResetAttachmentState();
    static std::string NormalizeName(const std::string& name);

    void KeyboardThread(int pollMs);
    void GamepadThread(int pollMs);
    void StartKeyboardThread(int pollMs);
    void StopKeyboardThread();
    void StopGamepadThread();
    void ProcessMonitorThread();

    bool CacheModule(const std::string& moduleName);

public:
    explicit DMA(std::shared_ptr<IVmmBackend> customBackend = {});
    ~DMA();
    DMA(const DMA&) = delete;
    DMA& operator=(const DMA&) = delete;

    static DMA& Get()
    {
        static DMA instance;
        return instance;
    }

    DMAOperationResult Initialize(const DMAInitializationOptions& options);
    void Disconnect();
    bool IsInitialized() const noexcept
    {
        return backend && backend->IsInitialized();
    }
    bool IsAttached() const noexcept { return IsInitialized() && targetPID != 0; }
    DMAVersionInfo GetVmmVersion() const;
    uint32_t GetWindowsBuild() const;

    DMAOperationResult Attach(const std::string& processName);
    DMAOperationResult Attach(DWORD pid, const std::string& mainModuleName = {});
    void Detach();
    DMAOperationResult RefreshProcess();
    std::vector<DWORD> FindProcessIds(const std::string& processName) const;
    std::vector<DMAProcessInfo> GetProcesses() const;
    DMAResult<DMAProcessInfo> GetProcessInfo(DWORD pid = 0) const;
    DMAResult<DMAPebInfo> GetProcessEnvironmentBlock(DWORD pid = 0,
        bool preferWow64 = true) const;

    // RecoverCR3(pid, module) also works before Attach(), which is important
    // when an invalid DTB prevents initial module discovery.
    bool IsCR3Valid();
    bool SetCR3(uint64_t dtb);
    DMAResult<DMACR3RecoveryReport> RecoverCR3(DWORD pid,
        const std::string& validationModule,
        const DMACR3RecoveryOptions& options = {});
    DMAResult<DMACR3RecoveryReport> RecoverCR3(
        const DMACR3RecoveryOptions& options = {});
    DMAResult<DMACR3RecoveryReport> AttachWithCR3Recovery(
        const std::string& processName,
        const DMACR3RecoveryOptions& options = {});
    bool ClearCache();

    DMAResult<std::vector<DMAPhysicalMemoryRange>> GetPhysicalMemoryMap(
        bool refresh = false) const;
    DMAOperationResult ExportPhysicalMemoryMap(const std::string& outPath,
        bool refresh = false) const;

    uint64_t GetModuleBase(const std::string& moduleName);
    uint32_t GetModuleSize(const std::string& moduleName);
    std::vector<DMAModuleInfo> GetModules(bool refresh = false);
    void ClearModuleCache();
    uint64_t GetMainBase() const noexcept { return mainModuleBase; }
    DWORD GetPID() const noexcept { return targetPID; }
    VMM_HANDLE GetVMM() const noexcept { return hVMM; }
    std::shared_ptr<IVmmBackend> GetBackend() const noexcept { return backend; }

    // Success requires every requested byte to be transferred. Results preserve
    // transfer counts and backend diagnostics.
    DMAOperationResult ReadRaw(uint64_t address, void* buffer, size_t size,
        ULONG64 flags = VMMDLL_FLAG_NOCACHE);
    DMAOperationResult ReadRaw(DWORD pid, uint64_t address, void* buffer,
        size_t size, ULONG64 flags = VMMDLL_FLAG_NOCACHE);
    DMAOperationResult WriteRaw(uint64_t address, const void* buffer, size_t size);
    DMAOperationResult WriteRaw(DWORD pid, uint64_t address,
        const void* buffer, size_t size);

    template <typename T>
    DMAResult<T> Read(uint64_t address,
        ULONG64 flags = VMMDLL_FLAG_NOCACHE)
    {
        static_assert(std::is_trivially_copyable<T>::value,
            "DMA reads require a trivially copyable type");
        DMAResult<T> result;
        result.operation = ReadRaw(address, &result.value, sizeof(T), flags);
        return result;
    }

    DMAResult<uint64_t> ReadChain(uint64_t base,
        const std::vector<uint64_t>& offsets);
    std::string ReadString(uint64_t address, size_t maxLength = 256);
    std::wstring ReadWString(uint64_t address, size_t maxLength = 256);
    uint64_t ResolveRelative(uint64_t instructionAddress,
        uint32_t offsetOffset, uint32_t instructionSize);
    DMAResult<uint64_t> VirtualToPhysical(uint64_t virtualAddress) const;
    DMAOperationResult PrefetchPages(const std::vector<uint64_t>& addresses) const;
    // pid == 0 selects the current attachment. KernelContext adds VMMDLL's
    // kernel-memory PID flag to the selected session process.
    DMAMemoryContext ProcessContext(DWORD pid = 0,
        ULONG64 flags = VMMDLL_FLAG_NOCACHE) const;
    DMAMemoryContext KernelContext(DWORD sessionPid = 0,
        ULONG64 flags = VMMDLL_FLAG_NOCACHE) const;
    DMAFrameContext CreateFrameContext(DWORD pid = 0,
        ULONG64 flags = VMMDLL_FLAG_NOCACHE) const;
    DMAScatterBatch CreateScatterBatch(DWORD pid = 0,
        DWORD flags = VMMDLL_FLAG_NOCACHE) const;

    // Native VMMDLL allocations are copied into owning C++ value types.
    DMAResult<std::vector<DMAMemoryRegion>> GetMemoryRegions(
        const DMAMemoryRegionFilter& filter = {}) const;
    DMAResult<std::vector<DMAModuleSection>> GetModuleSections(
        const std::string& moduleName) const;
    DMAResult<std::vector<DMAExportInfo>> GetModuleExports(
        const std::string& moduleName) const;
    DMAResult<std::vector<DMAImportInfo>> GetModuleImports(
        const std::string& moduleName) const;
    DMAResult<std::string> LoadModuleSymbols(const std::string& moduleName);
    DMAResult<uint64_t> ResolveSymbol(const std::string& symbolModule,
        const std::string& symbol) const;
    DMAResult<DMASymbolInfo> LookupSymbol(const std::string& symbolModule,
        uint64_t addressOrOffset) const;
    DMAResult<uint32_t> GetSymbolTypeSize(const std::string& symbolModule,
        const std::string& typeName) const;
    DMAResult<uint32_t> GetSymbolChildOffset(const std::string& symbolModule,
        const std::string& typeName, const std::string& childName) const;

    // DiffSnapshots requires matching PID/base/size and reports changed bytes.
    DMAResult<DMAMemorySnapshot> CaptureSnapshot(uint64_t address, size_t size,
        ULONG64 flags = VMMDLL_FLAG_NOCACHE) const;
    static DMAResult<std::vector<DMAMemoryChange>> DiffSnapshots(
        const DMAMemorySnapshot& before, const DMAMemorySnapshot& after,
        size_t maxChanges = 0);

    std::vector<uint8_t> DumpMemory(uint64_t address, size_t size,
        ULONG64 flags = VMMDLL_FLAG_ZEROPAD_ON_FAIL);
    std::vector<uint8_t> DumpMemoryEx(DWORD pid, uint64_t address, size_t size,
        ULONG64 flags = VMMDLL_FLAG_ZEROPAD_ON_FAIL);

    // Compiled patterns support nibble wildcards (A? and ?F) and typed captures.
    static DMAResult<DMACompiledPattern> CompilePattern(
        const std::string& signature,
        const std::vector<DMAScanCapture>& captures = {});
    static DMAResult<std::vector<DMAScanMatch>> ScanBufferAdvanced(
        const std::vector<uint8_t>& buffer, const DMACompiledPattern& pattern,
        uint64_t baseAddress = 0, const DMAScanOptions& options = {});
    DMAResult<std::vector<DMAScanMatch>> ScanModuleAdvanced(
        const std::string& moduleName, const DMACompiledPattern& pattern,
        const DMAScanOptions& options = {},
        const std::vector<std::string>& sectionNames = {});
    // Defaults require both PE-section and live PTE permissions to be RWX.
    DMAResult<DMACodeCaveScanReport> FindCodeCaves(
        const std::string& moduleName, size_t minimumSize,
        const DMACodeCaveOptions& options = {}) const;
    // The callback runs on the monitor thread. Stop before manually changing
    // lifecycle state; auto-re-attachment resets process-specific caches.
    bool StartProcessMonitor(const std::string& processName,
        int pollIntervalMs = 500, bool autoReattach = true,
        std::function<void(const DMAProcessEvent&)> callback = {},
        const std::string& mainModuleName = {});
    void StopProcessMonitor();
    bool IsProcessMonitorRunning() const noexcept
    {
        return processMonitorRunning.load();
    }

    DMAOperationResult DumpModule(const std::string& moduleName,
        const std::string& outPath);

    DMAOperationResult InitKeyboard(int pollMs = 10, bool debug = false);
    void StopKeyboard();
    bool IsKeyboardInitialized() const noexcept { return kb_running.load(); }
    DMAOperationResult InitGamepad(const DMAGamepadConfig& config);
    void StopGamepad();
    bool IsGamepadInitialized() const noexcept { return gamepad_running.load(); }
    GamepadState GetGamepadState() const;
    bool IsGamepadButtonPressed(uint16_t buttonMask) const;
    bool IsGamepadButtonJustPressed(uint16_t buttonMask);
    bool IsGamepadButtonJustReleased(uint16_t buttonMask);
    DMANormalizedGamepadState GetNormalizedGamepadState() const;
    bool IsKeyDown(uint32_t vk) const;
    bool IsKeyPressed(uint32_t vk);
    bool IsKeyReleased(uint32_t vk);
    POINT GetCursorPosition(bool debug = false);
    std::vector<uint8_t> GetLiveGamepadBuffer(bool debug = false);

    // Registry paths use VMMDLL syntax (for example HKLM\SOFTWARE\...).
    DMAResult<std::vector<DMARegistryHiveInfo>> GetRegistryHives() const;
    DMAResult<std::vector<DMARegistryKeyInfo>> EnumerateRegistryKeys(
        const std::string& path) const;
    DMAResult<std::vector<DMARegistryValue>> EnumerateRegistryValues(
        const std::string& path) const;
    DMAResult<DMARegistryValue> QueryRegistryValue(const std::string& path) const;
    DMAOperationResult ReadRegistryHive(uint64_t cmHiveAddress,
        uint32_t relativeAddress, void* buffer, size_t size,
        ULONG64 flags = 0) const;
    DMAOperationResult WriteRegistryHive(uint64_t cmHiveAddress,
        uint32_t relativeAddress, const void* buffer, size_t size);

    // VFS methods require DMAInitializationOptions::initializePlugins.
    DMAResult<std::vector<DMAVfsEntry>> ListVfs(const std::string& path) const;
    DMAResult<std::vector<uint8_t>> ReadVfsFile(const std::string& path,
        size_t maxBytes = 64 * 1024 * 1024) const;
    DMAOperationResult ReadVfs(const std::string& path, uint64_t offset,
        void* buffer, size_t size) const;
    DMAOperationResult WriteVfs(const std::string& path, uint64_t offset,
        const void* buffer, size_t size);
};
