#pragma once
#include "deps/vmmdll.h"
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

#include <chrono>
#include <filesystem>
#include <thread>
#include <mutex>

#pragma comment(lib, "vmm.lib")
#pragma comment(lib, "leechcore.lib")

struct HeapRegion {
  uint64_t start;
  uint64_t end;
};

class DMA {
private:
    VMM_HANDLE hVMM = nullptr;
    DWORD targetPID = 0;

    struct ModuleData {
        uint64_t baseAddress;
        uint32_t size;
    };

    std::unordered_map<std::string, ModuleData> moduleCache;
    uint64_t mainModuleBase = 0;

    VMMDLL_SCATTER_HANDLE hScatter = nullptr;

    // --- Signature Scanning Helpers ---
    struct PatternByte {
        uint8_t value;
        bool ignore;
    };

    struct SigScanRequest {
        std::string name;
        std::string signature;
    };

    std::unordered_map<std::string, std::vector<SigScanRequest>>
        queuedModuleScans;
    std::unordered_map<std::string, uint64_t> scanResults;

    struct HeapProfile {
        bool fPrivateMemory = false;
        DWORD VadType = 0;
        bool valid = false;
    };
    HeapProfile heapProfile;

    // --- Keyboard State ---
    uint64_t gafAsyncKeyStateExport = 0;
    DWORD win_logon_pid = 0;
    uint8_t state_bitmap[64] = { 0 };
    uint8_t prev_bitmap[64] = { 0 };
    std::atomic<bool> kb_running = false;
    std::thread kb_thread;
    std::mutex kb_mutex;
    uint8_t pressed_bitmap[64] = { 0 };
    uint8_t released_bitmap[64] = { 0 };

    inline void KeyboardThread(int poll_ms = 10) {
        while (kb_running.load()) {
            if (hVMM && gafAsyncKeyStateExport) {
                uint8_t tmp[64] = { 0 };
                DWORD bytesRead = 0;
                if (VMMDLL_MemReadEx(hVMM,
                    win_logon_pid | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY,
                    gafAsyncKeyStateExport,
                    reinterpret_cast<PBYTE>(tmp),
                    64, &bytesRead, VMMDLL_FLAG_NOCACHE)) {
                    std::lock_guard<std::mutex> lock(kb_mutex);
                    for (int i = 0; i < 64; i++) {
                        uint8_t became_set = tmp[i] & ~state_bitmap[i]; // bits that turned on
                        uint8_t became_clear = state_bitmap[i] & ~tmp[i]; // bits that turned off
                        pressed_bitmap[i] |= became_set;
                        released_bitmap[i] |= became_clear;
                    }
                    memcpy(state_bitmap, tmp, 64);
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(poll_ms));
        }
    }

    // Call this after InitKeyboard succeeds
    inline void StartKeyboardThread(int poll_ms = 10) {
        kb_running = true;
        kb_thread = std::thread(&DMA::KeyboardThread, this, poll_ms);
    }

    /// <summary>
    /// Stops the background keyboard polling thread.
    /// </summary>
    inline void StopKeyboardThread() {
        kb_running = false;
        if (kb_thread.joinable())
            kb_thread.join();
    }

    inline std::vector<PatternByte> ParseSignature(const std::string& signature) {
        std::vector<PatternByte> pattern;
        size_t i = 0;
        while (i < signature.size()) {
            if (signature[i] == ' ') {
                i++;
                continue;
            }
            if (signature[i] == '?') {
                pattern.push_back({ 0, true });
                i++;
                if (i < signature.size() && signature[i] == '?')
                    i++;
            }
            else {
                std::string byteStr = signature.substr(i, 2);
                pattern.push_back(
                    { (uint8_t)std::strtoul(byteStr.c_str(), nullptr, 16), false });
                i += 2;
            }
        }
        return pattern;
    }

    inline uint64_t ScanLocalBuffer(const std::vector<uint8_t>& buffer,
        uint64_t baseAddress,
        const std::vector<PatternByte>& pattern) {
        if (pattern.empty() || buffer.size() < pattern.size())
            return 0;
        for (size_t i = 0; i <= buffer.size() - pattern.size(); ++i) {
            bool found = true;
            for (size_t j = 0; j < pattern.size(); ++j) {
                if (!pattern[j].ignore && buffer[i + j] != pattern[j].value) {
                    found = false;
                    break;
                }
            }
            if (found)
                return baseAddress + i;
        }
        return 0;
    }

    inline bool CacheModule(const std::string& moduleName) {
        if (!hVMM || targetPID == 0)
            return false;
        PVMMDLL_MAP_MODULEENTRY pModuleMapEntry = nullptr;
        if (VMMDLL_Map_GetModuleFromNameU(hVMM, targetPID, moduleName.c_str(),
            &pModuleMapEntry, 0)) {
            moduleCache[moduleName] = { pModuleMapEntry->vaBase,
                                       pModuleMapEntry->cbImageSize };
            VMMDLL_MemFree(pModuleMapEntry);
            return true;
        }
        return false;
    }

    inline std::vector<HeapRegion> GetHeapRegions() {
        std::vector<HeapRegion> heaps;
        if (!hVMM || targetPID == 0)
            return heaps;

        PVMMDLL_MAP_VAD pVadMap = nullptr;
        if (!VMMDLL_Map_GetVadU(hVMM, targetPID, TRUE, &pVadMap) || !pVadMap)
            return heaps;

        for (DWORD i = 0; i < pVadMap->cMap; ++i) {
            const auto& vad = pVadMap->pMap[i];
            size_t sz = vad.vaEnd - vad.vaStart;

            if (vad.fImage || vad.fFile || vad.fTeb || vad.fStack) continue;
            if (sz == 0 || sz > 0x80000000) continue;
            if (!vad.fPrivateMemory) continue;  // learned: fPrivateMemory = 1
            if (vad.VadType != 0)   continue;  // learned: VadType = 0

            heaps.push_back({ vad.vaStart, vad.vaEnd });
        }

        VMMDLL_MemFree(pVadMap);
        return heaps;
    }

public:
    DMA() = default;

    inline ~DMA() { Disconnect(); }

    // ==========================================
    // Core Device Lifecycle
    // ==========================================

    /// <summary>
    /// Initializes the VMMDLL interface with default FPGA settings.
    /// </summary>
    /// <returns>True if initialization was successful, false otherwise.</returns>
    inline bool Initialize(bool memMap = true, bool debug = false)
    {
        // Start clean (prevents stale handles from breaking re-init attempts)
        Disconnect();

        auto build_and_init = [&](bool useMemMap) -> bool {
            // Keep backing strings alive until after Initialize returns
            std::vector<std::string> store;
            store.reserve(8);

            store.push_back("");               // argv[0] (dummy program name)
            store.push_back("-device");
            store.push_back("fpga://algo=0");

            if (debug) {
                store.push_back("-v");
                store.push_back("-printf");
            }

            std::string memMapPath;
            if (useMemMap) {
                try {
                    auto tmp = std::filesystem::temp_directory_path();
                    memMapPath = (tmp / "mmap.txt").string();
                }
                catch (...) {
                    useMemMap = false;
                }

                // Only add -memmap if the file exists (or you know you created it)
                if (useMemMap && std::filesystem::exists(memMapPath)) {
                    store.push_back("-memmap");
                    store.push_back(memMapPath);
                }
                else {
                    // If caller requested memmap but file doesn't exist, treat as "no memmap"
                    // (or you can return false here if you want strict behavior)
                }
            }

            std::vector<LPCSTR> argv;
            argv.reserve(store.size());
            for (auto& s : store) argv.push_back(s.c_str());

            // Prefer InitializeEx so you can inspect extended error info in a debugger if needed
            PLC_CONFIG_ERRORINFO pErr = nullptr;
            hVMM = VMMDLL_InitializeEx((DWORD)argv.size(), argv.data(), &pErr);

            if (!hVMM) {
                // If you have leechcore.h available, pErr can be inspected in the debugger.
                // Free if present.
                if (pErr) {
                    LcMemFree(pErr);
                }
                return false;
            }
            return true;
            };

        // First attempt: with memmap if requested
        if (memMap) {
            if (build_and_init(true)) return true;

            // Retry without memmap (matches your other codes behavior)
            Disconnect();
            return build_and_init(false);
        }

        // No memmap requested
        return build_and_init(false);
    }

    /// <summary>
    /// Closes all active VMMDLL handles and cleans up resources.
    /// </summary>
    inline void Disconnect() {
        StopKeyboardThread();
        if (hScatter) {
            VMMDLL_Scatter_CloseHandle(hScatter);
            hScatter = nullptr;
        }
        if (hVMM) {
            VMMDLL_Close(hVMM);
            hVMM = nullptr;
        }
    }

    /// <summary>
    /// Attempts to find and attach to a target process by name.
    /// </summary>
    /// <param name="processName">Name of the process (e.g., "game.exe").</param>
    /// <returns>True if process found and scatter handle initialized.</returns>
    inline bool Attach(const std::string& processName) {
        if (!hVMM)
            return false;
        if (VMMDLL_PidGetFromName(hVMM, processName.c_str(), &targetPID)) {
            mainModuleBase = GetModuleBase(processName);

            if (hScatter)
                VMMDLL_Scatter_CloseHandle(hScatter);
            hScatter =
                VMMDLL_Scatter_Initialize(hVMM, targetPID, VMMDLL_FLAG_NOCACHE);

            return true;
        }
        return false;
    }

    // ==========================================
    // CR3 / DTB Management (Anti-Cheat Bypass)
    // ==========================================

    /// <summary>
    /// Verifies if the current Directory Table Base (DTB/CR3) is valid.
    /// Checks for the "MZ" header at the main module base.
    /// </summary>
    /// <returns>True if the DTB is valid.</returns>
    inline bool IsCR3Valid() {
        if (!hVMM || targetPID == 0 || mainModuleBase == 0)
            return false;

        // Use NOCACHE to ensure we are querying the physical memory state right now
        uint16_t magic = Read<uint16_t>(mainModuleBase);
        return magic == 0x5A4D; // 0x5A4D is 'MZ'
    }

    /// <summary>
    /// Manually sets the process Directory Table Base (DTB/CR3).
    /// Useful for bypassing anti-cheats that scramble the DTB.
    /// </summary>
    /// <param name="dtb">The new Directory Table Base.</param>
    inline bool SetCR3(uint64_t dtb) {
        if (!hVMM || targetPID == 0)
            return false;

        // VMMDLL_OPT_PROCESS_DTB expects the PID in the lower DWORD
        uint64_t option = VMMDLL_OPT_PROCESS_DTB | targetPID;
        return VMMDLL_ConfigSet(hVMM, option, dtb);
    }

    /// <summary>
    /// Flushes the internal VMMDLL Transport Lookaside Buffer (TLB) and memory
    /// cache. Use this if memory reads fail due to anti-cheat memory swapping.
    /// </summary>
    inline bool ClearCache() {
        if (!hVMM)
            return false;
        bool tlb = VMMDLL_ConfigSet(hVMM, VMMDLL_OPT_REFRESH_FREQ_TLB, 1);
        bool mem = VMMDLL_ConfigSet(hVMM, VMMDLL_OPT_REFRESH_FREQ_MEM, 1);
        return tlb && mem;
    }

    // ==========================================
    // Module Management
    // ==========================================

    /// <summary>
    /// Retrieves the base address of a module in the target process.
    /// Caches the result to minimize VMMDLL calls.
    /// </summary>
    /// <param name="moduleName">Name of the module (e.g.,
    /// "kernel32.dll").</param> <returns>Base address of the module, or 0 if not
    /// found.</returns>
    inline uint64_t GetModuleBase(const std::string& moduleName) {
        if (moduleCache.find(moduleName) == moduleCache.end())
            if (!CacheModule(moduleName))
                return 0;
        return moduleCache[moduleName].baseAddress;
    }

    /// <summary>
    /// Retrieves the size of a module in bytes.
    /// </summary>
    /// <param name="moduleName">Name of the module.</param>
    /// <returns>Size of the module, or 0 if not found.</returns>
    inline uint32_t GetModuleSize(const std::string& moduleName) {
        if (moduleCache.find(moduleName) == moduleCache.end())
            if (!CacheModule(moduleName))
                return 0;
        return moduleCache[moduleName].size;
    }

    /// <summary>Returns the base address of the main module (process
    /// executable).</summary>
    inline uint64_t GetMainBase() const { return mainModuleBase; }
    /// <summary>Returns the Process ID (PID) of the attached target.</summary>
    inline DWORD GetPID() const { return targetPID; }

    // ==========================================
    // Raw Memory IO & Traversal
    // ==========================================

    /// <summary>
    /// Reads raw memory from the target process.
    /// </summary>
    /// <param name="address">Target virtual address.</param>
    /// <param name="buffer">Local buffer to store the read data.</param>
    /// <param name="size">Number of bytes to read.</param>
    /// <param name="flags">VMMDLL flags (e.g., VMMDLL_FLAG_NOCACHE).</param>
    /// <returns>True if the read was successful.</returns>
    inline bool ReadRaw(uint64_t address, void* buffer, size_t size) {
        if (!hVMM || targetPID == 0 || address == 0)
            return false;
        DWORD bytesRead = 0;
        return VMMDLL_MemReadEx(hVMM, targetPID, address, (PBYTE)buffer, size,
            &bytesRead, VMMDLL_FLAG_NOCACHE);
    }

    /// <summary>
    /// Writes raw memory to the target process.
    /// </summary>
    /// <param name="address">Target virtual address.</param>
    /// <param name="buffer">Local buffer containing data to write.</param>
    /// <param name="size">Number of bytes to write.</param>
    /// <returns>True if the write was successful.</returns>
    inline bool WriteRaw(uint64_t address, const void* buffer, size_t size) {
        if (!hVMM || targetPID == 0 || address == 0)
            return false;
        return VMMDLL_MemWrite(hVMM, targetPID, address, (PBYTE)buffer, size);
    }

    /// <summary>
    /// Reads a value of type T from the target process.
    /// </summary>
    /// <typeparam name="T">The type of data to read.</typeparam>
    /// <param name="address">Target virtual address.</param>
    /// <param name="flags">VMMDLL flags.</param>
    /// <returns>The read value, or T{} on failure.</returns>
    template <typename T> inline T Read(uint64_t address) {
        T buffer{};
        ReadRaw(address, &buffer, sizeof(T));
        return buffer;
    }

    /// <summary>
    /// Writes a value of type T to the target process.
    /// </summary>
    /// <typeparam name="T">The type of data to write.</typeparam>
    /// <param name="address">Target virtual address.</param>
    /// <param name="value">The value to write.</param>
    /// <returns>True if the write was successful.</returns>
    template <typename T> inline bool Write(uint64_t address, const T& value) {
        return WriteRaw(address, &value, sizeof(T));
    }

    /// <summary>
    /// Follows a pointer chain to retrieve the final address.
    /// </summary>
    /// <param name="base">Base address to start from.</param>
    /// <param name="offsets">List of offsets to apply sequentially.</param>
    /// <returns>The final address, or 0 if the chain is broken.</returns>
    inline uint64_t ReadChain(uint64_t base,
        const std::vector<uint64_t>& offsets) {
        uint64_t currentAddress = base;
        for (const auto& offset : offsets) {
            currentAddress = Read<uint64_t>(currentAddress);
            if (!currentAddress)
                break;
            currentAddress += offset;
        }
        return currentAddress;
    }

    /// <summary>
    /// Reads an ASCII string from the target process.
    /// </summary>
    /// <param name="address">Target virtual address.</param>
    /// <param name="maxLength">Maximum characters to read.</param>
    /// <returns>The read string, truncated at the first null
    /// terminator.</returns>
    inline std::string ReadString(uint64_t address, size_t maxLength = 256) {
        if (address == 0)
            return "";
        std::string result;
        result.resize(maxLength);
        if (ReadRaw(address, &result[0], maxLength)) {
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
    inline std::wstring ReadWString(uint64_t address, size_t maxLength = 256) {
        if (address == 0)
            return L"";
        std::wstring result;
        result.resize(maxLength);
        if (ReadRaw(address, &result[0], maxLength * sizeof(wchar_t))) {
            size_t nullTerminator = result.find(L'\0');
            if (nullTerminator != std::wstring::npos) {
                result.resize(nullTerminator);
            }
            return result;
        }
        return L"";
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
    inline uint64_t ResolveRelative(uint64_t instructionAddress,
        uint32_t offsetOffset,
        uint32_t instructionSize) {
        if (instructionAddress == 0)
            return 0;
        int32_t relativeOffset = Read<int32_t>(instructionAddress + offsetOffset);
        if (relativeOffset == 0)
            return 0;
        return instructionAddress + instructionSize + relativeOffset;
    }

    // ==========================================
    // Signature Scanning
    // ==========================================

    /// <summary>
    /// Reads a block of memory from the target process.
    /// </summary>
    inline std::vector<uint8_t>
        DumpMemory(uint64_t address, size_t size,
            ULONG64 flags = VMMDLL_FLAG_ZEROPAD_ON_FAIL) {
        std::vector<uint8_t> buffer;
        if (!hVMM || targetPID == 0 || address == 0 || size == 0)
            return buffer;
        buffer.resize(size);
        DWORD bytesRead = 0;
        if (!VMMDLL_MemReadEx(hVMM, targetPID, address, buffer.data(), size,
            &bytesRead, flags))
            buffer.clear();
        else if (bytesRead != size)
            buffer.resize(bytesRead);
        return buffer;
    }

    /// <summary>Add a signature scan request to the queue.</summary>
    inline void QueueModuleScan(const std::string& moduleName,
        const std::string& scanName,
        const std::string& signature) {
        queuedModuleScans[moduleName].push_back({ scanName, signature });
    }

    /// <summary>Execute all queued module scans.</summary>
    inline void ExecuteModuleScans() {
        for (const auto& [modName, requests] : queuedModuleScans) {
            uint64_t modBase = GetModuleBase(modName);
            uint32_t modSize = GetModuleSize(modName);

            if (modBase == 0 || modSize == 0)
                continue;

            std::vector<uint8_t> localDump = DumpMemory(modBase, modSize);
            if (localDump.empty())
                continue;

            for (const auto& req : requests) {
                std::vector<PatternByte> pattern = ParseSignature(req.signature);
                scanResults[req.name] = ScanLocalBuffer(localDump, modBase, pattern);
            }
        }
        queuedModuleScans.clear();
    }

    /// <summary>Retrieve the result of a previous scan.</summary>
    inline uint64_t GetScanResult(const std::string& scanName) {
        if (scanResults.find(scanName) != scanResults.end()) {
            return scanResults[scanName];
        }
        return 0;
    }

    /// <summary>
    /// Scans the private heap of the process for a signature.
    /// WARNING: This can be slow as it reads significant amounts of memory.
    /// </summary>
    inline uint64_t SigScanHeap(const std::string& signature) {
        std::vector<PatternByte> pattern = ParseSignature(signature);
        if (pattern.empty()) {
            std::cout << "[HEAP] Pattern empty after parse\n";
            return 0;
        }

        std::vector<HeapRegion> heaps = GetHeapRegions();
        std::cout << "[HEAP] Region count: " << heaps.size() << "\n";
        if (heaps.empty())
            return 0;

        constexpr size_t CHUNK_SIZE = 0x1000000;
        size_t totalBytesRead = 0;
        int failedDumps = 0;
        int successDumps = 0;

        for (const auto& r : heaps) {
            size_t regionSize = r.end - r.start;
            if (regionSize == 0)
                continue;

            for (size_t offset = 0; offset < regionSize; offset += CHUNK_SIZE) {
                size_t chunkSize = min(CHUNK_SIZE, regionSize - offset);
                std::vector<uint8_t> localDump = DumpMemory(
                    r.start + offset, chunkSize,
                    VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_ZEROPAD_ON_FAIL);

                if (localDump.empty()) {
                    failedDumps++;
                    std::cout << "[HEAP] DumpMemory FAILED: 0x" << std::hex
                        << (r.start + offset) << " size=0x" << chunkSize << std::dec << "\n";
                    continue;
                }

                successDumps++;
                totalBytesRead += localDump.size();

                // Check if dump is all zeros (ZEROPAD filled it but read failed silently)
                bool allZero = std::all_of(localDump.begin(), localDump.end(), [](uint8_t b) { return b == 0; });
                if (allZero) {
                    std::cout << "[HEAP] WARNING: Dump all-zero (silent fail?): 0x" << std::hex
                        << (r.start + offset) << std::dec << "\n";
                    continue;
                }

                uint64_t match = ScanLocalBuffer(localDump, r.start + offset, pattern);
                if (match) {
                    std::cout << "[HEAP] Match found at 0x" << std::hex << match << std::dec << "\n";
                    return match;
                }
            }
        }

        std::cout << "[HEAP] Scan complete. Successful dumps: " << successDumps
            << " Failed: " << failedDumps
            << " Total bytes scanned: 0x" << std::hex << totalBytesRead << std::dec << "\n";
        return 0;
    }

    // ==========================================
    // Automated Scatter Read System
    // ==========================================

    /// <summary>Prepares a scatter read request for a specific type.</summary>
    template <typename T> inline void AddScatter(uint64_t address, T* outBuffer) {
        if (!hScatter || address == 0 || !outBuffer)
            return;
        VMMDLL_Scatter_PrepareEx(hScatter, address, sizeof(T), (PBYTE)outBuffer,
            nullptr);
    }

    /// <summary>Prepares a raw scatter read request.</summary>
    inline void AddScatterRaw(uint64_t address, void* outBuffer, size_t size) {
        if (!hScatter || address == 0 || !outBuffer || size == 0)
            return;
        VMMDLL_Scatter_PrepareEx(hScatter, address, size, (PBYTE)outBuffer,
            nullptr);
    }

    /// <summary>Executes all prepared scatter reads.</summary>
    inline bool ExecuteScatter() {
        if (!hScatter)
            return false;

        if (VMMDLL_Scatter_ExecuteRead(hScatter)) {
            VMMDLL_Scatter_Clear(hScatter, targetPID, 0);
            return true;
        }
        return false;
    }

    /// <summary>
    /// Dumps a module from memory to disk, fixing Section Headers and IAT.
    /// Useful for unpacking and static analysis.
    /// </summary>
    /// <summary>
    /// Dumps a module from memory to disk using a Linear Dump strategy.
    /// This maps the file 1:1 with memory (Virtual Address == Raw Offset), which determines the best layout for packed/obfuscated files.
    /// </summary>
    inline bool DumpModule(const std::string& moduleName, const std::string& outPath) {
        uint64_t modBase = GetModuleBase(moduleName);
        uint32_t modSize = GetModuleSize(moduleName);
        if (modBase == 0 || modSize == 0)
            return false;

        // 1. Pull the complete module from memory
        // We use the full module size to ensure we get everything including the headers and all sections
        std::vector<uint8_t> buffer = DumpMemory(modBase, modSize);
        if (buffer.empty() || buffer.size() < sizeof(IMAGE_DOS_HEADER))
            return false;

        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer.data();
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(buffer.data() + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE)
            return false;

        // We are creating a "Linear Dump" / "Virtual Dump".
        // In this format, the file on disk is identical to the image in memory.
        // Raw Offset == Virtual Address.
        // This defeats packers that manipulate section headers to alias raw offsets to 
        // completely different parts of the file than where they end up in memory.

        bool is32Bit = (pNt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
        WORD numSections = pNt->FileHeader.NumberOfSections;
        PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

        // Force section alignment to match file alignment (usually page size 0x1000)
        // This tells tools that the file is effectively "flat"
        pNt->OptionalHeader.FileAlignment = pNt->OptionalHeader.SectionAlignment;
        
        // Fix section headers to point effectively to themselves
        for (WORD i = 0; i < numSections; i++) {
            // Point the raw data to the virtual address.
            // In a linear dump, the data exists in the file at the exact same offset as its RVA.
            pSection[i].PointerToRawData = pSection[i].VirtualAddress;
            
            // Ensure the size is aligned and valid
            pSection[i].SizeOfRawData = pSection[i].Misc.VirtualSize;
        }

        // Fix IAT if possible (Import Address Table)
        // Many packers will destroy the IAT or redirect it. VMMDLL can help us reconstruct it.
        
        // Zero bound imports directory as it is invalid in a dump
        if(pNt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT) {
             pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
             pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
        }

        // Zero IAT directory to force regeneration by analysis tools, or we can try to fix it.
        // For a raw dump, often better to clear it if we can't fully rebuild it, but we will try to patch what we can.
        
        // Attempt to fix imports using VMMDLL's analysis
        PVMMDLL_MAP_IAT pIatMap = nullptr;
        if (VMMDLL_Map_GetIATU(hVMM, targetPID, moduleName.c_str(), &pIatMap) && pIatMap) {
            for (DWORD i = 0; i < pIatMap->cMap; i++) {
                const auto& entry = pIatMap->pMap[i];
                if (entry.Thunk.rvaFirstThunk == 0)
                    continue;
                
                // Ensure we are within bounds of our dump
                if ((entry.Thunk.rvaFirstThunk + (is32Bit ? 4 : 8)) > buffer.size())
                    continue;

                // Patch the IAT entry in our buffer
                if (entry.Thunk.rvaNameFunction != 0) {
                     // We have a name/ordinal match
                    if (is32Bit)
                        *reinterpret_cast<uint32_t*>(buffer.data() + entry.Thunk.rvaFirstThunk) = entry.Thunk.rvaNameFunction;
                    else
                        *reinterpret_cast<uint64_t*>(buffer.data() + entry.Thunk.rvaFirstThunk) = entry.Thunk.rvaNameFunction;
                } else if (entry.Thunk.wHint != 0) {
                     // Ordinal import
                    if (is32Bit)
                        *reinterpret_cast<uint32_t*>(buffer.data() + entry.Thunk.rvaFirstThunk) = 0x80000000 | entry.Thunk.wHint;
                    else
                        *reinterpret_cast<uint64_t*>(buffer.data() + entry.Thunk.rvaFirstThunk) = 0x8000000000000000ULL | entry.Thunk.wHint;
                }
            }
            VMMDLL_MemFree(pIatMap);
        }

        // 8. Write to disk
        std::ofstream outFile(outPath, std::ios::binary);
        if (!outFile)
            return false;

        outFile.write(reinterpret_cast<char*>(buffer.data()), buffer.size());
        outFile.close();
        return true;
    }
    // ==========================================
    // Keyboard Support
    // ==========================================

    /// <summary>
    /// Initialize the keyboard state reader.
    /// Finds the gafAsyncKeyState export in win32kbase.sys/win32k.sys and starts a background thread to poll it.
    /// </summary>
    /// <param name="poll_ms">Interval in milliseconds to poll the keyboard state (default: 10ms).</param>
    /// <returns>True if initialization was successful, false otherwise.</returns>
    inline bool InitKeyboard(int poll_ms) {
        if (!hVMM)
            return false;

        std::string win = "0";
        DWORD type = 0;
        DWORD size = 0;

        if (VMMDLL_WinReg_QueryValueExU(hVMM,
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\CurrentBuild",
            &type, nullptr, &size)) {
            std::vector<uint8_t> buffer(size + 2, 0);
            if (VMMDLL_WinReg_QueryValueExU(hVMM,
                "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\CurrentBuild",
                &type, buffer.data(), &size)) {
                if (size >= 2 && buffer[1] == 0) {
                    std::wstring ws(reinterpret_cast<wchar_t*>(buffer.data()));
                    win = std::string(ws.begin(), ws.end());
                }
                else {
                    win = std::string(reinterpret_cast<char*>(buffer.data()));
                }
            }
        }

        int Winver = 0;
        try {
            Winver = std::stoi(win);
        }
        catch (...) {
            return false;
        }

        if (!VMMDLL_PidGetFromName(hVMM, "winlogon.exe", &win_logon_pid))
            return false;

        if (Winver > 22000) {
            SIZE_T cPids = 0;
            if (!VMMDLL_PidList(hVMM, nullptr, &cPids))
                return false;

            std::vector<DWORD> pids(cPids);
            if (!VMMDLL_PidList(hVMM, pids.data(), &cPids))
                return false;

            for (DWORD pid : pids) {
                LPSTR szName = VMMDLL_ProcessGetInformationString(
                    hVMM, pid, VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_USER_IMAGE);
                if (!szName)
                    continue;

                std::string procName(szName);
                VMMDLL_MemFree(szName);

                if (procName.find("csrss.exe") == std::string::npos)
                    continue;

                auto getModule = [&](const std::string& name) -> std::pair<uint64_t, uint32_t> {
                    PVMMDLL_MAP_MODULEENTRY pModuleMapEntry = nullptr;
                    if (VMMDLL_Map_GetModuleFromNameU(hVMM, pid, name.c_str(), &pModuleMapEntry, 0)) {
                        uint64_t base = pModuleMapEntry->vaBase;
                        uint32_t sz = pModuleMapEntry->cbImageSize;
                        VMMDLL_MemFree(pModuleMapEntry);
                        return { base, sz };
                    }
                    return { 0, 0 };
                    };

                auto [win32k_base, win32k_size] = getModule("win32ksgd.sys");
                if (!win32k_base) {
                    auto res = getModule("win32k.sys");
                    win32k_base = res.first;
                    win32k_size = res.second;
                    if (!win32k_base)
                        continue;
                }

                std::vector<uint8_t> win32k_dump = DumpMemory(win32k_base, win32k_size, 0);
                if (win32k_dump.empty())
                    continue;

                auto sig1 = ParseSignature("48 8B 05 ? ? ? ? 48 8B 04 C8");
                uint64_t g_session_ptr = ScanLocalBuffer(win32k_dump, win32k_base, sig1);

                if (!g_session_ptr) {
                    auto sig2 = ParseSignature("48 8B 05 ? ? ? ? FF C9");
                    g_session_ptr = ScanLocalBuffer(win32k_dump, win32k_base, sig2);
                }

                if (!g_session_ptr)
                    continue;

                int relative = Read<int>(g_session_ptr + 3);
                uint64_t g_session_global_slots = g_session_ptr + 7 + relative;

                uint64_t user_session_state = 0;
                for (int i = 0; i < 4; i++) {
                    uint64_t ptr1 = Read<uint64_t>(g_session_global_slots);
                    uint64_t ptr2 = Read<uint64_t>(ptr1 + 8 * i);
                    user_session_state = Read<uint64_t>(ptr2);
                    if (user_session_state > 0x7FFFFFFFFFFF)
                        break;
                }

                auto [win32kbase_base, win32kbase_size] = getModule("win32kbase.sys");
                if (!win32kbase_base)
                    continue;

                std::vector<uint8_t> win32kbase_dump = DumpMemory(win32kbase_base, win32kbase_size, 0);
                if (win32kbase_dump.empty())
                    continue;

                auto sig3 = ParseSignature("48 8D 90 ? ? ? ? E8 ? ? ? ? 0F 57 C0");
                uint64_t ptr = ScanLocalBuffer(win32kbase_dump, win32kbase_base, sig3);

                if (ptr) {
                    uint32_t session_offset = Read<uint32_t>(ptr + 3);
                    gafAsyncKeyStateExport = user_session_state + session_offset;
                }
                else {
                    continue;
                }

                if (gafAsyncKeyStateExport > 0x7FFFFFFFFFFF)
                    return true;
            }

            return false;

        }
        else {
            PVMMDLL_MAP_EAT pEatMap = nullptr;
            if (VMMDLL_Map_GetEATU(hVMM,
                win_logon_pid | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY,
                "win32kbase.sys", &pEatMap)) {
                if (pEatMap->dwVersion == VMMDLL_MAP_EAT_VERSION) {
                    for (DWORD i = 0; i < pEatMap->cMap; i++) {
                        if (strcmp(pEatMap->pMap[i].uszFunction, "gafAsyncKeyState") == 0) {
                            gafAsyncKeyStateExport = pEatMap->pMap[i].vaFunction;
                            break;
                        }
                    }
                }
                VMMDLL_MemFree(pEatMap);
            }

            if (gafAsyncKeyStateExport < 0x7FFFFFFFFFFF) {
                PVMMDLL_MAP_MODULEENTRY pModuleEntry = nullptr;
                if (VMMDLL_Map_GetModuleFromNameU(hVMM,
                    win_logon_pid | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY,
                    "win32kbase.sys", &pModuleEntry, 0)) {
                    char szModuleName[MAX_PATH] = {};
                    if (VMMDLL_PdbLoad(hVMM,
                        win_logon_pid | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY,
                        pModuleEntry->vaBase, szModuleName)) {
                        uint64_t va = 0;
                        if (VMMDLL_PdbSymbolAddress(hVMM, szModuleName, "gafAsyncKeyState", &va))
                            gafAsyncKeyStateExport = va;
                    }
                    VMMDLL_MemFree(pModuleEntry);
                }
            }
            bool valid = gafAsyncKeyStateExport > 0x7FFFFFFFFFFF;

            if (valid)
            {
                StartKeyboardThread(poll_ms);
            }

            return valid;
        }
    }

    // Is the key currently held
    /// <summary>
    /// Check if a key is currently held down.
    /// </summary>
    /// <param name="vk">Virtual Key code to check.</param>
    /// <returns>True if the key is down, false otherwise.</returns>
    inline bool IsKeyDown(uint32_t vk) {
        std::lock_guard<std::mutex> lock(kb_mutex);
        return (state_bitmap[(vk * 2 / 8)] & (1 << (vk % 4 * 2))) != 0;
    }

    // Was the key just pressed this poll (down now, not down before)
    /// <summary>
    /// Check if a key was just pressed since the last poll (rising edge).
    /// </summary>
    /// <param name="vk">Virtual Key code to check.</param>
    /// <returns>True if the key was just pressed, false otherwise.</returns>
    inline bool IsKeyPressed(uint32_t vk) {
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
    inline bool IsKeyReleased(uint32_t vk) {
        std::lock_guard<std::mutex> lock(kb_mutex);
        int byte = vk * 2 / 8;
        int bit = 1 << (vk % 4 * 2);
        if (released_bitmap[byte] & bit) {
            released_bitmap[byte] &= ~bit; // clear on read
            return true;
        }
        return false;
    }
};

inline DMA g_Dma;
