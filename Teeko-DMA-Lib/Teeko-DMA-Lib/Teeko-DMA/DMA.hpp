#pragma once
#include "deps/vmmdll.h"
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

#include <chrono>

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

    // --- Keyboard State ---
    uint64_t gafAsyncKeyStateExport = 0;
    uint8_t state_bitmap[64] = { 0 };
    std::chrono::time_point<std::chrono::system_clock> section_start;
    DWORD win_logon_pid = 0;

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

        heaps.reserve(pVadMap->cMap);
        for (DWORD i = 0; i < pVadMap->cMap; ++i) {
            const auto& vad = pVadMap->pMap[i];

            if (vad.MemCommit == 1 && vad.fPrivateMemory == 1 && vad.fImage == 0 &&
                vad.fFile == 0 && vad.fTeb == 0 && vad.fStack == 0 &&
                vad.VadType == 0) {
                heaps.push_back({ vad.vaStart, vad.vaEnd });
            }
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
    inline bool Initialize() {
        const char* args[] = { "", /*"-printf",*/ "-device", "fpga" };
        int argc = sizeof(args) / sizeof(args[0]);
        hVMM = VMMDLL_Initialize(argc, (LPCSTR*)args);
        return hVMM != nullptr;
    }

    /// <summary>
    /// Closes all active VMMDLL handles and cleans up resources.
    /// </summary>
    inline void Disconnect() {
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
        uint16_t magic = Read<uint16_t>(mainModuleBase, VMMDLL_FLAG_NOCACHE);
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
    inline bool ReadRaw(uint64_t address, void* buffer, size_t size,
        ULONG64 flags = 0) {
        if (!hVMM || targetPID == 0 || address == 0)
            return false;
        DWORD bytesRead = 0;
        return VMMDLL_MemReadEx(hVMM, targetPID, address, (PBYTE)buffer, size,
            &bytesRead, flags);
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
    template <typename T> inline T Read(uint64_t address, ULONG64 flags = 0) {
        T buffer{};
        ReadRaw(address, &buffer, sizeof(T), flags);
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
        if (pattern.empty())
            return 0;

        std::vector<HeapRegion> heaps = GetHeapRegions();
        if (heaps.empty())
            return 0;

        for (const auto& r : heaps) {
            size_t regionSize = r.end - r.start;
            if (regionSize == 0 || regionSize > 0x10000000)
                continue;

            std::vector<uint8_t> localDump =
                DumpMemory(r.start, regionSize,
                    VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_ZEROPAD_ON_FAIL);
            if (localDump.empty())
                continue;

            uint64_t match = ScanLocalBuffer(localDump, r.start, pattern);
            if (match)
                return match;
        }
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
    inline bool DumpModule(const std::string& moduleName,
        const std::string& outPath) {
        uint64_t modBase = GetModuleBase(moduleName);
        uint32_t modSize = GetModuleSize(moduleName);

        if (modBase == 0 || modSize == 0)
            return false;

        // 1. Pull the raw, unpacked module from live memory
        std::vector<uint8_t> buffer = DumpMemory(modBase, modSize);
        if (buffer.empty() || buffer.size() < sizeof(IMAGE_DOS_HEADER))
            return false;

        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)buffer.data();
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        PIMAGE_NT_HEADERS64 pNt =
            (PIMAGE_NT_HEADERS64)(buffer.data() + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE)
            return false;

        bool is32Bit = (pNt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);

        // 2. Fix the Section Headers (Memory Alignment -> File Alignment)
        WORD numSections = pNt->FileHeader.NumberOfSections;
        PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

        for (WORD i = 0; i < numSections; i++) {
            // Because we dumped it exactly as it was mapped in memory,
            // the raw offsets must now match the virtual RVAs.
            pSection[i].SizeOfRawData = pSection[i].Misc.VirtualSize;
            pSection[i].PointerToRawData = pSection[i].VirtualAddress;
        }

        // 3. Rebuild the Import Address Table (IAT)
        PVMMDLL_MAP_IAT pIatMap = nullptr;

        // Let vmmdll do the heavy lifting of parsing the target's imports
        if (VMMDLL_Map_GetIATU(hVMM, targetPID, moduleName.c_str(), &pIatMap) &&
            pIatMap) {
            for (DWORD i = 0; i < pIatMap->cMap; i++) {
                const auto& entry = pIatMap->pMap[i];

                // Ensure the thunk RVA is actually within our dumped memory range
                if (entry.Thunk.rvaFirstThunk != 0 &&
                    (entry.Thunk.rvaFirstThunk + 8) <= buffer.size()) {

                    // If this is a named import (e.g., "VirtualAlloc"), restore its RVA
                    if (entry.Thunk.rvaNameFunction != 0) {
                        if (is32Bit) {
                            uint32_t* pThunk =
                                (uint32_t*)(buffer.data() + entry.Thunk.rvaFirstThunk);
                            *pThunk = entry.Thunk.rvaNameFunction;
                        }
                        else {
                            uint64_t* pThunk =
                                (uint64_t*)(buffer.data() + entry.Thunk.rvaFirstThunk);
                            *pThunk = entry.Thunk.rvaNameFunction;
                        }
                    }
                    // If it is imported by Ordinal, restore the ordinal flag
                    else if (entry.Thunk.wHint != 0 || entry.uszFunction == nullptr) {
                        if (is32Bit) {
                            uint32_t* pThunk =
                                (uint32_t*)(buffer.data() + entry.Thunk.rvaFirstThunk);
                            *pThunk = 0x80000000 | entry.Thunk.wHint;
                        }
                        else {
                            uint64_t* pThunk =
                                (uint64_t*)(buffer.data() + entry.Thunk.rvaFirstThunk);
                            *pThunk = 0x8000000000000000 | entry.Thunk.wHint;
                        }
                    }
                }
            }
            VMMDLL_MemFree(pIatMap); // Critical: Free the allocated map
        }

        // 4. Write the repaired executable to disk
        std::ofstream outFile(outPath, std::ios::binary);
        if (!outFile)
            return false;

        outFile.write((char*)buffer.data(), buffer.size());
        outFile.close();

        return true;
    }

    // ==========================================
    // Keyboard Support
    // ==========================================

    inline bool InitKeyboard() {
        if (!hVMM)
            return false;

        std::string win = "0";
        DWORD type = 0;
        DWORD size = 0;

        // Query Windows Build Number
        if (VMMDLL_WinReg_QueryValueExU(hVMM,
            "HKLM\\SOFTWARE\\Microsoft\\Windows "
            "NT\\CurrentVersion\\CurrentBuild",
            &type, nullptr, &size)) {
            std::vector<uint8_t> buffer(size);
            if (VMMDLL_WinReg_QueryValueExU(hVMM,
                "HKLM\\SOFTWARE\\Microsoft\\Windows "
                "NT\\CurrentVersion\\CurrentBuild",
                &type, buffer.data(), &size)) {
                win = std::string((char*)buffer.data());
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
            // Windows 11+ Logic
            PDWORD pPids = nullptr;
            SIZE_T cPids = 0;
            if (!VMMDLL_PidList(hVMM, nullptr, &cPids))
                return false;

            std::vector<DWORD> pids(cPids);
            if (!VMMDLL_PidList(hVMM, pids.data(), &cPids))
                return false;

            for (DWORD pid : pids) {
                // Check if process is csrss.exe
                LPSTR szName = VMMDLL_ProcessGetInformationString(
                    hVMM, pid, VMMDLL_PROCESS_INFORMATION_OPT_STRING_PATH_USER_IMAGE);

                if (!szName)
                    continue;

                std::string procName(szName);
                VMMDLL_MemFree(szName); // Important: Free the string

                // Check if it contains "csrss.exe"
                if (procName.find("csrss.exe") == std::string::npos) {
                    continue;
                }

                auto getModule =
                    [&](const std::string& name) -> std::pair<uint64_t, uint32_t> {
                    PVMMDLL_MAP_MODULEENTRY pModuleMapEntry = nullptr;
                    if (VMMDLL_Map_GetModuleFromNameU(hVMM, pid, name.c_str(),
                        &pModuleMapEntry, 0)) {
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

                std::vector<uint8_t> win32k_dump =
                    DumpMemory(win32k_base, win32k_size, 0);
                if (win32k_dump.empty())
                    continue;

                auto sig1 = ParseSignature("48 8B 05 ? ? ? ? 48 8B 04 C8");
                uint64_t g_session_ptr =
                    ScanLocalBuffer(win32k_dump, win32k_base, sig1);

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

                std::vector<uint8_t> win32kbase_dump =
                    DumpMemory(win32kbase_base, win32kbase_size, 0);
                if (win32kbase_dump.empty())
                    continue;

                auto sig3 = ParseSignature("48 8D 90 ? ? ? ? E8 ? ? ? ? 0F 57 C0");
                uint64_t ptr = ScanLocalBuffer(win32kbase_dump, win32kbase_base, sig3);

                if (ptr) {
                    uint32_t session_offset = Read<uint32_t>(ptr + 3);
                    gafAsyncKeyStateExport = user_session_state + session_offset;
                }

                if (gafAsyncKeyStateExport > 0x7FFFFFFFFFFF)
                    return true;
            }
            return false;
        }
        else {
            // Windows 10 Logic
            PVMMDLL_MAP_EAT pEatMap = nullptr;
            if (VMMDLL_Map_GetEATU(
                hVMM, win_logon_pid | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY,
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
                if (VMMDLL_Map_GetModuleFromNameU(
                    hVMM, win_logon_pid | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY,
                    "win32kbase.sys", &pModuleEntry, 0)) {
                    char szModuleName[MAX_PATH];
                    if (VMMDLL_PdbLoad(
                        hVMM, win_logon_pid | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY,
                        pModuleEntry->vaBase, szModuleName)) {
                        uint64_t va = 0;
                        if (VMMDLL_PdbSymbolAddress(hVMM, szModuleName, "gafAsyncKeyState",
                            &va)) {
                            gafAsyncKeyStateExport = va;
                        }
                    }
                    VMMDLL_MemFree(pModuleEntry);
                }
            }

            return gafAsyncKeyStateExport > 0x7FFFFFFFFFFF;
        }
    }

    inline void UpdateKeys() {
        if (!hVMM || !gafAsyncKeyStateExport)
            return;
        ReadRaw(gafAsyncKeyStateExport, state_bitmap, 64,
            VMMDLL_FLAG_NOCACHE | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY);
    }

    inline bool IsKeyDown(uint32_t vk) {
        if (!hVMM || !gafAsyncKeyStateExport)
            return false;
        auto now = std::chrono::system_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(now -
            section_start)
            .count() > 100) {
            UpdateKeys();
            section_start = now;
        }
        return state_bitmap[(vk * 2 / 8)] & (1 << (vk % 4 * 2));
    }
};

inline DMA g_Dma;
