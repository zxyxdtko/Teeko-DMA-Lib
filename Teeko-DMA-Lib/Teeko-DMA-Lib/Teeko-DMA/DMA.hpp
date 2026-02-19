#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include "deps/vmmdll.h"

#pragma comment(lib, "libs/vmm.lib")
#pragma comment(lib, "libs/leechcore.lib")

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

    // The primary automated scatter handle for the rendering loop
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

    std::unordered_map<std::string, std::vector<SigScanRequest>> queuedModuleScans;
    std::unordered_map<std::string, uint64_t> scanResults;

    inline std::vector<PatternByte> ParseSignature(const std::string& signature) {
        std::vector<PatternByte> pattern;
        size_t i = 0;
        while (i < signature.size()) {
            if (signature[i] == ' ') { i++; continue; }
            if (signature[i] == '?') {
                pattern.push_back({ 0, true });
                i++;
                if (i < signature.size() && signature[i] == '?') i++;
            }
            else {
                std::string byteStr = signature.substr(i, 2);
                pattern.push_back({ (uint8_t)std::strtoul(byteStr.c_str(), nullptr, 16), false });
                i += 2;
            }
        }
        return pattern;
    }

    inline uint64_t ScanLocalBuffer(const std::vector<uint8_t>& buffer, uint64_t baseAddress, const std::vector<PatternByte>& pattern) {
        if (pattern.empty() || buffer.size() < pattern.size()) return 0;
        for (size_t i = 0; i <= buffer.size() - pattern.size(); ++i) {
            bool found = true;
            for (size_t j = 0; j < pattern.size(); ++j) {
                if (!pattern[j].ignore && buffer[i + j] != pattern[j].value) {
                    found = false;
                    break;
                }
            }
            if (found) return baseAddress + i;
        }
        return 0;
    }

    inline bool CacheModule(const std::string& moduleName) {
        if (!hVMM || targetPID == 0) return false;
        PVMMDLL_MAP_MODULEENTRY pModuleMapEntry = nullptr;
        if (VMMDLL_Map_GetModuleFromNameU(hVMM, targetPID, moduleName.c_str(), &pModuleMapEntry, 0)) {
            moduleCache[moduleName] = { pModuleMapEntry->vaBase, pModuleMapEntry->cbImageSize };
            VMMDLL_MemFree(pModuleMapEntry);
            return true;
        }
        return false;
    }

    inline std::vector<HeapRegion> GetHeapRegions() {
        std::vector<HeapRegion> heaps;
        if (!hVMM || targetPID == 0) return heaps;

        PVMMDLL_MAP_VAD pVadMap = nullptr;
        if (!VMMDLL_Map_GetVadU(hVMM, targetPID, TRUE, &pVadMap) || !pVadMap) return heaps;

        heaps.reserve(pVadMap->cMap);
        for (DWORD i = 0; i < pVadMap->cMap; ++i) {
            const auto& vad = pVadMap->pMap[i];

            if (vad.MemCommit == 1 &&
                vad.fPrivateMemory == 1 &&
                vad.fImage == 0 &&
                vad.fFile == 0 &&
                vad.fTeb == 0 &&
                vad.fStack == 0 &&
                vad.VadType == 0)
            {
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

    inline bool Initialize() {
        const char* args[] = { "", "-printf", "-device", "fpga" };
        int argc = sizeof(args) / sizeof(args[0]);
        hVMM = VMMDLL_Initialize(argc, (LPCSTR*)args);
        return hVMM != nullptr;
    }

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

    inline bool Attach(const std::string& processName) {
        if (!hVMM) return false;
        if (VMMDLL_PidGetFromName(hVMM, processName.c_str(), &targetPID)) {
            mainModuleBase = GetModuleBase(processName);

            if (hScatter) VMMDLL_Scatter_CloseHandle(hScatter);
            hScatter = VMMDLL_Scatter_Initialize(hVMM, targetPID, VMMDLL_FLAG_NOCACHE);

            return true;
        }
        return false;
    }

    // ==========================================
    // Module Management
    // ==========================================

    inline uint64_t GetModuleBase(const std::string& moduleName) {
        if (moduleCache.find(moduleName) == moduleCache.end()) if (!CacheModule(moduleName)) return 0;
        return moduleCache[moduleName].baseAddress;
    }

    inline uint32_t GetModuleSize(const std::string& moduleName) {
        if (moduleCache.find(moduleName) == moduleCache.end()) if (!CacheModule(moduleName)) return 0;
        return moduleCache[moduleName].size;
    }

    inline uint64_t GetMainBase() const { return mainModuleBase; }
    inline DWORD GetPID() const { return targetPID; }

    // ==========================================
    // Raw Memory IO & Traversal
    // ==========================================

    inline bool ReadRaw(uint64_t address, void* buffer, size_t size, ULONG64 flags = 0) {
        if (!hVMM || targetPID == 0 || address == 0) return false;
        DWORD bytesRead = 0;
        return VMMDLL_MemReadEx(hVMM, targetPID, address, (PBYTE)buffer, size, &bytesRead, flags);
    }

    inline bool WriteRaw(uint64_t address, const void* buffer, size_t size) {
        if (!hVMM || targetPID == 0 || address == 0) return false;
        return VMMDLL_MemWrite(hVMM, targetPID, address, (PBYTE)buffer, size);
    }

    template <typename T>
    inline T Read(uint64_t address, ULONG64 flags = 0) {
        T buffer{};
        ReadRaw(address, &buffer, sizeof(T), flags);
        return buffer;
    }

    template <typename T>
    inline bool Write(uint64_t address, const T& value) {
        return WriteRaw(address, &value, sizeof(T));
    }

    inline uint64_t ReadChain(uint64_t base, const std::vector<uint64_t>& offsets) {
        uint64_t currentAddress = base;
        for (const auto& offset : offsets) {
            currentAddress = Read<uint64_t>(currentAddress);
            if (!currentAddress) break;
            currentAddress += offset;
        }
        return currentAddress;
    }

    inline std::string ReadString(uint64_t address, size_t maxLength = 256) {
        if (address == 0) return "";
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

    inline uint64_t ResolveRelative(uint64_t instructionAddress, uint32_t offsetOffset, uint32_t instructionSize) {
        if (instructionAddress == 0) return 0;
        int32_t relativeOffset = Read<int32_t>(instructionAddress + offsetOffset);
        if (relativeOffset == 0) return 0;
        return instructionAddress + instructionSize + relativeOffset;
    }

    // ==========================================
    // Signature Scanning
    // ==========================================

    inline std::vector<uint8_t> DumpMemory(uint64_t address, size_t size, ULONG64 flags = VMMDLL_FLAG_ZEROPAD_ON_FAIL) {
        std::vector<uint8_t> buffer;
        if (!hVMM || targetPID == 0 || address == 0 || size == 0) return buffer;
        buffer.resize(size);
        DWORD bytesRead = 0;
        if (!VMMDLL_MemReadEx(hVMM, targetPID, address, buffer.data(), size, &bytesRead, flags)) buffer.clear();
        else if (bytesRead != size) buffer.resize(bytesRead);
        return buffer;
    }

    inline void QueueModuleScan(const std::string& moduleName, const std::string& scanName, const std::string& signature) {
        queuedModuleScans[moduleName].push_back({ scanName, signature });
    }

    inline void ExecuteModuleScans() {
        for (const auto& [modName, requests] : queuedModuleScans) {
            uint64_t modBase = GetModuleBase(modName);
            uint32_t modSize = GetModuleSize(modName);

            if (modBase == 0 || modSize == 0) continue;

            std::vector<uint8_t> localDump = DumpMemory(modBase, modSize);
            if (localDump.empty()) continue;

            for (const auto& req : requests) {
                std::vector<PatternByte> pattern = ParseSignature(req.signature);
                scanResults[req.name] = ScanLocalBuffer(localDump, modBase, pattern);
            }
        }
        queuedModuleScans.clear();
    }

    inline uint64_t GetScanResult(const std::string& scanName) {
        if (scanResults.find(scanName) != scanResults.end()) {
            return scanResults[scanName];
        }
        return 0;
    }

    inline uint64_t SigScanHeap(const std::string& signature) {
        std::vector<PatternByte> pattern = ParseSignature(signature);
        if (pattern.empty()) return 0;

        std::vector<HeapRegion> heaps = GetHeapRegions();
        if (heaps.empty()) return 0;

        for (const auto& r : heaps) {
            size_t regionSize = r.end - r.start;
            if (regionSize == 0 || regionSize > 0x10000000) continue;

            std::vector<uint8_t> localDump = DumpMemory(r.start, regionSize, VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_ZEROPAD_ON_FAIL);
            if (localDump.empty()) continue;

            uint64_t match = ScanLocalBuffer(localDump, r.start, pattern);
            if (match) return match;
        }
        return 0;
    }

    // ==========================================
    // Automated Scatter Read System
    // ==========================================

    template <typename T>
    inline void AddScatter(uint64_t address, T* outBuffer) {
        if (!hScatter || address == 0 || !outBuffer) return;
        VMMDLL_Scatter_PrepareEx(hScatter, address, sizeof(T), (PBYTE)outBuffer, nullptr);
    }

    inline void AddScatterRaw(uint64_t address, void* outBuffer, size_t size) {
        if (!hScatter || address == 0 || !outBuffer || size == 0) return;
        VMMDLL_Scatter_PrepareEx(hScatter, address, size, (PBYTE)outBuffer, nullptr);
    }

    inline bool ExecuteScatter() {
        if (!hScatter) return false;

        if (VMMDLL_Scatter_ExecuteRead(hScatter)) {
            VMMDLL_Scatter_Clear(hScatter, targetPID, 0);
            return true;
        }
        return false;
    }
};

inline DMA g_Dma;