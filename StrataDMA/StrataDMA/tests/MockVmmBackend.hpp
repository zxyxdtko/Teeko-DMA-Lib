#pragma once

#include "StrataDMA/DMA.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

class MockVmmBackend final : public IVmmBackend {
public:
    static constexpr uint64_t MemoryBase = 0x1000;
    static constexpr DWORD TargetPid = 42;
    static constexpr uint64_t ValidDtb = 0xabc000;

    MockVmmBackend();

    bool initialized = false;
    bool failInitialize = false;
    bool failPluginInitialization = false;
    bool failReads = false;
    bool failWrites = false;
    bool failPrefetch = false;
    bool failScatterCreate = false;
    bool failScatterPrepare = false;
    bool failScatterExecute = false;
    bool failPhysicalMap = false;
    bool moduleAvailable = true;
    bool requireConfiguredDtb = false;
    std::atomic<bool> processAvailable{ true };
    DWORD partialReadLimit = 0;
    uint64_t configuredDtb = 0;
    bool pluginsInitialized = false;

    std::vector<std::string> initializeArguments;
    std::vector<std::pair<ULONG64, uint64_t>> configWrites;
    std::unordered_map<ULONG64, uint64_t> configValues;
    std::vector<uint8_t> memory;
    std::vector<uint8_t> registryHiveBytes;
    std::vector<DMAProcessInfo> processes;
    std::vector<DMAModuleInfo> modules;
    std::vector<DMAMemoryRegion> regions;
    std::vector<DMAModuleSection> sections;
    std::vector<DMAExportInfo> exports;
    std::vector<DMAImportInfo> imports;
    std::vector<DMAPhysicalMemoryRange> physicalRanges;
    std::vector<DMARegistryHiveInfo> registryHives;
    std::vector<DMARegistryKeyInfo> registryKeys;
    std::vector<DMARegistryValue> registryValues;
    std::vector<DMAVfsEntry> vfsEntries;
    std::unordered_map<std::string, std::vector<uint8_t>> vfsFiles;

    std::atomic<size_t> initializeCalls{ 0 };
    std::atomic<size_t> closeCalls{ 0 };
    std::atomic<size_t> readCalls{ 0 };
    std::atomic<size_t> writeCalls{ 0 };
    mutable std::atomic<size_t> moduleCalls{ 0 };
    std::atomic<size_t> scatterPrepareCalls{ 0 };
    std::atomic<size_t> scatterExecuteCalls{ 0 };
    DWORD lastReadPid = 0;
    ULONG64 lastReadFlags = 0;
    DWORD lastWritePid = 0;
    std::vector<uint64_t> prefetchedPages;

    template <typename T>
    void Store(uint64_t address, const T& value)
    {
        static_assert(std::is_trivially_copyable<T>::value,
            "Mock memory values must be trivially copyable");
        StoreBytes(address, &value, sizeof(value));
    }

    void StoreBytes(uint64_t address, const void* source, size_t size);
    void Fill(uint64_t address, size_t size, uint8_t value);

    DMAOperationResult Initialize(const std::vector<std::string>& arguments) override;
    void Close() override;
    bool IsInitialized() const noexcept override { return initialized; }
    DMAOperationResult InitializePlugins() override;
    DMAOperationResult ConfigGet(ULONG64 option, uint64_t& value) const override;
    DMAOperationResult ConfigSet(ULONG64 option, uint64_t value) override;
    DMAOperationResult ReadMemory(DWORD pid, uint64_t address, void* buffer,
        DWORD size, ULONG64 flags, DWORD& transferred) override;
    DMAOperationResult WriteMemory(DWORD pid, uint64_t address,
        const void* buffer, DWORD size) override;
    DMAOperationResult PrefetchPages(DWORD pid,
        const std::vector<uint64_t>& addresses) override;
    DMAOperationResult VirtualToPhysical(DWORD pid, uint64_t virtualAddress,
        uint64_t& physicalAddress) const override;
    std::unique_ptr<IVmmScatterSession> CreateScatter(DWORD pid,
        DWORD flags) override;

    DMAOperationResult FindPid(const std::string& name, DWORD& pid) const override;
    DMAOperationResult GetProcess(DWORD pid, DMAProcessInfo& process) const override;
    DMAOperationResult GetProcesses(std::vector<DMAProcessInfo>& output) const override;
    DMAOperationResult GetModule(DWORD pid, const std::string& name,
        DMAModuleInfo& module) const override;
    DMAOperationResult GetModules(DWORD pid,
        std::vector<DMAModuleInfo>& output) const override;
    DMAOperationResult GetPhysicalMemoryMap(
        std::vector<DMAPhysicalMemoryRange>& output) const override;
    DMAOperationResult GetMemoryRegions(DWORD pid, bool includeVad,
        bool includePte, std::vector<DMAMemoryRegion>& output) const override;
    DMAOperationResult GetSections(DWORD pid, const std::string& module,
        std::vector<DMAModuleSection>& output) const override;
    DMAOperationResult GetExports(DWORD pid, const std::string& module,
        std::vector<DMAExportInfo>& output) const override;
    DMAOperationResult GetImports(DWORD pid, const std::string& module,
        std::vector<DMAImportInfo>& output) const override;

    DMAOperationResult LoadSymbols(DWORD pid, uint64_t moduleBase,
        std::string& symbolModule) override;
    DMAOperationResult ResolveSymbol(const std::string& symbolModule,
        const std::string& symbol, uint64_t& address) const override;
    DMAOperationResult LookupSymbol(const std::string& symbolModule,
        uint64_t addressOrOffset, DMASymbolInfo& symbol) const override;
    DMAOperationResult GetTypeSize(const std::string& symbolModule,
        const std::string& typeName, uint32_t& size) const override;
    DMAOperationResult GetTypeChildOffset(const std::string& symbolModule,
        const std::string& typeName, const std::string& childName,
        uint32_t& offset) const override;

    DMAOperationResult GetRegistryHives(
        std::vector<DMARegistryHiveInfo>& output) const override;
    DMAOperationResult EnumerateRegistryKeys(const std::string& path,
        std::vector<DMARegistryKeyInfo>& output) const override;
    DMAOperationResult EnumerateRegistryValues(const std::string& path,
        std::vector<DMARegistryValue>& output) const override;
    DMAOperationResult QueryRegistryValue(const std::string& path,
        DMARegistryValue& value) const override;
    DMAOperationResult ReadRegistryHive(uint64_t cmHiveAddress,
        uint32_t relativeAddress, void* buffer, DWORD size, ULONG64 flags,
        DWORD& transferred) const override;
    DMAOperationResult WriteRegistryHive(uint64_t cmHiveAddress,
        uint32_t relativeAddress, const void* buffer, DWORD size) override;

    DMAOperationResult ListVfs(const std::string& path,
        std::vector<DMAVfsEntry>& output) const override;
    DMAOperationResult ReadVfs(const std::string& path, uint64_t offset,
        void* buffer, DWORD size, DWORD& transferred) const override;
    DMAOperationResult WriteVfs(const std::string& path, uint64_t offset,
        const void* buffer, DWORD size, DWORD& transferred) override;

private:
    bool ResolveMemoryRange(uint64_t address, size_t size,
        size_t& offset) const noexcept;
};

struct MockDmaFixture {
    std::shared_ptr<MockVmmBackend> backend =
        std::make_shared<MockVmmBackend>();
    DMA dma{ backend };

    void Initialize(bool plugins = false);
    void Attach();
};
