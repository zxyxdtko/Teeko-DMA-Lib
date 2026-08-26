#pragma once

#include "DMA.Types.hpp"

#include <memory>
#include <string>
#include <vector>

class IVmmScatterSession {
public:
    virtual ~IVmmScatterSession() = default;
    virtual DMAOperationResult PrepareRead(uint64_t address, void* buffer,
        DWORD size, DWORD* transferred) = 0;
    virtual DMAOperationResult PrepareWrite(uint64_t address,
        const void* buffer, DWORD size) = 0;
    virtual DMAOperationResult Execute(bool includesWrites) = 0;
};

class IVmmBackend {
public:
    virtual ~IVmmBackend() = default;

    virtual DMAOperationResult Initialize(const std::vector<std::string>& arguments) = 0;
    virtual void Close() = 0;
    virtual bool IsInitialized() const noexcept = 0;
    virtual VMM_HANDLE NativeHandle() const noexcept { return nullptr; }

    virtual DMAOperationResult InitializePlugins();
    virtual DMAOperationResult ConfigGet(ULONG64 option, uint64_t& value) const;
    virtual DMAOperationResult ConfigSet(ULONG64 option, uint64_t value);

    virtual DMAOperationResult ReadMemory(DWORD pid, uint64_t address,
        void* buffer, DWORD size, ULONG64 flags, DWORD& transferred);
    virtual DMAOperationResult WriteMemory(DWORD pid, uint64_t address,
        const void* buffer, DWORD size);
    virtual DMAOperationResult PrefetchPages(DWORD pid,
        const std::vector<uint64_t>& addresses);
    virtual DMAOperationResult VirtualToPhysical(DWORD pid,
        uint64_t virtualAddress, uint64_t& physicalAddress) const;
    virtual std::unique_ptr<IVmmScatterSession> CreateScatter(
        DWORD pid, DWORD flags);

    virtual DMAOperationResult FindPid(const std::string& name, DWORD& pid) const;
    virtual DMAOperationResult GetProcess(DWORD pid, DMAProcessInfo& process) const;
    virtual DMAOperationResult GetProcesses(std::vector<DMAProcessInfo>& processes) const;
    virtual DMAOperationResult GetPhysicalMemoryMap(
        std::vector<DMAPhysicalMemoryRange>& ranges) const;
    virtual DMAOperationResult GetModule(DWORD pid, const std::string& name,
        DMAModuleInfo& module) const;
    virtual DMAOperationResult GetModules(DWORD pid,
        std::vector<DMAModuleInfo>& modules) const;

    virtual DMAOperationResult GetMemoryRegions(DWORD pid, bool includeVad,
        bool includePte, std::vector<DMAMemoryRegion>& regions) const;
    virtual DMAOperationResult GetSections(DWORD pid, const std::string& module,
        std::vector<DMAModuleSection>& sections) const;
    virtual DMAOperationResult GetExports(DWORD pid, const std::string& module,
        std::vector<DMAExportInfo>& exports) const;
    virtual DMAOperationResult GetImports(DWORD pid, const std::string& module,
        std::vector<DMAImportInfo>& imports) const;

    virtual DMAOperationResult LoadSymbols(DWORD pid, uint64_t moduleBase,
        std::string& symbolModule);
    virtual DMAOperationResult ResolveSymbol(const std::string& symbolModule,
        const std::string& symbol, uint64_t& address) const;
    virtual DMAOperationResult LookupSymbol(const std::string& symbolModule,
        uint64_t addressOrOffset, DMASymbolInfo& symbol) const;
    virtual DMAOperationResult GetTypeSize(const std::string& symbolModule,
        const std::string& typeName, uint32_t& size) const;
    virtual DMAOperationResult GetTypeChildOffset(const std::string& symbolModule,
        const std::string& typeName, const std::string& childName,
        uint32_t& offset) const;

    virtual DMAOperationResult GetRegistryHives(
        std::vector<DMARegistryHiveInfo>& hives) const;
    virtual DMAOperationResult EnumerateRegistryKeys(const std::string& path,
        std::vector<DMARegistryKeyInfo>& keys) const;
    virtual DMAOperationResult EnumerateRegistryValues(const std::string& path,
        std::vector<DMARegistryValue>& values) const;
    virtual DMAOperationResult QueryRegistryValue(const std::string& path,
        DMARegistryValue& value) const;
    virtual DMAOperationResult ReadRegistryHive(uint64_t cmHiveAddress,
        uint32_t relativeAddress, void* buffer, DWORD size, ULONG64 flags,
        DWORD& transferred) const;
    virtual DMAOperationResult WriteRegistryHive(uint64_t cmHiveAddress,
        uint32_t relativeAddress, const void* buffer, DWORD size);

    virtual DMAOperationResult ListVfs(const std::string& path,
        std::vector<DMAVfsEntry>& entries) const;
    virtual DMAOperationResult ReadVfs(const std::string& path, uint64_t offset,
        void* buffer, DWORD size, DWORD& transferred) const;
    virtual DMAOperationResult WriteVfs(const std::string& path, uint64_t offset,
        const void* buffer, DWORD size, DWORD& transferred);
};

class VmmdllBackend final : public IVmmBackend {
public:
    ~VmmdllBackend() override;

    DMAOperationResult Initialize(const std::vector<std::string>& arguments) override;
    void Close() override;
    bool IsInitialized() const noexcept override { return handle_ != nullptr; }
    VMM_HANDLE NativeHandle() const noexcept override { return handle_; }

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
    std::unique_ptr<IVmmScatterSession> CreateScatter(
        DWORD pid, DWORD flags) override;

    DMAOperationResult FindPid(const std::string& name, DWORD& pid) const override;
    DMAOperationResult GetProcess(DWORD pid, DMAProcessInfo& process) const override;
    DMAOperationResult GetProcesses(std::vector<DMAProcessInfo>& processes) const override;
    DMAOperationResult GetPhysicalMemoryMap(
        std::vector<DMAPhysicalMemoryRange>& ranges) const override;
    DMAOperationResult GetModule(DWORD pid, const std::string& name,
        DMAModuleInfo& module) const override;
    DMAOperationResult GetModules(DWORD pid,
        std::vector<DMAModuleInfo>& modules) const override;
    DMAOperationResult GetMemoryRegions(DWORD pid, bool includeVad,
        bool includePte, std::vector<DMAMemoryRegion>& regions) const override;
    DMAOperationResult GetSections(DWORD pid, const std::string& module,
        std::vector<DMAModuleSection>& sections) const override;
    DMAOperationResult GetExports(DWORD pid, const std::string& module,
        std::vector<DMAExportInfo>& exports) const override;
    DMAOperationResult GetImports(DWORD pid, const std::string& module,
        std::vector<DMAImportInfo>& imports) const override;

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
        std::vector<DMARegistryHiveInfo>& hives) const override;
    DMAOperationResult EnumerateRegistryKeys(const std::string& path,
        std::vector<DMARegistryKeyInfo>& keys) const override;
    DMAOperationResult EnumerateRegistryValues(const std::string& path,
        std::vector<DMARegistryValue>& values) const override;
    DMAOperationResult QueryRegistryValue(const std::string& path,
        DMARegistryValue& value) const override;
    DMAOperationResult ReadRegistryHive(uint64_t cmHiveAddress,
        uint32_t relativeAddress, void* buffer, DWORD size, ULONG64 flags,
        DWORD& transferred) const override;
    DMAOperationResult WriteRegistryHive(uint64_t cmHiveAddress,
        uint32_t relativeAddress, const void* buffer, DWORD size) override;

    DMAOperationResult ListVfs(const std::string& path,
        std::vector<DMAVfsEntry>& entries) const override;
    DMAOperationResult ReadVfs(const std::string& path, uint64_t offset,
        void* buffer, DWORD size, DWORD& transferred) const override;
    DMAOperationResult WriteVfs(const std::string& path, uint64_t offset,
        const void* buffer, DWORD size, DWORD& transferred) override;

private:
    VMM_HANDLE handle_ = nullptr;
};

std::shared_ptr<IVmmBackend> CreateVmmdllBackend();
