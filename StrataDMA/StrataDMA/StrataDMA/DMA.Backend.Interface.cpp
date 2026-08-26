#include "DMA.Backend.hpp"

namespace {
DMAOperationResult Unsupported(const char* operation)
{
    return DMAOperationResult::Failure(DMAStatus::Unsupported,
        std::string(operation) + " is not implemented by this backend.");
}
}

#define DMA_BACKEND_UNSUPPORTED(method, signature) \
    DMAOperationResult IVmmBackend::method signature { return Unsupported(#method); }

DMA_BACKEND_UNSUPPORTED(InitializePlugins, ())
DMA_BACKEND_UNSUPPORTED(ConfigGet, (ULONG64, uint64_t&) const)
DMA_BACKEND_UNSUPPORTED(ConfigSet, (ULONG64, uint64_t))
DMA_BACKEND_UNSUPPORTED(ReadMemory, (DWORD, uint64_t, void*, DWORD, ULONG64, DWORD&))
DMA_BACKEND_UNSUPPORTED(WriteMemory, (DWORD, uint64_t, const void*, DWORD))
DMA_BACKEND_UNSUPPORTED(PrefetchPages, (DWORD, const std::vector<uint64_t>&))
DMA_BACKEND_UNSUPPORTED(VirtualToPhysical, (DWORD, uint64_t, uint64_t&) const)
DMA_BACKEND_UNSUPPORTED(FindPid, (const std::string&, DWORD&) const)
DMA_BACKEND_UNSUPPORTED(GetProcess, (DWORD, DMAProcessInfo&) const)
DMA_BACKEND_UNSUPPORTED(GetProcesses, (std::vector<DMAProcessInfo>&) const)
DMA_BACKEND_UNSUPPORTED(GetPhysicalMemoryMap, (std::vector<DMAPhysicalMemoryRange>&) const)
DMA_BACKEND_UNSUPPORTED(GetModule, (DWORD, const std::string&, DMAModuleInfo&) const)
DMA_BACKEND_UNSUPPORTED(GetModules, (DWORD, std::vector<DMAModuleInfo>&) const)
DMA_BACKEND_UNSUPPORTED(GetMemoryRegions, (DWORD, bool, bool, std::vector<DMAMemoryRegion>&) const)
DMA_BACKEND_UNSUPPORTED(GetSections, (DWORD, const std::string&, std::vector<DMAModuleSection>&) const)
DMA_BACKEND_UNSUPPORTED(GetExports, (DWORD, const std::string&, std::vector<DMAExportInfo>&) const)
DMA_BACKEND_UNSUPPORTED(GetImports, (DWORD, const std::string&, std::vector<DMAImportInfo>&) const)
DMA_BACKEND_UNSUPPORTED(LoadSymbols, (DWORD, uint64_t, std::string&))
DMA_BACKEND_UNSUPPORTED(ResolveSymbol, (const std::string&, const std::string&, uint64_t&) const)
DMA_BACKEND_UNSUPPORTED(LookupSymbol, (const std::string&, uint64_t, DMASymbolInfo&) const)
DMA_BACKEND_UNSUPPORTED(GetTypeSize, (const std::string&, const std::string&, uint32_t&) const)
DMA_BACKEND_UNSUPPORTED(GetTypeChildOffset, (const std::string&, const std::string&, const std::string&, uint32_t&) const)
DMA_BACKEND_UNSUPPORTED(GetRegistryHives, (std::vector<DMARegistryHiveInfo>&) const)
DMA_BACKEND_UNSUPPORTED(EnumerateRegistryKeys, (const std::string&, std::vector<DMARegistryKeyInfo>&) const)
DMA_BACKEND_UNSUPPORTED(EnumerateRegistryValues, (const std::string&, std::vector<DMARegistryValue>&) const)
DMA_BACKEND_UNSUPPORTED(QueryRegistryValue, (const std::string&, DMARegistryValue&) const)
DMA_BACKEND_UNSUPPORTED(ReadRegistryHive, (uint64_t, uint32_t, void*, DWORD, ULONG64, DWORD&) const)
DMA_BACKEND_UNSUPPORTED(WriteRegistryHive, (uint64_t, uint32_t, const void*, DWORD))
DMA_BACKEND_UNSUPPORTED(ListVfs, (const std::string&, std::vector<DMAVfsEntry>&) const)
DMA_BACKEND_UNSUPPORTED(ReadVfs, (const std::string&, uint64_t, void*, DWORD, DWORD&) const)
DMA_BACKEND_UNSUPPORTED(WriteVfs, (const std::string&, uint64_t, const void*, DWORD, DWORD&))

#undef DMA_BACKEND_UNSUPPORTED

std::unique_ptr<IVmmScatterSession> IVmmBackend::CreateScatter(DWORD, DWORD)
{
    return {};
}
