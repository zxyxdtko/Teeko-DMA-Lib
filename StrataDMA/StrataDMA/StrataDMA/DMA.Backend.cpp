#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "DMA.Backend.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <utility>

namespace {
DMAOperationResult BackendFailure(const char* operation)
{
    return DMAOperationResult::Failure(DMAStatus::BackendError,
        std::string(operation) + " failed.");
}

DMAOperationResult NotInitialized()
{
    return DMAOperationResult::Failure(DMAStatus::NotInitialized,
        "The VMMDLL backend is not initialized.");
}

std::string CopyString(const char* value)
{
    return value ? value : "";
}

size_t BoundedStringLength(const char* value, size_t capacity)
{
    return static_cast<size_t>(
        std::find(value, value + capacity, '\0') - value);
}

DMAProcessInfo CopyProcessInfo(const VMMDLL_PROCESS_INFORMATION& native)
{
    DMAProcessInfo process;
    process.pid = native.dwPID;
    process.parentPid = native.dwPPID;
    process.state = native.dwState;
    process.sessionId = native.win.dwSessionId;
    process.dtb = native.paDTB;
    process.userDtb = native.paDTB_UserOpt;
    process.eprocessAddress = native.win.vaEPROCESS;
    process.pebAddress = native.win.vaPEB;
    process.wow64PebAddress = native.win.vaPEB32;
    process.luid = native.win.qwLUID;
    process.wow64 = native.win.fWow64 != FALSE;
    process.userOnly = native.fUserOnly != FALSE;
    process.memoryModel = native.tpMemoryModel;
    process.systemType = native.tpSystem;
    process.integrityLevel = native.win.IntegrityLevel;
    process.name = native.szName;
    process.longName = native.szNameLong;
    process.sid = native.win.szSID;
    return process;
}

bool VadReadable(DWORD protection)
{
    const DWORD base = protection & 7;
    return base == 1 || base == 3 || base == 4 || base == 5 ||
        base == 6 || base == 7;
}

bool VadWritable(DWORD protection)
{
    const DWORD base = protection & 7;
    return base == 4 || base == 5 || base == 6 || base == 7;
}

bool VadExecutable(DWORD protection)
{
    const DWORD base = protection & 7;
    return base == 2 || base == 3 || base == 6 || base == 7;
}

class VmmdllScatterSession final : public IVmmScatterSession {
public:
    explicit VmmdllScatterSession(VMMDLL_SCATTER_HANDLE handle)
        : handle_(handle) {}

    ~VmmdllScatterSession() override
    {
        if (handle_)
            VMMDLL_Scatter_CloseHandle(handle_);
    }

    DMAOperationResult PrepareRead(uint64_t address, void* buffer,
        DWORD size, DWORD* transferred) override
    {
        if (!handle_)
            return NotInitialized();
        if (!buffer || !transferred || size == 0 || address == 0)
            return DMAOperationResult::Failure(DMAStatus::InvalidArgument,
                "Invalid scatter-read request.");
        if (!VMMDLL_Scatter_PrepareEx(handle_, address, size,
            static_cast<PBYTE>(buffer), transferred)) {
            return BackendFailure("VMMDLL_Scatter_PrepareEx");
        }
        auto result = DMAOperationResult::Success();
        result.requestedBytes = size;
        result.address = address;
        return result;
    }

    DMAOperationResult PrepareWrite(uint64_t address, const void* buffer,
        DWORD size) override
    {
        if (!handle_)
            return NotInitialized();
        if (!buffer || size == 0 || address == 0)
            return DMAOperationResult::Failure(DMAStatus::InvalidArgument,
                "Invalid scatter-write request.");
        if (!VMMDLL_Scatter_PrepareWrite(handle_, address,
            const_cast<PBYTE>(static_cast<const BYTE*>(buffer)), size)) {
            return BackendFailure("VMMDLL_Scatter_PrepareWrite");
        }
        auto result = DMAOperationResult::Success();
        result.requestedBytes = size;
        result.address = address;
        return result;
    }

    DMAOperationResult Execute(bool includesWrites) override
    {
        if (!handle_)
            return NotInitialized();
        const BOOL success = includesWrites
            ? VMMDLL_Scatter_Execute(handle_)
            : VMMDLL_Scatter_ExecuteRead(handle_);
        return success ? DMAOperationResult::Success()
            : BackendFailure("VMMDLL scatter execution");
    }

private:
    VMMDLL_SCATTER_HANDLE handle_ = nullptr;
};
}

VmmdllBackend::~VmmdllBackend()
{
    Close();
}

DMAOperationResult VmmdllBackend::Initialize(
    const std::vector<std::string>& arguments)
{
    Close();
    if (arguments.empty())
        return DMAOperationResult::Failure(DMAStatus::InvalidArgument,
            "VMMDLL initialization requires at least argv[0].");

    std::vector<LPCSTR> argv;
    argv.reserve(arguments.size());
    for (const auto& argument : arguments)
        argv.push_back(argument.c_str());

    PLC_CONFIG_ERRORINFO errorInfo = nullptr;
    handle_ = VMMDLL_InitializeEx(static_cast<DWORD>(argv.size()), argv.data(),
        &errorInfo);
    std::string detail;
    if (errorInfo && errorInfo->cwszUserText != 0) {
        detail.reserve(errorInfo->cwszUserText);
        for (DWORD index = 0; index < errorInfo->cwszUserText; ++index) {
            const wchar_t value = errorInfo->wszUserText[index];
            if (value == L'\0')
                break;
            detail.push_back(value <= 0x7f ? static_cast<char>(value) : '?');
        }
    }
    if (errorInfo)
        LcMemFree(errorInfo);
    if (!handle_)
        return DMAOperationResult::Failure(DMAStatus::BackendError,
            detail.empty() ? "VMMDLL_InitializeEx failed." : detail);
    return DMAOperationResult::Success();
}

void VmmdllBackend::Close()
{
    if (handle_) {
        VMMDLL_Close(handle_);
        handle_ = nullptr;
    }
}

DMAOperationResult VmmdllBackend::InitializePlugins()
{
    if (!handle_)
        return NotInitialized();
    return VMMDLL_InitializePlugins(handle_) ? DMAOperationResult::Success()
        : BackendFailure("VMMDLL_InitializePlugins");
}

DMAOperationResult VmmdllBackend::ConfigGet(ULONG64 option, uint64_t& value) const
{
    value = 0;
    if (!handle_)
        return NotInitialized();
    ULONG64 nativeValue = 0;
    if (!VMMDLL_ConfigGet(handle_, option, &nativeValue))
        return BackendFailure("VMMDLL_ConfigGet");
    value = static_cast<uint64_t>(nativeValue);
    return DMAOperationResult::Success();
}

DMAOperationResult VmmdllBackend::ConfigSet(ULONG64 option, uint64_t value)
{
    if (!handle_)
        return NotInitialized();
    return VMMDLL_ConfigSet(handle_, option, value)
        ? DMAOperationResult::Success() : BackendFailure("VMMDLL_ConfigSet");
}

DMAOperationResult VmmdllBackend::ReadMemory(DWORD pid, uint64_t address,
    void* buffer, DWORD size, ULONG64 flags, DWORD& transferred)
{
    transferred = 0;
    if (!handle_)
        return NotInitialized();
    if (!buffer || size == 0 || address == 0)
        return DMAOperationResult::Failure(DMAStatus::InvalidArgument,
            "Invalid memory-read request.");
    const BOOL success = VMMDLL_MemReadEx(handle_, pid, address,
        static_cast<PBYTE>(buffer), size, &transferred, flags);
    DMAOperationResult result;
    result.status = success && transferred == size ? DMAStatus::Success
        : success ? DMAStatus::PartialTransfer : DMAStatus::BackendError;
    result.requestedBytes = size;
    result.transferredBytes = transferred;
    result.address = address;
    result.pid = pid;
    result.flags = flags;
    if (!result)
        result.message = success ? "The memory read returned partial data."
            : "VMMDLL_MemReadEx failed.";
    return result;
}

DMAOperationResult VmmdllBackend::WriteMemory(DWORD pid, uint64_t address,
    const void* buffer, DWORD size)
{
    if (!handle_)
        return NotInitialized();
    if (!buffer || size == 0 || address == 0)
        return DMAOperationResult::Failure(DMAStatus::InvalidArgument,
            "Invalid memory-write request.");
    DMAOperationResult result;
    result.status = VMMDLL_MemWrite(handle_, pid, address,
        const_cast<PBYTE>(static_cast<const BYTE*>(buffer)), size)
        ? DMAStatus::Success : DMAStatus::BackendError;
    result.requestedBytes = size;
    result.transferredBytes = result ? size : 0;
    result.address = address;
    result.pid = pid;
    if (!result)
        result.message = "VMMDLL_MemWrite failed.";
    return result;
}

DMAOperationResult VmmdllBackend::PrefetchPages(DWORD pid,
    const std::vector<uint64_t>& addresses)
{
    if (!handle_)
        return NotInitialized();
    if (addresses.empty() || addresses.size() > std::numeric_limits<DWORD>::max())
        return DMAOperationResult::Failure(DMAStatus::InvalidArgument,
            "Prefetch requires one or more addresses.");
    std::vector<ULONG64> nativeAddresses(addresses.begin(), addresses.end());
    return VMMDLL_MemPrefetchPages(handle_, pid, nativeAddresses.data(),
        static_cast<DWORD>(nativeAddresses.size()))
        ? DMAOperationResult::Success() : BackendFailure("VMMDLL_MemPrefetchPages");
}

DMAOperationResult VmmdllBackend::VirtualToPhysical(DWORD pid,
    uint64_t virtualAddress, uint64_t& physicalAddress) const
{
    physicalAddress = 0;
    if (!handle_)
        return NotInitialized();
    ULONG64 nativeAddress = 0;
    if (!VMMDLL_MemVirt2Phys(handle_, pid, virtualAddress, &nativeAddress))
        return BackendFailure("VMMDLL_MemVirt2Phys");
    physicalAddress = static_cast<uint64_t>(nativeAddress);
    return DMAOperationResult::Success();
}

std::unique_ptr<IVmmScatterSession> VmmdllBackend::CreateScatter(
    DWORD pid, DWORD flags)
{
    if (!handle_)
        return {};
    auto handle = VMMDLL_Scatter_Initialize(handle_, pid, flags);
    return handle ? std::make_unique<VmmdllScatterSession>(handle) : nullptr;
}

DMAOperationResult VmmdllBackend::FindPid(const std::string& name,
    DWORD& pid) const
{
    pid = 0;
    if (!handle_)
        return NotInitialized();
    return VMMDLL_PidGetFromName(handle_, name.c_str(), &pid)
        ? DMAOperationResult::Success()
        : DMAOperationResult::Failure(DMAStatus::NotFound,
            "The requested process was not found.");
}

DMAOperationResult VmmdllBackend::GetProcess(DWORD pid,
    DMAProcessInfo& process) const
{
    process = {};
    if (!handle_)
        return NotInitialized();
    VMMDLL_PROCESS_INFORMATION native{};
    native.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
    native.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
    native.wSize = sizeof(native);
    SIZE_T size = sizeof(native);
    if (!VMMDLL_ProcessGetInformation(handle_, pid, &native, &size))
        return DMAOperationResult::Failure(DMAStatus::NotFound,
            "Process information was unavailable.");
    process = CopyProcessInfo(native);
    return DMAOperationResult::Success();
}

DMAOperationResult VmmdllBackend::GetProcesses(
    std::vector<DMAProcessInfo>& processes) const
{
    processes.clear();
    if (!handle_)
        return NotInitialized();
    PVMMDLL_PROCESS_INFORMATION native = nullptr;
    DWORD count = 0;
    if (!VMMDLL_ProcessGetInformationAll(handle_, &native, &count) || !native)
        return BackendFailure("VMMDLL_ProcessGetInformationAll");
    processes.reserve(count);
    for (DWORD index = 0; index < count; ++index) {
        processes.push_back(CopyProcessInfo(native[index]));
    }
    VMMDLL_MemFree(native);
    return DMAOperationResult::Success();
}

DMAOperationResult VmmdllBackend::GetPhysicalMemoryMap(
    std::vector<DMAPhysicalMemoryRange>& ranges) const
{
    ranges.clear();
    if (!handle_)
        return NotInitialized();
    PVMMDLL_MAP_PHYSMEM native = nullptr;
    if (!VMMDLL_Map_GetPhysMem(handle_, &native) || !native)
        return BackendFailure("VMMDLL_Map_GetPhysMem");
    if (native->dwVersion != VMMDLL_MAP_PHYSMEM_VERSION) {
        VMMDLL_MemFree(native);
        return DMAOperationResult::Failure(DMAStatus::ParseError,
            "VMMDLL returned an unsupported physical-memory-map version.");
    }
    ranges.reserve(native->cMap);
    for (DWORD index = 0; index < native->cMap; ++index) {
        const auto& entry = native->pMap[index];
        if (entry.cb != 0)
            ranges.push_back({ entry.pa, entry.cb });
    }
    VMMDLL_MemFree(native);
    return DMAOperationResult::Success(ranges.size());
}

DMAOperationResult VmmdllBackend::GetModule(DWORD pid, const std::string& name,
    DMAModuleInfo& module) const
{
    module = {};
    if (!handle_)
        return NotInitialized();
    PVMMDLL_MAP_MODULEENTRY native = nullptr;
    const char* requested = name.empty() ? nullptr : name.c_str();
    if (!VMMDLL_Map_GetModuleFromNameU(handle_, pid, requested, &native, 0) ||
        !native) {
        return DMAOperationResult::Failure(DMAStatus::NotFound,
            "The requested module was not found.");
    }
    module.baseAddress = native->vaBase;
    module.entryPoint = native->vaEntry;
    module.imageSize = native->cbImageSize;
    module.rawFileSize = native->cbFileSizeRaw;
    module.wow64 = native->fWoW64 != FALSE;
    module.name = CopyString(native->uszText);
    module.fullName = CopyString(native->uszFullName);
    VMMDLL_MemFree(native);
    return DMAOperationResult::Success();
}

DMAOperationResult VmmdllBackend::GetModules(DWORD pid,
    std::vector<DMAModuleInfo>& modules) const
{
    modules.clear();
    if (!handle_)
        return NotInitialized();
    PVMMDLL_MAP_MODULE native = nullptr;
    if (!VMMDLL_Map_GetModuleU(handle_, pid, &native, 0) || !native)
        return BackendFailure("VMMDLL_Map_GetModuleU");
    modules.reserve(native->cMap);
    for (DWORD index = 0; index < native->cMap; ++index) {
        const auto& entry = native->pMap[index];
        DMAModuleInfo module;
        module.baseAddress = entry.vaBase;
        module.entryPoint = entry.vaEntry;
        module.imageSize = entry.cbImageSize;
        module.rawFileSize = entry.cbFileSizeRaw;
        module.wow64 = entry.fWoW64 != FALSE;
        module.name = CopyString(entry.uszText);
        module.fullName = CopyString(entry.uszFullName);
        modules.push_back(std::move(module));
    }
    VMMDLL_MemFree(native);
    return DMAOperationResult::Success();
}

DMAOperationResult VmmdllBackend::GetMemoryRegions(DWORD pid, bool includeVad,
    bool includePte, std::vector<DMAMemoryRegion>& regions) const
{
    regions.clear();
    if (!handle_)
        return NotInitialized();

    if (includeVad) {
        PVMMDLL_MAP_VAD map = nullptr;
        if (!VMMDLL_Map_GetVadU(handle_, pid, TRUE, &map) || !map)
            return BackendFailure("VMMDLL_Map_GetVadU");
        for (DWORD index = 0; index < map->cMap; ++index) {
            const auto& entry = map->pMap[index];
            if (entry.vaEnd < entry.vaStart ||
                entry.vaEnd == std::numeric_limits<uint64_t>::max())
                continue;
            DMAMemoryRegion region;
            region.baseAddress = entry.vaStart;
            region.size = entry.vaEnd - entry.vaStart + 1;
            region.protection = entry.Protection;
            region.source = DMAMemoryRegionSource::Vad;
            region.readable = VadReadable(entry.Protection);
            region.writable = VadWritable(entry.Protection);
            region.executable = VadExecutable(entry.Protection);
            region.committed = entry.MemCommit != 0;
            region.privateMemory = entry.fPrivateMemory != 0;
            region.image = entry.fImage != 0;
            region.mappedFile = entry.fFile != 0;
            region.stack = entry.fStack != 0;
            region.heap = entry.fHeap != 0;
            region.teb = entry.fTeb != 0;
            region.name = CopyString(entry.uszText);
            regions.push_back(std::move(region));
        }
        VMMDLL_MemFree(map);
    }

    if (includePte) {
        PVMMDLL_MAP_PTE map = nullptr;
        if (!VMMDLL_Map_GetPteU(handle_, pid, TRUE, &map) || !map)
            return BackendFailure("VMMDLL_Map_GetPteU");
        for (DWORD index = 0; index < map->cMap; ++index) {
            const auto& entry = map->pMap[index];
            if (entry.cPages > std::numeric_limits<uint64_t>::max() / 0x1000)
                continue;
            DMAMemoryRegion region;
            region.baseAddress = entry.vaBase;
            region.size = entry.cPages * 0x1000;
            region.pageFlags = entry.fPage;
            region.source = DMAMemoryRegionSource::Pte;
            region.readable = true;
            region.writable = (entry.fPage & VMMDLL_MEMMAP_FLAG_PAGE_W) != 0;
            region.executable = (entry.fPage & VMMDLL_MEMMAP_FLAG_PAGE_NX) == 0;
            region.committed = entry.cPages > entry.cSoftware;
            region.wow64 = entry.fWoW64 != FALSE;
            region.name = CopyString(entry.uszText);
            regions.push_back(std::move(region));
        }
        VMMDLL_MemFree(map);
    }
    return DMAOperationResult::Success();
}

DMAOperationResult VmmdllBackend::GetSections(DWORD pid,
    const std::string& module, std::vector<DMAModuleSection>& sections) const
{
    sections.clear();
    if (!handle_)
        return NotInitialized();
    DWORD count = 0;
    if (!VMMDLL_ProcessGetSectionsU(handle_, pid, module.c_str(), nullptr, 0,
        &count) || count == 0) {
        return BackendFailure("VMMDLL_ProcessGetSectionsU(size)");
    }
    std::vector<IMAGE_SECTION_HEADER> native(count);
    if (!VMMDLL_ProcessGetSectionsU(handle_, pid, module.c_str(), native.data(),
        count, &count)) {
        return BackendFailure("VMMDLL_ProcessGetSectionsU(data)");
    }
    native.resize(count);
    DMAModuleInfo moduleInfo;
    auto moduleResult = GetModule(pid, module, moduleInfo);
    if (!moduleResult)
        return moduleResult;
    sections.reserve(count);
    for (const auto& entry : native) {
        DMAModuleSection section;
        char name[IMAGE_SIZEOF_SHORT_NAME + 1]{};
        std::memcpy(name, entry.Name, IMAGE_SIZEOF_SHORT_NAME);
        section.name = name;
        section.address = moduleInfo.baseAddress + entry.VirtualAddress;
        section.virtualSize = entry.Misc.VirtualSize;
        section.rawSize = entry.SizeOfRawData;
        section.characteristics = entry.Characteristics;
        section.readable = (entry.Characteristics & IMAGE_SCN_MEM_READ) != 0;
        section.writable = (entry.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        section.executable = (entry.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        sections.push_back(std::move(section));
    }
    return DMAOperationResult::Success();
}

DMAOperationResult VmmdllBackend::GetExports(DWORD pid,
    const std::string& module, std::vector<DMAExportInfo>& exports) const
{
    exports.clear();
    if (!handle_)
        return NotInitialized();
    PVMMDLL_MAP_EAT map = nullptr;
    if (!VMMDLL_Map_GetEATU(handle_, pid, module.c_str(), &map) || !map)
        return BackendFailure("VMMDLL_Map_GetEATU");
    exports.reserve(map->cMap);
    for (DWORD index = 0; index < map->cMap; ++index) {
        DMAExportInfo entry;
        entry.name = CopyString(map->pMap[index].uszFunction);
        entry.forwardedName = CopyString(map->pMap[index].uszForwardedFunction);
        entry.address = map->pMap[index].vaFunction;
        entry.ordinal = map->pMap[index].dwOrdinal;
        entry.forwarded = !entry.forwardedName.empty();
        exports.push_back(std::move(entry));
    }
    VMMDLL_MemFree(map);
    return DMAOperationResult::Success();
}

DMAOperationResult VmmdllBackend::GetImports(DWORD pid,
    const std::string& module, std::vector<DMAImportInfo>& imports) const
{
    imports.clear();
    if (!handle_)
        return NotInitialized();
    PVMMDLL_MAP_IAT map = nullptr;
    if (!VMMDLL_Map_GetIATU(handle_, pid, module.c_str(), &map) || !map)
        return BackendFailure("VMMDLL_Map_GetIATU");
    imports.reserve(map->cMap);
    for (DWORD index = 0; index < map->cMap; ++index) {
        DMAImportInfo entry;
        entry.module = CopyString(map->pMap[index].uszModule);
        entry.name = CopyString(map->pMap[index].uszFunction);
        entry.address = map->pMap[index].vaFunction;
        entry.firstThunkRva = map->pMap[index].Thunk.rvaFirstThunk;
        entry.nameRva = map->pMap[index].Thunk.rvaNameFunction;
        entry.hint = map->pMap[index].Thunk.wHint;
        entry.is32Bit = map->pMap[index].Thunk.f32 != FALSE;
        imports.push_back(std::move(entry));
    }
    VMMDLL_MemFree(map);
    return DMAOperationResult::Success();
}

DMAOperationResult VmmdllBackend::LoadSymbols(DWORD pid, uint64_t moduleBase,
    std::string& symbolModule)
{
    symbolModule.clear();
    if (!handle_)
        return NotInitialized();
    char name[MAX_PATH]{};
    if (!VMMDLL_PdbLoad(handle_, pid, moduleBase, name))
        return BackendFailure("VMMDLL_PdbLoad");
    symbolModule = name;
    return DMAOperationResult::Success();
}

DMAOperationResult VmmdllBackend::ResolveSymbol(const std::string& symbolModule,
    const std::string& symbol, uint64_t& address) const
{
    address = 0;
    if (!handle_)
        return NotInitialized();
    ULONG64 nativeAddress = 0;
    if (!VMMDLL_PdbSymbolAddress(handle_, symbolModule.c_str(), symbol.c_str(),
        &nativeAddress)) {
        return DMAOperationResult::Failure(DMAStatus::NotFound,
            "The PDB symbol was not found.");
    }
    address = static_cast<uint64_t>(nativeAddress);
    return DMAOperationResult::Success();
}

DMAOperationResult VmmdllBackend::LookupSymbol(const std::string& symbolModule,
    uint64_t addressOrOffset, DMASymbolInfo& symbol) const
{
    symbol = {};
    if (!handle_)
        return NotInitialized();
    char name[MAX_PATH]{};
    DWORD displacement = 0;
    if (!VMMDLL_PdbSymbolName(handle_, symbolModule.c_str(), addressOrOffset,
        name, &displacement)) {
        return DMAOperationResult::Failure(DMAStatus::NotFound,
            "No PDB symbol contains the requested address.");
    }
    symbol.module = symbolModule;
    symbol.name = name;
    symbol.address = addressOrOffset - displacement;
    symbol.displacement = displacement;
    return DMAOperationResult::Success();
}

DMAOperationResult VmmdllBackend::GetTypeSize(const std::string& symbolModule,
    const std::string& typeName, uint32_t& size) const
{
    size = 0;
    if (!handle_)
        return NotInitialized();
    DWORD nativeSize = 0;
    if (!VMMDLL_PdbTypeSize(handle_, symbolModule.c_str(), typeName.c_str(),
        &nativeSize)) {
        return DMAOperationResult::Failure(DMAStatus::NotFound,
            "The PDB type was not found.");
    }
    size = nativeSize;
    return DMAOperationResult::Success();
}

DMAOperationResult VmmdllBackend::GetTypeChildOffset(
    const std::string& symbolModule, const std::string& typeName,
    const std::string& childName, uint32_t& offset) const
{
    offset = 0;
    if (!handle_)
        return NotInitialized();
    DWORD nativeOffset = 0;
    if (!VMMDLL_PdbTypeChildOffset(handle_, symbolModule.c_str(),
        typeName.c_str(), childName.c_str(), &nativeOffset)) {
        return DMAOperationResult::Failure(DMAStatus::NotFound,
            "The PDB type child was not found.");
    }
    offset = nativeOffset;
    return DMAOperationResult::Success();
}

DMAOperationResult VmmdllBackend::GetRegistryHives(
    std::vector<DMARegistryHiveInfo>& hives) const
{
    hives.clear();
    if (!handle_)
        return NotInitialized();
    DWORD count = 0;
    if (!VMMDLL_WinReg_HiveList(handle_, nullptr, 0, &count))
        return BackendFailure("VMMDLL_WinReg_HiveList(size)");
    std::vector<VMMDLL_REGISTRY_HIVE_INFORMATION> native(count);
    for (auto& hive : native) {
        hive.magic = VMMDLL_REGISTRY_HIVE_INFORMATION_MAGIC;
        hive.wVersion = VMMDLL_REGISTRY_HIVE_INFORMATION_VERSION;
        hive.wSize = sizeof(hive);
    }
    DWORD readCount = 0;
    if (!VMMDLL_WinReg_HiveList(handle_, native.data(), count, &readCount))
        return BackendFailure("VMMDLL_WinReg_HiveList(data)");
    hives.reserve(readCount);
    for (DWORD index = 0; index < readCount; ++index) {
        DMARegistryHiveInfo hive;
        hive.cmHiveAddress = native[index].vaCMHIVE;
        hive.baseBlockAddress = native[index].vaHBASE_BLOCK;
        hive.length = native[index].cbLength;
        hive.name = native[index].uszName;
        hive.shortName = native[index].uszNameShort;
        hive.rootPath = native[index].uszHiveRootPath;
        hives.push_back(std::move(hive));
    }
    return DMAOperationResult::Success();
}

DMAOperationResult VmmdllBackend::EnumerateRegistryKeys(const std::string& path,
    std::vector<DMARegistryKeyInfo>& keys) const
{
    keys.clear();
    if (!handle_)
        return NotInitialized();
    for (DWORD index = 0;; ++index) {
        std::vector<char> name(32768, 0);
        DWORD chars = static_cast<DWORD>(name.size());
        FILETIME time{};
        if (!VMMDLL_WinReg_EnumKeyExU(handle_, path.c_str(), index, name.data(),
            &chars, &time))
            break;
        DMARegistryKeyInfo key;
        key.name = name.data();
#ifdef _WIN32
        key.lastWriteTime = (static_cast<uint64_t>(time.dwHighDateTime) << 32) |
            time.dwLowDateTime;
#else
        key.lastWriteTime = static_cast<uint64_t>(time);
#endif
        keys.push_back(std::move(key));
    }
    return DMAOperationResult::Success();
}

DMAOperationResult VmmdllBackend::EnumerateRegistryValues(
    const std::string& path, std::vector<DMARegistryValue>& values) const
{
    values.clear();
    if (!handle_)
        return NotInitialized();
    for (DWORD index = 0;; ++index) {
        std::vector<char> name(32768, 0);
        DWORD nameChars = static_cast<DWORD>(name.size());
        DWORD dataSize = 0;
        DWORD type = 0;
        if (!VMMDLL_WinReg_EnumValueU(handle_, path.c_str(), index, name.data(),
            &nameChars, &type, nullptr, &dataSize))
            break;
        std::vector<uint8_t> data(dataSize);
        DWORD nameCapacity = static_cast<DWORD>(name.size());
        DWORD dataCapacity = dataSize;
        if (!VMMDLL_WinReg_EnumValueU(handle_, path.c_str(), index, name.data(),
            &nameCapacity, &type, data.empty() ? nullptr : data.data(),
            &dataCapacity)) {
            return BackendFailure("VMMDLL_WinReg_EnumValueU(data)");
        }
        data.resize(dataCapacity);
        DMARegistryValue value;
        value.name = name.data();
        value.type = type;
        value.data = std::move(data);
        values.push_back(std::move(value));
    }
    return DMAOperationResult::Success();
}

DMAOperationResult VmmdllBackend::QueryRegistryValue(const std::string& path,
    DMARegistryValue& value) const
{
    value = {};
    if (!handle_)
        return NotInitialized();
    DWORD size = 0;
    DWORD type = 0;
    if (!VMMDLL_WinReg_QueryValueExU(handle_, path.c_str(), &type, nullptr,
        &size)) {
        return DMAOperationResult::Failure(DMAStatus::NotFound,
            "The registry value was not found.");
    }
    value.type = type;
    value.data.resize(size);
    if (size != 0 && !VMMDLL_WinReg_QueryValueExU(handle_, path.c_str(), &type,
        value.data.data(), &size)) {
        value = {};
        return BackendFailure("VMMDLL_WinReg_QueryValueExU(data)");
    }
    value.type = type;
    value.data.resize(size);
    const auto separator = path.find_last_of("\\/");
    value.name = separator == std::string::npos ? path : path.substr(separator + 1);
    return DMAOperationResult::Success();
}

DMAOperationResult VmmdllBackend::ReadRegistryHive(uint64_t cmHiveAddress,
    uint32_t relativeAddress, void* buffer, DWORD size, ULONG64 flags,
    DWORD& transferred) const
{
    transferred = 0;
    if (!handle_)
        return NotInitialized();
    if (!buffer || size == 0)
        return DMAOperationResult::Failure(DMAStatus::InvalidArgument,
            "Invalid registry-hive read request.");
    const BOOL success = VMMDLL_WinReg_HiveReadEx(handle_, cmHiveAddress,
        relativeAddress, static_cast<PBYTE>(buffer), size, &transferred, flags);
    DMAOperationResult result;
    result.status = success && transferred == size ? DMAStatus::Success
        : success ? DMAStatus::PartialTransfer : DMAStatus::BackendError;
    result.requestedBytes = size;
    result.transferredBytes = transferred;
    result.address = relativeAddress;
    result.flags = flags;
    if (!result)
        result.message = success ? "The registry-hive read was partial."
            : "VMMDLL_WinReg_HiveReadEx failed.";
    return result;
}

DMAOperationResult VmmdllBackend::WriteRegistryHive(uint64_t cmHiveAddress,
    uint32_t relativeAddress, const void* buffer, DWORD size)
{
    if (!handle_)
        return NotInitialized();
    if (!buffer || size == 0)
        return DMAOperationResult::Failure(DMAStatus::InvalidArgument,
            "Invalid registry-hive write request.");
    return VMMDLL_WinReg_HiveWrite(handle_, cmHiveAddress, relativeAddress,
        const_cast<PBYTE>(static_cast<const BYTE*>(buffer)), size)
        ? DMAOperationResult::Success(size)
        : BackendFailure("VMMDLL_WinReg_HiveWrite");
}

DMAOperationResult VmmdllBackend::ListVfs(const std::string& path,
    std::vector<DMAVfsEntry>& entries) const
{
    entries.clear();
    if (!handle_)
        return NotInitialized();
    PVMMDLL_VFS_FILELISTBLOB blob = VMMDLL_VfsListBlobU(handle_, path.c_str());
    if (!blob)
        return DMAOperationResult::Failure(DMAStatus::NotFound,
            "The VFS directory was not found or plugins are unavailable.");
    if (blob->dwVersion != VMMDLL_VFS_FILELISTBLOB_VERSION) {
        VMMDLL_MemFree(blob);
        return DMAOperationResult::Failure(DMAStatus::BackendError,
            "Unexpected VMMDLL VFS list version.");
    }
    entries.reserve(blob->cFileEntry);
    for (DWORD index = 0; index < blob->cFileEntry; ++index) {
        const auto& native = blob->FileEntry[index];
        if (native.ouszName >= blob->cbMultiText)
            continue;
        DMAVfsEntry entry;
        const char* name = blob->uszMultiText + native.ouszName;
        const size_t remaining = blob->cbMultiText -
            static_cast<size_t>(native.ouszName);
        entry.name.assign(name, BoundedStringLength(name, remaining));
        entry.directory = native.cbFileSize == std::numeric_limits<uint64_t>::max();
        entry.size = entry.directory ? 0 : native.cbFileSize;
        if (native.ExInfo.dwVersion == VMMDLL_VFS_FILELIST_EXINFO_VERSION) {
            entry.compressed = native.ExInfo.fCompressed != FALSE;
            entry.creationTime = native.ExInfo.qwCreationTime;
            entry.lastAccessTime = native.ExInfo.qwLastAccessTime;
            entry.lastWriteTime = native.ExInfo.qwLastWriteTime;
        }
        entries.push_back(std::move(entry));
    }
    VMMDLL_MemFree(blob);
    return DMAOperationResult::Success();
}

DMAOperationResult VmmdllBackend::ReadVfs(const std::string& path,
    uint64_t offset, void* buffer, DWORD size, DWORD& transferred) const
{
    transferred = 0;
    if (!handle_)
        return NotInitialized();
    if (!buffer || size == 0)
        return DMAOperationResult::Failure(DMAStatus::InvalidArgument,
            "Invalid VFS read request.");
    const NTSTATUS status = VMMDLL_VfsReadU(handle_, path.c_str(),
        static_cast<PBYTE>(buffer), size, &transferred, offset);
    DMAOperationResult result;
    result.requestedBytes = size;
    result.transferredBytes = transferred;
    result.address = offset;
    if (status == VMMDLL_STATUS_SUCCESS || status == VMMDLL_STATUS_END_OF_FILE) {
        result.status = DMAStatus::Success;
    }
    else if (status == VMMDLL_STATUS_FILE_INVALID) {
        result.status = DMAStatus::NotFound;
        result.message = "The VFS file was not found.";
    }
    else {
        result.status = DMAStatus::IoError;
        result.message = "VMMDLL_VfsReadU failed.";
    }
    return result;
}

DMAOperationResult VmmdllBackend::WriteVfs(const std::string& path,
    uint64_t offset, const void* buffer, DWORD size, DWORD& transferred)
{
    transferred = 0;
    if (!handle_)
        return NotInitialized();
    if (!buffer || size == 0)
        return DMAOperationResult::Failure(DMAStatus::InvalidArgument,
            "Invalid VFS write request.");
    const NTSTATUS status = VMMDLL_VfsWriteU(handle_, path.c_str(),
        const_cast<PBYTE>(static_cast<const BYTE*>(buffer)), size, &transferred,
        offset);
    DMAOperationResult result;
    result.status = status == VMMDLL_STATUS_SUCCESS && transferred == size
        ? DMAStatus::Success
        : status == VMMDLL_STATUS_SUCCESS ? DMAStatus::PartialTransfer
        : DMAStatus::IoError;
    result.requestedBytes = size;
    result.transferredBytes = transferred;
    result.address = offset;
    if (!result)
        result.message = "VMMDLL_VfsWriteU failed or wrote partial data.";
    return result;
}

std::shared_ptr<IVmmBackend> CreateVmmdllBackend()
{
    return std::make_shared<VmmdllBackend>();
}
