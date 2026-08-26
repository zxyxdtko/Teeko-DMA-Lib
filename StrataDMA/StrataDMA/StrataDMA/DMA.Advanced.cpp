#include "DMA.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <limits>

namespace {
DMAOperationResult InvalidResult(const char* message, DWORD pid = 0,
    uint64_t address = 0, size_t size = 0)
{
    auto result = DMAOperationResult::Failure(DMAStatus::InvalidArgument, message);
    result.pid = pid;
    result.address = address;
    result.requestedBytes = size;
    return result;
}

bool RegionMatches(const DMAMemoryRegion& region,
    const DMAMemoryRegionFilter& filter)
{
    return (!filter.requireReadable || region.readable) &&
        (!filter.requireWritable || region.writable) &&
        (!filter.requireExecutable || region.executable) &&
        (!filter.requireCommitted || region.committed) &&
        (!filter.privateOnly || region.privateMemory) &&
        (!filter.imageOnly || region.image) &&
        (!filter.mappedFileOnly || region.mappedFile) &&
        (!filter.stackOnly || region.stack) &&
        (!filter.heapOnly || region.heap);
}
}

DMAOperationResult DMA::ReadRaw(uint64_t address, void* buffer,
    size_t size, ULONG64 flags)
{
    return ReadRaw(targetPID, address, buffer, size, flags);
}

DMAOperationResult DMA::ReadRaw(DWORD pid, uint64_t address,
    void* buffer, size_t size, ULONG64 flags)
{
    if (!IsInitialized())
        return DMAOperationResult::Failure(DMAStatus::NotInitialized,
            "DMA is not initialized.");
    if (pid == 0 || address == 0 || !buffer || size == 0 ||
        size > std::numeric_limits<DWORD>::max()) {
        return InvalidResult("Invalid memory read request.", pid, address, size);
    }
    DWORD transferred = 0;
    auto result = backend->ReadMemory(pid, address, buffer,
        static_cast<DWORD>(size), flags, transferred);
    result.pid = pid;
    result.address = address;
    result.requestedBytes = size;
    result.transferredBytes = transferred;
    result.flags = flags;
    if (result && transferred != size) {
        result.status = DMAStatus::PartialTransfer;
        result.message = "Memory read returned partial data.";
    }
    return result;
}

DMAOperationResult DMA::WriteRaw(uint64_t address, const void* buffer,
    size_t size)
{
    return WriteRaw(targetPID, address, buffer, size);
}

DMAOperationResult DMA::WriteRaw(DWORD pid, uint64_t address,
    const void* buffer, size_t size)
{
    if (!IsInitialized())
        return DMAOperationResult::Failure(DMAStatus::NotInitialized,
            "DMA is not initialized.");
    if (pid == 0 || address == 0 || !buffer || size == 0 ||
        size > std::numeric_limits<DWORD>::max()) {
        return InvalidResult("Invalid memory write request.", pid, address, size);
    }
    auto result = backend->WriteMemory(pid, address, buffer,
        static_cast<DWORD>(size));
    result.pid = pid;
    result.address = address;
    result.requestedBytes = size;
    if (result)
        result.transferredBytes = size;
    return result;
}

DMAMemoryContext DMA::ProcessContext(DWORD pid, ULONG64 flags) const
{
    return DMAMemoryContext(backend, pid == 0 ? targetPID : pid, flags);
}

DMAMemoryContext DMA::KernelContext(DWORD sessionPid, ULONG64 flags) const
{
    DWORD pid = sessionPid == 0 ? targetPID : sessionPid;
    return DMAMemoryContext(backend,
        pid == 0 ? 0 : pid | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY, flags);
}

DMAFrameContext DMA::CreateFrameContext(DWORD pid, ULONG64 flags) const
{
    return DMAFrameContext(backend, pid == 0 ? targetPID : pid, flags);
}

DMAScatterBatch DMA::CreateScatterBatch(DWORD pid, DWORD flags) const
{
    return DMAScatterBatch(backend, pid == 0 ? targetPID : pid, flags);
}

DMAResult<std::vector<DMAMemoryRegion>> DMA::GetMemoryRegions(
    const DMAMemoryRegionFilter& filter) const
{
    DMAResult<std::vector<DMAMemoryRegion>> result;
    if (!IsAttached()) {
        result.operation = DMAOperationResult::Failure(DMAStatus::NotAttached,
            "Attach to a process before enumerating memory regions.");
        return result;
    }
    std::vector<DMAMemoryRegion> all;
    result.operation = backend->GetMemoryRegions(targetPID, filter.includeVad,
        filter.includePte, all);
    if (!result.operation)
        return result;
    for (auto& region : all) {
        if (RegionMatches(region, filter))
            result.value.push_back(std::move(region));
    }
    return result;
}

DMAResult<std::vector<DMAModuleSection>> DMA::GetModuleSections(
    const std::string& moduleName) const
{
    DMAResult<std::vector<DMAModuleSection>> result;
    if (!IsAttached()) {
        result.operation = DMAOperationResult::Failure(DMAStatus::NotAttached,
            "Attach to a process before enumerating module sections.");
        return result;
    }
    result.operation = backend->GetSections(targetPID, moduleName, result.value);
    return result;
}

DMAResult<std::vector<DMAExportInfo>> DMA::GetModuleExports(
    const std::string& moduleName) const
{
    DMAResult<std::vector<DMAExportInfo>> result;
    if (!IsAttached()) {
        result.operation = DMAOperationResult::Failure(DMAStatus::NotAttached,
            "Attach to a process before enumerating exports.");
        return result;
    }
    result.operation = backend->GetExports(targetPID, moduleName, result.value);
    return result;
}

DMAResult<std::vector<DMAImportInfo>> DMA::GetModuleImports(
    const std::string& moduleName) const
{
    DMAResult<std::vector<DMAImportInfo>> result;
    if (!IsAttached()) {
        result.operation = DMAOperationResult::Failure(DMAStatus::NotAttached,
            "Attach to a process before enumerating imports.");
        return result;
    }
    result.operation = backend->GetImports(targetPID, moduleName, result.value);
    return result;
}

DMAResult<std::string> DMA::LoadModuleSymbols(const std::string& moduleName)
{
    DMAResult<std::string> result;
    const uint64_t base = GetModuleBase(moduleName);
    if (base == 0) {
        result.operation = DMAOperationResult::Failure(DMAStatus::NotFound,
            "The module was not found.");
        return result;
    }
    result.operation = backend->LoadSymbols(targetPID, base, result.value);
    return result;
}

DMAResult<uint64_t> DMA::ResolveSymbol(const std::string& symbolModule,
    const std::string& symbol) const
{
    DMAResult<uint64_t> result;
    result.operation = backend->ResolveSymbol(symbolModule, symbol, result.value);
    return result;
}

DMAResult<DMASymbolInfo> DMA::LookupSymbol(const std::string& symbolModule,
    uint64_t addressOrOffset) const
{
    DMAResult<DMASymbolInfo> result;
    result.operation = backend->LookupSymbol(symbolModule, addressOrOffset,
        result.value);
    return result;
}

DMAResult<uint32_t> DMA::GetSymbolTypeSize(const std::string& symbolModule,
    const std::string& typeName) const
{
    DMAResult<uint32_t> result;
    result.operation = backend->GetTypeSize(symbolModule, typeName, result.value);
    return result;
}

DMAResult<uint32_t> DMA::GetSymbolChildOffset(
    const std::string& symbolModule, const std::string& typeName,
    const std::string& childName) const
{
    DMAResult<uint32_t> result;
    result.operation = backend->GetTypeChildOffset(symbolModule, typeName,
        childName, result.value);
    return result;
}

DMAResult<DMAMemorySnapshot> DMA::CaptureSnapshot(uint64_t address,
    size_t size, ULONG64 flags) const
{
    DMAResult<DMAMemorySnapshot> result;
    result.value.pid = targetPID;
    result.value.address = address;
    result.value.flags = flags;
    result.value.capturedAt = std::chrono::system_clock::now();
    result.value.bytes.resize(size);
    if (!IsAttached()) {
        result.operation = DMAOperationResult::Failure(DMAStatus::NotAttached,
            "Attach to a process before capturing a snapshot.");
        result.value.bytes.clear();
        return result;
    }
    if (size == 0 || size > std::numeric_limits<DWORD>::max()) {
        result.operation = InvalidResult("Invalid snapshot range.", targetPID,
            address, size);
        result.value.bytes.clear();
        return result;
    }
    DWORD transferred = 0;
    result.operation = backend->ReadMemory(targetPID, address,
        result.value.bytes.data(), static_cast<DWORD>(size), flags, transferred);
    result.operation.pid = targetPID;
    result.operation.address = address;
    result.operation.requestedBytes = size;
    result.operation.transferredBytes = transferred;
    result.operation.flags = flags;
    if (result.operation && transferred != size) {
        result.operation.status = DMAStatus::PartialTransfer;
        result.operation.message = "Snapshot capture returned partial data.";
        result.value.bytes.resize(transferred);
    }
    return result;
}

DMAResult<std::vector<DMAMemoryChange>> DMA::DiffSnapshots(
    const DMAMemorySnapshot& before, const DMAMemorySnapshot& after,
    size_t maxChanges)
{
    DMAResult<std::vector<DMAMemoryChange>> result;
    if (before.address != after.address || before.pid != after.pid ||
        before.bytes.size() != after.bytes.size()) {
        result.operation = DMAOperationResult::Failure(DMAStatus::InvalidArgument,
            "Snapshots must have the same PID, base address, and size.");
        return result;
    }
    for (size_t offset = 0; offset < before.bytes.size(); ++offset) {
        if (before.bytes[offset] != after.bytes[offset]) {
            result.value.push_back({ before.address + offset, offset,
                before.bytes[offset], after.bytes[offset] });
            if (maxChanges != 0 && result.value.size() >= maxChanges)
                break;
        }
    }
    result.operation = DMAOperationResult::Success(before.bytes.size());
    return result;
}

bool DMA::StartProcessMonitor(const std::string& processName,
    int pollIntervalMs, bool autoReattach,
    std::function<void(const DMAProcessEvent&)> callback,
    const std::string& mainModuleName)
{
    if (!IsInitialized() || processName.empty() || processMonitorRunning.load())
        return false;
    monitoredProcessName = processName;
    monitoredMainModuleName = mainModuleName;
    processMonitorAutoReattach = autoReattach;
    processMonitorPollMs = std::max(10, pollIntervalMs);
    processMonitorCallback = std::move(callback);
    processMonitorRunning.store(true);
    processMonitorThread = std::thread(&DMA::ProcessMonitorThread, this);
    return true;
}

void DMA::StopProcessMonitor()
{
    processMonitorRunning.store(false);
    if (processMonitorThread.joinable() &&
        processMonitorThread.get_id() != std::this_thread::get_id()) {
        processMonitorThread.join();
    }
}

void DMA::ProcessMonitorThread()
{
    bool hadProcess = targetPID != 0;
    bool reportedAttachError = false;
    while (processMonitorRunning.load()) {
        const DWORD previous = targetPID;
        DMAProcessInfo info;
        const bool alive = previous != 0 &&
            static_cast<bool>(backend->GetProcess(previous, info));
        if (!alive && hadProcess) {
            hadProcess = false;
            Detach();
            if (processMonitorCallback) {
                try { processMonitorCallback({ DMAProcessEventKind::Exited,
                    previous, 0, monitoredProcessName, {} }); }
                catch (...) {}
            }
        }
        if (!alive && processMonitorAutoReattach) {
            DWORD found = 0;
            if (backend->FindPid(monitoredProcessName, found) && found != 0) {
                const auto attached = Attach(found,
                    monitoredMainModuleName.empty() ? monitoredProcessName
                    : monitoredMainModuleName);
                if (attached) {
                    hadProcess = true;
                    reportedAttachError = false;
                    if (processMonitorCallback) {
                        try { processMonitorCallback({ previous == 0
                            ? DMAProcessEventKind::Attached
                            : DMAProcessEventKind::Reattached, previous, found,
                            monitoredProcessName, {} }); }
                        catch (...) {}
                    }
                }
                else if (!reportedAttachError && processMonitorCallback) {
                    reportedAttachError = true;
                    try { processMonitorCallback({ DMAProcessEventKind::Error,
                        previous, found, monitoredProcessName,
                        attached.message }); }
                    catch (...) {}
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(processMonitorPollMs));
    }
}

DMAResult<std::vector<DMARegistryHiveInfo>> DMA::GetRegistryHives() const
{
    DMAResult<std::vector<DMARegistryHiveInfo>> result;
    result.operation = backend->GetRegistryHives(result.value);
    return result;
}

DMAResult<std::vector<DMARegistryKeyInfo>> DMA::EnumerateRegistryKeys(
    const std::string& path) const
{
    DMAResult<std::vector<DMARegistryKeyInfo>> result;
    result.operation = backend->EnumerateRegistryKeys(path, result.value);
    return result;
}

DMAResult<std::vector<DMARegistryValue>> DMA::EnumerateRegistryValues(
    const std::string& path) const
{
    DMAResult<std::vector<DMARegistryValue>> result;
    result.operation = backend->EnumerateRegistryValues(path, result.value);
    return result;
}

DMAResult<DMARegistryValue> DMA::QueryRegistryValue(const std::string& path) const
{
    DMAResult<DMARegistryValue> result;
    result.operation = backend->QueryRegistryValue(path, result.value);
    return result;
}

DMAOperationResult DMA::ReadRegistryHive(uint64_t cmHiveAddress,
    uint32_t relativeAddress, void* buffer, size_t size, ULONG64 flags) const
{
    if (size == 0 || size > std::numeric_limits<DWORD>::max())
        return InvalidResult("Invalid registry hive read size.");
    DWORD transferred = 0;
    auto result = backend->ReadRegistryHive(cmHiveAddress, relativeAddress,
        buffer, static_cast<DWORD>(size), flags, transferred);
    result.requestedBytes = size;
    result.transferredBytes = transferred;
    return result;
}

DMAOperationResult DMA::WriteRegistryHive(uint64_t cmHiveAddress,
    uint32_t relativeAddress, const void* buffer, size_t size)
{
    if (size == 0 || size > std::numeric_limits<DWORD>::max())
        return InvalidResult("Invalid registry hive write size.");
    return backend->WriteRegistryHive(cmHiveAddress, relativeAddress, buffer,
        static_cast<DWORD>(size));
}

DMAResult<std::vector<DMAVfsEntry>> DMA::ListVfs(const std::string& path) const
{
    DMAResult<std::vector<DMAVfsEntry>> result;
    result.operation = backend->ListVfs(path, result.value);
    return result;
}

DMAOperationResult DMA::ReadVfs(const std::string& path, uint64_t offset,
    void* buffer, size_t size) const
{
    if (size == 0 || size > std::numeric_limits<DWORD>::max())
        return InvalidResult("Invalid VFS read size.");
    DWORD transferred = 0;
    auto result = backend->ReadVfs(path, offset, buffer,
        static_cast<DWORD>(size), transferred);
    result.requestedBytes = size;
    result.transferredBytes = transferred;
    result.address = offset;
    return result;
}

DMAResult<std::vector<uint8_t>> DMA::ReadVfsFile(const std::string& path,
    size_t maxBytes) const
{
    DMAResult<std::vector<uint8_t>> result;
    if (path.empty() || maxBytes == 0) {
        result.operation = InvalidResult("A VFS path and non-zero limit are required.");
        return result;
    }
    constexpr DWORD chunkSize = 1024 * 1024;
    while (result.value.size() < maxBytes) {
        const DWORD request = static_cast<DWORD>(std::min<size_t>(chunkSize,
            maxBytes - result.value.size()));
        const size_t oldSize = result.value.size();
        result.value.resize(oldSize + request);
        DWORD transferred = 0;
        auto operation = backend->ReadVfs(path, oldSize,
            result.value.data() + oldSize, request, transferred);
        if (!operation) {
            result.value.resize(oldSize);
            result.operation = operation;
            return result;
        }
        result.value.resize(oldSize + transferred);
        if (transferred < request)
            break;
    }
    result.operation = DMAOperationResult::Success(result.value.size());
    if (result.value.size() == maxBytes) {
        uint8_t probe = 0;
        DWORD transferred = 0;
        const auto probeResult = backend->ReadVfs(path, maxBytes, &probe, 1,
            transferred);
        if (probeResult && transferred != 0) {
            result.operation.status = DMAStatus::PartialTransfer;
            result.operation.message = "VFS read reached the configured size limit.";
        }
    }
    return result;
}

DMAOperationResult DMA::WriteVfs(const std::string& path, uint64_t offset,
    const void* buffer, size_t size)
{
    if (size == 0 || size > std::numeric_limits<DWORD>::max())
        return InvalidResult("Invalid VFS write size.");
    DWORD transferred = 0;
    auto result = backend->WriteVfs(path, offset, buffer,
        static_cast<DWORD>(size), transferred);
    result.requestedBytes = size;
    result.transferredBytes = transferred;
    result.address = offset;
    return result;
}
