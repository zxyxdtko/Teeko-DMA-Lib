#include "MockVmmBackend.hpp"

#include "TestHarness.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace {
DMAOperationResult Failure(DMAStatus status, const char* message)
{
    return DMAOperationResult::Failure(status, message);
}

std::string Lower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    return value;
}

class MockScatterSession final : public IVmmScatterSession {
public:
    MockScatterSession(MockVmmBackend& backend, DWORD pid, DWORD flags)
        : backend_(backend), pid_(pid), flags_(flags) {}

    DMAOperationResult PrepareRead(uint64_t address, void* buffer,
        DWORD size, DWORD* transferred) override
    {
        ++backend_.scatterPrepareCalls;
        if (backend_.failScatterPrepare)
            return Failure(DMAStatus::BackendError, "mock scatter prepare failed");
        requests_.push_back({ false, address, buffer, size, transferred });
        return DMAOperationResult::Success();
    }

    DMAOperationResult PrepareWrite(uint64_t address, const void* buffer,
        DWORD size) override
    {
        ++backend_.scatterPrepareCalls;
        if (backend_.failScatterPrepare)
            return Failure(DMAStatus::BackendError, "mock scatter prepare failed");
        requests_.push_back({ true, address, const_cast<void*>(buffer), size,
            nullptr });
        return DMAOperationResult::Success();
    }

    DMAOperationResult Execute(bool) override
    {
        ++backend_.scatterExecuteCalls;
        if (backend_.failScatterExecute)
            return Failure(DMAStatus::BackendError, "mock scatter execute failed");
        for (const auto& request : requests_) {
            if (request.write) {
                auto operation = backend_.WriteMemory(pid_, request.address,
                    request.buffer, request.size);
                if (!operation)
                    return operation;
            }
            else {
                DWORD transferred = 0;
                auto operation = backend_.ReadMemory(pid_, request.address,
                    request.buffer, request.size, flags_, transferred);
                if (request.transferred)
                    *request.transferred = transferred;
                if (!operation && operation.status != DMAStatus::PartialTransfer)
                    return operation;
            }
        }
        return DMAOperationResult::Success();
    }

private:
    struct Request {
        bool write;
        uint64_t address;
        void* buffer;
        DWORD size;
        DWORD* transferred;
    };
    MockVmmBackend& backend_;
    DWORD pid_;
    DWORD flags_;
    std::vector<Request> requests_;
};
}

MockVmmBackend::MockVmmBackend()
    : memory(0x20000), registryHiveBytes(0x1000)
{
    DMAProcessInfo process;
    process.pid = TargetPid;
    process.parentPid = 4;
    process.sessionId = 1;
    process.dtb = 0x111000;
    process.userDtb = 0x112000;
    process.eprocessAddress = 0xffff800000001000ULL;
    process.pebAddress = 0x8000;
    process.luid = 0x1234;
    process.memoryModel = VMMDLL_MEMORYMODEL_X64;
    process.systemType = VMMDLL_SYSTEM_WINDOWS_64;
    process.integrityLevel = VMMDLL_PROCESS_INTEGRITY_LEVEL_HIGH;
    process.name = "test.exe";
    process.longName = "C:\\mock\\test.exe";
    process.sid = "S-1-5-21-mock";
    processes.push_back(process);

    modules.push_back({ MemoryBase, MemoryBase + 0x100, 0x8000, 0x7000,
        false, "test.exe", "C:\\mock\\test.exe" });
    modules.push_back({ 0x9000, 0x9100, 0x2000, 0x1800,
        false, "helper.dll", "C:\\mock\\helper.dll" });

    DMAMemoryRegion privateWritable;
    privateWritable.baseAddress = 0x1000;
    privateWritable.size = 0x1000;
    privateWritable.source = DMAMemoryRegionSource::Vad;
    privateWritable.readable = true;
    privateWritable.writable = true;
    privateWritable.committed = true;
    privateWritable.privateMemory = true;
    regions.push_back(privateWritable);

    DMAMemoryRegion imageExecutable;
    imageExecutable.baseAddress = 0x2000;
    imageExecutable.size = 0x1000;
    imageExecutable.source = DMAMemoryRegionSource::Vad;
    imageExecutable.readable = true;
    imageExecutable.executable = true;
    imageExecutable.committed = true;
    imageExecutable.image = true;
    imageExecutable.name = "test.exe";
    regions.push_back(imageExecutable);

    DMAMemoryRegion pteRwx;
    pteRwx.baseAddress = 0x5000;
    pteRwx.size = 0x1000;
    pteRwx.source = DMAMemoryRegionSource::Pte;
    pteRwx.pageFlags = VMMDLL_MEMMAP_FLAG_PAGE_W;
    pteRwx.readable = true;
    pteRwx.writable = true;
    pteRwx.executable = true;
    pteRwx.committed = true;
    pteRwx.name = "test.exe";
    regions.push_back(pteRwx);

    DMAMemoryRegion pteRx = pteRwx;
    pteRx.baseAddress = 0x6000;
    pteRx.pageFlags = 0;
    pteRx.writable = false;
    regions.push_back(pteRx);

    sections = {
        { ".text", 0x2000, 0x1000, 0x1000,
          IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE, true, false, true },
        { ".rwx", 0x5000, 0x1000, 0x1000,
          IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE,
          true, true, true },
        { ".runtime_rx", 0x6000, 0x1000, 0x1000,
          IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE,
          true, true, true }
    };
    exports = { { "Exported", {}, 0x2100, 1, false } };
    imports = { { "kernel32.dll", "CreateFileW", 0x2200, 0x300, 0x400,
        0, false } };
    physicalRanges = { { 0x1000, 0x9000 }, { 0x10000, 0x2000 } };
    registryHives = { { 0x1111, 0x2222, 0x1000, "SYSTEM", "SYSTEM",
        "HKLM\\SYSTEM" } };
    registryKeys = { { "Child", 123 } };

    DMARegistryValue dword;
    dword.name = "Answer";
    dword.type = REG_DWORD;
    dword.data.resize(sizeof(uint32_t));
    const uint32_t answer = 42;
    std::memcpy(dword.data.data(), &answer, sizeof(answer));
    registryValues.push_back(dword);

    vfsEntries = { { "mock.txt", 4, false }, { "dir", 0, true } };
    vfsFiles["\\mock.txt"] = { 'm', 'o', 'c', 'k' };
    vfsFiles["\\misc\\procinfo\\progress_percent.txt"] = { '1', '0', '0' };
    const std::string dtb = "0000 0 0000000000abc000 0 test.exe\n";
    vfsFiles["\\misc\\procinfo\\dtb.txt"] =
        std::vector<uint8_t>(dtb.begin(), dtb.end());

    configValues[VMMDLL_OPT_CONFIG_VMM_VERSION_MAJOR] = 5;
    configValues[VMMDLL_OPT_CONFIG_VMM_VERSION_MINOR] = 16;
    configValues[VMMDLL_OPT_CONFIG_VMM_VERSION_REVISION] = 5;
    configValues[VMMDLL_OPT_WIN_VERSION_BUILD] = 26100;

    const uint16_t mz = IMAGE_DOS_SIGNATURE;
    Store(MemoryBase, mz);
}

bool MockVmmBackend::ResolveMemoryRange(uint64_t address, size_t size,
    size_t& offset) const noexcept
{
    offset = 0;
    if (address < MemoryBase || size > memory.size())
        return false;
    const uint64_t relative = address - MemoryBase;
    if (relative > memory.size() || size > memory.size() - relative)
        return false;
    offset = static_cast<size_t>(relative);
    return true;
}

void MockVmmBackend::StoreBytes(uint64_t address, const void* source,
    size_t size)
{
    size_t offset = 0;
    if (!source || !ResolveMemoryRange(address, size, offset))
        throw std::out_of_range("mock memory store is out of range");
    std::memcpy(memory.data() + offset, source, size);
}

void MockVmmBackend::Fill(uint64_t address, size_t size, uint8_t value)
{
    size_t offset = 0;
    if (!ResolveMemoryRange(address, size, offset))
        throw std::out_of_range("mock memory fill is out of range");
    std::fill(memory.begin() + offset, memory.begin() + offset + size, value);
}

DMAOperationResult MockVmmBackend::Initialize(
    const std::vector<std::string>& arguments)
{
    ++initializeCalls;
    initializeArguments = arguments;
    if (failInitialize)
        return Failure(DMAStatus::BackendError, "mock initialization failed");
    initialized = true;
    return DMAOperationResult::Success();
}

void MockVmmBackend::Close()
{
    ++closeCalls;
    initialized = false;
}

DMAOperationResult MockVmmBackend::InitializePlugins()
{
    if (failPluginInitialization)
        return Failure(DMAStatus::BackendError, "mock plugin initialization failed");
    pluginsInitialized = true;
    return DMAOperationResult::Success();
}

DMAOperationResult MockVmmBackend::ConfigGet(ULONG64 option,
    uint64_t& value) const
{
    const auto found = configValues.find(option);
    if (found == configValues.end())
        return Failure(DMAStatus::NotFound, "mock configuration missing");
    value = found->second;
    return DMAOperationResult::Success();
}

DMAOperationResult MockVmmBackend::ConfigSet(ULONG64 option, uint64_t value)
{
    configWrites.push_back({ option, value });
    if ((option & 0xffffffff00000000ULL) == VMMDLL_OPT_PROCESS_DTB)
        configuredDtb = value;
    configValues[option] = value;
    return DMAOperationResult::Success();
}

DMAOperationResult MockVmmBackend::ReadMemory(DWORD pid, uint64_t address,
    void* buffer, DWORD size, ULONG64 flags, DWORD& transferred)
{
    ++readCalls;
    lastReadPid = pid;
    lastReadFlags = flags;
    transferred = 0;
    if (failReads)
        return Failure(DMAStatus::BackendError, "mock read failed");
    size_t offset = 0;
    if (!buffer || size == 0 || !ResolveMemoryRange(address, size, offset))
        return Failure(DMAStatus::BackendError, "mock read out of range");
    transferred = partialReadLimit == 0 ? size
        : std::min(size, partialReadLimit);
    std::memcpy(buffer, memory.data() + offset, transferred);
    if (transferred != size) {
        auto result = Failure(DMAStatus::PartialTransfer, "mock partial read");
        result.requestedBytes = size;
        result.transferredBytes = transferred;
        return result;
    }
    return DMAOperationResult::Success(size);
}

DMAOperationResult MockVmmBackend::WriteMemory(DWORD pid, uint64_t address,
    const void* buffer, DWORD size)
{
    ++writeCalls;
    lastWritePid = pid;
    if (failWrites)
        return Failure(DMAStatus::BackendError, "mock write failed");
    size_t offset = 0;
    if (!buffer || size == 0 || !ResolveMemoryRange(address, size, offset))
        return Failure(DMAStatus::BackendError, "mock write out of range");
    std::memcpy(memory.data() + offset, buffer, size);
    return DMAOperationResult::Success(size);
}

DMAOperationResult MockVmmBackend::PrefetchPages(DWORD,
    const std::vector<uint64_t>& addresses)
{
    if (failPrefetch)
        return Failure(DMAStatus::BackendError, "mock prefetch failed");
    prefetchedPages = addresses;
    return DMAOperationResult::Success();
}

DMAOperationResult MockVmmBackend::VirtualToPhysical(DWORD,
    uint64_t virtualAddress, uint64_t& physicalAddress) const
{
    if (virtualAddress < MemoryBase)
        return Failure(DMAStatus::NotFound, "mock translation failed");
    physicalAddress = virtualAddress - MemoryBase + 0x100000;
    return DMAOperationResult::Success();
}

std::unique_ptr<IVmmScatterSession> MockVmmBackend::CreateScatter(DWORD pid,
    DWORD flags)
{
    if (!initialized || failScatterCreate)
        return {};
    return std::make_unique<MockScatterSession>(*this, pid, flags);
}

DMAOperationResult MockVmmBackend::FindPid(const std::string& name,
    DWORD& pid) const
{
    pid = 0;
    if (!processAvailable.load() || Lower(name) != "test.exe")
        return Failure(DMAStatus::NotFound, "mock process not found");
    pid = TargetPid;
    return DMAOperationResult::Success();
}

DMAOperationResult MockVmmBackend::GetProcess(DWORD pid,
    DMAProcessInfo& process) const
{
    process = {};
    if (!processAvailable.load() || processes.empty() || pid != TargetPid)
        return Failure(DMAStatus::NotFound, "mock process not found");
    process = processes.front();
    return DMAOperationResult::Success();
}

DMAOperationResult MockVmmBackend::GetProcesses(
    std::vector<DMAProcessInfo>& output) const
{
    output.clear();
    if (processAvailable.load())
        output = processes;
    return DMAOperationResult::Success();
}

DMAOperationResult MockVmmBackend::GetModule(DWORD pid,
    const std::string& name, DMAModuleInfo& module) const
{
    ++moduleCalls;
    module = {};
    if (pid != TargetPid || !moduleAvailable ||
        (requireConfiguredDtb && configuredDtb != ValidDtb)) {
        return Failure(DMAStatus::NotFound, "mock module not found");
    }
    const std::string requested = Lower(name);
    for (const auto& candidate : modules) {
        if (name.empty() || Lower(candidate.name) == requested) {
            module = candidate;
            return DMAOperationResult::Success();
        }
    }
    return Failure(DMAStatus::NotFound, "mock module not found");
}

DMAOperationResult MockVmmBackend::GetModules(DWORD pid,
    std::vector<DMAModuleInfo>& output) const
{
    if (pid != TargetPid)
        return Failure(DMAStatus::NotFound, "mock process not found");
    output = modules;
    return DMAOperationResult::Success();
}

DMAOperationResult MockVmmBackend::GetPhysicalMemoryMap(
    std::vector<DMAPhysicalMemoryRange>& output) const
{
    if (failPhysicalMap)
        return Failure(DMAStatus::BackendError, "mock physical map failed");
    output = physicalRanges;
    return DMAOperationResult::Success();
}

DMAOperationResult MockVmmBackend::GetMemoryRegions(DWORD pid,
    bool includeVad, bool includePte,
    std::vector<DMAMemoryRegion>& output) const
{
    output.clear();
    if (pid != TargetPid)
        return Failure(DMAStatus::NotFound, "mock process not found");
    for (const auto& region : regions) {
        if ((region.source == DMAMemoryRegionSource::Vad && includeVad) ||
            (region.source == DMAMemoryRegionSource::Pte && includePte)) {
            output.push_back(region);
        }
    }
    return DMAOperationResult::Success();
}

DMAOperationResult MockVmmBackend::GetSections(DWORD pid,
    const std::string&, std::vector<DMAModuleSection>& output) const
{
    if (pid != TargetPid)
        return Failure(DMAStatus::NotFound, "mock process not found");
    output = sections;
    return DMAOperationResult::Success();
}

DMAOperationResult MockVmmBackend::GetExports(DWORD pid,
    const std::string&, std::vector<DMAExportInfo>& output) const
{
    if (pid != TargetPid)
        return Failure(DMAStatus::NotFound, "mock process not found");
    output = exports;
    return DMAOperationResult::Success();
}

DMAOperationResult MockVmmBackend::GetImports(DWORD pid,
    const std::string&, std::vector<DMAImportInfo>& output) const
{
    if (pid != TargetPid)
        return Failure(DMAStatus::NotFound, "mock process not found");
    output = imports;
    return DMAOperationResult::Success();
}

DMAOperationResult MockVmmBackend::LoadSymbols(DWORD pid, uint64_t moduleBase,
    std::string& symbolModule)
{
    if (pid != TargetPid || moduleBase == 0)
        return Failure(DMAStatus::NotFound, "mock symbols not found");
    symbolModule = "test";
    return DMAOperationResult::Success();
}

DMAOperationResult MockVmmBackend::ResolveSymbol(const std::string& symbolModule,
    const std::string& symbol, uint64_t& address) const
{
    if (symbolModule != "test" || symbol != "Symbol")
        return Failure(DMAStatus::NotFound, "mock symbol not found");
    address = 0x2345;
    return DMAOperationResult::Success();
}

DMAOperationResult MockVmmBackend::LookupSymbol(const std::string& symbolModule,
    uint64_t addressOrOffset, DMASymbolInfo& symbol) const
{
    if (symbolModule != "test")
        return Failure(DMAStatus::NotFound, "mock symbol not found");
    symbol = { symbolModule, "Symbol", addressOrOffset - 5, 5 };
    return DMAOperationResult::Success();
}

DMAOperationResult MockVmmBackend::GetTypeSize(const std::string& symbolModule,
    const std::string& typeName, uint32_t& size) const
{
    if (symbolModule != "test" || typeName != "_TYPE")
        return Failure(DMAStatus::NotFound, "mock type not found");
    size = 0x80;
    return DMAOperationResult::Success();
}

DMAOperationResult MockVmmBackend::GetTypeChildOffset(
    const std::string& symbolModule, const std::string& typeName,
    const std::string& childName, uint32_t& offset) const
{
    if (symbolModule != "test" || typeName != "_TYPE" ||
        childName != "Child") {
        return Failure(DMAStatus::NotFound, "mock type child not found");
    }
    offset = 0x20;
    return DMAOperationResult::Success();
}

DMAOperationResult MockVmmBackend::GetRegistryHives(
    std::vector<DMARegistryHiveInfo>& output) const
{
    output = registryHives;
    return DMAOperationResult::Success();
}

DMAOperationResult MockVmmBackend::EnumerateRegistryKeys(const std::string& path,
    std::vector<DMARegistryKeyInfo>& output) const
{
    if (path.empty())
        return Failure(DMAStatus::InvalidArgument, "mock registry path missing");
    output = registryKeys;
    return DMAOperationResult::Success();
}

DMAOperationResult MockVmmBackend::EnumerateRegistryValues(
    const std::string& path, std::vector<DMARegistryValue>& output) const
{
    if (path.empty())
        return Failure(DMAStatus::InvalidArgument, "mock registry path missing");
    output = registryValues;
    return DMAOperationResult::Success();
}

DMAOperationResult MockVmmBackend::QueryRegistryValue(const std::string& path,
    DMARegistryValue& value) const
{
    if (path.empty() || registryValues.empty())
        return Failure(DMAStatus::NotFound, "mock registry value not found");
    value = registryValues.front();
    return DMAOperationResult::Success();
}

DMAOperationResult MockVmmBackend::ReadRegistryHive(uint64_t,
    uint32_t relativeAddress, void* buffer, DWORD size, ULONG64,
    DWORD& transferred) const
{
    transferred = 0;
    if (!buffer || relativeAddress > registryHiveBytes.size() ||
        size > registryHiveBytes.size() - relativeAddress) {
        return Failure(DMAStatus::InvalidArgument, "mock hive read out of range");
    }
    std::memcpy(buffer, registryHiveBytes.data() + relativeAddress, size);
    transferred = size;
    return DMAOperationResult::Success(size);
}

DMAOperationResult MockVmmBackend::WriteRegistryHive(uint64_t,
    uint32_t relativeAddress, const void* buffer, DWORD size)
{
    if (!buffer || relativeAddress > registryHiveBytes.size() ||
        size > registryHiveBytes.size() - relativeAddress) {
        return Failure(DMAStatus::InvalidArgument, "mock hive write out of range");
    }
    std::memcpy(registryHiveBytes.data() + relativeAddress, buffer, size);
    return DMAOperationResult::Success(size);
}

DMAOperationResult MockVmmBackend::ListVfs(const std::string&,
    std::vector<DMAVfsEntry>& output) const
{
    output = vfsEntries;
    return DMAOperationResult::Success();
}

DMAOperationResult MockVmmBackend::ReadVfs(const std::string& path,
    uint64_t offset, void* buffer, DWORD size, DWORD& transferred) const
{
    transferred = 0;
    const auto found = vfsFiles.find(path);
    if (found == vfsFiles.end())
        return Failure(DMAStatus::NotFound, "mock VFS file not found");
    if (!buffer || offset >= found->second.size())
        return DMAOperationResult::Success();
    transferred = static_cast<DWORD>(std::min<uint64_t>(size,
        found->second.size() - offset));
    std::memcpy(buffer, found->second.data() + offset, transferred);
    return DMAOperationResult::Success(transferred);
}

DMAOperationResult MockVmmBackend::WriteVfs(const std::string& path,
    uint64_t offset, const void* buffer, DWORD size, DWORD& transferred)
{
    transferred = 0;
    if (!buffer)
        return Failure(DMAStatus::InvalidArgument, "mock VFS write missing buffer");
    auto& file = vfsFiles[path];
    if (offset > std::numeric_limits<size_t>::max() - size)
        return Failure(DMAStatus::InvalidArgument, "mock VFS write too large");
    const size_t required = static_cast<size_t>(offset) + size;
    if (file.size() < required)
        file.resize(required);
    std::memcpy(file.data() + static_cast<size_t>(offset), buffer, size);
    transferred = size;
    return DMAOperationResult::Success(size);
}

void MockDmaFixture::Initialize(bool plugins)
{
    DMAInitializationOptions options;
    options.useMemoryMap = false;
    options.initializePlugins = plugins;
    STRATA_REQUIRE(dma.Initialize(options));
}

void MockDmaFixture::Attach()
{
    if (!dma.IsInitialized())
        Initialize();
    STRATA_REQUIRE(dma.Attach("test.exe"));
}
