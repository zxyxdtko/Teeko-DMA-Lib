#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "DMA.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <thread>
#include <unordered_set>

namespace {
std::string Lowercase(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    return value;
}

template <typename T>
T ReadUnaligned(const uint8_t* bytes)
{
    T value{};
    std::memcpy(&value, bytes, sizeof(value));
    return value;
}

DMAOperationResult ValidateModule(IVmmBackend& backend, DWORD pid,
    const std::string& moduleName, bool validateImageHeader,
    DMAModuleInfo* moduleOut = nullptr)
{
    DMAModuleInfo module;
    auto operation = backend.GetModule(pid, moduleName, module);
    if (!operation)
        return operation;
    if (module.baseAddress == 0 || module.imageSize < sizeof(uint16_t)) {
        return DMAOperationResult::Failure(DMAStatus::NotFound,
            "The validation module has no readable image range.");
    }
    if (validateImageHeader) {
        uint16_t signature = 0;
        DWORD transferred = 0;
        operation = backend.ReadMemory(pid, module.baseAddress, &signature,
            sizeof(signature), VMMDLL_FLAG_NOCACHE, transferred);
        if (!operation || transferred != sizeof(signature) ||
            signature != IMAGE_DOS_SIGNATURE) {
            auto failure = DMAOperationResult::Failure(DMAStatus::BackendError,
                "The candidate DTB did not expose a valid MZ image header.");
            failure.pid = pid;
            failure.address = module.baseAddress;
            failure.requestedBytes = sizeof(signature);
            failure.transferredBytes = transferred;
            return failure;
        }
    }
    if (moduleOut)
        *moduleOut = std::move(module);
    return DMAOperationResult::Success();
}

DMAResult<std::string> ReadVfsText(IVmmBackend& backend,
    const std::string& path, size_t maximumSize)
{
    DMAResult<std::string> result;
    constexpr DWORD chunkSize = 64 * 1024;
    std::array<char, chunkSize> buffer{};
    while (result.value.size() < maximumSize) {
        const DWORD request = static_cast<DWORD>(std::min<size_t>(
            buffer.size(), maximumSize - result.value.size()));
        DWORD transferred = 0;
        auto operation = backend.ReadVfs(path, result.value.size(),
            buffer.data(), request, transferred);
        if (!operation) {
            result.operation = operation;
            return result;
        }
        result.value.append(buffer.data(), transferred);
        if (transferred < request)
            break;
    }
    result.operation = DMAOperationResult::Success(result.value.size());
    if (result.value.size() == maximumSize) {
        result.operation.status = DMAStatus::PartialTransfer;
        result.operation.message = "The VFS text file exceeded its size limit.";
    }
    return result;
}

bool PermissionMatches(bool readable, bool writable, bool executable,
    const DMACodeCaveOptions& options)
{
    return (!options.requireReadable || readable) &&
        (!options.requireWritable || writable) &&
        (!options.requireExecutable || executable);
}

uint64_t SaturatingAdd(uint64_t left, uint64_t right)
{
    return right > std::numeric_limits<uint64_t>::max() - left
        ? std::numeric_limits<uint64_t>::max() : left + right;
}

bool AlignUp(uint64_t value, size_t alignment, uint64_t& aligned)
{
    const uint64_t divisor = static_cast<uint64_t>(alignment);
    const uint64_t remainder = value % divisor;
    if (remainder == 0) {
        aligned = value;
        return true;
    }
    const uint64_t increment = divisor - remainder;
    if (increment > std::numeric_limits<uint64_t>::max() - value)
        return false;
    aligned = value + increment;
    return true;
}
}

DMAResult<DMAProcessInfo> DMA::GetProcessInfo(DWORD pid) const
{
    DMAResult<DMAProcessInfo> result;
    if (!IsInitialized()) {
        result.operation = DMAOperationResult::Failure(DMAStatus::NotInitialized,
            "Initialize DMA before requesting process information.");
        return result;
    }
    if (pid == 0)
        pid = targetPID;
    if (pid == 0) {
        result.operation = DMAOperationResult::Failure(DMAStatus::InvalidArgument,
            "A non-zero PID or current attachment is required.");
        return result;
    }
    result.operation = backend->GetProcess(pid, result.value);
    result.operation.pid = pid;
    return result;
}

DMAResult<DMAPebInfo> DMA::GetProcessEnvironmentBlock(DWORD pid,
    bool preferWow64) const
{
    DMAResult<DMAPebInfo> result;
    auto process = GetProcessInfo(pid);
    if (!process) {
        result.operation = process.operation;
        return result;
    }

    const bool native32Bit =
        process.value.memoryModel == VMMDLL_MEMORYMODEL_X86 ||
        process.value.memoryModel == VMMDLL_MEMORYMODEL_X86PAE;
    result.value.pid = process.value.pid;
    result.value.is32Bit = native32Bit ||
        (preferWow64 && process.value.wow64 &&
            process.value.wow64PebAddress != 0);
    result.value.address = result.value.is32Bit &&
        process.value.wow64PebAddress != 0
        ? process.value.wow64PebAddress : process.value.pebAddress;
    if (result.value.address == 0) {
        result.operation = DMAOperationResult::Failure(DMAStatus::NotFound,
            "The process does not expose the requested PEB address.");
        result.operation.pid = process.value.pid;
        return result;
    }

    std::array<uint8_t, 0x38> bytes{};
    const DWORD required = result.value.is32Bit ? 0x1c : 0x38;
    DWORD transferred = 0;
    result.operation = backend->ReadMemory(process.value.pid,
        result.value.address, bytes.data(), required, VMMDLL_FLAG_NOCACHE,
        transferred);
    result.operation.pid = process.value.pid;
    result.operation.address = result.value.address;
    result.operation.requestedBytes = required;
    result.operation.transferredBytes = transferred;
    if (!result.operation || transferred != required)
        return result;

    result.value.inheritedAddressSpace = bytes[0] != 0;
    result.value.readImageFileExecOptions = bytes[1] != 0;
    result.value.beingDebugged = bytes[2] != 0;
    if (result.value.is32Bit) {
        result.value.imageBaseAddress = ReadUnaligned<uint32_t>(&bytes[0x08]);
        result.value.loaderDataAddress = ReadUnaligned<uint32_t>(&bytes[0x0c]);
        result.value.processParametersAddress =
            ReadUnaligned<uint32_t>(&bytes[0x10]);
        result.value.processHeapAddress = ReadUnaligned<uint32_t>(&bytes[0x18]);
    }
    else {
        result.value.imageBaseAddress = ReadUnaligned<uint64_t>(&bytes[0x10]);
        result.value.loaderDataAddress = ReadUnaligned<uint64_t>(&bytes[0x18]);
        result.value.processParametersAddress =
            ReadUnaligned<uint64_t>(&bytes[0x20]);
        result.value.processHeapAddress = ReadUnaligned<uint64_t>(&bytes[0x30]);
    }
    return result;
}

DMAResult<DMACR3RecoveryReport> DMA::RecoverCR3(DWORD pid,
    const std::string& validationModule,
    const DMACR3RecoveryOptions& options)
{
    DMAResult<DMACR3RecoveryReport> result;
    result.value.pid = pid;
    result.value.moduleName = validationModule;
    if (!IsInitialized()) {
        result.operation = DMAOperationResult::Failure(DMAStatus::NotInitialized,
            "Initialize DMA before recovering a process DTB.");
        return result;
    }
    if (pid == 0 || validationModule.empty() || options.timeout.count() < 0 ||
        options.pollInterval.count() <= 0) {
        result.operation = DMAOperationResult::Failure(DMAStatus::InvalidArgument,
            "CR3 recovery requires a PID, module, non-negative timeout, and positive poll interval.");
        return result;
    }

    DMAProcessInfo process;
    const auto processOperation = backend->GetProcess(pid, process);
    if (processOperation) {
        result.value.originalDtb = process.dtb;
        if (process.name.empty())
            process.name = validationModule;
    }
    else {
        process.pid = pid;
        process.name = validationModule;
    }

    DMAModuleInfo validatedModule;
    auto current = ValidateModule(*backend, pid, validationModule,
        options.validateImageHeader, &validatedModule);
    if (current) {
        result.value.recoveryNeeded = false;
        result.value.recoveredDtb = process.dtb;
        result.operation = DMAOperationResult::Success();
        result.operation.pid = pid;
        return result;
    }

    if (options.initializePlugins) {
        const auto plugins = backend->InitializePlugins();
        if (!plugins) {
            result.operation = plugins;
            result.operation.message = "CR3 recovery could not initialize MemProcFS plugins: " +
                plugins.message;
            result.operation.pid = pid;
            return result;
        }
    }

    const auto deadline = std::chrono::steady_clock::now() + options.timeout;
    DMAResult<std::string> dtbText;
    while (true) {
        std::array<char, 16> progressBytes{};
        DWORD progressRead = 0;
        const auto progress = backend->ReadVfs(
            "\\misc\\procinfo\\progress_percent.txt", 0,
            progressBytes.data(), static_cast<DWORD>(progressBytes.size() - 1),
            progressRead);
        int percent = -1;
        if (progress && progressRead != 0) {
            progressBytes[std::min<size_t>(progressRead,
                progressBytes.size() - 1)] = '\0';
            percent = std::atoi(progressBytes.data());
        }

        if (percent >= 100 || !progress) {
            dtbText = ReadVfsText(*backend, "\\misc\\procinfo\\dtb.txt",
                16 * 1024 * 1024);
            if (dtbText && !dtbText.value.empty())
                break;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            result.operation = DMAOperationResult::Failure(DMAStatus::Timeout,
                "Timed out waiting for MemProcFS procinfo DTB analysis.");
            result.operation.pid = pid;
            return result;
        }
        std::this_thread::sleep_for(options.pollInterval);
    }

    struct Candidate {
        uint64_t dtb;
        DWORD sourcePid;
        std::string sourceName;
    };
    std::vector<Candidate> candidates;
    std::unordered_set<uint64_t> uniqueDtbs;
    auto addCandidate = [&](uint64_t dtb, DWORD sourcePid,
        const std::string& sourceName) {
        if (dtb == 0 || uniqueDtbs.find(dtb) != uniqueDtbs.end())
            return;
        if (options.maxCandidates != 0 &&
            candidates.size() >= options.maxCandidates)
            return;
        uniqueDtbs.insert(dtb);
        candidates.push_back({ dtb, sourcePid, sourceName });
    };

    if (options.includeKnownProcessDtbs && processOperation) {
        addCandidate(process.dtb, process.pid, process.name);
        addCandidate(process.userDtb, process.pid, process.name);
    }

    const std::string requestedName = Lowercase(process.name.empty()
        ? validationModule : process.name);
    std::istringstream lines(dtbText.value);
    std::string line;
    while (std::getline(lines, line)) {
        uint64_t index = 0;
        DWORD sourcePid = 0;
        uint64_t dtb = 0;
        uint64_t kernelAddress = 0;
        std::string sourceName;
        std::istringstream fields(line);
        if (!(fields >> std::hex >> index >> std::dec >> sourcePid >>
            std::hex >> dtb >> kernelAddress >> sourceName)) {
            continue;
        }
        const bool selected =
            (options.includeTargetPidEntries && sourcePid == pid) ||
            (options.includePidZeroEntries && sourcePid == 0) ||
            (options.includeProcessNameMatches &&
                Lowercase(sourceName) == requestedName);
        if (selected)
            addCandidate(dtb, sourcePid, sourceName);
    }

    if (candidates.empty()) {
        result.operation = DMAOperationResult::Failure(DMAStatus::NotFound,
            "MemProcFS procinfo did not produce any applicable DTB candidates.");
        result.operation.pid = pid;
        return result;
    }

    const ULONG64 dtbOption = VMMDLL_OPT_PROCESS_DTB | pid;
    for (const auto& candidate : candidates) {
        DMACR3Attempt attempt;
        attempt.dtb = candidate.dtb;
        attempt.sourcePid = candidate.sourcePid;
        attempt.sourceName = candidate.sourceName;
        attempt.operation = backend->ConfigSet(dtbOption, candidate.dtb);
        attempt.operation.pid = pid;
        attempt.operation.address = candidate.dtb;
        if (attempt.operation) {
            backend->ConfigSet(VMMDLL_OPT_REFRESH_FREQ_TLB, 1);
            backend->ConfigSet(VMMDLL_OPT_REFRESH_FREQ_MEM, 1);
            attempt.operation = ValidateModule(*backend, pid, validationModule,
                options.validateImageHeader, &validatedModule);
            attempt.operation.pid = pid;
            attempt.operation.address = candidate.dtb;
        }
        result.value.attempts.push_back(attempt);
        if (!attempt.operation)
            continue;

        result.value.recoveredDtb = candidate.dtb;
        if (targetPID == pid) {
            mainModuleBase = validatedModule.baseAddress;
            attachedMainModuleName = validatedModule.name.empty()
                ? validationModule : validatedModule.name;
            moduleCache[NormalizeName(attachedMainModuleName)] = {
                validatedModule.baseAddress, validatedModule.imageSize
            };
            moduleCache[NormalizeName(validationModule)] = {
                validatedModule.baseAddress, validatedModule.imageSize
            };
        }
        result.operation = DMAOperationResult::Success();
        result.operation.pid = pid;
        result.operation.address = candidate.dtb;
        return result;
    }

    if (options.restoreOriginalDtbOnFailure) {
        result.value.restoredOriginalDtb = static_cast<bool>(
            backend->ConfigSet(dtbOption, result.value.originalDtb));
        backend->ConfigSet(VMMDLL_OPT_REFRESH_FREQ_TLB, 1);
        backend->ConfigSet(VMMDLL_OPT_REFRESH_FREQ_MEM, 1);
    }
    result.operation = DMAOperationResult::Failure(DMAStatus::NotFound,
        "None of the MemProcFS DTB candidates validated the target module.");
    result.operation.pid = pid;
    return result;
}

DMAResult<DMACR3RecoveryReport> DMA::RecoverCR3(
    const DMACR3RecoveryOptions& options)
{
    if (!IsAttached()) {
        DMAResult<DMACR3RecoveryReport> result;
        result.operation = DMAOperationResult::Failure(DMAStatus::NotAttached,
            "Attach first or use RecoverCR3(pid, validationModule, options).");
        return result;
    }
    std::string module = attachedMainModuleName;
    if (module.empty()) {
        DMAProcessInfo process;
        if (backend->GetProcess(targetPID, process))
            module = process.name;
    }
    return RecoverCR3(targetPID, module, options);
}

DMAResult<DMACR3RecoveryReport> DMA::AttachWithCR3Recovery(
    const std::string& processName, const DMACR3RecoveryOptions& options)
{
    DMAResult<DMACR3RecoveryReport> result;
    if (!IsInitialized()) {
        result.operation = DMAOperationResult::Failure(DMAStatus::NotInitialized,
            "Initialize DMA before attaching to a process.");
        return result;
    }
    DWORD pid = 0;
    result.operation = backend->FindPid(processName, pid);
    if (!result.operation)
        return result;

    DMAProcessInfo process;
    backend->GetProcess(pid, process);
    auto attached = Attach(pid, processName);
    if (attached) {
        result.value.pid = pid;
        result.value.moduleName = processName;
        result.value.originalDtb = process.dtb;
        result.value.recoveredDtb = process.dtb;
        result.value.recoveryNeeded = false;
        result.operation = DMAOperationResult::Success();
        result.operation.pid = pid;
        return result;
    }

    result = RecoverCR3(pid, processName, options);
    if (!result)
        return result;
    attached = Attach(pid, processName);
    if (!attached) {
        result.operation = attached;
        result.operation.message =
            "The DTB validated, but attaching to the process still failed: " +
            attached.message;
        result.operation.pid = pid;
    }
    return result;
}

DMAResult<std::vector<DMAPhysicalMemoryRange>> DMA::GetPhysicalMemoryMap(
    bool refresh) const
{
    DMAResult<std::vector<DMAPhysicalMemoryRange>> result;
    if (!IsInitialized()) {
        result.operation = DMAOperationResult::Failure(DMAStatus::NotInitialized,
            "Initialize DMA before retrieving the physical-memory map.");
        return result;
    }
    if (refresh) {
        result.operation = backend->ConfigSet(
            VMMDLL_OPT_REFRESH_SPECIFIC_PHYSMEMMAP, 1);
        if (!result.operation)
            return result;
    }
    result.operation = backend->GetPhysicalMemoryMap(result.value);
    if (result.operation) {
        std::sort(result.value.begin(), result.value.end(),
            [](const auto& left, const auto& right) {
                return left.baseAddress < right.baseAddress;
            });
    }
    return result;
}

DMAOperationResult DMA::ExportPhysicalMemoryMap(const std::string& outPath,
    bool refresh) const
{
    if (outPath.empty())
        return DMAOperationResult::Failure(DMAStatus::InvalidArgument,
            "A physical-memory-map output path is required.");
    auto ranges = GetPhysicalMemoryMap(refresh);
    if (!ranges)
        return ranges.operation;

    std::ofstream output(outPath, std::ios::out | std::ios::trunc);
    if (!output)
        return DMAOperationResult::Failure(DMAStatus::IoError,
            "Unable to open the physical-memory-map output file.");
    output << std::hex << std::setfill('0');
    for (const auto& range : ranges.value) {
        if (range.size == 0)
            continue;
        output << std::setw(16) << range.baseAddress << ' '
            << std::setw(16) << range.LastAddress() << '\n';
    }
    if (!output)
        return DMAOperationResult::Failure(DMAStatus::IoError,
            "Writing the physical-memory-map output file failed.");
    return DMAOperationResult::Success();
}

DMAResult<DMACodeCaveScanReport> DMA::FindCodeCaves(
    const std::string& requestedModule, size_t minimumSize,
    const DMACodeCaveOptions& options) const
{
    DMAResult<DMACodeCaveScanReport> result;
    if (!IsAttached()) {
        result.operation = DMAOperationResult::Failure(DMAStatus::NotAttached,
            "Attach to a process before scanning for code caves.");
        return result;
    }
    if (requestedModule.empty() || minimumSize == 0 || options.alignment == 0 ||
        options.readChunkSize == 0 ||
        options.readChunkSize > std::numeric_limits<DWORD>::max() ||
        options.paddingBytes.empty()) {
        result.operation = DMAOperationResult::Failure(DMAStatus::InvalidArgument,
            "Code-cave scanning requires a module, size, alignment, read chunk, and padding bytes.");
        return result;
    }

    auto sections = GetModuleSections(requestedModule);
    if (!sections) {
        result.operation = sections.operation;
        return result;
    }

    std::vector<DMAMemoryRegion> runtimeRegions;
    if (options.requireRuntimePagePermissions) {
        result.operation = backend->GetMemoryRegions(targetPID, false, true,
            runtimeRegions);
        if (!result.operation)
            return result;
    }

    struct ScanRange {
        uint64_t start = 0;
        uint64_t end = 0;
        std::string sectionName;
        uint32_t sectionCharacteristics = 0;
        uint64_t pageFlags = 0;
        bool readable = false;
        bool writable = false;
        bool executable = false;
    };
    std::vector<ScanRange> ranges;
    for (const auto& section : sections.value) {
        if (!PermissionMatches(section.readable, section.writable,
            section.executable, options)) {
            continue;
        }
        const uint64_t sectionSize = section.virtualSize != 0
            ? section.virtualSize : section.rawSize;
        if (sectionSize == 0)
            continue;
        const uint64_t sectionEnd = SaturatingAdd(section.address, sectionSize);
        if (!options.requireRuntimePagePermissions) {
            ranges.push_back({ section.address, sectionEnd, section.name,
                section.characteristics, 0, section.readable, section.writable,
                section.executable });
            continue;
        }
        for (const auto& region : runtimeRegions) {
            if (!PermissionMatches(region.readable, region.writable,
                region.executable, options)) {
                continue;
            }
            const uint64_t regionEnd = SaturatingAdd(region.baseAddress,
                region.size);
            const uint64_t start = std::max(section.address,
                region.baseAddress);
            const uint64_t end = std::min(sectionEnd, regionEnd);
            if (start < end) {
                ranges.push_back({ start, end, section.name,
                    section.characteristics, region.pageFlags,
                    region.readable, region.writable, region.executable });
            }
        }
    }

    std::sort(ranges.begin(), ranges.end(), [](const auto& left,
        const auto& right) {
        return left.start < right.start ||
            (left.start == right.start && left.end < right.end);
    });
    std::vector<ScanRange> merged;
    for (auto& range : ranges) {
        if (!merged.empty() && merged.back().end == range.start &&
            merged.back().sectionName == range.sectionName &&
            merged.back().readable == range.readable &&
            merged.back().writable == range.writable &&
            merged.back().executable == range.executable) {
            merged.back().end = range.end;
            merged.back().pageFlags |= range.pageFlags;
        }
        else {
            merged.push_back(std::move(range));
        }
    }

    const size_t chunkSize = std::min<size_t>(options.readChunkSize,
        std::numeric_limits<DWORD>::max());
    std::vector<uint8_t> bytes(chunkSize);
    bool stop = false;
    for (const auto& range : merged) {
        result.value.candidateBytes = SaturatingAdd(
            result.value.candidateBytes, range.end - range.start);
        uint64_t runStart = 0;
        uint64_t runLength = 0;
        auto flushRun = [&] {
            if (runLength < minimumSize) {
                runLength = 0;
                return;
            }
            uint64_t alignedStart = 0;
            if (!AlignUp(runStart, options.alignment, alignedStart)) {
                runLength = 0;
                return;
            }
            const uint64_t runEnd = SaturatingAdd(runStart, runLength);
            if (alignedStart < runEnd && runEnd - alignedStart >= minimumSize) {
                result.value.caves.push_back({ alignedStart,
                    runEnd - alignedStart, requestedModule, range.sectionName,
                    range.sectionCharacteristics, range.pageFlags,
                    range.readable, range.writable, range.executable });
                if (options.maxResults != 0 &&
                    result.value.caves.size() >= options.maxResults) {
                    stop = true;
                }
            }
            runLength = 0;
        };

        for (uint64_t cursor = range.start; cursor < range.end && !stop;) {
            const DWORD request = static_cast<DWORD>(std::min<uint64_t>(
                chunkSize, range.end - cursor));
            DWORD transferred = 0;
            const auto read = backend->ReadMemory(targetPID, cursor,
                bytes.data(), request, options.readFlags, transferred);
            const DWORD usable = std::min(request, transferred);
            result.value.scannedBytes = SaturatingAdd(
                result.value.scannedBytes, usable);
            for (DWORD index = 0; index < usable && !stop; ++index) {
                const bool padding = std::find(options.paddingBytes.begin(),
                    options.paddingBytes.end(), bytes[index]) !=
                    options.paddingBytes.end();
                if (padding) {
                    if (runLength == 0)
                        runStart = cursor + index;
                    ++runLength;
                }
                else {
                    flushRun();
                }
            }
            if (!read || usable != request) {
                flushRun();
                result.value.skippedBytes = SaturatingAdd(
                    result.value.skippedBytes, request - usable);
            }
            cursor += request;
        }
        flushRun();
        if (stop)
            break;
    }

    std::sort(result.value.caves.begin(), result.value.caves.end(),
        [](const auto& left, const auto& right) {
            return left.address < right.address;
        });
    if (result.value.candidateBytes != 0 && result.value.scannedBytes == 0) {
        result.operation = DMAOperationResult::Failure(DMAStatus::BackendError,
            "No candidate RWX memory could be read during the code-cave scan.");
    }
    else {
        result.operation = DMAOperationResult::Success(
            static_cast<size_t>(std::min<uint64_t>(result.value.scannedBytes,
                std::numeric_limits<size_t>::max())));
        if (result.value.skippedBytes != 0)
            result.operation.message = "The scan skipped one or more unreadable ranges.";
    }
    result.operation.pid = targetPID;
    result.operation.requestedBytes = static_cast<size_t>(
        std::min<uint64_t>(result.value.candidateBytes,
            std::numeric_limits<size_t>::max()));
    result.operation.transferredBytes = static_cast<size_t>(
        std::min<uint64_t>(result.value.scannedBytes,
            std::numeric_limits<size_t>::max()));
    return result;
}
