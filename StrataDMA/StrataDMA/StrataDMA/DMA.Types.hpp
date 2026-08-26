#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4200 4201)
#endif
#include "deps/vmmdll.h"
#ifdef _MSC_VER
#pragma warning(pop)
#endif
#include "DMA.Platform.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

enum class DMAStatus {
    Success,
    NotInitialized,
    NotAttached,
    InvalidArgument,
    NotFound,
    AlreadyRunning,
    PartialTransfer,
    ParseError,
    Unsupported,
    Timeout,
    BackendError,
    IoError
};

struct DMAOperationResult {
    DMAStatus status = DMAStatus::Success;
    size_t requestedBytes = 0;
    size_t transferredBytes = 0;
    uint64_t address = 0;
    DWORD pid = 0;
    ULONG64 flags = 0;
    std::string message;

    explicit operator bool() const noexcept { return status == DMAStatus::Success; }

    static DMAOperationResult Success(size_t transferred = 0)
    {
        DMAOperationResult result;
        result.transferredBytes = transferred;
        result.requestedBytes = transferred;
        return result;
    }

    static DMAOperationResult Failure(DMAStatus value, std::string detail)
    {
        DMAOperationResult result;
        result.status = value;
        result.message = std::move(detail);
        return result;
    }
};

template <typename T>
struct DMAResult {
    DMAOperationResult operation;
    T value{};

    explicit operator bool() const noexcept { return static_cast<bool>(operation); }
};

struct DMAInitializationOptions {
    std::string device = "fpga://algo=0";
    bool useMemoryMap = true;
    std::string memoryMapPath;
    bool fallbackWithoutMemoryMap = true;
    bool debug = false;
    bool waitForInitialization = false;
    bool initializePlugins = false;
    std::vector<std::string> extraArguments;
};

struct DMAProcessInfo {
    DWORD pid = 0;
    DWORD parentPid = 0;
    DWORD state = 0;
    DWORD sessionId = 0;
    uint64_t dtb = 0;
    uint64_t userDtb = 0;
    uint64_t eprocessAddress = 0;
    uint64_t pebAddress = 0;
    uint64_t wow64PebAddress = 0;
    uint64_t luid = 0;
    bool wow64 = false;
    bool userOnly = false;
    VMMDLL_MEMORYMODEL_TP memoryModel = VMMDLL_MEMORYMODEL_NA;
    VMMDLL_SYSTEM_TP systemType = VMMDLL_SYSTEM_UNKNOWN_PHYSICAL;
    VMMDLL_PROCESS_INTEGRITY_LEVEL integrityLevel =
        VMMDLL_PROCESS_INTEGRITY_LEVEL_UNKNOWN;
    std::string name;
    std::string longName;
    std::string sid;
};

// Stable, commonly useful fields parsed from either a native or WoW64 PEB.
// The raw Windows PEB is intentionally not exposed because its complete layout
// is private and changes between Windows versions.
struct DMAPebInfo {
    DWORD pid = 0;
    uint64_t address = 0;
    bool is32Bit = false;
    bool inheritedAddressSpace = false;
    bool readImageFileExecOptions = false;
    bool beingDebugged = false;
    uint64_t imageBaseAddress = 0;
    uint64_t loaderDataAddress = 0;
    uint64_t processParametersAddress = 0;
    uint64_t processHeapAddress = 0;
};

struct DMAPhysicalMemoryRange {
    uint64_t baseAddress = 0;
    uint64_t size = 0;

    uint64_t EndAddress() const noexcept
    {
        return size > UINT64_MAX - baseAddress
            ? UINT64_MAX : baseAddress + size;
    }

    uint64_t LastAddress() const noexcept
    {
        return size == 0 ? baseAddress
            : size - 1 > UINT64_MAX - baseAddress
                ? UINT64_MAX : baseAddress + size - 1;
    }
};

struct DMACR3RecoveryOptions {
    std::chrono::milliseconds timeout{ 15000 };
    std::chrono::milliseconds pollInterval{ 100 };
    bool initializePlugins = true;
    bool includeTargetPidEntries = true;
    bool includePidZeroEntries = true;
    bool includeProcessNameMatches = true;
    bool includeKnownProcessDtbs = true;
    bool validateImageHeader = true;
    bool restoreOriginalDtbOnFailure = true;
    size_t maxCandidates = 0;
};

struct DMACR3Attempt {
    uint64_t dtb = 0;
    DWORD sourcePid = 0;
    std::string sourceName;
    DMAOperationResult operation;
};

struct DMACR3RecoveryReport {
    DWORD pid = 0;
    std::string moduleName;
    uint64_t originalDtb = 0;
    uint64_t recoveredDtb = 0;
    bool recoveryNeeded = true;
    bool restoredOriginalDtb = false;
    std::vector<DMACR3Attempt> attempts;
};

struct DMAModuleInfo {
    uint64_t baseAddress = 0;
    uint64_t entryPoint = 0;
    uint32_t imageSize = 0;
    uint32_t rawFileSize = 0;
    bool wow64 = false;
    std::string name;
    std::string fullName;
};

struct DMAVersionInfo {
    uint64_t major = 0;
    uint64_t minor = 0;
    uint64_t revision = 0;
};

enum class DMAMemoryRegionSource {
    Vad,
    Pte
};

struct DMAMemoryRegion {
    uint64_t baseAddress = 0;
    uint64_t size = 0;
    uint32_t protection = 0;
    uint64_t pageFlags = 0;
    DMAMemoryRegionSource source = DMAMemoryRegionSource::Vad;
    bool readable = false;
    bool writable = false;
    bool executable = false;
    bool committed = false;
    bool privateMemory = false;
    bool image = false;
    bool mappedFile = false;
    bool stack = false;
    bool heap = false;
    bool teb = false;
    bool wow64 = false;
    std::string name;

    uint64_t EndAddress() const noexcept { return baseAddress + size; }
};

struct DMAMemoryRegionFilter {
    bool requireReadable = false;
    bool requireWritable = false;
    bool requireExecutable = false;
    bool requireCommitted = false;
    bool privateOnly = false;
    bool imageOnly = false;
    bool mappedFileOnly = false;
    bool stackOnly = false;
    bool heapOnly = false;
    bool includeVad = true;
    bool includePte = false;
};

struct DMAModuleSection {
    std::string name;
    uint64_t address = 0;
    uint32_t virtualSize = 0;
    uint32_t rawSize = 0;
    uint32_t characteristics = 0;
    bool readable = false;
    bool writable = false;
    bool executable = false;
};

struct DMACodeCaveOptions {
    bool requireReadable = true;
    bool requireWritable = true;
    bool requireExecutable = true;
    bool requireRuntimePagePermissions = true;
    std::vector<uint8_t> paddingBytes{ 0x00, 0xcc };
    size_t alignment = 1;
    size_t maxResults = 0;
    size_t readChunkSize = 1024 * 1024;
    ULONG64 readFlags = VMMDLL_FLAG_NOCACHE;
};

struct DMACodeCave {
    uint64_t address = 0;
    uint64_t size = 0;
    std::string moduleName;
    std::string sectionName;
    uint32_t sectionCharacteristics = 0;
    uint64_t pageFlags = 0;
    bool readable = false;
    bool writable = false;
    bool executable = false;
};

struct DMACodeCaveScanReport {
    uint64_t candidateBytes = 0;
    uint64_t scannedBytes = 0;
    uint64_t skippedBytes = 0;
    std::vector<DMACodeCave> caves;
};

struct DMAExportInfo {
    std::string name;
    std::string forwardedName;
    uint64_t address = 0;
    uint32_t ordinal = 0;
    bool forwarded = false;
};

struct DMAImportInfo {
    std::string module;
    std::string name;
    uint64_t address = 0;
    uint32_t firstThunkRva = 0;
    uint32_t nameRva = 0;
    uint16_t hint = 0;
    bool is32Bit = false;
};

struct DMASymbolInfo {
    std::string module;
    std::string name;
    uint64_t address = 0;
    uint32_t displacement = 0;
};

struct DMAMemorySnapshot {
    DWORD pid = 0;
    uint64_t address = 0;
    ULONG64 flags = 0;
    std::chrono::system_clock::time_point capturedAt{};
    std::vector<uint8_t> bytes;
};

struct DMAMemoryChange {
    uint64_t address = 0;
    size_t offset = 0;
    uint8_t before = 0;
    uint8_t after = 0;
};

enum class DMAScanCaptureKind {
    Bytes,
    Rel8,
    Rel32,
    UInt16,
    UInt32,
    UInt64
};

struct DMAScanCapture {
    std::string name;
    DMAScanCaptureKind kind = DMAScanCaptureKind::Bytes;
    size_t offset = 0;
    size_t size = 0;
};

struct DMAScanMatch {
    uint64_t address = 0;
    uint64_t transformedAddress = 0;
    std::unordered_map<std::string, uint64_t> numericCaptures;
    std::unordered_map<std::string, std::vector<uint8_t>> byteCaptures;
};

struct DMAScanOptions {
    size_t alignment = 1;
    size_t nthMatch = 0;
    size_t maxResults = 0;
    bool parallel = false;
    bool transformFromFirstRelativeCapture = false;
};

struct DMACompiledPatternByte {
    uint8_t value = 0;
    uint8_t mask = 0;
};

struct DMACompiledPattern {
    std::vector<DMACompiledPatternByte> bytes;
    std::vector<DMAScanCapture> captures;

    bool IsValid() const noexcept { return !bytes.empty(); }
};

enum class DMAProcessEventKind {
    Attached,
    Exited,
    Reattached,
    Error
};

struct DMAProcessEvent {
    DMAProcessEventKind kind = DMAProcessEventKind::Error;
    DWORD previousPid = 0;
    DWORD pid = 0;
    std::string processName;
    std::string message;
};

struct DMARegistryHiveInfo {
    uint64_t cmHiveAddress = 0;
    uint64_t baseBlockAddress = 0;
    uint32_t length = 0;
    std::string name;
    std::string shortName;
    std::string rootPath;
};

struct DMARegistryKeyInfo {
    std::string name;
    uint64_t lastWriteTime = 0;
};

struct DMARegistryValue {
    std::string name;
    DWORD type = 0;
    std::vector<uint8_t> data;

    std::string AsString() const;
    uint32_t AsDword(uint32_t fallback = 0) const;
    uint64_t AsQword(uint64_t fallback = 0) const;
};

struct DMAVfsEntry {
    std::string name;
    uint64_t size = 0;
    bool directory = false;
    bool compressed = false;
    uint64_t creationTime = 0;
    uint64_t lastAccessTime = 0;
    uint64_t lastWriteTime = 0;
};

struct DMAGamepadConfig {
    int pollIntervalMs = 4;
    bool debug = false;
    std::string moduleName = "xboxgip.sys";
    std::string slotArraySignature = "48 8D 05 ? ? ? ? 33 D2";
    size_t slotCount = 8;
    uint64_t slotStride = 8056;
    uint64_t activeOffset = 0x140;
    uint64_t stateOffset = 0x1CEC;
    size_t stateSize = 24;
    int16_t leftStickDeadZone = 7849;
    int16_t rightStickDeadZone = 8689;
    uint8_t triggerThreshold = 30;
};

struct GamepadState {
    uint16_t buttons = 0;
    uint8_t leftTrigger = 0;
    uint8_t rightTrigger = 0;
    int16_t thumbLX = 0;
    int16_t thumbLY = 0;
    int16_t thumbRX = 0;
    int16_t thumbRY = 0;
    bool connected = false;
    uint64_t packetNumber = 0;
};

struct DMANormalizedGamepadState {
    uint16_t buttons = 0;
    float leftTrigger = 0.0f;
    float rightTrigger = 0.0f;
    float thumbLX = 0.0f;
    float thumbLY = 0.0f;
    float thumbRX = 0.0f;
    float thumbRY = 0.0f;
    bool connected = false;
};
