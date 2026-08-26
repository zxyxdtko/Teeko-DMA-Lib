#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "DMA.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>


DMAOperationResult DMA::DumpModule(const std::string& moduleName,
    const std::string& outPath) {
    const auto failure = [&](DMAStatus status, const char* message) {
        auto result = DMAOperationResult::Failure(status, message);
        result.pid = targetPID;
        return result;
    };
    if (!IsAttached())
        return failure(DMAStatus::NotAttached,
            "DMA is not attached to a process.");
    if (moduleName.empty() || outPath.empty()) {
        return failure(DMAStatus::InvalidArgument,
            "DumpModule requires a module name and output path.");
    }
    const uint64_t modBase = GetModuleBase(moduleName);
    const uint32_t modSize = GetModuleSize(moduleName);
    if (modBase == 0 || modSize == 0)
        return failure(DMAStatus::NotFound,
            "The requested module was not found.");

    std::vector<uint8_t> buffer = DumpMemory(modBase, modSize);
    if (buffer.size() < sizeof(IMAGE_DOS_HEADER)) {
        return failure(DMAStatus::BackendError,
            "The module DOS header could not be read.");
    }

    auto* dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || dosHeader->e_lfanew < 0) {
        return failure(DMAStatus::ParseError,
            "The module does not contain a valid DOS header.");
    }

    const size_t ntOffset = static_cast<size_t>(dosHeader->e_lfanew);
    constexpr size_t signatureAndFileHeaderSize =
        sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (ntOffset > buffer.size() ||
        signatureAndFileHeaderSize > buffer.size() - ntOffset) {
        return failure(DMAStatus::ParseError,
            "The PE header offset is outside the module image.");
    }

    DWORD signature = 0;
    std::memcpy(&signature, buffer.data() + ntOffset, sizeof(signature));
    if (signature != IMAGE_NT_SIGNATURE) {
        return failure(DMAStatus::ParseError,
            "The module does not contain a valid PE signature.");
    }

    auto* fileHeader = reinterpret_cast<PIMAGE_FILE_HEADER>(
        buffer.data() + ntOffset + sizeof(DWORD));
    const size_t optionalOffset = ntOffset + signatureAndFileHeaderSize;
    if (fileHeader->SizeOfOptionalHeader > buffer.size() - optionalOffset) {
        return failure(DMAStatus::ParseError,
            "The PE optional header is truncated.");
    }

    WORD optionalMagic = 0;
    if (fileHeader->SizeOfOptionalHeader < sizeof(optionalMagic)) {
        return failure(DMAStatus::ParseError,
            "The PE optional header is missing.");
    }
    std::memcpy(&optionalMagic, buffer.data() + optionalOffset,
        sizeof(optionalMagic));

    bool is32Bit = false;
    if (optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (fileHeader->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32)) {
            return failure(DMAStatus::ParseError,
                "The PE32 optional header is truncated.");
        }
        auto* optional = reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(
            buffer.data() + optionalOffset);
        optional->FileAlignment = optional->SectionAlignment;
        if (optional->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT) {
            optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT] = {};
        }
        is32Bit = true;
    }
    else if (optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (fileHeader->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) {
            return failure(DMAStatus::ParseError,
                "The PE32+ optional header is truncated.");
        }
        auto* optional = reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(
            buffer.data() + optionalOffset);
        optional->FileAlignment = optional->SectionAlignment;
        if (optional->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT) {
            optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT] = {};
        }
    }
    else {
        return failure(DMAStatus::ParseError,
            "The module has an unsupported PE optional-header format.");
    }

    const size_t sectionOffset = optionalOffset + fileHeader->SizeOfOptionalHeader;
    const size_t sectionBytes =
        static_cast<size_t>(fileHeader->NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
    if (sectionOffset > buffer.size() || sectionBytes > buffer.size() - sectionOffset) {
        return failure(DMAStatus::ParseError,
            "The PE section table is truncated.");
    }

    auto* sections = reinterpret_cast<PIMAGE_SECTION_HEADER>(
        buffer.data() + sectionOffset);
    for (WORD index = 0; index < fileHeader->NumberOfSections; ++index) {
        auto& section = sections[index];
        section.PointerToRawData = section.VirtualAddress;
        section.SizeOfRawData = section.VirtualAddress < buffer.size()
            ? static_cast<DWORD>(std::min<size_t>(section.Misc.VirtualSize,
                buffer.size() - section.VirtualAddress))
            : 0;
    }

    std::vector<DMAImportInfo> imports;
    if (backend->GetImports(targetPID, moduleName, imports)) {
        for (const auto& entry : imports) {
            if (entry.firstThunkRva == 0)
                continue;

            const size_t thunkOffset = entry.firstThunkRva;
            const size_t thunkSize = is32Bit ? sizeof(uint32_t) : sizeof(uint64_t);
            if (thunkOffset > buffer.size() || thunkSize > buffer.size() - thunkOffset)
                continue;

            if (entry.nameRva != 0) {
                if (is32Bit) {
                    const uint32_t value = entry.nameRva;
                    std::memcpy(buffer.data() + thunkOffset, &value, sizeof(value));
                }
                else {
                    const uint64_t value = entry.nameRva;
                    std::memcpy(buffer.data() + thunkOffset, &value, sizeof(value));
                }
            }
            else if (entry.hint != 0) {
                if (is32Bit) {
                    const uint32_t value = 0x80000000U | entry.hint;
                    std::memcpy(buffer.data() + thunkOffset, &value, sizeof(value));
                }
                else {
                    const uint64_t value = 0x8000000000000000ULL | entry.hint;
                    std::memcpy(buffer.data() + thunkOffset, &value, sizeof(value));
                }
            }
        }
    }

    std::ofstream outFile(outPath, std::ios::binary | std::ios::trunc);
    if (!outFile) {
        return failure(DMAStatus::IoError,
            "Unable to open the module dump output file.");
    }

    outFile.write(reinterpret_cast<const char*>(buffer.data()),
        static_cast<std::streamsize>(buffer.size()));
    if (!outFile) {
        return failure(DMAStatus::IoError, "Writing the module dump failed.");
    }
    auto result = DMAOperationResult::Success(buffer.size());
    result.pid = targetPID;
    result.address = modBase;
    return result;
}
