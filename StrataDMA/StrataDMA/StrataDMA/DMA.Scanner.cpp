#include "DMA.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <future>
#include <limits>
#include <sstream>

namespace {
int HexValue(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    value = static_cast<char>(std::tolower(static_cast<unsigned char>(value)));
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

bool MatchesAt(const std::vector<uint8_t>& buffer, size_t offset,
    const DMACompiledPattern& pattern)
{
    for (size_t index = 0; index < pattern.bytes.size(); ++index) {
        const auto& byte = pattern.bytes[index];
        if ((buffer[offset + index] & byte.mask) != (byte.value & byte.mask))
            return false;
    }
    return true;
}

std::vector<size_t> ScanOffsets(const std::vector<uint8_t>& buffer,
    const DMACompiledPattern& pattern, size_t begin, size_t end, size_t alignment,
    uint64_t baseAddress)
{
    std::vector<size_t> offsets;
    if (pattern.bytes.empty() || buffer.size() < pattern.bytes.size())
        return offsets;
    const size_t last = std::min(end, buffer.size() - pattern.bytes.size() + 1);
    for (size_t offset = begin; offset < last; ++offset) {
        if (alignment > 1 && (baseAddress + offset) % alignment != 0)
            continue;
        if (MatchesAt(buffer, offset, pattern))
            offsets.push_back(offset);
    }
    return offsets;
}

uint64_t ReadUnsigned(const uint8_t* data, size_t size)
{
    uint64_t value = 0;
    std::memcpy(&value, data, std::min(size, sizeof(value)));
    return value;
}

std::string Lower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}
}

DMAResult<DMACompiledPattern> DMA::CompilePattern(
    const std::string& signature, const std::vector<DMAScanCapture>& captures)
{
    DMAResult<DMACompiledPattern> result;
    std::istringstream stream(signature);
    std::string token;
    while (stream >> token) {
        if (token.size() == 1 && token[0] == '?')
            token = "??";
        if (token.size() != 2) {
            result.operation = DMAOperationResult::Failure(DMAStatus::ParseError,
                "Pattern tokens must be two hexadecimal/wildcard nibbles.");
            return result;
        }
        DMACompiledPatternByte byte;
        for (size_t nibble = 0; nibble < 2; ++nibble) {
            if (token[nibble] == '?')
                continue;
            const int value = HexValue(token[nibble]);
            if (value < 0) {
                result.operation = DMAOperationResult::Failure(DMAStatus::ParseError,
                    "Pattern contains a non-hexadecimal token.");
                result.value.bytes.clear();
                return result;
            }
            const unsigned shift = nibble == 0 ? 4 : 0;
            byte.value |= static_cast<uint8_t>(value << shift);
            byte.mask |= static_cast<uint8_t>(0x0f << shift);
        }
        result.value.bytes.push_back(byte);
    }
    if (result.value.bytes.empty()) {
        result.operation = DMAOperationResult::Failure(DMAStatus::ParseError,
            "Pattern cannot be empty.");
        return result;
    }
    for (const auto& capture : captures) {
        size_t required = capture.size;
        if (required == 0) {
            switch (capture.kind) {
            case DMAScanCaptureKind::Rel8: required = 1; break;
            case DMAScanCaptureKind::Rel32:
            case DMAScanCaptureKind::UInt32: required = 4; break;
            case DMAScanCaptureKind::UInt16: required = 2; break;
            case DMAScanCaptureKind::UInt64: required = 8; break;
            case DMAScanCaptureKind::Bytes: break;
            }
        }
        if (required == 0 || capture.offset > result.value.bytes.size() ||
            required > result.value.bytes.size() - capture.offset) {
            result.operation = DMAOperationResult::Failure(DMAStatus::InvalidArgument,
                "A pattern capture lies outside the compiled pattern.");
            result.value.bytes.clear();
            return result;
        }
        auto normalized = capture;
        normalized.size = required;
        result.value.captures.push_back(std::move(normalized));
    }
    result.operation = DMAOperationResult::Success(result.value.bytes.size());
    return result;
}

DMAResult<std::vector<DMAScanMatch>> DMA::ScanBufferAdvanced(
    const std::vector<uint8_t>& buffer, const DMACompiledPattern& pattern,
    uint64_t baseAddress, const DMAScanOptions& options)
{
    DMAResult<std::vector<DMAScanMatch>> result;
    if (!pattern.IsValid() || options.alignment == 0) {
        result.operation = DMAOperationResult::Failure(DMAStatus::InvalidArgument,
            "A valid pattern and non-zero alignment are required.");
        return result;
    }
    std::vector<size_t> offsets;
    const size_t candidates = buffer.size() >= pattern.bytes.size()
        ? buffer.size() - pattern.bytes.size() + 1 : 0;
    const unsigned workers = options.parallel && candidates >= 1024 * 1024
        ? std::max(1u, std::thread::hardware_concurrency()) : 1u;
    if (workers == 1) {
        offsets = ScanOffsets(buffer, pattern, 0, candidates, options.alignment,
            baseAddress);
    }
    else {
        std::vector<std::future<std::vector<size_t>>> jobs;
        const size_t chunk = (candidates + workers - 1) / workers;
        for (unsigned worker = 0; worker < workers; ++worker) {
            const size_t begin = std::min(candidates, chunk * worker);
            const size_t end = std::min(candidates, begin + chunk);
            if (begin == end)
                continue;
            jobs.push_back(std::async(std::launch::async,
                [&buffer, &pattern, begin, end, &options, baseAddress] {
                    return ScanOffsets(buffer, pattern, begin, end,
                        options.alignment, baseAddress);
                }));
        }
        for (auto& job : jobs) {
            auto part = job.get();
            offsets.insert(offsets.end(), part.begin(), part.end());
        }
        std::sort(offsets.begin(), offsets.end());
    }

    if (options.nthMatch != 0) {
        if (options.nthMatch > offsets.size())
            offsets.clear();
        else
            offsets = { offsets[options.nthMatch - 1] };
    }
    if (options.maxResults != 0 && offsets.size() > options.maxResults)
        offsets.resize(options.maxResults);

    for (const size_t offset : offsets) {
        DMAScanMatch match;
        match.address = baseAddress + offset;
        for (const auto& capture : pattern.captures) {
            const uint8_t* data = buffer.data() + offset + capture.offset;
            if (capture.kind == DMAScanCaptureKind::Bytes) {
                match.byteCaptures[capture.name] =
                    std::vector<uint8_t>(data, data + capture.size);
                continue;
            }
            uint64_t value = ReadUnsigned(data, capture.size);
            bool relative = false;
            if (capture.kind == DMAScanCaptureKind::Rel8) {
                const auto displacement = static_cast<int8_t>(value);
                value = static_cast<uint64_t>(static_cast<int64_t>(
                    match.address + capture.offset + 1) + displacement);
                relative = true;
            }
            else if (capture.kind == DMAScanCaptureKind::Rel32) {
                int32_t displacement = 0;
                std::memcpy(&displacement, data, sizeof(displacement));
                value = static_cast<uint64_t>(static_cast<int64_t>(
                    match.address + capture.offset + 4) + displacement);
                relative = true;
            }
            match.numericCaptures[capture.name] = value;
            if (relative && options.transformFromFirstRelativeCapture &&
                match.transformedAddress == 0) {
                match.transformedAddress = value;
            }
        }
        result.value.push_back(std::move(match));
    }
    result.operation = DMAOperationResult::Success(buffer.size());
    return result;
}

DMAResult<std::vector<DMAScanMatch>> DMA::ScanModuleAdvanced(
    const std::string& moduleName, const DMACompiledPattern& pattern,
    const DMAScanOptions& options,
    const std::vector<std::string>& sectionNames)
{
    DMAResult<std::vector<DMAScanMatch>> result;
    const uint64_t base = GetModuleBase(moduleName);
    const uint32_t size = GetModuleSize(moduleName);
    if (base == 0 || size == 0) {
        result.operation = DMAOperationResult::Failure(DMAStatus::NotFound,
            "The requested module was not found.");
        return result;
    }
    if (sectionNames.empty()) {
        auto bytes = DumpMemory(base, size);
        if (bytes.empty()) {
            result.operation = DMAOperationResult::Failure(DMAStatus::BackendError,
                "Unable to read the module image.");
            return result;
        }
        return ScanBufferAdvanced(bytes, pattern, base, options);
    }

    auto sections = GetModuleSections(moduleName);
    if (!sections)
        return { sections.operation, {} };
    std::vector<std::string> requested;
    for (const auto& name : sectionNames)
        requested.push_back(Lower(name));
    DMAScanOptions sectionOptions = options;
    sectionOptions.nthMatch = 0;
    sectionOptions.maxResults = 0;
    for (const auto& section : sections.value) {
        if (std::find(requested.begin(), requested.end(), Lower(section.name)) ==
            requested.end()) {
            continue;
        }
        const size_t sectionSize = section.virtualSize != 0
            ? section.virtualSize : section.rawSize;
        auto bytes = DumpMemory(section.address, sectionSize);
        if (bytes.empty())
            continue;
        auto matches = ScanBufferAdvanced(bytes, pattern, section.address,
            sectionOptions);
        if (!matches) {
            result.operation = matches.operation;
            return result;
        }
        result.value.insert(result.value.end(), matches.value.begin(),
            matches.value.end());
    }
    std::sort(result.value.begin(), result.value.end(),
        [](const auto& left, const auto& right) { return left.address < right.address; });
    if (options.nthMatch != 0) {
        if (options.nthMatch <= result.value.size())
            result.value = { result.value[options.nthMatch - 1] };
        else
            result.value.clear();
    }
    if (options.maxResults != 0 && result.value.size() > options.maxResults)
        result.value.resize(options.maxResults);
    result.operation = DMAOperationResult::Success();
    return result;
}
