#include "DMA.Context.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <unordered_set>

namespace {
DMAOperationResult InvalidTransfer(const char* message, DWORD pid,
    uint64_t address, size_t size, ULONG64 flags = 0)
{
    auto result = DMAOperationResult::Failure(DMAStatus::InvalidArgument, message);
    result.pid = pid;
    result.address = address;
    result.requestedBytes = size;
    result.flags = flags;
    return result;
}
}

DMAScatterBatch::DMAScatterBatch(std::shared_ptr<IVmmBackend> backend,
    DWORD pid, DWORD flags)
    : backend_(std::move(backend)), pid_(pid), flags_(flags)
{
    if (backend_ && backend_->IsInitialized() && pid_ != 0)
        session_ = backend_->CreateScatter(pid_, flags_);
}

DMAOperationResult DMAScatterBatch::AddRead(uint64_t address, void* buffer,
    size_t size)
{
    if (!session_ || address == 0 || !buffer || size == 0 ||
        size > std::numeric_limits<DWORD>::max()) {
        return InvalidTransfer("Invalid scatter read request.", pid_, address, size);
    }
    const size_t requestIndex = requests_.size();
    requests_.push_back({ false, static_cast<DWORD>(size), 0, address, {} });
    auto& request = requests_.back();
    auto* destination = static_cast<uint8_t*>(buffer);
    uint64_t current = address;
    size_t remaining = size;
    while (remaining != 0) {
        const size_t chunkSize = std::min(remaining,
            size_t{ 0x1000 } - static_cast<size_t>(current & 0xfff));
        readChunks_.push_back({ requestIndex, static_cast<DWORD>(chunkSize), 0 });
        auto& chunk = readChunks_.back();
        request.preparation = session_->PrepareRead(current, destination,
            chunk.requested, &chunk.transferred);
        if (!request.preparation) {
            const auto failure = request.preparation;
            session_.reset();
            requests_.clear();
            readChunks_.clear();
            return failure;
        }
        current += chunkSize;
        destination += chunkSize;
        remaining -= chunkSize;
    }
    request.preparation.pid = pid_;
    request.preparation.address = address;
    request.preparation.requestedBytes = size;
    request.preparation.flags = flags_;
    return request.preparation;
}

DMAOperationResult DMAScatterBatch::AddWrite(uint64_t address,
    const void* buffer, size_t size)
{
    if (!session_ || address == 0 || !buffer || size == 0 ||
        size > std::numeric_limits<DWORD>::max()) {
        return InvalidTransfer("Invalid scatter write request.", pid_, address, size);
    }
    requests_.push_back({ true, static_cast<DWORD>(size), 0, address, {} });
    auto& request = requests_.back();
    const auto* source = static_cast<const uint8_t*>(buffer);
    uint64_t current = address;
    size_t remaining = size;
    while (remaining != 0) {
        const size_t chunkSize = std::min(remaining,
            size_t{ 0x1000 } - static_cast<size_t>(current & 0xfff));
        request.preparation = session_->PrepareWrite(current, source,
            static_cast<DWORD>(chunkSize));
        if (!request.preparation) {
            const auto failure = request.preparation;
            session_.reset();
            requests_.clear();
            readChunks_.clear();
            return failure;
        }
        current += chunkSize;
        source += chunkSize;
        remaining -= chunkSize;
    }
    request.preparation.pid = pid_;
    request.preparation.address = address;
    request.preparation.requestedBytes = size;
    hasWrites_ = true;
    return request.preparation;
}

DMAResult<std::vector<DMAScatterRequestResult>> DMAScatterBatch::Execute()
{
    DMAResult<std::vector<DMAScatterRequestResult>> result;
    if (!session_ || requests_.empty()) {
        result.operation = DMAOperationResult::Failure(DMAStatus::InvalidArgument,
            "The scatter batch is invalid or empty.");
        return result;
    }
    result.operation = session_->Execute(hasWrites_);
    result.operation.pid = pid_;
    result.value.reserve(requests_.size());
    for (const auto& chunk : readChunks_) {
        if (chunk.requestIndex < requests_.size())
            requests_[chunk.requestIndex].transferred += chunk.transferred;
    }
    size_t index = 0;
    bool partial = false;
    for (const auto& request : requests_) {
        DMAOperationResult operation = request.preparation;
        operation.transferredBytes = request.write && result.operation
            ? request.requested : request.transferred;
        if (!result.operation) {
            operation.status = result.operation.status;
            operation.message = result.operation.message;
        }
        else if (operation.transferredBytes != request.requested) {
            operation.status = DMAStatus::PartialTransfer;
            operation.message = "Scatter request returned partial data.";
            partial = true;
        }
        result.value.push_back({ index++, request.write, std::move(operation) });
    }
    if (partial && result.operation) {
        result.operation.status = DMAStatus::PartialTransfer;
        result.operation.message = "One or more scatter requests were partial.";
    }
    session_.reset();
    return result;
}

DMAMemoryContext::DMAMemoryContext(std::shared_ptr<IVmmBackend> backend,
    DWORD pid, ULONG64 defaultFlags)
    : backend_(std::move(backend)), pid_(pid), defaultFlags_(defaultFlags)
{
}

bool DMAMemoryContext::IsValid() const noexcept
{
    return backend_ && backend_->IsInitialized() && pid_ != 0;
}

DMAOperationResult DMAMemoryContext::ReadRaw(uint64_t address, void* buffer,
    size_t size, ULONG64 flags) const
{
    const ULONG64 resolvedFlags = flags == 0 ? defaultFlags_ : flags;
    if (!IsValid() || address == 0 || !buffer || size == 0 ||
        size > std::numeric_limits<DWORD>::max()) {
        return InvalidTransfer("Invalid contextual read request.", pid_, address,
            size, resolvedFlags);
    }
    DWORD transferred = 0;
    auto result = backend_->ReadMemory(pid_, address, buffer,
        static_cast<DWORD>(size), resolvedFlags, transferred);
    result.pid = pid_;
    result.address = address;
    result.requestedBytes = size;
    result.transferredBytes = transferred;
    result.flags = resolvedFlags;
    if (result && transferred != size) {
        result.status = DMAStatus::PartialTransfer;
        result.message = "The contextual read returned partial data.";
    }
    return result;
}

DMAOperationResult DMAMemoryContext::WriteRaw(uint64_t address,
    const void* buffer, size_t size) const
{
    if (!IsValid() || address == 0 || !buffer || size == 0 ||
        size > std::numeric_limits<DWORD>::max()) {
        return InvalidTransfer("Invalid contextual write request.", pid_, address, size);
    }
    auto result = backend_->WriteMemory(pid_, address, buffer,
        static_cast<DWORD>(size));
    result.pid = pid_;
    result.address = address;
    result.requestedBytes = size;
    if (result)
        result.transferredBytes = size;
    return result;
}

DMAScatterBatch DMAMemoryContext::CreateScatter(DWORD flags) const
{
    return DMAScatterBatch(backend_, pid_, flags);
}

DMAResult<std::vector<DMAReadBlock>> DMAFrameContext::Gather(
    const std::vector<DMAReadRequest>& requests)
{
    DMAResult<std::vector<DMAReadBlock>> result;
    if (!IsValid() || requests.empty()) {
        result.operation = DMAOperationResult::Failure(DMAStatus::InvalidArgument,
            "Gather requires a valid context and at least one request.");
        return result;
    }
    std::unordered_set<uint64_t> pageSet;
    for (const auto& request : requests) {
        if (request.address == 0 || request.size == 0 ||
            request.size > std::numeric_limits<DWORD>::max() ||
            request.size - 1 > std::numeric_limits<uint64_t>::max() - request.address) {
            result.operation = InvalidTransfer("Invalid gather request.", pid_,
                request.address, request.size, defaultFlags_);
            return result;
        }
        const uint64_t end = request.address + request.size - 1;
        for (uint64_t page = request.address & ~uint64_t{ 0xfff };
            page <= (end & ~uint64_t{ 0xfff }); page += 0x1000) {
            pageSet.insert(page);
            if (page > std::numeric_limits<uint64_t>::max() - 0x1000)
                break;
        }
    }
    std::vector<uint64_t> pages(pageSet.begin(), pageSet.end());
    backend_->PrefetchPages(pid_, pages);

    for (const auto& request : requests) {
        DMAReadBlock block;
        block.address = request.address;
        block.bytes.resize(request.size);
        auto operation = DMAMemoryContext::ReadRaw(request.address,
            block.bytes.data(), block.bytes.size(), defaultFlags_);
        if (!operation) {
            result.operation = operation;
            return result;
        }
        result.value.push_back(block);
    }
    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        cache_.insert(cache_.end(), result.value.begin(), result.value.end());
    }
    size_t bytes = 0;
    for (const auto& block : result.value)
        bytes += block.bytes.size();
    result.operation = DMAOperationResult::Success(bytes);
    result.operation.pid = pid_;
    return result;
}

DMAOperationResult DMAFrameContext::ReadRaw(uint64_t address, void* buffer,
    size_t size, ULONG64 flags)
{
    if (buffer && size != 0 &&
        size - 1 <= std::numeric_limits<uint64_t>::max() - address) {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        const uint64_t end = address + size;
        for (const auto& block : cache_) {
            const uint64_t blockEnd = block.address + block.bytes.size();
            if (address >= block.address && end <= blockEnd) {
                std::memcpy(buffer, block.bytes.data() + (address - block.address), size);
                auto result = DMAOperationResult::Success(size);
                result.address = address;
                result.pid = pid_;
                result.flags = flags == 0 ? defaultFlags_ : flags;
                return result;
            }
        }
    }
    auto result = DMAMemoryContext::ReadRaw(address, buffer, size, flags);
    if (result) {
        DMAReadBlock block;
        block.address = address;
        block.bytes.resize(size);
        std::memcpy(block.bytes.data(), buffer, size);
        std::lock_guard<std::mutex> lock(cacheMutex_);
        cache_.push_back(std::move(block));
    }
    return result;
}

void DMAFrameContext::Clear()
{
    std::lock_guard<std::mutex> lock(cacheMutex_);
    cache_.clear();
}

size_t DMAFrameContext::CachedBlockCount() const
{
    std::lock_guard<std::mutex> lock(cacheMutex_);
    return cache_.size();
}
