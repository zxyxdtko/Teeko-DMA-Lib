#pragma once

#include "DMA.Backend.hpp"

#include <deque>
#include <memory>
#include <mutex>
#include <type_traits>
#include <vector>

struct DMAReadRequest {
    uint64_t address = 0;
    size_t size = 0;
};

struct DMAReadBlock {
    uint64_t address = 0;
    std::vector<uint8_t> bytes;
};

struct DMAScatterRequestResult {
    size_t index = 0;
    bool write = false;
    DMAOperationResult operation;
};

// Owns one VMMDLL scatter handle. Buffers supplied to AddRead/AddWrite must
// remain alive until Execute returns. A batch is single-use by design.
class DMAScatterBatch {
public:
    DMAScatterBatch() = default;
    DMAScatterBatch(std::shared_ptr<IVmmBackend> backend, DWORD pid, DWORD flags);
    ~DMAScatterBatch() = default;
    DMAScatterBatch(DMAScatterBatch&&) noexcept = default;
    DMAScatterBatch& operator=(DMAScatterBatch&&) noexcept = default;
    DMAScatterBatch(const DMAScatterBatch&) = delete;
    DMAScatterBatch& operator=(const DMAScatterBatch&) = delete;

    DMAOperationResult AddRead(uint64_t address, void* buffer, size_t size);
    DMAOperationResult AddWrite(uint64_t address, const void* buffer, size_t size);

    template <typename T>
    DMAOperationResult AddRead(uint64_t address, T& value)
    {
        static_assert(std::is_trivially_copyable<T>::value,
            "Scatter reads require a trivially copyable type");
        return AddRead(address, &value, sizeof(value));
    }

    template <typename T>
    DMAOperationResult AddWrite(uint64_t address, const T& value)
    {
        static_assert(std::is_trivially_copyable<T>::value,
            "Scatter writes require a trivially copyable type");
        return AddWrite(address, &value, sizeof(value));
    }

    DMAResult<std::vector<DMAScatterRequestResult>> Execute();
    bool IsValid() const noexcept { return session_ != nullptr; }
    size_t Size() const noexcept { return requests_.size(); }

private:
    struct Request {
        bool write = false;
        DWORD requested = 0;
        DWORD transferred = 0;
        uint64_t address = 0;
        DMAOperationResult preparation;
    };
    struct ReadChunk {
        size_t requestIndex = 0;
        DWORD requested = 0;
        DWORD transferred = 0;
    };

    std::shared_ptr<IVmmBackend> backend_;
    DWORD pid_ = 0;
    DWORD flags_ = 0;
    std::unique_ptr<IVmmScatterSession> session_;
    std::deque<Request> requests_;
    std::deque<ReadChunk> readChunks_;
    bool hasWrites_ = false;
};

// Lightweight process-bound view. It is safe to keep while DMA changes its
// primary attachment because every operation carries this context's PID.
class DMAMemoryContext {
public:
    DMAMemoryContext() = default;
    DMAMemoryContext(std::shared_ptr<IVmmBackend> backend, DWORD pid,
        ULONG64 defaultFlags = VMMDLL_FLAG_NOCACHE);

    DMAOperationResult ReadRaw(uint64_t address, void* buffer, size_t size,
        ULONG64 flags = 0) const;
    DMAOperationResult WriteRaw(uint64_t address, const void* buffer,
        size_t size) const;

    template <typename T>
    DMAResult<T> Read(uint64_t address, ULONG64 flags = 0) const
    {
        static_assert(std::is_trivially_copyable<T>::value,
            "DMA reads require a trivially copyable type");
        DMAResult<T> result;
        result.operation = ReadRaw(address, &result.value, sizeof(T), flags);
        return result;
    }

    template <typename T>
    DMAOperationResult Write(uint64_t address, const T& value) const
    {
        static_assert(std::is_trivially_copyable<T>::value,
            "DMA writes require a trivially copyable type");
        return WriteRaw(address, &value, sizeof(T));
    }

    DMAScatterBatch CreateScatter(DWORD flags = VMMDLL_FLAG_NOCACHE) const;
    DWORD GetPID() const noexcept { return pid_; }
    ULONG64 GetDefaultFlags() const noexcept { return defaultFlags_; }
    bool IsValid() const noexcept;

protected:
    std::shared_ptr<IVmmBackend> backend_;
    DWORD pid_ = 0;
    ULONG64 defaultFlags_ = VMMDLL_FLAG_NOCACHE;
};

// Per-frame coherent read cache. Gather prefetches all involved pages and
// captures blocks once; later reads reuse any containing cached block.
class DMAFrameContext : public DMAMemoryContext {
public:
    using DMAMemoryContext::DMAMemoryContext;

    DMAResult<std::vector<DMAReadBlock>> Gather(
        const std::vector<DMAReadRequest>& requests);
    DMAOperationResult ReadRaw(uint64_t address, void* buffer, size_t size,
        ULONG64 flags = 0);

    template <typename T>
    DMAResult<T> Read(uint64_t address, ULONG64 flags = 0)
    {
        static_assert(std::is_trivially_copyable<T>::value,
            "DMA reads require a trivially copyable type");
        DMAResult<T> result;
        result.operation = ReadRaw(address, &result.value, sizeof(T), flags);
        return result;
    }

    void Clear();
    size_t CachedBlockCount() const;

private:
    mutable std::mutex cacheMutex_;
    std::vector<DMAReadBlock> cache_;
};
