#include "StrataDMA/DMA.Backend.hpp"

// The mock test always supplies its own backend. This stub keeps the test
// executable independent from the VMMDLL import libraries and runtime DLLs.
std::shared_ptr<IVmmBackend> CreateVmmdllBackend()
{
    return {};
}
