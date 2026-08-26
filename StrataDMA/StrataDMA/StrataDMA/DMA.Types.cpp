#include "DMA.Types.hpp"

#include <cstring>

std::string DMARegistryValue::AsString() const
{
    if (data.empty())
        return {};

    // REG_SZ, REG_EXPAND_SZ and REG_MULTI_SZ are stored as UTF-16LE.
    if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) {
        std::string result;
        const size_t characters = data.size() / sizeof(char16_t);
        result.reserve(characters);
        for (size_t index = 0; index < characters; ++index) {
            char16_t value = 0;
            std::memcpy(&value, data.data() + index * sizeof(value), sizeof(value));
            if (value == u'\0')
                break;
            result.push_back(value <= 0x7f ? static_cast<char>(value) : '?');
        }
        return result;
    }

    const auto* end = static_cast<const uint8_t*>(
        std::memchr(data.data(), 0, data.size()));
    const size_t length = end ? static_cast<size_t>(end - data.data()) : data.size();
    return std::string(reinterpret_cast<const char*>(data.data()), length);
}

uint32_t DMARegistryValue::AsDword(uint32_t fallback) const
{
    if (type != REG_DWORD || data.size() < sizeof(uint32_t))
        return fallback;
    uint32_t value = 0;
    std::memcpy(&value, data.data(), sizeof(value));
    return value;
}

uint64_t DMARegistryValue::AsQword(uint64_t fallback) const
{
    if (type != REG_QWORD || data.size() < sizeof(uint64_t))
        return fallback;
    uint64_t value = 0;
    std::memcpy(&value, data.data(), sizeof(value));
    return value;
}
