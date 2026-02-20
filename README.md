# Teeko-DMA-Lib

A lightweight, header-only C++ DMA (Direct Memory Access) library wrapper around [MemProcFS](https://github.com/ufrisk/MemProcFS) (vmmdll). Designed for game hacking and security research, it simplifies memory operations, scatter reading, signature scanning, and module dumping.

## Features

-   **Easy Initialization**: Simple wrapper around `VMMDLL_Initialize`.
-   **Process Attachment**: detailed process finding and module base caching.
-   **Memory I/O**: Read/Write primitives for standard types and raw buffers.
-   **Scatter Reading**: Efficiently batched memory reads using VMMDLL scatter functionality.
-   **Signature Scanning**:
    -   Pattern scanning within specific modules.
    -   Heap scanning support.
-   **Anti-Cheat Bypass Helpers**:
    -   `IsCR3Valid` check.
    -   `SetCR3` for DTB preservation/fixing.
    -   `ClearCache` to handle memory layout changes.
-   **Module Dumping**: `DumpModule` function to reconstruct modules from memory to disk (fixes Section Headers and IAT).

## Prerequisites

-   **Hardware/Software**: A compatible DMA device (FPGA) or a software solution supported by MemProcFS.
-   **Libraries**:
    -   `vmm.dll` and `leechcore.dll` must be present in the binary directory.
    -   `vmm.lib` and `leechcore.lib` for linking.

## Installation

1.  Clone this repository.
2.  Ensure `deps/vmmdll.h` and libraries are in the correct paths.
3.  Include `Teeko-DMA/DMA.hpp` in your project.

## Usage

### Basic Setup
```cpp
#include <iostream>
#include "Teeko-DMA/DMA.hpp"

int main() {
    // 1. Initialize VMMDLL (assumes FPGA device by default)
    if (!g_Dma.Initialize()) {
        std::cout << "[-] Failed to initialize DMA" << std::endl;
        return 1;
    }

    // 2. Attach to target process
    if (!g_Dma.Attach("target_game.exe")) {
        std::cout << "[-] Failed to attach to process" << std::endl;
        return 1;
    }

    std::cout << "[+] DMA Initialized & Attached!" << std::endl;
    return 0;
}
```

### Reading Memory
```cpp
uint64_t base = g_Dma.GetMainBase();
int health = g_Dma.Read<int>(base + 0x1234);
std::string playerName = g_Dma.ReadString(base + 0xABCD, 32);
```

### Scatter Reading (High Performance)
```cpp
struct PlayerData {
    int health;
    int ammo;
    float pos[3];
};

PlayerData data;
g_Dma.AddScatter(playerPtr + 0x100, &data.health);
g_Dma.AddScatter(playerPtr + 0x104, &data.ammo);
g_Dma.AddScatter(playerPtr + 0x200, &data.pos);

if (g_Dma.ExecuteScatter()) {
    std::cout << "Health: " << data.health << std::endl;
}
```


### Module Dumping (Linear Dump)
The `DumpModule` function now uses a **Linear Dump (Virtual Dump)** strategy. It maps the file on disk exactly as it appears in memory (Virtual Address == Raw Offset). This is highly effective for dumping packed or obfuscated modules (e.g., Themida, VMProtect).

**Note:** The output file will have `FileAlignment` set to match `SectionAlignment`. Tools like IDA Pro load this perfectly, but the raw file on disk will be larger due to memory alignment.

```cpp
if (g_Dma.DumpModule("unityplayer.dll", "C:\\Dumps\\unityplayer_dump.dll")) {
    std::cout << "[+] Module dumped successfully!" << std::endl;
}
```

### Keyboard Support
Teeko-DMA-Lib includes built-in support for reading keyboard state directly from kernel memory (via `win32kbase.sys`), allowing for low-latency key detection without standard Windows APIs.

```cpp
// 1. Initialize Keyboard (starts a background polling thread)
if (g_Dma.InitKeyboard(10)) { // Poll every 10ms
    std::cout << "[+] Keyboard initialized" << std::endl;
}

// 2. Check Key State
if (g_Dma.IsKeyDown('A')) {
    std::cout << "A key is held down" << std::endl;
}

if (g_Dma.IsKeyPressed(VK_SPACE)) {
    std::cout << "Space bar was just pressed" << std::endl;
}
```
