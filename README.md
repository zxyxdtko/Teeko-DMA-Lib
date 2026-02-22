# Teeko-DMA-Lib

A lightweight, header-only C++ DMA (Direct Memory Access) library wrapper around [MemProcFS](https://github.com/ufrisk/MemProcFS) (vmmdll). Designed for game hacking and security research, it simplifies memory operations, scatter reading, signature scanning, and module dumping.

## Features

-   **Easy Initialization**: Simple wrapper around `VMMDLL_InitializeEx`, configurable to use memory-map files and enable debugging.
-   **Process Attachment**: Detailed process finding and module base caching.
-   **Memory I/O**: Read/Write primitives for standard types and raw buffers.
-   **Advanced Memory Traversal**: Helpers for resolving RIP-relative addressing (`ResolveRelative`), reading strings (`ReadString`, `ReadWString`), and following multi-level pointer chains (`ReadChain`).
-   **Scatter Reading**: Efficiently batched memory reads using VMMDLL scatter functionality (`AddScatter`, `ExecuteScatter`).
-   **Signature Scanning**:
    -   Pattern scanning within specific modules (batch/queued via `QueueModuleScan` / `ExecuteModuleScans`).
    -   Heap scanning support (`SigScanHeap`) for locating signatures in dynamically allocated private process memory.
-   **Anti-Cheat Bypass Helpers**:
    -   `IsCR3Valid` check.
    -   `SetCR3` for DTB preservation/fixing.
    -   `ClearCache` to handle memory layout changes.
-   **Module Dumping**: `DumpModule` function to reconstruct modules from memory to disk using a **Linear Dump** strategy (fixes Section Headers and IAT).
-   **Keyboard & Mouse Support**: Reads global keyboard states (`IsKeyDown`, `IsKeyPressed`, `IsKeyReleased`) and cursor coordinates (`GetCursorPosition`) directly from `win32kbase.sys`.

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
    // 1. Initialize VMMDLL
    // arg 1: bool memMap - whether to use a local memory map file (mmap.txt)
    // arg 2: bool debug - whether to enable VMMDLL -v and -printf debug logging
    if (!g_Dma.Initialize(true, false)) {
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

### Reading Memory & Following Chains
```cpp
uint64_t base = g_Dma.GetMainBase();
int health = g_Dma.Read<int>(base + 0x1234);
std::string playerName = g_Dma.ReadString(base + 0xABCD, 32);

// Resolve relative offsets (e.g. from an instruction like mov rax, [rip+0x1234])
uint64_t absoluteAddr = g_Dma.ResolveRelative(instructionAddr, 3, 7);

// Follow pointer chains automatically
std::vector<uint64_t> offsets = {0x10, 0x20, 0x280};
uint64_t finalAddr = g_Dma.ReadChain(base + 0x5000, offsets);
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

### Signature Scanning

**Module Scanning (Batched):**
```cpp
// Queue multiple scans for a module to execute them efficiently over a single module dump
g_Dma.QueueModuleScan("svchost.exe", "RegQueryDword", "40 53 48 83 EC ? 49 8B D8");
g_Dma.QueueModuleScan("svchost.exe", "AnotherPattern", "48 8B 05 ? ? ? ? 48 85 C0");

g_Dma.ExecuteModuleScans();

uint64_t funcAddr = g_Dma.GetScanResult("RegQueryDword");
```

**Heap Scanning:**
```cpp
// Scan the entire private process heap (Warning: Potentially slow on large games)
uint64_t localPlayerPtrMatch = g_Dma.SigScanHeap("48 8B 05 ? ? ? ? 48 85 C0 74 05");
```

### Module Dumping (Linear Dump)
The `DumpModule` function now uses a **Linear Dump (Virtual Dump)** strategy. It maps the file on disk exactly as it appears in memory (Virtual Address == Raw Offset). This is highly effective for dumping packed or obfuscated modules (e.g., Themida, VMProtect).

**Note:** The output file will have `FileAlignment` set to match `SectionAlignment`. Tools like IDA Pro load this perfectly, but the raw file on disk will be larger due to memory alignment.

```cpp
if (g_Dma.DumpModule("unityplayer.dll", "C:\\Dumps\\unityplayer_dump.dll")) {
    std::cout << "[+] Module dumped successfully!" << std::endl;
}
```

### Keyboard & Mouse Support
Teeko-DMA-Lib includes built-in support for reading keyboard state and global cursor coordinates directly from kernel memory (via `win32kbase.sys`), allowing for low-latency detection without standard Windows APIs.

```cpp
// 1. Initialize Keyboard (starts a background polling thread)
// This will automatically parse PDB data/EAT data for exports needed to read from win32kbase.sys
if (g_Dma.InitKeyboard(10)) { // Poll every 10ms
    std::cout << "[+] Keyboard initialized" << std::endl;
}

// 2. Check Key State
if (g_Dma.IsKeyDown('A')) {
    std::cout << "A key is held down" << std::endl;
}

if (g_Dma.IsKeyPressed(VK_SPACE)) {
    std::cout << "Space bar was just pressed (rising edge)" << std::endl;
}

// 3. Read Mouse State
POINT pt = g_Dma.GetCursorPosition();
std::cout << "Cursor X: " << pt.x << ", Y: " << pt.y << std::endl;
```
