# Teeko-DMA-Lib

A lightweight, header-only C++ DMA (Direct Memory Access) library wrapper around [MemProcFS](https://github.com/ufrisk/MemProcFS) (vmmdll). Designed for game hacking and security research, it simplifies memory operations, scatter reading, signature scanning, and module dumping.

## Features

- **Easy Initialization**: Simple wrapper around `VMMDLL_InitializeEx`, configurable to use memory-map files and enable debugging.
- **Process Attachment**: Process finding and module base caching.
- **Memory I/O**: Read/Write primitives for standard types and raw buffers.
- **Advanced Memory Traversal**: Helpers for resolving RIP-relative addressing (`ResolveRelative`), reading strings (`ReadString`, `ReadWString`), and following multi-level pointer chains (`ReadChain`).
- **Scatter Reading**: Efficiently batched memory reads using VMMDLL scatter functionality (`AddScatter`, `ExecuteScatter`).
- **Signature Scanning**:
    - Pattern scanning within specific modules (batch/queued via `QueueModuleScan` / `ExecuteModuleScans`).
    - Heap scanning support (`SigScanHeap`) for locating signatures in dynamically allocated private process memory.
- **Anti-Cheat Bypass Helpers**: `IsCR3Valid`, `SetCR3`, and `ClearCache`.
- **Module Dumping**: `DumpModule` reconstructs modules from memory to disk using a **Linear Dump** strategy (fixes Section Headers and IAT).
- **Keyboard & Mouse Support**: Reads global keyboard state (`IsKeyDown`, `IsKeyPressed`, `IsKeyReleased`) and cursor coordinates (`GetCursorPosition`) directly from `win32kbase.sys`, with built-in debug logging.
- **Xbox Gamepad Support**: Reads raw physical memory from the Game Input Protocol driver (`xboxgip.sys`), completely bypassing user-mode APIs, and translates the raw hardware payload into standard XInput formats on the fly.

## Prerequisites

- **Hardware/Software**: A compatible DMA device (FPGA) or a software solution supported by MemProcFS.
- **Libraries**:
    - `vmm.dll` and `leechcore.dll` must be present in the binary directory.
    - `vmm.lib` and `leechcore.lib` for linking.

## Installation

1. Clone this repository.
2. Ensure `deps/vmmdll.h` and the required libraries are in the correct paths.
3. Include `Teeko-DMA/DMA.hpp` in your project.

## Usage

### Basic Setup

The library exposes a singleton via `_DMA::Get()`.

```cpp
#include <iostream>
#include "Teeko-DMA/DMA.hpp"

auto main() -> int
{
    auto& dma = _DMA::Get();

    // arg 1: bool memMap  - use a local memory map file (mmap.txt in temp dir)
    // arg 2: bool debug   - enable VMMDLL -v and -printf verbose logging
    if (!dma.Initialize(true, false)) {
        std::cout << "[-] Failed to initialize DMA!" << std::endl;
        return -1;
    }
    std::cout << "[+] DMA initialized successfully!" << std::endl;

    if (!dma.Attach("target_game.exe")) {
        std::cout << "[-] Failed to attach to process" << std::endl;
        return -2;
    }

    return 0;
}
```

### Reading Memory & Following Chains

```cpp
uint64_t base = dma.GetMainBase();
int health = dma.Read<int>(base + 0x1234);
std::string playerName = dma.ReadString(base + 0xABCD, 32);

// Resolve a RIP-relative address (e.g. from: mov rax, [rip+0x1234])
uint64_t absoluteAddr = dma.ResolveRelative(instructionAddr, 3, 7);

// Follow a multi-level pointer chain
uint64_t finalAddr = dma.ReadChain(base + 0x5000, { 0x10, 0x20, 0x280 });
```

### Scatter Reading (High Performance)

```cpp
struct PlayerData {
    int health;
    int ammo;
    float pos[3];
};

PlayerData data;
dma.AddScatter(playerPtr + 0x100, &data.health);
dma.AddScatter(playerPtr + 0x104, &data.ammo);
dma.AddScatter(playerPtr + 0x200, &data.pos);

if (dma.ExecuteScatter()) {
    std::cout << "Health: " << data.health << std::endl;
}
```

### Signature Scanning

**Module Scanning (Batched):**

```cpp
// Queue multiple scans — a single module dump is shared across all of them
dma.QueueModuleScan("svchost.exe", "RegQueryDword", "40 53 48 83 EC ? 49 8B D8");
dma.QueueModuleScan("svchost.exe", "AnotherPattern", "48 8B 05 ? ? ? ? 48 85 C0");

dma.ExecuteModuleScans();

uint64_t funcAddr = dma.GetScanResult("RegQueryDword");
std::cout << "RegQueryDword: 0x" << std::hex << funcAddr << std::endl;
```

**Heap Scanning:**

```cpp
// Scan the entire private process heap (can be slow on large processes)
uint64_t result = dma.SigScanHeap("48 8B 05 ? ? ? ? 48 85 C0 74 05");
```

### Memory Dumping

**`DumpMemory` / `DumpMemoryEx`:**

`DumpMemory` reads from the attached target process. `DumpMemoryEx` takes an explicit PID, which is required when reading kernel-space addresses (e.g. `win32k.sys`, `win32kbase.sys`) — pass the PID ORed with `VMMDLL_PID_PROCESS_WITH_KERNELMEMORY`.

```cpp
// Standard process memory dump
std::vector<uint8_t> buf = dma.DumpMemory(address, size);

// Kernel module dump (must use explicit kernel-context PID)
std::vector<uint8_t> kbuf = dma.DumpMemoryEx(
    csrss_pid | VMMDLL_PID_PROCESS_WITH_KERNELMEMORY,
    win32k_base, win32k_size);
```

**`DumpModule` (Linear Dump to disk):**

Reconstructs a full module from memory to disk. Uses a **Linear Dump** strategy where Virtual Address == Raw Offset, which bypasses packers that manipulate section headers (e.g. VMProtect, Themida). The output loads correctly in IDA Pro.

```cpp
if (dma.DumpModule("unityplayer.dll", "C:\\Dumps\\unityplayer_dump.dll")) {
    std::cout << "[+] Module dumped successfully!" << std::endl;
}
```

### Keyboard & Mouse Support

Reads keyboard state and cursor position directly from `win32kbase.sys` kernel memory, bypassing standard Windows APIs. Supports both Win10 (EAT/PDB lookup) and Win11 (csrss session sig-scan) automatically.

```cpp
// Initialize keyboard — starts a background polling thread
// arg 1: poll interval in milliseconds
// arg 2: bool debug — prints verbose diagnostic output to console
if (dma.InitKeyboard(10, false)) {
    std::cout << "[+] Keyboard initialized" << std::endl;
}

// Key state queries
if (dma.IsKeyDown('A'))         std::cout << "A is held" << std::endl;
if (dma.IsKeyPressed(VK_SPACE)) std::cout << "Space just pressed" << std::endl;
if (dma.IsKeyReleased('D'))     std::cout << "D just released" << std::endl;

// Cursor position (requires InitKeyboard to have run first)
POINT pt = dma.GetCursorPosition();
std::cout << "Cursor: " << pt.x << ", " << pt.y << std::endl;
```

### Xbox Gamepad Support

Reads raw physical memory from the Game Input Protocol driver (`xboxgip.sys`), completely bypassing user-mode APIs like `xinput1_4.dll` and `gameinputsvc.exe`. The library handles the reverse-engineered layout and automatically translates the raw 10-bit hardware payload into standard XInput formats for perfect compatibility.

```cpp
// Initialize gamepad — locates the driver, scans for the active controller slot,
// and spins up a background polling thread.
// arg 1: poll interval in milliseconds (4ms is standard for Xbox controllers)
// arg 2: bool debug — prints signature scanning diagnostics
if (dma.InitGamepad(4, false)) {
    std::cout << "[+] Gamepad initialized" << std::endl;
}

// Check standard XInput discrete buttons
if (dma.IsGamepadButtonPressed(XINPUT_GAMEPAD_A)) {
    std::cout << "A button pressed!" << std::endl;
}

if (dma.IsGamepadButtonPressed(XINPUT_GAMEPAD_DPAD_UP)) {
    std::cout << "D-Pad Up pressed!" << std::endl;
}

// Fetch the full analog state (Triggers are scaled 0-255, sticks are -32768 to 32767)
GamepadState state = dma.GetGamepadState();
std::cout << "Left Trigger: " << (int)state.leftTrigger << std::endl;
std::cout << "Right Stick X: " << state.thumbRX << std::endl;
```