# StrataDMA

[![Windows and Linux tests](https://github.com/chase-irql/StrataDMA/actions/workflows/tests.yml/badge.svg)](https://github.com/chase-irql/StrataDMA/actions/workflows/tests.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

A cross-platform C++17 wrapper around MemProcFS/VMMDLL for authorized
DMA-backed Windows memory inspection. Windows and 64-bit Linux hosts are
supported; the inspected target remains Windows. The repository vendors the
MemProcFS 5.16.5 and LeechCore headers plus Windows x64 import libraries.

Use it only on systems and processes you are authorized to inspect.

## Highlights

- Configurable VMMDLL initialization with device URIs, memory maps, extra
  arguments, plugin initialization, fallback behavior, and readable errors.
- Attach by name or PID, process/module enumeration, monitoring, exit events,
  optional automatic re-attachment, expanded Windows process metadata, and
  native/WoW64 PEB inspection.
- Strict `DMAOperationResult`/`DMAResult<T>` memory APIs that report status,
  PID, address, flags, and requested/transferred byte counts.
- Explicit process and kernel memory contexts, per-frame coherent read caching,
  page prefetch gathers, and RAII scatter batches with per-request results.
- VAD/PTE memory-region maps and filters; module sections, imports, exports,
  PDB symbol lookup, type sizes, and child offsets.
- Bounded automatic CR3/DTB recovery with candidate diagnostics and rollback,
  plus structured physical-memory-map retrieval and VMMDLL-compatible export.
- Snapshots and byte-level diffs.
- Compiled signature patterns with full/nibble wildcards, captures, relative
  address transforms, alignment, nth-match selection, section scans, and
  optional parallel scanning; code-cave discovery cross-checks PE and live PTE
  read/write/execute permissions.
- Registry hive/key/value access and MemProcFS VFS directory/file access.
- PE32/PE32+ linear module dumping with bounds validation and IAT repair.
- Experimental keyboard, cursor, and configurable Xbox controller polling,
  including edge events, reconnect discovery, dead zones, and normalized axes.
- An injectable backend and hardware-free mock tests.

## Build and package

The existing Visual Studio solution builds the example executable:

```powershell
msbuild StrataDMA\StrataDMA.sln `
  /p:Configuration=Release /p:Platform=x64
```

The root CMake project provides the reusable static target
`StrataDMA::StrataDMA`, the example, an install layout, and mock tests:

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
cmake --install build --config Release --prefix package
```

Options are `STRATA_DMA_BUILD_EXAMPLE`, `STRATA_DMA_BUILD_TESTS`, and
`STRATA_DMA_LINK_RUNTIME`. The last option is Linux-only in effect and defaults
to `ON`. Dynamic hosts that preload `leechcore.so` and `vmm.so` themselves may
turn it off; the final module must then allow and resolve the VMMDLL symbols.

At runtime, place `vmm.dll` and `leechcore.dll` beside the consuming executable.
Place `info.db` there as well when InfoDB/symbol functionality is used. The
repository contains import libraries, not the two runtime DLLs.

On Fedora, install the compiler and MemProcFS's USB dependency, unpack the
matching official MemProcFS Linux release, and point CMake at that directory:

```bash
sudo dnf install cmake gcc-c++ libusb1 ninja-build
export STRATA_DMA_RUNTIME_DIR=/opt/memprocfs
cmake -S . -B build -G Ninja \
  -DSTRATA_DMA_BUILD_EXAMPLE=ON \
  -DSTRATA_DMA_BUILD_TESTS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The Linux runtime directory must contain `vmm.so` and `leechcore.so`; keep
`info.db` and any device or symbol plugins from the same MemProcFS release in
that directory. CMake links against the two shared libraries without copying
them into the install tree. At runtime, put the directory in the loader search
path or launch with `LD_LIBRARY_PATH="$STRATA_DMA_RUNTIME_DIR"`.

## Initialization and attachment

```cpp
#include "StrataDMA/DMA.hpp"

DMA dma;
DMAInitializationOptions options;
options.device = "fpga://algo=0";
options.memoryMapPath = "C:\\DMA\\mmap.txt";
options.fallbackWithoutMemoryMap = true;
options.initializePlugins = true; // required by VFS APIs; opt-in

const auto initialized = dma.Initialize(options);
if (!initialized) {
    std::cerr << initialized.message << '\n';
    return;
}

const auto attached = dma.Attach("target.exe");
if (!attached) {
    std::cerr << attached.message << '\n';
    return;
}
```

An empty memory-map path uses `%TEMP%\mmap.txt`.

For duplicate process names, use `FindProcessIds`, inspect each
`DMAProcessInfo`, and call `Attach(pid)`. `GetProcesses`, `GetModules`, and
`GetProcessInfo` expose the underlying discovery data without returning native
VMMDLL allocations.

## Process metadata, PEB, CR3, and physical ranges

`DMAProcessInfo` includes the DTB/user DTB, EPROCESS, native and WoW64 PEB
addresses, LUID, SID, integrity level, memory/system model, session, and names.
The stable leading fields of either PEB layout can be parsed without depending
on a private full Windows structure:

```cpp
auto process = dma.GetProcessInfo(); // PID 0 means current attachment
auto peb = dma.GetProcessEnvironmentBlock(); // prefers WoW64 PEB when present
if (peb) {
    std::cout << std::hex << peb.value.imageBaseAddress << '\n';
}
```

CR3 recovery may be used before attachment when an invalid DTB prevents module
discovery. It initializes the MemProcFS procinfo plugin, waits with a bounded
timeout, parses `\\misc\\procinfo\\dtb.txt`, tests applicable candidates against
the module and MZ header, and restores the original DTB if none work:

```cpp
auto attached = dma.AttachWithCR3Recovery("target.exe");
if (!attached) {
    std::cerr << attached.operation.message << '\n';
}

// Or recover explicitly after obtaining a PID:
auto recovered = dma.RecoverCR3(pid, "target.exe");
```

`DMACR3RecoveryOptions` controls the timeout, polling, candidate sources,
candidate limit, header validation, and rollback. Each attempted DTB has its
own structured result in the returned report. CR3 recovery needs `info.db` and
the symbol-support DLLs expected by the matching MemProcFS distribution.

Physical ranges can be consumed directly or exported in the two-column,
inclusive hexadecimal format accepted by VMMDLL's `-memmap` option:

```cpp
auto ranges = dma.GetPhysicalMemoryMap(true); // true refreshes the map first
auto exported = dma.ExportPhysicalMemoryMap("C:\\DMA\\mmap.txt");
```

## Results and memory contexts

Memory operations return structured results that retain failure details:

```cpp
auto health = dma.Read<int>(player + 0x100);
if (!health) {
    std::cerr << health.operation.message << " ("
              << health.operation.transferredBytes << "/"
              << health.operation.requestedBytes << ")\n";
}

auto process = dma.ProcessContext();
auto system = dma.KernelContext(4); // adds PROCESS_WITH_KERNELMEMORY
auto value = system.Read<uint64_t>(kernelAddress);
```

`DMAStatus` distinguishes invalid input, missing attachment, partial transfer,
not-found, unsupported backend operations, I/O errors, and backend failures.
Lifecycle, raw memory, address translation, prefetch, module-dump, and input
initialization calls use the same result model. Check the returned object and
read its `message`; there is no shared last-error state.

```cpp
std::array<std::byte, 64> bytes{};
auto read = dma.ReadRaw(address, bytes.data(), bytes.size());
auto physical = dma.VirtualToPhysical(address);
auto chain = dma.ReadChain(root, { 0x10, 0x28 });
```

For a group of reads that should stay coherent during one update:

```cpp
auto frame = dma.CreateFrameContext();
auto gathered = frame.Gather({
    { player + 0x100, sizeof(int) },
    { player + 0x200, sizeof(float) * 3 }
});

// Reuses a containing gathered block instead of issuing another DMA read.
auto cachedHealth = frame.Read<int>(player + 0x100);
```

`Gather` deduplicates and prefetches involved 4 KiB pages before capturing the
requested blocks. A frame cache never silently refreshes; create a new frame or
call `Clear()` when the next update begins.

## Scatter batches

The scatter API owns its handle and is single-use:

```cpp
int health = 0;
float position[3]{};
auto batch = dma.CreateScatterBatch();
batch.AddRead(player + 0x100, health);
batch.AddRead(player + 0x200, position);

auto executed = batch.Execute();
for (const auto& request : executed.value) {
    if (!request.operation) {
        std::cerr << request.operation.message << '\n';
    }
}
```

Requests are split at 4 KiB boundaries and recombined into one result per user
request. Buffers must remain alive through `Execute`.

## Regions, modules, and symbols

```cpp
DMAMemoryRegionFilter filter;
filter.requireReadable = true;
filter.requireWritable = true;
filter.privateOnly = true;
auto writablePrivate = dma.GetMemoryRegions(filter);

auto sections = dma.GetModuleSections("target.exe");
auto imports = dma.GetModuleImports("target.exe");
auto exports = dma.GetModuleExports("target.exe");

auto pdb = dma.LoadModuleSymbols("target.exe");
if (pdb) {
    auto address = dma.ResolveSymbol(pdb.value, "SomeSymbol");
    auto size = dma.GetSymbolTypeSize(pdb.value, "SomeType");
    auto offset = dma.GetSymbolChildOffset(pdb.value, "SomeType", "Member");
}
```

VAD regions are enabled by default. Set `includePte` in the filter when PTE
regions are also needed; duplicate/overlapping entries are intentionally
preserved because they come from different VMMDLL maps.

## Snapshots and diffs

```cpp
auto before = dma.CaptureSnapshot(address, 0x1000);
// ...later...
auto after = dma.CaptureSnapshot(address, 0x1000);
auto changes = DMA::DiffSnapshots(before.value, after.value, 100);
```

Snapshots must have the same PID, base, and byte count. Each change contains
the absolute address, relative offset, old byte, and new byte.

## Advanced scanning

Compiled patterns accept `??`, full bytes, and nibble wildcards such as `A?`
or `?F`:

```cpp
auto pattern = DMA::CompilePattern("48 8B 05 ?? ?? ?? ??", {
    { "target", DMAScanCaptureKind::Rel32, 3, 4 }
});

DMAScanOptions scan;
scan.alignment = 1;
scan.parallel = true;
scan.transformFromFirstRelativeCapture = true;
auto matches = dma.ScanModuleAdvanced(
    "target.exe", pattern.value, scan, { ".text" });
```

`nthMatch` is one-based (`0` means all). `maxResults == 0` means unlimited.
Numeric relative captures contain the resolved absolute address; byte captures
retain their raw bytes.

Code-cave scanning defaults to sections that are RWX in the PE header and also
RWX in the live PTE map. It verifies actual memory bytes and accepts zero and
`0xCC` padding by default:

```cpp
DMACodeCaveOptions caves;
caves.alignment = 16;
caves.maxResults = 20;
auto found = dma.FindCodeCaves("target.exe", 128, caves);
for (const auto& cave : found.value.caves) {
    std::cout << std::hex << cave.address << " size=" << cave.size << '\n';
}
```

Padding bytes and read chunk size are configurable. Runtime permission checks
can be disabled explicitly, but keeping them enabled avoids treating PE flags
alone as proof that the live pages are writable and executable.

## Process monitoring

```cpp
dma.StartProcessMonitor("target.exe", 500, true,
    [](const DMAProcessEvent& event) {
        // Attached, Exited, Reattached, or Error.
    });
```

Call `StopProcessMonitor` before manually changing lifecycle state. Callbacks run
on the monitor thread and should return quickly. A re-attachment clears cached
modules, scans, scatter work, and input state just like a manual attachment.

## Registry and VFS

```cpp
auto hives = dma.GetRegistryHives();
auto keys = dma.EnumerateRegistryKeys("HKLM\\SOFTWARE");
auto value = dma.QueryRegistryValue(
    "HKLM\\SOFTWARE\\Vendor\\Product\\Setting");

auto root = dma.ListVfs("\\");
auto text = dma.ReadVfsFile("\\sys\\version.txt");
```

Registry values expose raw type/data plus `AsString`, `AsDword`, and `AsQword`
helpers. Raw hive writes and VFS writes are available but should be used only
when the underlying VMMDLL provider documents the path as writable. VFS calls
require successful plugin initialization.

## Input support

Keyboard edge events are consumed when read. Gamepad state has connection and
packet metadata, configurable signatures/offsets, reconnect discovery, button
edges, and normalized dead-zone-aware axes:

```cpp
auto keyboard = dma.InitKeyboard(10);
if (dma.IsKeyPressed(VK_SPACE)) { /* rising edge */ }

DMAGamepadConfig gamepad;
gamepad.pollIntervalMs = 4;
auto gamepadResult = dma.InitGamepad(gamepad);
if (gamepadResult) {
    auto state = dma.GetNormalizedGamepadState();
    if (dma.IsGamepadButtonJustPressed(XINPUT_GAMEPAD_A)) { /* edge */ }
}
```

These helpers depend on Windows kernel layouts, exports, symbols, and the
reverse-engineered `xboxgip.sys` layout. Treat their defaults as versioned
starting points and validate them on the target Windows build.

## Automated tests

All VMMDLL function calls are contained in `DMA.Backend.cpp`. Implement
`IVmmBackend` and pass a `shared_ptr` to `DMA` to test higher-level behavior
without hardware. Optional methods return `DMAStatus::Unsupported` unless the
mock overrides them.

CTest runs six hardware-independent executables. The suites cover lifecycle
and initialization errors, strict and partial memory transfers, pointer chains,
process/kernel contexts, monitoring, frame caching, RAII scatter,
patterns and captures, parallel/region/section scans, snapshots, symbols,
PE-dump reconstruction, CR3 recovery and rollback, native/WoW64 PEB parsing,
physical-map export, RWX cave scanning, registry, VFS, and unsupported backend
operations. Failure injection exercises prepare/execute, read/write, plugin,
timeout, malformed-data, and I/O paths. MSVC warnings are errors for the mock
test core. GitHub Actions runs Windows Debug/Release builds and a Fedora GCC
build.

```powershell
cmake -S . -B build -A x64 `
  -DSTRATA_DMA_BUILD_EXAMPLE=OFF `
  -DSTRATA_DMA_BUILD_TESTS=ON
cmake --build build --config Debug --parallel
ctest --test-dir build -C Debug --output-on-failure

# Run one labeled area while developing:
ctest --test-dir build -C Debug -L scatter --output-on-failure
```

The equivalent Linux label command omits the multi-config argument:

```bash
ctest --test-dir build -L scatter --output-on-failure
```

All native VMMDLL function calls are contained in `DMA.Backend.cpp`.
Implement `IVmmBackend` and pass a `shared_ptr` to `DMA` to add deterministic
fixtures without hardware. Optional methods return `DMAStatus::Unsupported`
unless the mock overrides them.

## Second-PC hardware smoke test

The example includes a finite, target-memory-read-only hardware check. Copy the
compiled example, matching VMMDLL/LeechCore runtime files, `info.db`, and symbol
support files from the same MemProcFS release to the acquisition PC, then run
on Windows:

```powershell
.\strata_dma_example.exe --hardware-test explorer.exe
```

On Linux, use the matching `.so` runtime and run:

```bash
LD_LIBRARY_PATH="$STRATA_DMA_RUNTIME_DIR" \
  ./strata_dma_example --hardware-test explorer.exe
```

It validates initialization/version discovery, the physical map, normal attach
with bounded CR3-recovery fallback, expanded process information, an MZ read,
scatter, module/section and VAD/PTE enumeration, then attempts PEB and VFS
checks. PEB and VFS are warnings because target choice and plugin availability
can make them legitimately unavailable. The runner never calls a target-memory
write API. Its console output is intended to be copied back when hardware-only
failures need diagnosis.

Hardware-dependent validation must still be done on the acquisition PC. A
useful order is initialization/version, process discovery, attach/module maps,
known reads, cross-page scatter, region/section scans, symbols, registry/VFS,
then input support. Test writes and DTB changes last.

## License

StrataDMA is free and open-source software licensed under the
[GNU Affero General Public License version 3](LICENSE). The vendored MemProcFS
and LeechCore components retain their upstream AGPLv3 and GPLv3 licenses; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for versions, file scope, and
source links.

## Source layout

- `DMA.hpp`: main public facade.
- `DMA.Types.*`: result and data-transfer types.
- `DMA.Backend.*`: injectable interface and native VMMDLL adapter.
- `DMA.Context.*`: process/kernel contexts, frame cache, and RAII scatter.
- `DMA.Advanced.cpp`: results, maps, symbols, snapshots, monitoring, registry,
  and VFS facade methods.
- `DMA.Scanner.cpp`: compiled-pattern and module scanners.
- `DMA.System.cpp`: process/PEB metadata, CR3 recovery, physical maps, and
  permission-aware code-cave discovery.
- `DMA.Module.cpp`: PE reconstruction.
- `DMA.Input.cpp`: keyboard, cursor, and gamepad support.
