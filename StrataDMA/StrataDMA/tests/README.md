# Test suite

These tests exercise the public `DMA.hpp` API against `MockVmmBackend`; they do
not load `vmm.dll`, contact a DMA device, or access another process.

| Executable | Primary coverage |
| --- | --- |
| `strata_dma_lifecycle_tests` | initialization, attachment, metadata, reads/writes, strings, chains, contexts, monitoring |
| `strata_dma_scatter_tests` | RAII scatter, cross-page splitting, frame gathering and caching, partial/failure paths |
| `strata_dma_scanner_tests` | pattern parsing, captures, parallel scans, regions, sections, symbols, snapshots, RWX caves |
| `strata_dma_system_tests` | native/WoW64 PEB parsing, CR3 recovery/rollback/timeout, physical maps and export |
| `strata_dma_registry_vfs_tests` | registry conversion/enumeration/raw hive access, VFS list/read/write/limits |
| `strata_dma_module_tests` | PE32+ layout reconstruction, IAT repair, malformed headers, partial dumps and file errors |

Configure, build, and run from the repository root:

```powershell
cmake -S . -B build -A x64 `
  -DSTRATA_DMA_BUILD_EXAMPLE=OFF `
  -DSTRATA_DMA_BUILD_TESTS=ON
cmake --build build --config Debug --parallel
ctest --test-dir build -C Debug --output-on-failure
```

New high-level behavior should generally receive a test in the closest suite.
Extend `MockVmmBackend` only when the public behavior needs additional backend
state or a failure-injection switch. Each test case receives a fresh backend,
so cases must not depend on execution order.

Public operations return `DMAOperationResult` or `DMAResult<T>`; failure tests
assert directly on that result's status and message rather than shared error
state.
