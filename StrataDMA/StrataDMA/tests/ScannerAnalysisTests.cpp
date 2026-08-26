#include "MockVmmBackend.hpp"
#include "TestHarness.hpp"

#include <algorithm>
#include <cstdint>
#include <vector>

STRATA_TEST_CASE(compiled_patterns_validate_tokens_and_captures)
{
    STRATA_REQUIRE(!DMA::CompilePattern(""));
    STRATA_REQUIRE(!DMA::CompilePattern("4"));
    STRATA_REQUIRE(!DMA::CompilePattern("GG"));
    STRATA_REQUIRE(!DMA::CompilePattern("48 8B", {
        { "outside", DMAScanCaptureKind::UInt32, 1, 4 }
    }));

    auto compiled = DMA::CompilePattern("4? ?F ??", {
        { "bytes", DMAScanCaptureKind::Bytes, 0, 3 }
    });
    STRATA_REQUIRE(compiled);
    STRATA_REQUIRE(compiled.value.bytes.size() == 3);
    STRATA_REQUIRE(compiled.value.bytes[0].mask == 0xf0);
    STRATA_REQUIRE(compiled.value.bytes[1].mask == 0x0f);
    STRATA_REQUIRE(compiled.value.bytes[2].mask == 0x00);
}

STRATA_TEST_CASE(advanced_scanning_supports_alignment_limits_and_nth_match)
{
    auto pattern = DMA::CompilePattern("48 8? ?? 05");
    STRATA_REQUIRE(pattern);
    const std::vector<uint8_t> bytes{
        0x48, 0x8f, 0xaa, 0x05,
        0x90,
        0x48, 0x80, 0xbb, 0x05,
        0x90, 0x90, 0x90,
        0x48, 0x81, 0xcc, 0x05
    };

    auto all = DMA::ScanBufferAdvanced(bytes, pattern.value, 0x1000);
    STRATA_REQUIRE(all && all.value.size() == 3);

    DMAScanOptions aligned;
    aligned.alignment = 4;
    auto alignedMatches = DMA::ScanBufferAdvanced(bytes, pattern.value,
        0x1000, aligned);
    STRATA_REQUIRE(alignedMatches && alignedMatches.value.size() == 2);
    STRATA_REQUIRE(alignedMatches.value[0].address == 0x1000);
    STRATA_REQUIRE(alignedMatches.value[1].address == 0x100c);

    DMAScanOptions nth;
    nth.nthMatch = 2;
    auto second = DMA::ScanBufferAdvanced(bytes, pattern.value, 0x1000, nth);
    STRATA_REQUIRE(second && second.value.size() == 1);
    STRATA_REQUIRE(second.value[0].address == 0x1005);

    DMAScanOptions limited;
    limited.maxResults = 1;
    auto one = DMA::ScanBufferAdvanced(bytes, pattern.value, 0x1000, limited);
    STRATA_REQUIRE(one && one.value.size() == 1);
}

STRATA_TEST_CASE(relative_and_numeric_captures_are_decoded)
{
    auto compiled = DMA::CompilePattern("E8 04 00 00 00 34 12", {
        { "destination", DMAScanCaptureKind::Rel32, 1, 0 },
        { "number", DMAScanCaptureKind::UInt16, 5, 0 },
        { "raw", DMAScanCaptureKind::Bytes, 5, 2 }
    });
    STRATA_REQUIRE(compiled);
    DMAScanOptions options;
    options.transformFromFirstRelativeCapture = true;
    auto matches = DMA::ScanBufferAdvanced(
        { 0xe8, 0x04, 0x00, 0x00, 0x00, 0x34, 0x12 },
        compiled.value, 0x5000, options);
    STRATA_REQUIRE(matches && matches.value.size() == 1);
    STRATA_REQUIRE(matches.value[0].numericCaptures.at("destination") == 0x5009);
    STRATA_REQUIRE(matches.value[0].transformedAddress == 0x5009);
    STRATA_REQUIRE(matches.value[0].numericCaptures.at("number") == 0x1234);
    STRATA_REQUIRE(matches.value[0].byteCaptures.at("raw") ==
        std::vector<uint8_t>({ 0x34, 0x12 }));
}

STRATA_TEST_CASE(parallel_scanning_matches_sequential_results)
{
    std::vector<uint8_t> bytes(1024 * 1024 + 64, 0x90);
    const std::vector<size_t> offsets{ 10, 500000, 900000 };
    for (const size_t offset : offsets) {
        bytes[offset] = 0xde;
        bytes[offset + 1] = 0xad;
        bytes[offset + 2] = 0xbe;
        bytes[offset + 3] = 0xef;
    }
    auto pattern = DMA::CompilePattern("DE AD BE EF");
    STRATA_REQUIRE(pattern);
    DMAScanOptions sequential;
    DMAScanOptions parallel;
    parallel.parallel = true;
    const auto first = DMA::ScanBufferAdvanced(bytes, pattern.value, 0x1000,
        sequential);
    const auto second = DMA::ScanBufferAdvanced(bytes, pattern.value, 0x1000,
        parallel);
    STRATA_REQUIRE(first && second);
    STRATA_REQUIRE(first.value.size() == offsets.size());
    STRATA_REQUIRE(second.value.size() == first.value.size());
    for (size_t index = 0; index < first.value.size(); ++index)
        STRATA_REQUIRE(first.value[index].address == second.value[index].address);
}

STRATA_TEST_CASE(region_filters_select_requested_vad_and_pte_properties)
{
    MockDmaFixture fixture;
    fixture.Attach();
    DMAMemoryRegionFilter writablePrivate;
    writablePrivate.requireWritable = true;
    writablePrivate.privateOnly = true;
    auto privateRegions = fixture.dma.GetMemoryRegions(writablePrivate);
    STRATA_REQUIRE(privateRegions && privateRegions.value.size() == 1);
    STRATA_REQUIRE(privateRegions.value[0].baseAddress == 0x1000);

    DMAMemoryRegionFilter executablePte;
    executablePte.includeVad = false;
    executablePte.includePte = true;
    executablePte.requireExecutable = true;
    auto pteRegions = fixture.dma.GetMemoryRegions(executablePte);
    STRATA_REQUIRE(pteRegions && pteRegions.value.size() == 2);

    DMAMemoryRegionFilter rwx;
    rwx.includeVad = false;
    rwx.includePte = true;
    rwx.requireReadable = true;
    rwx.requireWritable = true;
    rwx.requireExecutable = true;
    auto rwxRegions = fixture.dma.GetMemoryRegions(rwx);
    STRATA_REQUIRE(rwxRegions && rwxRegions.value.size() == 1);
    STRATA_REQUIRE(rwxRegions.value[0].baseAddress == 0x5000);
}

STRATA_TEST_CASE(module_metadata_and_symbol_facades_return_owned_values)
{
    MockDmaFixture fixture;
    fixture.Attach();
    auto sections = fixture.dma.GetModuleSections("test.exe");
    auto exports = fixture.dma.GetModuleExports("test.exe");
    auto imports = fixture.dma.GetModuleImports("test.exe");
    STRATA_REQUIRE(sections && sections.value.size() == 3);
    STRATA_REQUIRE(exports && exports.value[0].name == "Exported");
    STRATA_REQUIRE(imports && imports.value[0].name == "CreateFileW");

    auto symbols = fixture.dma.LoadModuleSymbols("test.exe");
    STRATA_REQUIRE(symbols && symbols.value == "test");
    auto address = fixture.dma.ResolveSymbol(symbols.value, "Symbol");
    auto lookup = fixture.dma.LookupSymbol(symbols.value, 0x234a);
    auto size = fixture.dma.GetSymbolTypeSize(symbols.value, "_TYPE");
    auto child = fixture.dma.GetSymbolChildOffset(symbols.value, "_TYPE",
        "Child");
    STRATA_REQUIRE(address && address.value == 0x2345);
    STRATA_REQUIRE(lookup && lookup.value.displacement == 5);
    STRATA_REQUIRE(size && size.value == 0x80);
    STRATA_REQUIRE(child && child.value == 0x20);
}

STRATA_TEST_CASE(snapshot_diff_reports_changes_limits_and_mismatches)
{
    MockDmaFixture fixture;
    fixture.Attach();
    fixture.backend->Fill(0x3000, 8, 0x00);
    auto before = fixture.dma.CaptureSnapshot(0x3000, 8);
    fixture.backend->memory[0x2001] = 1;
    fixture.backend->memory[0x2003] = 2;
    fixture.backend->memory[0x2007] = 3;
    auto after = fixture.dma.CaptureSnapshot(0x3000, 8);
    STRATA_REQUIRE(before && after);
    auto all = DMA::DiffSnapshots(before.value, after.value);
    STRATA_REQUIRE(all && all.value.size() == 3);
    STRATA_REQUIRE(all.value[0].address == 0x3001);
    auto limited = DMA::DiffSnapshots(before.value, after.value, 2);
    STRATA_REQUIRE(limited && limited.value.size() == 2);

    auto mismatched = after.value;
    mismatched.address++;
    auto invalid = DMA::DiffSnapshots(before.value, mismatched);
    STRATA_REQUIRE(!invalid);
    STRATA_REQUIRE_STATUS(invalid.operation, DMAStatus::InvalidArgument);
}

STRATA_TEST_CASE(module_and_section_scanning_honor_selection)
{
    MockDmaFixture fixture;
    fixture.Attach();
    const std::vector<uint8_t> signature{ 0xde, 0xad, 0xbe, 0xef };
    fixture.backend->StoreBytes(0x2100, signature.data(), signature.size());
    fixture.backend->StoreBytes(0x5100, signature.data(), signature.size());
    auto pattern = DMA::CompilePattern("DE AD BE EF");
    STRATA_REQUIRE(pattern);

    auto textOnly = fixture.dma.ScanModuleAdvanced("test.exe", pattern.value,
        {}, { ".text" });
    STRATA_REQUIRE(textOnly && textOnly.value.size() == 1);
    STRATA_REQUIRE(textOnly.value[0].address == 0x2100);

    auto rwxOnly = fixture.dma.ScanModuleAdvanced("test.exe", pattern.value,
        {}, { ".rwx" });
    STRATA_REQUIRE(rwxOnly && rwxOnly.value.size() == 1);
    STRATA_REQUIRE(rwxOnly.value[0].address == 0x5100);
}

STRATA_TEST_CASE(code_caves_require_live_rwx_permissions_and_alignment)
{
    MockDmaFixture fixture;
    fixture.Attach();
    fixture.backend->Fill(0x5000, 0x1000, 0x90);
    fixture.backend->Fill(0x5103, 0x40, 0x00);
    fixture.backend->Fill(0x6000, 0x1000, 0x00);

    DMACodeCaveOptions options;
    options.alignment = 16;
    auto caves = fixture.dma.FindCodeCaves("test.exe", 32, options);
    STRATA_REQUIRE(caves);
    STRATA_REQUIRE(caves.value.caves.size() == 1);
    STRATA_REQUIRE(caves.value.caves[0].address == 0x5110);
    STRATA_REQUIRE(caves.value.caves[0].size == 0x33);
    STRATA_REQUIRE(caves.value.caves[0].writable);
    STRATA_REQUIRE(caves.value.candidateBytes == 0x1000);

    options.maxResults = 1;
    options.paddingBytes = { 0x90 };
    auto nopCaves = fixture.dma.FindCodeCaves("test.exe", 64, options);
    STRATA_REQUIRE(nopCaves && nopCaves.value.caves.size() == 1);
}
