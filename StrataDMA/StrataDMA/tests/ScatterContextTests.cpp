#include "MockVmmBackend.hpp"
#include "TestHarness.hpp"

#include <array>
#include <cstdint>
#include <vector>

STRATA_TEST_CASE(raii_scatter_reads_writes_and_reports_each_request)
{
    MockDmaFixture fixture;
    fixture.Attach();
    const uint32_t source = 0x12345678;
    fixture.backend->Store(0x1800, source);
    uint32_t readValue = 0;
    const uint32_t writeValue = 0xaabbccdd;

    auto batch = fixture.dma.CreateScatterBatch();
    STRATA_REQUIRE(batch.IsValid());
    STRATA_REQUIRE(batch.AddRead(0x1800, readValue));
    STRATA_REQUIRE(batch.AddWrite(0x1900, writeValue));
    STRATA_REQUIRE(batch.Size() == 2);
    auto executed = batch.Execute();
    STRATA_REQUIRE(executed);
    STRATA_REQUIRE(readValue == source);
    STRATA_REQUIRE(executed.value.size() == 2);
    STRATA_REQUIRE(!executed.value[0].write);
    STRATA_REQUIRE(executed.value[0].operation.transferredBytes == sizeof(source));
    STRATA_REQUIRE(executed.value[1].write);
    const auto written = fixture.dma.Read<uint32_t>(0x1900);
    STRATA_REQUIRE(written && written.value == writeValue);

    auto secondExecution = batch.Execute();
    STRATA_REQUIRE(!secondExecution);
    STRATA_REQUIRE_STATUS(secondExecution.operation, DMAStatus::InvalidArgument);
}

STRATA_TEST_CASE(scatter_requests_are_split_at_page_boundaries)
{
    MockDmaFixture fixture;
    fixture.Attach();
    const std::array<uint8_t, 8> expected{ 1, 2, 3, 4, 5, 6, 7, 8 };
    fixture.backend->StoreBytes(0x1ffc, expected.data(), expected.size());
    std::array<uint8_t, 8> actual{};

    const size_t before = fixture.backend->scatterPrepareCalls.load();
    auto batch = fixture.dma.CreateScatterBatch();
    STRATA_REQUIRE(batch.AddRead(0x1ffc, actual));
    auto executed = batch.Execute();
    STRATA_REQUIRE(executed && actual == expected);
    STRATA_REQUIRE(fixture.backend->scatterPrepareCalls.load() - before == 2);
    STRATA_REQUIRE(executed.value[0].operation.transferredBytes == expected.size());
}

STRATA_TEST_CASE(scatter_partial_and_execution_failures_are_propagated)
{
    MockDmaFixture fixture;
    fixture.Attach();
    fixture.backend->Fill(0x1800, 16, 0x5a);
    std::array<uint8_t, 16> buffer{};

    fixture.backend->partialReadLimit = 4;
    auto partialBatch = fixture.dma.CreateScatterBatch();
    STRATA_REQUIRE(partialBatch.AddRead(0x1800, buffer));
    auto partial = partialBatch.Execute();
    STRATA_REQUIRE(!partial);
    STRATA_REQUIRE_STATUS(partial.operation, DMAStatus::PartialTransfer);
    STRATA_REQUIRE(partial.value[0].operation.transferredBytes == 4);

    fixture.backend->partialReadLimit = 0;
    fixture.backend->failScatterExecute = true;
    auto failedBatch = fixture.dma.CreateScatterBatch();
    STRATA_REQUIRE(failedBatch.AddRead(0x1800, buffer));
    auto failed = failedBatch.Execute();
    STRATA_REQUIRE(!failed);
    STRATA_REQUIRE_STATUS(failed.operation, DMAStatus::BackendError);
    STRATA_REQUIRE_STATUS(failed.value[0].operation, DMAStatus::BackendError);
}

STRATA_TEST_CASE(scatter_prepare_failure_invalidates_the_batch)
{
    MockDmaFixture fixture;
    fixture.Attach();
    fixture.backend->failScatterPrepare = true;
    uint32_t value = 0;
    auto batch = fixture.dma.CreateScatterBatch();
    auto prepared = batch.AddRead(0x1800, value);
    STRATA_REQUIRE(!prepared);
    STRATA_REQUIRE(!batch.IsValid());
    STRATA_REQUIRE(batch.Size() == 0);
    STRATA_REQUIRE(!batch.Execute());
}

STRATA_TEST_CASE(scatter_creation_and_input_validation_fail_cleanly)
{
    MockDmaFixture fixture;
    fixture.Attach();
    fixture.backend->failScatterCreate = true;
    auto invalidBatch = fixture.dma.CreateScatterBatch();
    STRATA_REQUIRE(!invalidBatch.IsValid());
    uint32_t value = 0;
    STRATA_REQUIRE_STATUS(invalidBatch.AddRead(0x1800, value),
        DMAStatus::InvalidArgument);

    fixture.backend->failScatterCreate = false;
    auto batch = fixture.dma.CreateScatterBatch();
    STRATA_REQUIRE_STATUS(batch.AddRead(0, value), DMAStatus::InvalidArgument);
    STRATA_REQUIRE_STATUS(batch.AddRead(0x1800, nullptr, sizeof(value)),
        DMAStatus::InvalidArgument);
    STRATA_REQUIRE_STATUS(batch.AddWrite(0x1800, nullptr, sizeof(value)),
        DMAStatus::InvalidArgument);
}

STRATA_TEST_CASE(frame_gather_prefetches_deduplicated_pages_and_caches_reads)
{
    MockDmaFixture fixture;
    fixture.Attach();
    const uint32_t first = 11;
    const uint32_t second = 22;
    fixture.backend->Store(0x1800, first);
    fixture.backend->Store(0x1ffc, second);

    auto frame = fixture.dma.CreateFrameContext();
    auto gathered = frame.Gather({
        { 0x1800, sizeof(first) },
        { 0x1ffc, 8 }
    });
    STRATA_REQUIRE(gathered && gathered.value.size() == 2);
    STRATA_REQUIRE(frame.CachedBlockCount() == 2);
    STRATA_REQUIRE(fixture.backend->prefetchedPages.size() == 2);

    const size_t reads = fixture.backend->readCalls.load();
    const uint32_t replacement = 99;
    fixture.backend->Store(0x1800, replacement);
    auto cached = frame.Read<uint32_t>(0x1800);
    STRATA_REQUIRE(cached && cached.value == first);
    STRATA_REQUIRE(fixture.backend->readCalls.load() == reads);

    frame.Clear();
    STRATA_REQUIRE(frame.CachedBlockCount() == 0);
    auto refreshed = frame.Read<uint32_t>(0x1800);
    STRATA_REQUIRE(refreshed && refreshed.value == replacement);
    STRATA_REQUIRE(fixture.backend->readCalls.load() == reads + 1);
}

STRATA_TEST_CASE(frame_gather_rejects_invalid_ranges_and_read_failures)
{
    MockDmaFixture fixture;
    fixture.Attach();
    auto frame = fixture.dma.CreateFrameContext();
    STRATA_REQUIRE(!frame.Gather({}));
    auto invalid = frame.Gather({ { 0, 4 } });
    STRATA_REQUIRE(!invalid);
    STRATA_REQUIRE_STATUS(invalid.operation, DMAStatus::InvalidArgument);

    fixture.backend->failReads = true;
    auto failed = frame.Gather({ { 0x1800, 4 } });
    STRATA_REQUIRE(!failed);
    STRATA_REQUIRE_STATUS(failed.operation, DMAStatus::BackendError);
    STRATA_REQUIRE(frame.CachedBlockCount() == 0);
}
