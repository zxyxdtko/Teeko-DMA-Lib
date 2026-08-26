#include "TestHarness.hpp"

#ifndef STRATA_TEST_SUITE
#define STRATA_TEST_SUITE "StrataDMA tests"
#endif

int main()
{
    return strata::test::RunAll(STRATA_TEST_SUITE);
}
