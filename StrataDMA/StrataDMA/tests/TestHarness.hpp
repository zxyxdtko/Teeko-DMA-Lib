#pragma once

#include <exception>
#include <functional>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace strata::test {
struct TestCase {
    std::string name;
    std::function<void()> function;
};

inline std::vector<TestCase>& Registry()
{
    static std::vector<TestCase> tests;
    return tests;
}

class Registrar {
public:
    Registrar(const char* name, std::function<void()> function)
    {
        Registry().push_back({ name, std::move(function) });
    }
};

[[noreturn]] inline void Fail(const char* expression, const char* file,
    int line, const std::string& detail = {})
{
    std::ostringstream message;
    message << file << ':' << line << ": check failed: " << expression;
    if (!detail.empty())
        message << " (" << detail << ')';
    throw std::runtime_error(message.str());
}

inline int RunAll(const char* suite)
{
    size_t passed = 0;
    std::cout << "[suite] " << suite << " (" << Registry().size()
        << " cases)\n";
    for (const auto& test : Registry()) {
        try {
            test.function();
            ++passed;
            std::cout << "  [pass] " << test.name << '\n';
        }
        catch (const std::exception& exception) {
            std::cerr << "  [fail] " << test.name << ": "
                << exception.what() << '\n';
        }
        catch (...) {
            std::cerr << "  [fail] " << test.name
                << ": unknown exception\n";
        }
    }
    std::cout << "[result] " << passed << '/' << Registry().size()
        << " passed\n";
    return passed == Registry().size() ? 0 : 1;
}
}

#define STRATA_TEST_CASE(name) \
    static void name(); \
    static ::strata::test::Registrar registrar_##name(#name, &name); \
    static void name()

#define STRATA_REQUIRE(expression) \
    do { \
        if (!(expression)) \
            ::strata::test::Fail(#expression, __FILE__, __LINE__); \
    } while (false)

#define STRATA_REQUIRE_STATUS(operation, expected) \
    do { \
        const auto& strata_operation = (operation); \
        if (strata_operation.status != (expected)) \
            ::strata::test::Fail(#operation ".status == " #expected, \
                __FILE__, __LINE__, strata_operation.message); \
    } while (false)
