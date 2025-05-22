//
// Created by Damian Netter on 20/05/2025.
//

#include "guarded_ptr.hpp"

#include "data.hpp"
#include "memory.hpp"
#include "catch2/catch_test_macros.hpp"

TEST_CASE("Construction and destruction", "[guarded_ptr]")
{
    const auto buffer = ze_kit::memory::allocate(10);
    auto data = new ze_kit::data(buffer, 10);

    const ze_kit::guarded_ptr ptr(data);
    REQUIRE(ptr.get() == data);
}

TEST_CASE("Nullptr handling", "[guarded_ptr]")
{
    const ze_kit::guarded_ptr ptr(nullptr);
    REQUIRE(ptr.get() == nullptr);
}