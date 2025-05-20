//
// Created by Damian Netter on 20/05/2025.
//

#include "library.hpp"
#include "catch2/catch_test_macros.hpp"

TEST_CASE("Library initialization", "[library]")
{
    /*
     * ZEKit uses 0 as a success code and 1 as a failure code.
     * Which makes it different compared to default C definition.
     */
    REQUIRE(ze_kit::library::initialize() == 0);
}