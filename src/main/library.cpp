//
// Created by Damian Netter on 19/05/2025.
//

#include "ZEKit/library.hpp"

#include "ZNBKit/debug.hpp"

#include <sodium/core.h>

std::unordered_map<uint64_t, ze_kit::session *> ze_kit::library::sessions;

bool ze_kit::library::initialized = false;

bool ze_kit::library::initialize()
{
    if (initialized)
    {
        return FAILURE;
    }

    if (sodium_init() != SUCCESS)
    {
        debug_print_cerr("[ZE] Failed to initialize libsodium");
        return FAILURE;
    }

    debug_print("[ZE] Successfully initialized libsodium");

    initialized = true;
    return SUCCESS;
}
