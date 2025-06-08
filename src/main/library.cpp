//
// Created by Damian Netter on 19/05/2025.
//

#include "ZEKit/library.hpp"

#include <cstdio>
#include <sodium/core.h>

bool ze_kit::library::initialized = false;

bool ze_kit::library::initialize()
{
    if (initialized)
    {
        return FAILURE;
    }

    if (sodium_init() != SUCCESS)
    {
        printf("Failed to initialize libsodium");
        return FAILURE;
    }

    printf("Successfully initialized libsodium\n");

    initialized = true;
    return SUCCESS;
}
