//
// Created by Damian Netter on 19/05/2025.
//

#include "ZEKit/library.hpp"

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
        return FAILURE;
    }

    initialized = true;
    return SUCCESS;
}
