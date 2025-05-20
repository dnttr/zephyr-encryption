//
// Created by Damian Netter on 19/05/2025.
//

#include "library.hpp"

#include <sodium/core.h>

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

    return SUCCESS;
}
