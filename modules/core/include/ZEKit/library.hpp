//
// Created by Damian Netter on 20/05/2025.
//

#pragma once

#define SUCCESS 0
#define FAILURE 1

#include <unordered_map>

#include "ZEKit/session.hpp"

namespace ze_kit
{
    class library
    {
        static bool initialized;
    public:
        static std::unordered_map<uint64_t, session *> sessions;

        static bool initialize();
    };
}
