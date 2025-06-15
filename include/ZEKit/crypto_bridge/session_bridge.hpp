//
// Created by Damian Netter on 15/06/2025.
//

#pragma once

#include "ZEKit/bridge.hpp"

namespace ze_kit
{
    class session_bridge
    {
    public:
        static void close_library(DEFAULT);

        static jlong create_session(DEFAULT);
        static jint delete_session(DEFAULT, UUID);
    };
}
