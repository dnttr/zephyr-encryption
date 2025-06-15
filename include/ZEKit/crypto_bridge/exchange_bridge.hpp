//
// Created by Damian Netter on 15/06/2025.
//

#pragma once

#include "ZEKit/bridge.hpp"

namespace ze_kit
{
    class exchange_bridge
    {
    public:
        static jbyteArray create_key_exchange(DEFAULT, UUID);
        static jint process_key_exchange(DEFAULT, UUID, jbyteArray message_buffer);
    };
}