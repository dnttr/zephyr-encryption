//
// Created by Damian Netter on 15/06/2025.
//

#pragma once

#include "ZEKit/bridge.hpp"

namespace ze_kit
{
    class encryption_bridge
    {
    public:
        static jbyteArray encrypt_data(DEFAULT, UUID, jbyteArray message_buffer, jbyteArray aead_buffer);
        static jbyteArray decrypt_data(DEFAULT, UUID, jbyteArray message_buffer, jbyteArray aead_buffer);
        static jbyteArray encrypt_with_public_key(DEFAULT, UUID, jbyteArray message_buffer);
        static jbyteArray decrypt_with_private_key(DEFAULT, UUID, jbyteArray message_buffer);
    };
}
