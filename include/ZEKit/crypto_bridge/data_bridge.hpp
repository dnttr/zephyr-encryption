//
// Created by Damian Netter on 15/06/2025.
//

#pragma once

#include "ZEKit/bridge.hpp"

namespace ze_kit
{
    class data_bridge
    {
    public:
        static void set_encryption_key(DEFAULT, UUID, jbyteArray key_buffer);
        static void set_keypair(DEFAULT, UUID, jint mode, jbyteArray key_buffer);
        static void set_partner_public_key(DEFAULT, UUID, jbyteArray key_buffer);
        static void set_nonce(DEFAULT, UUID, jint mode, jbyteArray nonce_buffer);

        static jbyteArray get_encryption_key(DEFAULT, UUID);
        static jbyteArray get_keypair(DEFAULT, UUID, jint mode);
        static jbyteArray get_nonce(DEFAULT, UUID, jint mode);

        static void generate_nonce(DEFAULT, UUID, jint mode);
        static void generate_keys(DEFAULT, UUID, jint mode);
    };
}