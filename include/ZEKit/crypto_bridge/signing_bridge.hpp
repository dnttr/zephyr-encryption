//
// Created by Damian Netter on 15/06/2025.
//


#pragma once

#include "ZEKit/bridge.hpp"

namespace ze_kit
{
    class signing_bridge
    {
    public:
        static jbyteArray get_signing_public_key(DEFAULT, UUID);
        static jbyteArray get_base_signing_key(DEFAULT, UUID);

        static jint set_signing_public_key(DEFAULT, UUID, jbyteArray key_buffer);

        static jint derive_signing_keys(DEFAULT, UUID, jint mode);
        static jint finalize_signing_key(DEFAULT, UUID, jint mode);
        static jint generate_signing_keypair(DEFAULT, UUID);

        static jbyteArray create_signature(DEFAULT, UUID, jbyteArray message_buffer);
        static jint verify_signature(DEFAULT, UUID, jbyteArray hash_buffer, jbyteArray message_buffer);
    };
}
