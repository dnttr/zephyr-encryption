//
// Created by Damian Netter on 20/05/2025.
//

#pragma once

#include "guarded_ptr.hpp"

namespace ze_kit
{
    class security
    {
        //todo: implement keys
        static guarded_ptr encrypt_symmetric(const data &aead, const data &buffer, const data &nonce);
        static guarded_ptr decrypt_symmetric(const data &aead, const data &buffer, const data &nonce);

        static guarded_ptr encrypt_asymmetric(const data &buffer, const data &nonce);
        static guarded_ptr decrypt_asymmetric(const data &buffer, const data &nonce);

        static guarded_ptr build_nonce_symmetric();
        static guarded_ptr build_nonce_asymmetric();

        static guarded_ptr build_key_symmetric();
        static guarded_ptr build_key_asymmetric();
    };
}
