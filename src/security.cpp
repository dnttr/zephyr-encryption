//
// Created by Damian Netter on 20/05/2025.
//

#define PUBLIC_KEY crypto_box_PUBLICKEYBYTES
#define PRIVATE_KEY crypto_box_SECRETKEYBYTES
#define SHARED_KEY crypto_aead_xchacha20poly1305_ietf_KEYBYTES

#include "security.hpp"

#include <sodium.h>

ze_kit::guarded_ptr ze_kit::security::encrypt_symmetric(const data &aead, const data &buffer, const data &nonce)
{
}

ze_kit::guarded_ptr ze_kit::security::decrypt_symmetric(const data &aead, const data &buffer, const data &nonce)
{
}

ze_kit::guarded_ptr ze_kit::security::encrypt_asymmetric(const data &buffer, const data &nonce)
{
}

ze_kit::guarded_ptr ze_kit::security::decrypt_asymmetric(const data &buffer, const data &nonce)
{
}

ze_kit::guarded_ptr ze_kit::security::build_nonce_symmetric()
{
}

ze_kit::guarded_ptr ze_kit::security::build_nonce_asymmetric()
{
}

ze_kit::guarded_ptr ze_kit::security::build_key_symmetric()
{
    const auto key = memory::allocate(SHARED_KEY);

    crypto_aead_xchacha20poly1305_ietf_keygen(key);

    return guarded_ptr(new data(key, SHARED_KEY));
}

std::pair<ze_kit::guarded_ptr, ze_kit::guarded_ptr> ze_kit::security::build_key_asymmetric()
{
    const auto public_key = memory::allocate(PUBLIC_KEY);
    const auto private_key = memory::allocate(PRIVATE_KEY);

    crypto_box_curve25519xchacha20poly1305_keypair(public_key, private_key);

    guarded_ptr public_key_ptr(new data(public_key, PUBLIC_KEY));
    guarded_ptr private_key_ptr(new data(private_key, PRIVATE_KEY));

    return std::make_pair(public_key_ptr, private_key_ptr);
}
