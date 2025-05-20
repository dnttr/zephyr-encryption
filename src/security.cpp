//
// Created by Damian Netter on 20/05/2025.
//

#define PUBLIC_KEY crypto_box_PUBLICKEYBYTES
#define PRIVATE_KEY crypto_box_SECRETKEYBYTES

#define SYMMETRIC_KEY crypto_aead_xchacha20poly1305_ietf_KEYBYTES

// I think they're equal, though for the sake of clarity let's keep them separate
#define SYMMETRIC_NONCE crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define ASYMMETRIC_NONCE crypto_box_curve25519xchacha20poly1305_NONCEBYTES

#include "security.hpp"

#include <sodium.h>

ze_kit::guarded_ptr ze_kit::security::encrypt_symmetric(const data &key, const data &aead, const data &buffer, const data &nonce)
{
    return guarded_ptr(nullptr);
}

ze_kit::guarded_ptr ze_kit::security::decrypt_symmetric(const data &key, const data &aead, const data &buffer, const data &nonce)
{
    return guarded_ptr(nullptr);
}

ze_kit::guarded_ptr ze_kit::security::encrypt_asymmetric(const data &key, const data &buffer, const data &nonce)
{
    return guarded_ptr(nullptr);
}

ze_kit::guarded_ptr ze_kit::security::decrypt_asymmetric(const data &key, const data &buffer, const data &nonce)
{
    return guarded_ptr(nullptr);
}

ze_kit::guarded_ptr ze_kit::security::build_nonce(const size_t size)
{
    const auto buffer = memory::allocate(size);
    randombytes(buffer, size);

    return guarded_ptr(new data(buffer, size));
}

ze_kit::guarded_ptr ze_kit::security::build_nonce_symmetric()
{
    return build_nonce(SYMMETRIC_NONCE);
}

ze_kit::guarded_ptr ze_kit::security::build_nonce_asymmetric()
{
    return build_nonce(ASYMMETRIC_NONCE);
}

ze_kit::guarded_ptr ze_kit::security::build_key_symmetric()
{
    const auto key = memory::allocate(SYMMETRIC_KEY);

    crypto_aead_xchacha20poly1305_ietf_keygen(key);

    return guarded_ptr(new data(key, SYMMETRIC_KEY));
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
