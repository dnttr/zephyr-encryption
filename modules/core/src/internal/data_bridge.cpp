//
// Created by Damian Netter on 15/06/2025.
//

#include "ZEKit/internal/data_bridge.hpp"

#include "ZEKit/util.hpp"

namespace ze_kit
{
    jint data_bridge::generate_nonce([[maybe_unused]] JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid,
                                const jint mode)
    {
        if (!validate_session(uuid))
        {
            return FAILURE;
        }
        const auto current_session = library::sessions[uuid];
        debug_print("[ZE] Building nonce for session: " + std::to_string(uuid));

        if (mode == static_cast<jint>(EncryptionMode::SYMMETRIC))
        {
            guarded_ptr nonce = security::build_nonce_symmetric();
            if (nonce)
            {
                current_session->symmetric_nonce = std::move(nonce);
                debug_print("[ZE] Successfully built symmetric nonce for session: " + std::to_string(uuid));
            }
            else
            {
                debug_print_cerr("[ZE] Failed to build symmetric nonce for session: " + std::to_string(uuid));
                return FAILURE;
            }
        }
        else if (mode == static_cast<jint>(EncryptionMode::ASYMMETRIC))
        {
            guarded_ptr nonce = security::build_nonce_asymmetric();
            if (nonce)
            {
                current_session->asymmetric_nonce = std::move(nonce);
                debug_print("[ZE] Successfully built asymmetric nonce for session: " + std::to_string(uuid));
            }
            else
            {
                debug_print_cerr("[ZE] Failed to build asymmetric nonce for session: " + std::to_string(uuid));
                return FAILURE;
            }
        }
        else
        {
            debug_print_cerr("[ZE] Invalid mode for nonce building: " + std::to_string(mode));
            return FAILURE;
        }

        return SUCCESS;
    }

    jint data_bridge::generate_keys([[maybe_unused]] JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid,
                               const jint mode)
    {
        if (!validate_session(uuid))
        {
            return FAILURE;
        }
        const auto current_session = library::sessions[uuid];
        debug_print("[ZE] Building key for session: " + std::to_string(uuid));

        if (mode == static_cast<jint>(EncryptionMode::SYMMETRIC))
        {
            if (guarded_ptr key = security::build_key_symmetric())
            {
                current_session->shared_key_1 = std::move(key);
                debug_print("[ZE] Successfully built symmetric key for session: " + std::to_string(uuid));
            }
            else
            {
                debug_print_cerr("[ZE] Failed to build symmetric key for session: " + std::to_string(uuid));
                return FAILURE;
            }
        }
        else if (mode == static_cast<jint>(EncryptionMode::ASYMMETRIC))
        {
            if (auto [pub_key, sec_key] = security::build_key_asymmetric(); pub_key && sec_key)
            {
                current_session->built_public_key = std::move(pub_key);
                current_session->built_private_key = std::move(sec_key);
                debug_print("[ZE] Successfully built asymmetric keys for session: " + std::to_string(uuid));
            }
            else
            {
                debug_print_cerr("[ZE] Failed to build asymmetric keys for session: " + std::to_string(uuid));
                return FAILURE;
            }
        }
        else
        {
            debug_print_cerr("[ZE] Invalid mode for key building: " + std::to_string(mode));
            return FAILURE;
        }

        return SUCCESS;
    }

    jint data_bridge::set_encryption_key(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid,
                                    const jbyteArray key_buffer)
    {
        if (!validate_session(uuid))
        {
            return FAILURE;
        }
        const auto current_session = library::sessions[uuid];
        debug_print("[ZE] Setting key for session: " + std::to_string(uuid));

        if (key_buffer == nullptr)
        {
            debug_print_cerr("[ZE] Provided key is null for session: " + std::to_string(uuid));
            return FAILURE;
        }

        auto key = util::byteArray_to_data(jni, key_buffer);
        if (key == nullptr)
        {
            debug_print_cerr("[ZE] Failed to convert key buffer to ze_kit::data for session: " + std::to_string(uuid));
            return FAILURE;
        }

        if (!security::is_key_buffer_valid(0, key->get_size()))
        {
            debug_print_cerr("[ZE] Provided key is invalid for session: " + std::to_string(uuid));
            return FAILURE;
        }

        debug_print("[ZE] Setting symmetric key for session: " + std::to_string(uuid));
        std::swap(current_session->shared_key_1, key);

        return SUCCESS;
    }

    jint data_bridge::set_keypair(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid, const jint mode,
                             const jbyteArray key_buffer)
    {
        if (!validate_session(uuid))
        {
            return FAILURE;
        }
        const auto current_session = library::sessions[uuid];
        debug_print("[ZE] Setting key for session: " + std::to_string(uuid));

        if (key_buffer == nullptr)
        {
            debug_print_cerr("[ZE] Provided key is null for session: " + std::to_string(uuid));
            return FAILURE;
        }

        auto key = util::byteArray_to_data(jni, key_buffer);
        if (key == nullptr)
        {
            debug_print_cerr("[ZE] Failed to convert key buffer to ze_kit::data for session: " + std::to_string(uuid));
            return FAILURE;
        }

        if (!security::is_key_buffer_valid(1, key->get_size()))
        {
            debug_print_cerr("[ZE] Provided key is invalid for session: " + std::to_string(uuid));
            return FAILURE;
        }

        switch (mode)
        {
        case static_cast<jint>(KeyType::PUBLIC):
            {
                debug_print("[ZE] Setting asymmetric public key for session: " + std::to_string(uuid));
                std::swap(current_session->built_public_key, key);
                break;
            }
        case static_cast<jint>(KeyType::PRIVATE):
            {
                debug_print("[ZE] Setting asymmetric private key for session: " + std::to_string(uuid));
                std::swap(current_session->built_private_key, key);
                break;
            }
        default:
            {
                debug_print_cerr("[ZE] Invalid mode for asymmetric key setting: " + std::to_string(mode));
                return FAILURE;
            }
        }

        return SUCCESS;
    }

    jint data_bridge::set_nonce(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid, const jint mode,
                           const jbyteArray nonce_buffer)
    {
        if (!validate_session(uuid))
        {
            return FAILURE;
        }
        const auto current_session = library::sessions[uuid];
        debug_print("[ZE] Setting nonce for session: " + std::to_string(uuid));

        if (nonce_buffer == nullptr)
        {
            debug_print_cerr("[ZE] Provided nonce is null for session: " + std::to_string(uuid));
            return FAILURE;
        }

        auto nonce = util::byteArray_to_data(jni, nonce_buffer);
        if (nonce == nullptr)
        {
            debug_print_cerr(
                "[ZE] Failed to convert nonce buffer to ze_kit::data for session: " + std::to_string(uuid));
            return FAILURE;
        }

        if (!security::is_nonce_buffer_valid(mode, nonce->get_size()))
        {
            debug_print_cerr("[ZE] Provided nonce is invalid for session: " + std::to_string(uuid));
            return FAILURE;
        }

        switch (mode)
        {
        case static_cast<jint>(EncryptionMode::SYMMETRIC):
            {
                debug_print("[ZE] Setting symmetric nonce for session: " + std::to_string(uuid));
                std::swap(current_session->symmetric_nonce, nonce);
                break;
            }
        case static_cast<jint>(EncryptionMode::ASYMMETRIC):
            {
                debug_print("[ZE] Setting asymmetric nonce for session: " + std::to_string(uuid));
                std::swap(current_session->asymmetric_nonce, nonce);
                break;
            }
        default:
            {
                debug_print_cerr("[ZE] Invalid mode for nonce setting: " + std::to_string(mode));
                return FAILURE;
            }
        }

        return SUCCESS;
    }

    jint data_bridge::set_partner_public_key(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid,
                                        const jbyteArray key_buffer)
    {
        if (!validate_session(uuid))
        {
            return FAILURE;
        }
        const auto current_session = library::sessions[uuid];

        debug_print("[ZE] Setting public key for session: " + std::to_string(uuid));

        if (key_buffer == nullptr)
        {
            debug_print_cerr("[ZE] Provided key is null for session: " + std::to_string(uuid));
            return FAILURE;
        }

        auto key = util::byteArray_to_data(jni, key_buffer);
        if (key == nullptr)
        {
            debug_print_cerr("[ZE] Failed to convert key buffer to ze_kit::data for session: " + std::to_string(uuid));
            return FAILURE;
        }

        std::swap(current_session->received_public_key_2, key);

        debug_print("[ZE] Successfully set public key for session: " + std::to_string(uuid));
        return SUCCESS;
    }

    jbyteArray data_bridge::get_encryption_key(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid)
    {
        if (!validate_session(uuid))
        {
            return nullptr;
        }
        debug_print("[ZE] Getting symmetric key for session: " + std::to_string(uuid));

        const auto current_session = library::sessions[uuid];

        if (!current_session->shared_key_1)
        {
            debug_print_cerr("[ZE] No symmetric key set for session: " + std::to_string(uuid));
            return nullptr;
        }

        const auto array = util::data_to_byteArray(jni, current_session->shared_key_1.get());

        if (array == nullptr)
        {
            debug_print_cerr("[ZE] Failed to convert symmetric key to byte array for session: " + std::to_string(uuid));
            return nullptr;
        }

        debug_print("[ZE] Successfully retrieved symmetric key for session: " + std::to_string(uuid));
        return array;
    }

    jbyteArray data_bridge::get_keypair(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid, const jint mode)
    {
        if (!validate_session(uuid))
        {
            return nullptr;
        }
        debug_print("[ZE] Getting asymmetric key for session: " + std::to_string(uuid));

        const auto current_session = library::sessions[uuid];

        switch (mode)
        {
        case static_cast<jint>(KeyType::PUBLIC):
            {
                if (!current_session->built_public_key)
                {
                    debug_print_cerr("[ZE] No public key set for session: " + std::to_string(uuid));
                    return nullptr;
                }

                const auto array = util::data_to_byteArray(jni, current_session->built_public_key.get());

                if (array == nullptr)
                {
                    debug_print_cerr("[ZE] Failed to convert public key to byte array for session: " + std::to_string(uuid));
                    return nullptr;
                }

                debug_print("[ZE] Successfully retrieved public key for session: " + std::to_string(uuid));

                return array;
            }
        case static_cast<jint>(KeyType::PRIVATE):
            {
                if (!current_session->built_private_key)
                {
                    debug_print_cerr("[ZE] No private key set for session: " + std::to_string(uuid));
                    return nullptr;
                }

                const auto array = util::data_to_byteArray(jni, current_session->built_private_key.get());

                if (array == nullptr)
                {
                    debug_print_cerr("[ZE] Failed to convert private key to byte array for session: " + std::to_string(uuid));
                    return nullptr;
                }

                debug_print("[ZE] Successfully retrieved private key for session: " + std::to_string(uuid));

                return array;
            }
        default:
            {
                debug_print_cerr("[ZE] Invalid mode for asymmetric key retrieval: " + std::to_string(mode));
                return nullptr;
            }
        }
    }

    jbyteArray data_bridge::get_nonce(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid, const jint mode)
    {
        if (!validate_session(uuid))
        {
            return nullptr;
        }
        const auto current_session = library::sessions[uuid];
        debug_print("[ZE] Getting nonce for session: " + std::to_string(uuid));

        switch (mode)
        {
        case static_cast<jint>(EncryptionMode::SYMMETRIC):
            {
                debug_print("[ZE] Getting symmetric nonce for session: " + std::to_string(uuid));
                if (!current_session->symmetric_nonce)
                {
                    debug_print_cerr("[ZE] No symmetric nonce set for session: " + std::to_string(uuid));
                    return nullptr;
                }
                const auto array = util::data_to_byteArray(jni, current_session->symmetric_nonce.get());

                if (array == nullptr)
                {
                    debug_print_cerr("[ZE] Failed to convert symmetric nonce to byte array for session: " + std::to_string(uuid));
                    return nullptr;
                }

                debug_print("[ZE] Successfully retrieved symmetric nonce for session: " + std::to_string(uuid));
                return array;
            }
        case static_cast<jint>(EncryptionMode::ASYMMETRIC):
            {
                debug_print("[ZE] Getting asymmetric nonce for session: " + std::to_string(uuid));
                if (!current_session->asymmetric_nonce)
                {
                    debug_print_cerr("[ZE] No asymmetric nonce set for session: " + std::to_string(uuid));
                    return nullptr;
                }

                const auto array = util::data_to_byteArray(jni, current_session->asymmetric_nonce.get());

                if (array == nullptr)
                {
                    debug_print_cerr("[ZE] Failed to convert asymmetric nonce to byte array for session: " + std::to_string(uuid));
                    return nullptr;
                }

                debug_print("[ZE] Successfully retrieved asymmetric nonce for session: " + std::to_string(uuid));
                return array;
            }
        default:
            {
                debug_print_cerr("[ZE] Invalid mode for nonce retrieval: " + std::to_string(mode));
                return nullptr;
            }
        }
    }
}
