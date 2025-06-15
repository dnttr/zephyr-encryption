//
// Created by Damian Netter on 15/06/2025.
//

#include "ZEKit/crypto_bridge/signing_bridge.hpp"

#include "ZEKit/util.hpp"

namespace ze_kit
{
    jint signing_bridge::set_signing_public_key(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid,
                                   const jbyteArray key_buffer)
    {
        if (!validate_session(uuid))
        {
            return FAILURE;
        }
        const auto current_session = library::sessions[uuid];

        if (key_buffer == nullptr)
        {
            debug_print_cerr("[ZE] Provided key is null for session: " + std::to_string(uuid));
            return FAILURE;
        }

        auto key_data = util::byteArray_to_data(jni, key_buffer);
        if (key_data == nullptr)
        {
            debug_print_cerr("[ZE] Failed to convert key buffer to ze_kit::data for session: " + std::to_string(uuid));
            return FAILURE;
        }

        current_session->received_public_key_0 = std::move(key_data);

        return SUCCESS;
    }

    jbyteArray signing_bridge::create_signature(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid,
                                        const jbyteArray message_buffer)
    {
        if (!validate_session(uuid))
        {
            return nullptr;
        }
        const auto current_session = library::sessions[uuid];
        debug_print("[ZE] Building hash for session: " + std::to_string(uuid));

        if (message_buffer == nullptr)
        {
            debug_print_cerr("[ZE] Provided message is null for session: " + std::to_string(uuid));
            return nullptr;
        }

        const auto message_ptr = util::byteArray_to_data(jni, message_buffer);
        if (message_ptr == nullptr)
        {
            debug_print_cerr(
                "[ZE] Failed to convert message buffer to ze_kit::data for session: " + std::to_string(uuid));
            return nullptr;
        }

        if (current_session->shared_key_0 == nullptr)
        {
            debug_print_cerr("[ZE] No hash key set for session: " + std::to_string(uuid));
            return nullptr;
        }

        const auto hash = security::build_hash_using_shared_key(*current_session->shared_key_0, *message_ptr);
        if (hash == nullptr)
        {
            debug_print_cerr("[ZE] Failed to build hash for session: " + std::to_string(uuid));
            return nullptr;
        }

        return util::data_to_byteArray(jni, hash.get());
    }

    jbyteArray signing_bridge::get_signing_public_key(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid)
    {
        if (!validate_session(uuid))
        {
            return nullptr;
        }
        const auto current_session = library::sessions[uuid];

        if (!current_session->received_public_key_0)
        {
            debug_print_cerr("[ZE] No received public key available for session: " + std::to_string(uuid));
            return nullptr;
        }

        return util::data_to_byteArray(jni, current_session->received_public_key_0.get());
    }

    jbyteArray signing_bridge::get_base_signing_key(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid)
    {
        if (!validate_session(uuid))
        {
            return nullptr;
        }
        const auto current_session = library::sessions[uuid];

        if (!current_session->shared_key_0_base.first)
        {
            debug_print_cerr("[ZE] No base public key available for session: " + std::to_string(uuid));
            return nullptr;
        }

        return util::data_to_byteArray(jni, current_session->shared_key_0_base.first.get());
    }

    jint signing_bridge::verify_signature(JNIEnv *jni, [[maybe_unused]] jobject object, const jlong uuid,
                                  const jbyteArray hash_buffer,
                                  const jbyteArray message_buffer)
    {
        if (!validate_session(uuid))
        {
            return FAILURE;
        }
        const auto current_session = library::sessions[uuid];
        debug_print("[ZE] Comparing hash for session: " + std::to_string(uuid));

        if (message_buffer == nullptr || hash_buffer == nullptr)
        {
            debug_print_cerr("[ZE] Provided message or hash is null for session: " + std::to_string(uuid));
            return FAILURE;
        }

        const auto message_ptr = util::byteArray_to_data(jni, message_buffer);
        const auto hash_ptr = util::byteArray_to_data(jni, hash_buffer);

        if (message_ptr == nullptr || hash_ptr == nullptr)
        {
            debug_print_cerr(
                "[ZE] Failed to convert message or hash buffer to ze_kit::data for session: " + std::to_string(uuid));
            return FAILURE;
        }

        if (current_session->shared_key_0 == nullptr)
        {
            debug_print_cerr("[ZE] No hash key set for session: " + std::to_string(uuid));
            return FAILURE;
        }

        const bool integrity = security::compare_hash(*current_session->shared_key_0, *hash_ptr, *message_ptr);

        debug_print(
            "[ZE] Hash comparison result for session: " + std::to_string(uuid) + " - " + (integrity ? "MATCH" :
                "NO MATCH"));

        return integrity ? SUCCESS : FAILURE;
    }

    jint signing_bridge::derive_signing_keys([[maybe_unused]] JNIEnv *, [[maybe_unused]] jobject, const jlong uuid,
                                     const jint mode)
    {
        if (!validate_session(uuid))
        {
            return FAILURE;
        }
        const auto current_session = library::sessions[uuid];
        debug_print("[ZE] Deriving secret key for session: " + std::to_string(uuid));

        if (current_session->received_public_key_0 == nullptr)
        {
            debug_print_cerr("[ZE] Provided public key is null for session: " + std::to_string(uuid));
            return FAILURE;
        }

        if (current_session->shared_key_0_base.first == nullptr || current_session->shared_key_0_base.second == nullptr)
        {
            debug_print_cerr("[ZE] No public or private BASE key set for session: " + std::to_string(uuid));
            return FAILURE;
        }

        const auto public_key = *current_session->shared_key_0_base.first;
        const auto private_key = *current_session->shared_key_0_base.second;

        std::pair<guarded_ptr, guarded_ptr> derived;

        switch (mode)
        {
        case static_cast<jint>(SideType::SERVER):
            {
                derived = security::derive_server_key(*current_session->received_public_key_0, public_key, private_key);
                break;
            }
        case static_cast<jint>(SideType::CLIENT):
            {
                derived = security::derive_client_key(*current_session->received_public_key_0, public_key, private_key);
                break;
            }
        default:
            {
                debug_print_cerr("[ZE] Invalid mode for deriving secret key: " + std::to_string(mode));
                return FAILURE;
            }
        }

        if (derived.first == nullptr || derived.second == nullptr)
        {
            debug_print_cerr("[ZE] Failed to derive keys for session: " + std::to_string(uuid));
            return FAILURE;
        }

        current_session->shared_key_0_derivative = std::move(derived);
        debug_print("[ZE] Successfully derived secret key for session: " + std::to_string(uuid));

        return SUCCESS;
    }

    jint signing_bridge::generate_signing_keypair([[maybe_unused]] JNIEnv *, [[maybe_unused]] jobject, const jlong uuid)
    {
        if (!validate_session(uuid))
        {
            return FAILURE;
        }
        const auto current_session = library::sessions[uuid];
        debug_print("[ZE] Building derivable key for session: " + std::to_string(uuid));

        auto keypair = security::build_d_keypair();

        if (keypair.first == nullptr || keypair.second == nullptr)
        {
            debug_print_cerr("[ZE] Failed to build derivable keys for session: " + std::to_string(uuid));
            return FAILURE;
        }

        current_session->shared_key_0_base = std::move(keypair);
        debug_print("[ZE] Successfully built derivable keys for session: " + std::to_string(uuid));

        return SUCCESS;
    }

    jint signing_bridge::finalize_signing_key([[maybe_unused]] JNIEnv *, [[maybe_unused]] jobject, const jlong uuid,
                                      const jint mode)
    {
        if (!validate_session(uuid))
        {
            return FAILURE;
        }
        const auto current_session = library::sessions[uuid];
        debug_print("[ZE] Deriving hash key for session: " + std::to_string(uuid));

        if (current_session->shared_key_0_derivative.first == nullptr || current_session->shared_key_0_derivative.second
            == nullptr)
        {
            debug_print_cerr("[ZE] Missing derived keys for session: " + std::to_string(uuid));
            return FAILURE;
        }

        guarded_ptr hash_key;

        switch (mode)
        {
        case static_cast<jint>(SideType::CLIENT):
            {
                hash_key = security::derive_hash_key(*current_session->shared_key_0_derivative.second);
                break;
            }
        case static_cast<jint>(SideType::SERVER):
            {
                hash_key = security::derive_hash_key(*current_session->shared_key_0_derivative.first);
                break;
            }
        default:
            {
                debug_print_cerr("[ZE] Invalid mode for deriving hash key: " + std::to_string(mode));
                return FAILURE;
            }
        }


        if (hash_key == nullptr)
        {
            debug_print_cerr("[ZE] Failed to derive hash key for session: " + std::to_string(uuid));
            return FAILURE;
        }

        current_session->shared_key_0 = std::move(hash_key);
        debug_print("[ZE] Successfully derived hash key for session: " + std::to_string(uuid));

        return SUCCESS;
    }
}
