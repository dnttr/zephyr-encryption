//
// Created by Damian Netter on 15/06/2025.
//

#include "ZEKit/crypto_bridge/exchange_bridge.hpp"

#include "ZEKit/util.hpp"

namespace ze_kit
{
    jbyteArray exchange_bridge::create_key_exchange(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid)
    {
        if (!validate_session(uuid))
        {
            return nullptr;
        }
        const auto current_session = library::sessions[uuid];

        if (current_session->shared_key_1 == nullptr)
        {
            debug_print_cerr("[ZE] No symmetric key available for session: " + std::to_string(uuid));
            return nullptr;
        }

        const auto key = encrypt_asymmetric_message(current_session, current_session->shared_key_1);
        if (!key)
        {
            debug_print_cerr("[ZE] Failed to encrypt symmetric key for session: " + std::to_string(uuid));
            return nullptr;
        }

        const jbyteArray result = util::data_to_byteArray(jni, key.get());

        debug_print("[ZE] Exchange message prepared for session: " + std::to_string(uuid));

        return result;
    }

    void exchange_bridge::process_key_exchange(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid,
                                      const jbyteArray message_buffer)
    {
        if (!validate_session(uuid))
        {
            return;
        }
        const auto current_session = library::sessions[uuid];
        debug_print("[ZE] Setting exchange message for session: " + std::to_string(uuid));

        if (message_buffer == nullptr)
        {
            debug_print_cerr("[ZE] Provided exchange message is null for session: " + std::to_string(uuid));
            return;
        }

        const guarded_ptr input_data = util::byteArray_to_data(jni, message_buffer);
        if (input_data == nullptr)
        {
            debug_print_cerr(
                "[ZE] Failed to convert exchange message to ze_kit::data for session: " + std::to_string(uuid));
            return;
        }

        if (!current_session->built_private_key || !current_session->received_public_key_2)
        {
            debug_print_cerr("[ZE] Missing asymmetric keys for session: " + std::to_string(uuid));
            return;
        }

        if (!current_session->asymmetric_nonce)
        {
            debug_print_cerr("[ZE] Missing asymmetric nonce for session: " + std::to_string(uuid));
            return;
        }

        guarded_ptr decrypted_key = decrypt_asymmetric_message(current_session, input_data);
        if (!decrypted_key)
        {
            debug_print_cerr("[ZE] Failed to decrypt exchange message for session: " + std::to_string(uuid));
            return;
        }

        current_session->shared_key_1 = std::move(decrypted_key);

        debug_print("[ZE] Successfully set exchange message for session: " + std::to_string(uuid));
    }
}
