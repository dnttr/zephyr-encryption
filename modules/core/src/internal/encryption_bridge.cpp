//
// Created by Damian Netter on 15/06/2025.
//

#include "ZEKit/internal/encryption_bridge.hpp"

#include "ZEKit/util.hpp"

namespace ze_kit
{
    jbyteArray encryption_bridge::encrypt_data(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid,
                                    const jbyteArray message_buffer, const jbyteArray aead_buffer)
    {
        if (!validate_session(uuid))
        {
            return nullptr;
        }

        debug_print("[ZE] Encrypting data (SYMMETRIC) with UUID: " + std::to_string(uuid));

        if (message_buffer == nullptr)
        {
            debug_print_cerr("[ZE] Provided data is null for session: " + std::to_string(uuid));
            return nullptr;
        }

        const auto current_session = library::sessions[uuid];
        const guarded_ptr input_data = util::byteArray_to_data(jni, message_buffer);

        if (input_data == nullptr)
        {
            debug_print_cerr("[ZE] Failed to convert input data to ze_kit::data for session: " + std::to_string(uuid));
            return nullptr;
        }

        if (!current_session->shared_key_1)
        {
            debug_print_cerr("[ZE] Missing symmetric key for session: " + std::to_string(uuid));
            return nullptr;
        }

        guarded_ptr aead_data;

        if (aead_buffer != nullptr)
        {
            aead_data = util::byteArray_to_data(jni, aead_buffer);
            debug_print("[ZE] AEAD data provided for session: " + std::to_string(uuid));
        }
        else
        {
            aead_data = guarded_ptr(new data(nullptr, 0));
            debug_print("[ZE] No AEAD data provided for session: " + std::to_string(uuid));
        }

        const data &key = *current_session->shared_key_1;
        const data &nonce = current_session->get_symmetric_nonce();

        const guarded_ptr encrypted = security::encrypt_symmetric(key, *aead_data, *input_data, nonce);

        if (encrypted == nullptr)
        {
            debug_print_cerr("[ZE] Encryption (SYMMETRIC) failed for session: " + std::to_string(uuid));
            return nullptr;
        }

        debug_print("[ZE] Encrypted data with UUID: " + std::to_string(uuid));
        return util::data_to_byteArray(jni, encrypted.get());
    }

    jbyteArray encryption_bridge::decrypt_data(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid,
                                    const jbyteArray message_buffer, const jbyteArray aead_buffer)
    {
        if (!validate_session(uuid))
        {
            return nullptr;
        }
        debug_print("[ZE] Decrypting data (SYMMETRIC) with UUID: " + std::to_string(uuid));

        if (message_buffer == nullptr)
        {
            debug_print_cerr("[ZE] Provided data is null for session: " + std::to_string(uuid));
            return nullptr;
        }

        const auto current_session = library::sessions[uuid];
        const guarded_ptr input_data = util::byteArray_to_data(jni, message_buffer);

        if (input_data == nullptr)
        {
            debug_print_cerr("[ZE] Failed to convert input data to ze_kit::data for session: " + std::to_string(uuid));
            return nullptr;
        }

        if (!current_session->shared_key_1)
        {
            debug_print_cerr("[ZE] Missing symmetric key for session: " + std::to_string(uuid));
            return nullptr;
        }

        guarded_ptr aead_data;
        if (aead_buffer != nullptr)
        {
            aead_data = util::byteArray_to_data(jni, aead_buffer);
        }
        else
        {
            aead_data = guarded_ptr(new data(nullptr, 0));
        }

        const data &key = *current_session->shared_key_1;
        const data &nonce = current_session->get_symmetric_nonce();

        const guarded_ptr decrypted = security::decrypt_symmetric(key, *aead_data, *input_data, nonce);

        if (decrypted == nullptr)
        {
            debug_print_cerr("[ZE] Decryption (SYMMETRIC) failed for session: " + std::to_string(uuid));
            return nullptr;
        }

        return util::data_to_byteArray(jni, decrypted.get());
    }

    jbyteArray encryption_bridge::encrypt_with_public_key(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid,
                                               const jbyteArray message_buffer)
    {
        if (!validate_session(uuid))
        {
            return nullptr;
        }
        debug_print("[ZE] Encrypting data (ASYMMETRIC) with UUID: " + std::to_string(uuid));

        if (message_buffer == nullptr)
        {
            debug_print_cerr("[ZE] Data is null for session: " + std::to_string(uuid));
            return nullptr;
        }

        const auto current_session = library::sessions[uuid];
        const guarded_ptr input_data = util::byteArray_to_data(jni, message_buffer);

        if (input_data == nullptr)
        {
            debug_print_cerr("[ZE] Failed to convert input data to ze_kit::data for session: " + std::to_string(uuid));
            return nullptr;
        }

        if (!current_session->built_private_key || !current_session->received_public_key_2)
        {
            debug_print_cerr("[ZE] Missing asymmetric keys for session: " + std::to_string(uuid));
            return nullptr;
        }

        if (!current_session->asymmetric_nonce)
        {
            debug_print_cerr("[ZE] Missing asymmetric nonce for session: " + std::to_string(uuid));
            return nullptr;
        }

        const guarded_ptr encrypted = encrypt_asymmetric_message(current_session, input_data);

        if (!encrypted)
        {
            debug_print_cerr("[ZE] Encryption (ASYMMETRIC) failed for session: " + std::to_string(uuid));
            return nullptr;
        }

        return util::data_to_byteArray(jni, encrypted.get());
    }

    jbyteArray encryption_bridge::decrypt_with_private_key(JNIEnv *jni, [[maybe_unused]] jobject, const jlong uuid,
                                                const jbyteArray message_buffer)
    {
        if (!validate_session(uuid))
        {
            return nullptr;
        }
        debug_print("[ZE] Decrypting data (ASYMMETRIC) with UUID: " + std::to_string(uuid));

        if (message_buffer == nullptr)
        {
            debug_print_cerr("[ZE] Data is null for session: " + std::to_string(uuid));
            return nullptr;
        }

        const auto current_session = library::sessions[uuid];
        const guarded_ptr input_data = util::byteArray_to_data(jni, message_buffer);

        if (input_data == nullptr)
        {
            debug_print_cerr("[ZE] Failed to convert input data to ze_kit::data for session: " + std::to_string(uuid));
            return nullptr;
        }

        if (!current_session->built_private_key || !current_session->received_public_key_2)
        {
            debug_print_cerr("[ZE] Missing asymmetric keys for session: " + std::to_string(uuid));
            return nullptr;
        }

        if (!current_session->asymmetric_nonce)
        {
            debug_print_cerr("[ZE] Missing asymmetric nonce for session: " + std::to_string(uuid));
            return nullptr;
        }

        const guarded_ptr decrypted = decrypt_asymmetric_message(current_session, input_data);

        if (decrypted == nullptr)
        {
            debug_print_cerr("[ZE] Decryption (ASYMMETRIC) failed for session: " + std::to_string(uuid));
            return nullptr;
        }

        return util::data_to_byteArray(jni, decrypted.get());
    }
}
