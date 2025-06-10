//
// Created by Damian Netter on 08/06/2025.
//

#pragma once

#include "jni.h"

#define DEFAULT JNIEnv *jni, jobject object
#define UUID jlong uuid

namespace ze_kit
{
    class bridge {
    public:

        static void close_lib(DEFAULT);

        static jlong open_session(DEFAULT);

        static jint close_session(DEFAULT, UUID);

        static jbyteArray encrypt_symmetric(DEFAULT, UUID, jbyteArray message_buffer, jbyteArray aead_buffer);

        static jbyteArray decrypt_symmetric(DEFAULT, UUID, jbyteArray message_buffer, jbyteArray aead_buffer);

        static jbyteArray encrypt_asymmetric(DEFAULT, UUID, jbyteArray message_buffer);

        static jbyteArray decrypt_asymmetric(DEFAULT, UUID, jbyteArray message_buffer);

        static void build_nonce(DEFAULT, UUID, jint mode);

        static void build_key(DEFAULT, UUID, jint mode);

        static void set_symmetric_key(DEFAULT, UUID, jbyteArray key_buffer);

        static void set_asymmetric_key(DEFAULT, UUID, jint mode, jbyteArray key_buffer);

        static void set_nonce(DEFAULT, UUID, jint mode, jbyteArray nonce_buffer);

        static jbyteArray get_symmetric_key(DEFAULT, UUID);

        static jbyteArray get_asymmetric_key(DEFAULT, UUID, jint mode);

        static jbyteArray get_nonce(DEFAULT, UUID, jint mode);

        static jbyteArray build_hash(DEFAULT, UUID, jbyteArray message_buffer);

        static bool compare_hash(DEFAULT, UUID, jbyteArray hash_buffer, jbyteArray message_buffer);

        static void derive_secret_key(DEFAULT, UUID, jint mode, jbyteArray public_key_buffer);

        static void build_derivable_key(DEFAULT, UUID);

        static void derive_hash_key(DEFAULT, UUID);
    };
}