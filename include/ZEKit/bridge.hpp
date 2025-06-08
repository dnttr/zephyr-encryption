//
// Created by Damian Netter on 08/06/2025.
//

#pragma once

#include "jni.h"

namespace ze_kit
{
    class bridge {
    public:

        static void close_lib(JNIEnv *jni, jobject object);

        static jlong open_session(JNIEnv* env, jobject object, jlong identifier);

        static void close_session(JNIEnv* env, jobject object, jlong session_id);

        static jbyteArray encrypt_symmetric(JNIEnv* env, jobject object, jlong session_id,
                                     jbyteArray data, jbyteArray key, jbyteArray nonce);

        static jbyteArray decrypt_symmetric(JNIEnv* env, jobject object, jlong session_id,
                                     jbyteArray encrypted_data, jbyteArray key, jbyteArray nonce);

        static jbyteArray encrypt_asymmetric(JNIEnv* env, jobject object, jlong session_id,
                                      jbyteArray data, jbyteArray public_key);

        static jbyteArray decrypt_asymmetric(JNIEnv* env, jobject object, jlong session_id,
                                      jbyteArray encrypted_data, jbyteArray private_key);

        static jbyteArray build_nonce(JNIEnv* env, jclass clazz, jlong session_id, jint mode);

        static jbyteArray build_key(JNIEnv* env, jclass clazz, jlong session_id, jint key_type);
    };
}