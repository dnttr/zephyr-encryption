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

        static jlong open_session(JNIEnv* env, jobject object);

        static jint close_session(JNIEnv *env, jobject object, jlong uuid);

        static jbyteArray encrypt_symmetric(JNIEnv* env, jobject object, jlong uuid, jbyteArray data, jbyteArray aead);

        static jbyteArray decrypt_symmetric(JNIEnv* env, jobject object, jlong uuid, jbyteArray encrypted_data, jbyteArray aead);

        static jbyteArray encrypt_asymmetric(JNIEnv* env, jobject object, jlong uuid, jbyteArray data);

        static jbyteArray decrypt_asymmetric(JNIEnv* env, jobject object, jlong uuid, jbyteArray encrypted_data);

        static void build_nonce(JNIEnv* env, jobject object, jlong uuid, jint mode);

        static void build_key(JNIEnv* env, jobject object, jlong uuid, jint key_type);
    };
}