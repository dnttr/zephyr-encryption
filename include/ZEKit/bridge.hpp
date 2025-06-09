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

        static jlong open_session(JNIEnv* jni, jobject object);

        static jint close_session(JNIEnv *jni, jobject object, jlong uuid);

        static jbyteArray encrypt_symmetric(JNIEnv* jni, jobject object, jlong uuid, jbyteArray data, jbyteArray aead);

        static jbyteArray decrypt_symmetric(JNIEnv* jni, jobject object, jlong uuid, jbyteArray encrypted_data, jbyteArray aead);

        static jbyteArray encrypt_asymmetric(JNIEnv* jni, jobject object, jlong uuid, jbyteArray data);

        static jbyteArray decrypt_asymmetric(JNIEnv* jni, jobject object, jlong uuid, jbyteArray encrypted_data);

        static void build_nonce(JNIEnv* jni, jobject object, jlong uuid, jint mode);

        static void build_key(JNIEnv* jni, jobject object, jlong uuid, jint mode);

        static void set_symmetric_key(JNIEnv* jni, jobject object, jlong uuid, jbyteArray key_buffer);

        static void set_asymmetric_key(JNIEnv* jni, jobject object, jlong uuid, jint mode, jbyteArray key_buffer);

        static void set_nonce(JNIEnv* jni, jobject object, jlong uuid, jint mode, jbyteArray nonce_buffer);

        static jbyteArray get_symmetric_key(JNIEnv* jni, jobject object, jlong uuid);

        static jbyteArray get_asymmetric_key(JNIEnv* jni, jobject object, jlong uuid, jint mode);

        static jbyteArray get_nonce(JNIEnv* jni, jobject object, jlong uuid, jint mode);
    };
}