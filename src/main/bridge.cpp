//
// Created by Damian Netter on 08/06/2025.
//

#include "ZEKit/bridge.hpp"

#include <ZNBKit/jni/internal/wrapper.hpp>

#include "ZEKit/loader.hpp"

namespace ze_kit
{
    void bridge::close_lib(JNIEnv *jni, jobject object)
    {
        znb_kit::wrapper::unregister_natives(jni, loader::name);
        znb_kit::wrapper::check_for_corruption();
    }

    jlong bridge::open_session(JNIEnv *env, jobject object, jlong identifier)
    {
    }

    void bridge::close_session(JNIEnv *env, jobject object, jlong session_id)
    {
    }

    jbyteArray bridge::encrypt_symmetric(JNIEnv *env, jobject object, jlong session_id, jbyteArray data, jbyteArray key,
        jbyteArray nonce)
    {
    }

    jbyteArray bridge::decrypt_symmetric(JNIEnv *env, jobject object, jlong session_id, jbyteArray encrypted_data,
        jbyteArray key, jbyteArray nonce)
    {
    }

    jbyteArray bridge::encrypt_asymmetric(JNIEnv *env, jobject object, jlong session_id, jbyteArray data,
        jbyteArray public_key)
    {
    }

    jbyteArray bridge::decrypt_asymmetric(JNIEnv *env, jobject object, jlong session_id, jbyteArray encrypted_data,
        jbyteArray private_key)
    {
    }

    jbyteArray bridge::build_nonce(JNIEnv *env, jclass clazz, jlong session_id, jint mode)
    {
    }

    jbyteArray bridge::build_key(JNIEnv *env, jclass clazz, jlong session_id, jint key_type)
    {
    }
}
