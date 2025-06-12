//
// Created by Damian Netter on 08/06/2025.
//

#pragma once
#include "ZEKit/guarded_ptr.hpp"

namespace ze_kit
{
    class session
    {
    public:
        guarded_ptr built_public_key;
        guarded_ptr built_private_key;

        guarded_ptr received_public_key_0;
        guarded_ptr received_public_key_2;

        guarded_ptr shared_key_0; // for hashing
        guarded_ptr shared_key_1; // for symmetric encryption

        guarded_ptr symmetric_nonce;
        guarded_ptr asymmetric_nonce;

        std::pair<guarded_ptr, guarded_ptr> shared_key_0_base;
        std::pair<guarded_ptr, guarded_ptr> shared_key_0_derivative;

        [[nodiscard]] const data& get_symmetric_nonce() const {
            return symmetric_nonce ? *symmetric_nonce : empty_data;
        }

        [[nodiscard]] const data& get_asymmetric_nonce() const {
            return asymmetric_nonce ? *asymmetric_nonce : empty_data;
        }

        void set_symmetric_nonce(const data& nonce) {
            symmetric_nonce = guarded_ptr(new data(nonce));
        }

        void set_asymmetric_nonce(const data& nonce) {
            asymmetric_nonce = guarded_ptr(new data(nonce));
        }

    private:
        static const data empty_data;
    };
}