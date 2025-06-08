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
        guarded_ptr secret_key;
        guarded_ptr public_key;
        guarded_ptr shared_key;
        guarded_ptr symmetric_nonce;
        guarded_ptr asymmetric_nonce;

        // Getter methods for nonces
        [[nodiscard]] const data& get_symmetric_nonce() const {
            return symmetric_nonce ? *symmetric_nonce : empty_data;
        }

        [[nodiscard]] const data& get_asymmetric_nonce() const {
            return asymmetric_nonce ? *asymmetric_nonce : empty_data;
        }

        // Setter methods for nonces
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