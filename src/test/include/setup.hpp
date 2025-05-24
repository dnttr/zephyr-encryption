//
// Created by Damian Netter on 22/05/2025.
//

#pragma once

#include "catch2/catch_all.hpp"
#include "ZEKit/library.hpp"

class setup {
public:
    struct init_listener final : Catch::EventListenerBase
    {
        using EventListenerBase::EventListenerBase;

        void testRunStarting(Catch::TestRunInfo const &testRunInfo) override
        {
            ze_kit::library::initialize();
        }
    };
};

CATCH_REGISTER_LISTENER(setup::init_listener);
