//
// Created by Damian Netter on 20/05/2025.
//

#pragma once

namespace ze_kit
{
    #define SUCCESS 0
    #define FAILURE 1

    class library
    {
        static bool initialized;
    public:
        static bool initialize();
    };
}
