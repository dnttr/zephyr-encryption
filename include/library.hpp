//
// Created by Damian Netter on 20/05/2025.
//

#pragma once

#define SUCCESS 0
#define FAILURE 1

namespace ze_kit
{
    class library
    {
        static bool initialized;
    public:
        static bool initialize();
    };
}