cmake_minimum_required(VERSION 3.22)
project(zephyr-encryption VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
elseif(MSVC)
    add_compile_options(/W4)
endif()

find_path(LIBSODIUM_INCLUDE_DIR
        NAMES sodium.h
        PATHS
        /usr/local/include
        /opt/homebrew/include
        NO_DEFAULT_PATH
)

find_library(LIBSODIUM_LIBRARY
        NAMES sodium libsodium
        PATHS
        /usr/local/lib
        /opt/homebrew/lib
        NO_DEFAULT_PATH
)

if(NOT LIBSODIUM_INCLUDE_DIR OR NOT LIBSODIUM_LIBRARY)
    message(FATAL_ERROR "Could not find libsodium, is it installed via Homebrew?")
endif()

include_directories(
        ${PROJECT_SOURCE_DIR}/include
        ${LIBSODIUM_INCLUDE_DIR}
)

add_library(${PROJECT_NAME} STATIC
        src/main/library.cpp
        src/main/memory.cpp
        src/main/security.cpp
)

target_link_libraries(${PROJECT_NAME} PRIVATE ${LIBSODIUM_LIBRARY})

set_target_properties(${PROJECT_NAME}
        PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

install(TARGETS ${PROJECT_NAME}
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
)

install(DIRECTORY include/
        DESTINATION include
)