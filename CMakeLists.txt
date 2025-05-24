cmake_minimum_required(VERSION 3.22)
project(zephyr-encryption VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(${CMAKE_SOURCE_DIR}/tools/Dependencies.cmake)

#------------------------ Library ------------------------#

set(SOURCE_FILES
        src/main/library.cpp
        src/main/memory.cpp
        src/main/security.cpp
)

include_directories(
        ${PROJECT_SOURCE_DIR}/include
)

add_library(${PROJECT_NAME} SHARED
        ${SOURCE_FILES}
)

prepare_sodium(sodium_lib)

target_link_libraries(${PROJECT_NAME} PRIVATE sodium_lib)

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

set_target_properties(${PROJECT_NAME} PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
        OUTPUT_NAME "ze"
        INSTALL_RPATH "@loader_path"
)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(TARGET_PATH "${CMAKE_CURRENT_BINARY_DIR}/lib/libze.dylib")
    set(LIBSODIUM_DIR "${PROJECT_SOURCE_DIR}/external")
    set(OLD_LIBSODIUM_PATH "${LIBSODIUM_DIR}/libsodium.26.dylib")
    set(NEW_LIBSODIUM_PATH "@rpath/libsodium.26.dylib")

    set(LIBSODIUM_26_PATH "${LIBSODIUM_DIR}/libsodium.26.dylib")
    set(LIBSODIUM_PATH "${LIBSODIUM_DIR}/libsodium.dylib")

    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND install_name_tool -change ${OLD_LIBSODIUM_PATH} ${NEW_LIBSODIUM_PATH} ${TARGET_PATH}
            COMMENT "Patched libsodium dylib path in libze.dylib"
    )

    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND install_name_tool -id @rpath/libsodium.26.dylib ${LIBSODIUM_26_PATH}
            COMMENT "Set install_name for libsodium.26.dylib to @rpath/libsodium.26.dylib"
    )

    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND install_name_tool -id @rpath/libsodium.dylib ${LIBSODIUM_PATH}
            COMMENT "Set install_name for libsodium.dylib to @rpath/libsodium.dylib"
    )

elseif(CMAKE_BUILD_TYPE STREQUAL "Debug")
    # Use original absolute paths for debug build (example)
    set(TARGET_PATH "${CMAKE_CURRENT_BINARY_DIR}/lib/libze.dylib")
    set(LIBSODIUM_DIR "${PROJECT_SOURCE_DIR}/external")
    set(OLD_LIBSODIUM_PATH "${LIBSODIUM_DIR}/libsodium.26.dylib")
    set(NEW_LIBSODIUM_PATH "${OLD_LIBSODIUM_PATH}")

    set(LIBSODIUM_26_PATH "${LIBSODIUM_DIR}/libsodium.26.dylib")
    set(LIBSODIUM_PATH "${LIBSODIUM_DIR}/libsodium.dylib")

    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND install_name_tool -change ${OLD_LIBSODIUM_PATH} ${NEW_LIBSODIUM_PATH} ${TARGET_PATH}
            COMMENT "Using original libsodium dylib path in libze.dylib for Debug"
    )

    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND install_name_tool -id ${LIBSODIUM_26_PATH} ${LIBSODIUM_26_PATH}
            COMMENT "Set install_name for libsodium.26.dylib to original path for Debug"
    )

    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND install_name_tool -id ${LIBSODIUM_PATH} ${LIBSODIUM_PATH}
            COMMENT "Set install_name for libsodium.dylib to original path for Debug"
    )
endif()


#------------------------ Tests ------------------------#

prepare_catch2(catch2_lib)

enable_testing()

file(GLOB_RECURSE TEST_SOURCES "src/test/src/*.cpp")
message(STATUS "Found test sources: ${TEST_SOURCES}")

add_executable(${PROJECT_NAME}-tests ${TEST_SOURCES})

target_include_directories(${PROJECT_NAME}-tests PRIVATE
        ${PROJECT_SOURCE_DIR}/include/
        ${PROJECT_SOURCE_DIR}/src/test/include
        sodium_lib
)

target_link_libraries(${PROJECT_NAME}-tests PRIVATE
        ${PROJECT_NAME}
        catch2_lib
        sodium_lib
)

set_target_properties(${PROJECT_NAME}-tests
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

catch_discover_tests(${PROJECT_NAME}-tests)
