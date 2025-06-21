function(adjust_path)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        set(LIBSODIUM_SRC_DIR "${PROJECT_SOURCE_DIR}/extern")
        set(LIBSODIUM_BUILD_DIR "${CMAKE_CURRENT_BINARY_DIR}/lib")
        set(TARGET_DYLIB "${LIBSODIUM_BUILD_DIR}/libze.dylib")

        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy
                "${LIBSODIUM_SRC_DIR}/libsodium.26.dylib"
                "${LIBSODIUM_BUILD_DIR}"
                COMMAND ${CMAKE_COMMAND} -E copy
                "${LIBSODIUM_SRC_DIR}/libsodium.dylib"
                "${LIBSODIUM_BUILD_DIR}"

                COMMAND install_name_tool -change
                "${LIBSODIUM_SRC_DIR}/libsodium.dylib"
                "@rpath/libsodium.dylib"
                "${TARGET_DYLIB}"

                COMMAND install_name_tool -id "@rpath/libsodium.26.dylib"
                "${LIBSODIUM_BUILD_DIR}/libsodium.26.dylib"
                COMMAND install_name_tool -id "@rpath/libsodium.dylib"
                "${LIBSODIUM_BUILD_DIR}/libsodium.dylib"
                COMMENT "Copying and patching libsodium dylibs for Release build"
        )
    endif()
endfunction()