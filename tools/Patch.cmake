function(patch_libs)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        set(TARGET_PATH "${CMAKE_CURRENT_BINARY_DIR}/lib/libze.dylib")
        set(LIBSODIUM_DIR "${PROJECT_SOURCE_DIR}/external")
        set(LIBSODIUM_BUILD_DIR "${CMAKE_CURRENT_BINARY_DIR}/lib")

        set(OLD_LIBSODIUM_PATH "${LIBSODIUM_DIR}/libsodium.26.dylib")
        set(NEW_LIBSODIUM_PATH "@rpath/libsodium.26.dylib")

        set(LIBSODIUM_26_PATH "${LIBSODIUM_DIR}/libsodium.26.dylib")
        set(LIBSODIUM_PATH "${LIBSODIUM_DIR}/libsodium.dylib")

        # Copy libsodium dylibs to the build lib directory
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy ${LIBSODIUM_26_PATH} ${LIBSODIUM_BUILD_DIR}
                COMMENT "Copy libsodium.26.dylib to build lib directory"
        )
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy ${LIBSODIUM_PATH} ${LIBSODIUM_BUILD_DIR}
                COMMENT "Copy libsodium.dylib to build lib directory"
        )

        # Patch libze to use @rpath/libsodium.26.dylib
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                COMMAND install_name_tool -change ${OLD_LIBSODIUM_PATH} ${NEW_LIBSODIUM_PATH} ${TARGET_PATH}
                COMMENT "Patched libsodium dylib path in libze.dylib"
        )

        # Patch libsodium dylibs install_name to @rpath
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                COMMAND install_name_tool -id @rpath/libsodium.26.dylib ${LIBSODIUM_BUILD_DIR}/libsodium.26.dylib
                COMMENT "Set install_name for libsodium.26.dylib to @rpath/libsodium.26.dylib"
        )
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                COMMAND install_name_tool -id @rpath/libsodium.dylib ${LIBSODIUM_BUILD_DIR}/libsodium.dylib
                COMMENT "Set install_name for libsodium.dylib to @rpath/libsodium.dylib"
        )
    elseif(CMAKE_BUILD_TYPE STREQUAL "Debug")
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
endfunction()