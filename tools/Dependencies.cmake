include(FetchContent)

function(prepare_catch2 TARGET_NAME)
    if(NOT TARGET_NAME)
        message(FATAL_ERROR "prepare_catch2: No target name provided")
    endif()

    find_package(Catch2 3 REQUIRED)

    message(STATUS "prepare_catch2: Found Catch2: ${Catch2_VERSION}")

    add_library(${TARGET_NAME} INTERFACE)
    target_include_directories(${TARGET_NAME} INTERFACE ${Catch2_INCLUDE_DIRS})
    target_link_libraries(${TARGET_NAME} INTERFACE Catch2::Catch2WithMain)

    include(CTest)
    include(Catch)
endfunction()

function(prepare_sodium TARGET_NAME)
    if(NOT TARGET_NAME)
        set(TARGET_NAME sodium)
    endif()

    set(_sodium_root "${SODIUM_ROOT}" CACHE PATH "Optional libsodium root directory" FORCE)

    find_path(_include_dir sodium.h
            PATHS
            "${_sodium_root}/include"
            /usr/include
            /usr/local/include
            /opt/local/include
    )

    find_library(_lib sodium
            PATHS
            "${_sodium_root}/lib"
            /usr/lib
            /usr/local/lib
            /opt/local/lib
    )

    if(NOT _include_dir OR NOT _lib)
        message(STATUS "prepare_sodium: libsodium not found, downloading and building with FetchContent...")

        include(FetchContent)
        FetchContent_Declare(
                sodium
                URL https://download.libsodium.org/libsodium/releases/libsodium-1.0.19.tar.gz
                SOURCE_DIR ${CMAKE_BINARY_DIR}/external/libsodium-src
        )
        FetchContent_GetProperties(sodium)
        if(NOT sodium_POPULATED)
            FetchContent_Populate(sodium)

            execute_process(
                    COMMAND ./configure --prefix=${CMAKE_BINARY_DIR}/external/libsodium-install
                    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/external/libsodium-src
                    RESULT_VARIABLE conf_result
                    OUTPUT_QUIET ERROR_QUIET
            )
            if(NOT conf_result EQUAL 0)
                message(FATAL_ERROR "prepare_sodium: Failed to configure libsodium")
            endif()

            execute_process(
                    COMMAND make
                    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/external/libsodium-src
                    RESULT_VARIABLE build_result
                    OUTPUT_QUIET ERROR_QUIET
            )
            if(NOT build_result EQUAL 0)
                message(FATAL_ERROR "prepare_sodium: Failed to build libsodium")
            endif()

            execute_process(
                    COMMAND make install
                    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/external/libsodium-src
                    RESULT_VARIABLE install_result
                    OUTPUT_QUIET ERROR_QUIET
            )
            if(NOT install_result EQUAL 0)
                message(FATAL_ERROR "prepare_sodium: Failed to install libsodium")
            endif()
        endif()

        set(_include_dir "${CMAKE_BINARY_DIR}/external/libsodium-install/include")
        set(_lib "${CMAKE_BINARY_DIR}/external/libsodium-install/lib/libsodium.a")
    endif()

    if(TARGET ${TARGET_NAME})
        message(STATUS "prepare_sodium: Target ${TARGET_NAME} already exists, skipping creation")
    else()
        add_library(${TARGET_NAME} INTERFACE)
        target_include_directories(${TARGET_NAME} INTERFACE "${_include_dir}")
        target_link_libraries(${TARGET_NAME} INTERFACE "${_lib}")
    endif()
endfunction()

