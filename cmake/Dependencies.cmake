include(FetchContent)

find_package(Java REQUIRED)
find_package(JNI REQUIRED)
find_package(Catch2 3 REQUIRED)

function(configure_sodium)
    set(TARGET_NAME sodium)
    set(_lib_dylib "${PROJECT_SOURCE_DIR}/extern/libsodium.dylib")
    set(_lib_a "${PROJECT_SOURCE_DIR}/extern/libsodium.a")
    set(_include_dir "${PROJECT_SOURCE_DIR}/extern/include")
    set(_lib_to_use "")

    if(EXISTS "${_lib_dylib}" AND EXISTS "${_include_dir}/sodium.h")
        message(STATUS "Sodium: Using pre-built dylib and headers.")

        set(_lib_to_use "${_lib_dylib}")
    elseif(EXISTS "${_lib_a}" AND EXISTS "${_include_dir}/sodium.h")
        message(STATUS "Sodium: Using pre-built static library and headers.")

        set(_lib_to_use "${_lib_a}")
    else()
        message(STATUS "Sodium: Pre-built library not found, fetching from source...")

        FetchContent_Declare(
                sodium_fetch
                URL https://download.libsodium.org/libsodium/releases/libsodium-1.0.20.tar.gz
                SOURCE_DIR ${PROJECT_SOURCE_DIR}/extern/libsodium-src

        )
        FetchContent_GetProperties(sodium_fetch)

        if(NOT sodium_fetch_POPULATED)
            FetchContent_Populate(sodium_fetch)
            set(INSTALL_DIR ${PROJECT_SOURCE_DIR}/extern/libsodium-install)

            execute_process(COMMAND ./configure --prefix=${INSTALL_DIR}
                    WORKING_DIRECTORY ${sodium_fetch_SOURCE_DIR} RESULT_VARIABLE result OUTPUT_QUIET ERROR_QUIET)

            if(NOT result EQUAL 0)
                message(FATAL_ERROR "Sodium: Failed to configure.")
            endif()

            execute_process(COMMAND make -j install
                    WORKING_DIRECTORY ${sodium_fetch_SOURCE_DIR} RESULT_VARIABLE result OUTPUT_QUIET ERROR_QUIET)

            if(NOT result EQUAL 0)
                message(FATAL_ERROR "Sodium: Failed to build or install.")
            endif()

            file(COPY "${INSTALL_DIR}/lib/" DESTINATION "${PROJECT_SOURCE_DIR}/extern/")
            file(COPY "${INSTALL_DIR}/include/" DESTINATION "${PROJECT_SOURCE_DIR}/extern/")
        endif()

        if(EXISTS "${_lib_dylib}")
            set(_lib_to_use "${_lib_dylib}")
        elseif(EXISTS "${_lib_a}")
            set(_lib_to_use "${_lib_a}")
        else()
            message(FATAL_ERROR "Sodium: Library not found after build attempt.")
        endif()
    endif()

    if(NOT TARGET ${TARGET_NAME})
        add_library(${TARGET_NAME} INTERFACE)

        target_include_directories(${TARGET_NAME} INTERFACE "${_include_dir}")
        target_link_libraries(${TARGET_NAME} INTERFACE "${_lib_to_use}")

        message(STATUS "Sodium: Configured target '${TARGET_NAME}'")
    endif()
endfunction()

function(configure_jni)
    if (NOT JAVA_FOUND OR NOT JNI_FOUND)
        message(FATAL_ERROR "JNI: Java or JNI not found.")
    endif ()

    message(STATUS "JNI: Found Java and JNI.")

    set(JNI_INCLUDES_OUT ${JNI_INCLUDE_DIRS} PARENT_SCOPE)
    set(JNI_LIBS_OUT ${JNI_LIBRARIES} PARENT_SCOPE)
endfunction()

function(configure_testing)
    if (NOT Catch2_FOUND)
        message(FATAL_ERROR "Tests: Catch2 not found.")
    endif ()

    message(STATUS "Tests: Found Catch2 ${Catch2_VERSION}.")

    include(CTest)
    include(Catch)

    set(TEST_FRAMEWORK_LIBS_OUT Catch2::Catch2WithMain PARENT_SCOPE)
endfunction()

function(configure_znb)
    set(TARGET_NAME znb)
    set(LIBZNB_PATH "${PROJECT_SOURCE_DIR}/extern/libznb.dylib")

    if(NOT EXISTS "${LIBZNB_PATH}")
        message(FATAL_ERROR "ZNB: Library not found at ${LIBZNB_PATH}.")
    endif()

    if(NOT TARGET ${TARGET_NAME})
        add_library(${TARGET_NAME} INTERFACE)
        target_link_libraries(${TARGET_NAME} INTERFACE "${LIBZNB_PATH}")

        message(STATUS "ZNB: Configured target '${TARGET_NAME}'")
    endif()
endfunction()

configure_sodium()
configure_jni()
configure_testing()
configure_znb()

set(COMMON_INCLUDE_DIRS
        ${JNI_INCLUDES_OUT}
)

set(COMMON_LIBRARIES
        sodium
        znb
        ${JNI_LIBS_OUT}
)

set(TEST_LIBRARIES
        ${TEST_FRAMEWORK_LIBS_OUT}
)