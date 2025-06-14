include(FetchContent)

find_package(Java REQUIRED)
find_package(JNI REQUIRED)

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

    set(_lib "${PROJECT_SOURCE_DIR}/external/libsodium.dylib")
    set(_include_dir "${PROJECT_SOURCE_DIR}/external/include")

    if(EXISTS "${_lib}" AND EXISTS "${_include_dir}/sodium.h")
        message(STATUS "prepare_sodium: Using existing libsodium.dylib and headers")

    else()
        message(STATUS "prepare_sodium: Prebuilt libsodium not found, falling back to FetchContent...")

        include(FetchContent)
        FetchContent_Declare(
                sodium
                URL https://download.libsodium.org/libsodium/releases/libsodium-1.0.20.tar.gz
                SOURCE_DIR ${PROJECT_SOURCE_DIR}/external/libsodium-src
                DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        )
        FetchContent_GetProperties(sodium)
        if(NOT sodium_AVAILABLE)
            FetchContent_MakeAvailable(sodium)

            execute_process(
                    COMMAND ./configure --prefix=${PROJECT_SOURCE_DIR}/external/libsodium-install
                    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/external/libsodium-src
                    RESULT_VARIABLE conf_result
                    OUTPUT_QUIET ERROR_QUIET
            )
            if(NOT conf_result EQUAL 0)
                message(FATAL_ERROR "prepare_sodium: Failed to configure libsodium")
            endif()

            execute_process(
                    COMMAND make
                    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/external/libsodium-src
                    RESULT_VARIABLE build_result
                    OUTPUT_QUIET ERROR_QUIET
            )
            if(NOT build_result EQUAL 0)
                message(FATAL_ERROR "prepare_sodium: Failed to build libsodium")
            endif()

            execute_process(
                    COMMAND make install
                    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/external/libsodium-src
                    RESULT_VARIABLE install_result
                    OUTPUT_QUIET ERROR_QUIET
            )
            if(NOT install_result EQUAL 0)
                message(FATAL_ERROR "prepare_sodium: Failed to install libsodium")
            endif()

            file(GLOB libs "${PROJECT_SOURCE_DIR}/external/libsodium-install/lib/libsodium.*")

            foreach(lib ${libs})
                file(COPY ${lib} DESTINATION "${PROJECT_SOURCE_DIR}/external")
            endforeach()
        endif()

        set(_include_dir "${PROJECT_SOURCE_DIR}/external/include")
        # Prefer .dylib if available, fallback to .a
        if(EXISTS "${PROJECT_SOURCE_DIR}/external/libsodium.dylib")
            set(_lib "${PROJECT_SOURCE_DIR}/external/libsodium.dylib")
        else()
            set(_lib "${PROJECT_SOURCE_DIR}/external/libsodium.a")
        endif()
    endif()

    if(TARGET ${TARGET_NAME})
        message(STATUS "prepare_sodium: Target ${TARGET_NAME} already exists, skipping creation")
    else()
        add_library(${TARGET_NAME} INTERFACE)
        target_include_directories(${TARGET_NAME} INTERFACE "${_include_dir}")
        target_link_libraries(${TARGET_NAME} INTERFACE "${_lib}")
    endif()
endfunction()

function(_prepare_jvm_toolset)
    set(JNI_HEADER "jni.h")
    set(JNI_MD_HEADER "jni_md.h")

    if (NOT JAVA_FOUND OR NOT JNI_FOUND)
        message(FATAL_ERROR "Java or JNI not found.")
    endif ()

    find_path(JNI_H_PATH ${JNI_HEADER} PATHS ${JNI_INCLUDE_DIRS} REQUIRED)
    find_path(JNI_H_MD_PATH ${JNI_MD_HEADER} PATHS ${JNI_INCLUDE_DIRS} REQUIRED)

    if (NOT JNI_H_PATH OR NOT JNI_H_MD_PATH)
        message(FATAL_ERROR "JNI header not found.")
    endif ()

    message(STATUS "Found JNI.")

    set(JNI_INCLUDE_OS_SPECIFIC "${JNI_H_PATH}/${OS}")

    if (NOT JNI_INCLUDE_OS_SPECIFIC)
        message(FATAL_ERROR "JNI OS specific header not found.")
    endif ()

    target_include_directories(${PROJECT_NAME} PUBLIC ${JNI_INCLUDE_DIRS} ${JNI_INCLUDE_OS_SPECIFIC} )

    target_link_libraries(${PROJECT_NAME} PUBLIC ${JNI_LIBRARIES})
endfunction()

function(prepare_znb TARGET_NAME)
    if(NOT TARGET_NAME)
        message(FATAL_ERROR "prepare_znb: No target name provided")
    endif()

    set(LIBZNB_PATH "${PROJECT_SOURCE_DIR}/external/libznb.dylib")

    if(NOT EXISTS "${LIBZNB_PATH}")
        message(FATAL_ERROR "libznb.dylib not found at ${LIBZNB_PATH}. Please ensure it is built and available.")
    endif()

    if(NOT TARGET ${TARGET_NAME})
        add_library(${TARGET_NAME} INTERFACE)
        target_link_libraries(${TARGET_NAME} INTERFACE "${LIBZNB_PATH}")
        message(STATUS "Configured libznb.dylib for target '${TARGET_NAME}': ${LIBZNB_PATH}")
    else()
        message(STATUS "Target ${TARGET_NAME} already exists, skipping creation for libznb.")
    endif()
endfunction()