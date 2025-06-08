cmake_minimum_required(VERSION 3.22)
project(zephyr-encryption VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(${CMAKE_SOURCE_DIR}/tools/Dependencies.cmake)
include(${CMAKE_SOURCE_DIR}/tools/Patch.cmake)

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
prepare_znb(znb_lib)
_prepare_jvm_toolset()

target_link_libraries(${PROJECT_NAME} PRIVATE sodium_lib znb_lib)

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

patch_libs()

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
