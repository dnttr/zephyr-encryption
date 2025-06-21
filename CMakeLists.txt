cmake_minimum_required(VERSION 3.31.)

project(zephyr-encryption VERSION 1.0.5 LANGUAGES C CXX)

if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-diagnostics-show-template-tree")
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ftemplate-backtrace-limit=0")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(${CMAKE_SOURCE_DIR}/cmake/Dependencies.cmake)
include(${CMAKE_SOURCE_DIR}/cmake/AdjustPath.cmake)

file(GLOB_RECURSE SOURCE_FILES "modules/core/src/*.cpp")

add_library(${PROJECT_NAME} SHARED
        ${SOURCE_FILES}
)

target_include_directories(${PROJECT_NAME} PUBLIC
        modules/core/include
        ${COMMON_INCLUDE_DIRS}
)

target_link_libraries(${PROJECT_NAME} PRIVATE
        ${COMMON_LIBRARIES}
)

set_target_properties(${PROJECT_NAME}
        PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

install(TARGETS ${PROJECT_NAME}
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
)

install(DIRECTORY modules/core/include/
        DESTINATION modules/core/include
)

set_target_properties(${PROJECT_NAME} PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
        OUTPUT_NAME "ze"
        INSTALL_RPATH "@loader_path"
)

adjust_path()

#------------------------ Tests ------------------------#

enable_testing()

file(GLOB_RECURSE TEST_SOURCES "tests/src/*.cpp")
message(STATUS "Found test sources: ${TEST_SOURCES}")

add_executable(${PROJECT_NAME}-tests ${TEST_SOURCES})

target_include_directories(${PROJECT_NAME}-tests PRIVATE
        tests/include
)

target_link_libraries(${PROJECT_NAME}-tests PRIVATE
        ${PROJECT_NAME}
        ${TEST_LIBRARIES}
        sodium
)

set_target_properties(${PROJECT_NAME}-tests
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

catch_discover_tests(${PROJECT_NAME}-tests)