# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.21)

option(LIBVRF_BUILD_TESTS      "Build the tests."      OFF)
option(LIBVRF_BUILD_BENCHMARKS "Build the benchmarks." OFF)

# Currently we do not support shared builds. Warn the user.
if(BUILD_SHARED_LIBS)
    message(WARNING "BUILD_SHARED_LIBS is set but libvrf only supports static"
                    "builds. Ignoring BUILD_SHARED_LIBS.")
endif()

# Conditionally enable VCPKG manifest features for tests and benchmarks.
if(LIBVRF_BUILD_TESTS)
    list(APPEND VCPKG_MANIFEST_FEATURES "tests")
endif()
if(LIBVRF_BUILD_BENCHMARKS)
    list(APPEND VCPKG_MANIFEST_FEATURES "benchmarks")
endif()

# Where to look for our helper modules.
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

project(libvrf VERSION 0.5.0 LANGUAGES CXX)

# Define additional directory path variables.
include(GNUInstallDirs)

# Setup runtime path.
# set(CMAKE_INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
# set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# Define source tree variables.
set(libvrf_INCLUDES_DIR "${CMAKE_CURRENT_LIST_DIR}")
set(libvrf_CONFIG_IN_FILENAME ${CMAKE_CURRENT_LIST_DIR}/cmake/libvrfConfig.cmake.in)

# Define build tree variables.
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY
    "${CMAKE_CURRENT_BINARY_DIR}/lib")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY
    "${CMAKE_CURRENT_BINARY_DIR}/lib")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY
    "${CMAKE_CURRENT_BINARY_DIR}/bin")
set(libvrf_CONFIG_FILENAME
    "${CMAKE_CURRENT_BINARY_DIR}/cmake/libvrfConfig.cmake")
set(libvrf_TARGETS_FILENAME
    "${CMAKE_CURRENT_BINARY_DIR}/cmake/libvrfTargets.cmake")
set(libvrf_CONFIG_VERSION_FILENAME
    "${CMAKE_CURRENT_BINARY_DIR}/cmake/libvrfConfigVersion.cmake")

# Define the install directories.
set(libvrf_VERSION_MM "${libvrf_VERSION_MAJOR}.${libvrf_VERSION_MINOR}")
set(libvrf_CONFIG_INSTALL_DIR
    "${CMAKE_INSTALL_LIBDIR}/cmake/libvrf-${libvrf_VERSION_MM}")
set(libvrf_INCLUDES_INSTALL_DIR
    "${CMAKE_INSTALL_INCLUDEDIR}/libvrf-${libvrf_VERSION_MM}")

# Find all source files.
set(libvrf_SOURCE_FILES "")
add_subdirectory(vrf)

# libvrf can only be built as a static library for now.
add_library(libvrf STATIC ${libvrf_SOURCE_FILES})
message(STATUS "[libvrf] Building static library")

# Require C++20 for libvrf and downstream.
target_compile_features(libvrf PUBLIC cxx_std_20)

find_package(spdlog REQUIRED)
target_link_libraries(libvrf PRIVATE spdlog::spdlog_header_only)

find_package(OpenSSL 3.2 REQUIRED)
target_link_libraries(libvrf PUBLIC OpenSSL::Crypto)

# For debug builds, append "_debug" to the library name.
set_target_properties(libvrf PROPERTIES DEBUG_POSTFIX "_debug")

# Since the project is called "libvrf", we want the output file to be "libvrf.a"
# (or "libvrf_debug.a" for debug builds) instead of just "liblibvrf.a".
set_target_properties(libvrf PROPERTIES OUTPUT_NAME "vrf")

# Set the VERSION and SOVERSION properties for semantic versioning.
# set_target_properties(libvrf PROPERTIES
#     VERSION ${libvrf_VERSION}
#     SOVERSION ${libvrf_VERSION_MAJOR}
# )

# Set our include directories.
target_include_directories(libvrf PUBLIC
    $<BUILD_INTERFACE:${libvrf_INCLUDES_DIR}>
    $<INSTALL_INTERFACE:${libvrf_INCLUDES_INSTALL_DIR}>
)

# Create an export set for libvrf.
install(TARGETS libvrf
    EXPORT libvrfTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/libvrf-${libvrf_VERSION_MM}
)

# Create the CMake config file.
include(CMakePackageConfigHelpers)
configure_package_config_file(
    ${libvrf_CONFIG_IN_FILENAME} ${libvrf_CONFIG_FILENAME}
    INSTALL_DESTINATION ${libvrf_CONFIG_INSTALL_DIR}
    PATH_VARS libvrf_INCLUDES_INSTALL_DIR libvrf_CONFIG_INSTALL_DIR
)

install(
    EXPORT libvrfTargets
    NAMESPACE libvrf::
    DESTINATION ${libvrf_CONFIG_INSTALL_DIR}
)

# Create a version file.
write_basic_package_version_file(
    ${libvrf_CONFIG_VERSION_FILENAME}
    VERSION ${libvrf_VERSION}
    COMPATIBILITY SameMajorVersion
)

# Install the CMake config file.
install(
    FILES ${libvrf_CONFIG_FILENAME} ${libvrf_CONFIG_VERSION_FILENAME}
    DESTINATION ${libvrf_CONFIG_INSTALL_DIR}
)

# Export libvrfTargets from the build tree so it can be used without installing.
export(
    EXPORT libvrfTargets
    NAMESPACE libvrf::
    FILE ${libvrf_TARGETS_FILENAME}
)

# Test suite.
if(LIBVRF_BUILD_TESTS)
    find_package(GTest REQUIRED)

    set(libvrf_TESTS_FILES "")
    add_subdirectory(tests)

    add_executable(vrf_tests ${libvrf_TESTS_FILES})
    target_link_libraries(vrf_tests PRIVATE
        libvrf
        GTest::gtest
    )
endif()

# Benchmark suite.
if(LIBVRF_BUILD_BENCHMARKS)
    find_package(benchmark REQUIRED)

    set(libvrf_BENCHMARKS_FILES "")
    add_subdirectory(benchmarks)

    add_executable(vrf_benchmarks ${libvrf_BENCHMARKS_FILES})
    target_link_libraries(vrf_benchmarks PRIVATE
        libvrf
        benchmark::benchmark
    )
endif()
