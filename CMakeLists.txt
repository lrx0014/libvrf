# Set up basic project that links with OpenSSL crypto library.
cmake_minimum_required(VERSION 3.21)

project(VRF_example VERSION 0.0.1 LANGUAGES C CXX)

# Set the output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

find_package(spdlog REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(GTest REQUIRED)
find_package(benchmark REQUIRED)

add_library(vrf
    lib/log.cpp
    lib/vrf.cpp
    lib/rsa/rsavrf.cpp
    lib/rsa/params.cpp
)


target_compile_features(vrf PUBLIC cxx_std_20)
target_include_directories(vrf PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/lib)
target_link_libraries(vrf PRIVATE spdlog::spdlog_header_only)
target_link_libraries(vrf PUBLIC OpenSSL::Crypto)

add_executable(test test/main.cpp)
target_include_directories(test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/test
    ${CMAKE_CURRENT_SOURCE_DIR}/lib)
target_link_libraries(test PRIVATE
    vrf
    GTest::gtest
)

add_executable(bench bench/main.cpp)
target_include_directories(bench PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/bench
    ${CMAKE_CURRENT_SOURCE_DIR}/lib)
target_link_libraries(bench PRIVATE
    vrf 
    benchmark::benchmark
)
