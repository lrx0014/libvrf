# Check that this CMake file is not invoked directly.
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
    message(FATAL_ERROR "${CMAKE_CURRENT_LIST_FILE} must not be invoked directly.")
endif()

set(libvrf_BENCHMARKS_FILES ${libvrf_BENCHMARKS_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/vrf_benchmarks.cpp
)

# Update libvrf_BENCHMARKS_FILES variable in the parent scope.
set(libvrf_BENCHMARKS_FILES ${libvrf_BENCHMARKS_FILES} PARENT_SCOPE)
