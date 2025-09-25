# Check that this CMake file is not invoked directly.
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
    message(FATAL_ERROR "${CMAKE_CURRENT_LIST_FILE} must not be invoked directly.")
endif()

# Add the source files from this directory.
set(libvrf_SOURCE_FILES ${libvrf_SOURCE_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/keys.cpp
    ${CMAKE_CURRENT_LIST_DIR}/params.cpp
    ${CMAKE_CURRENT_LIST_DIR}/rsavrf.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_LIST_DIR}/keys.h
        ${CMAKE_CURRENT_LIST_DIR}/params.h
        ${CMAKE_CURRENT_LIST_DIR}/rsavrf.h
    DESTINATION
        ${libvrf_INCLUDES_INSTALL_DIR}/vrf/rsa
)

# Update libvrf_SOURCE_FILES variable in the parent scope.
set(libvrf_SOURCE_FILES ${libvrf_SOURCE_FILES} PARENT_SCOPE)
