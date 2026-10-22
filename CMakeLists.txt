cmake_minimum_required(VERSION 3.16)
project(SAGEArtifact VERSION 1.0 LANGUAGES CXX)
include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(CMAKE_BUILD_TYPE STREQUAL Debug)
    ADD_DEFINITIONS(-DSAGE_DEBUG)
    message(STATUS "SAGE debug mode")
    set(CMAKE_CXX_FLAGS "-O0 -g")
else() 
    set(CMAKE_CXX_FLAGS "-march=native -O3 -g -funroll-loops -mprefer-vector-width=512")
ENDIF()

#--------------------------Source tree-----------------------------
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")


#------------------------------Install-----------------------------
set(SAGE_INCLUDES_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR}/SAGE)

# ------Add source files to library and header files to install----
set(SAGE_SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/matmul.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/pbc.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/public_matrix.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sage_batch_protocol.cpp
)

install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/src/matmul.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/pbc.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/public_matrix.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/sage_batch_protocol.h
    DESTINATION
        ${SAGE_INCLUDES_INSTALL_DIR}
)
# -------------------------Add thirdparties--------------------------
# SAGE vendors only the native SEAL core and uses uncompressed serialization.
# Disable optional dependencies so a clean build never downloads unrelated code.
set(SEAL_BUILD_DEPS OFF CACHE BOOL "" FORCE)
set(SEAL_USE_MSGSL OFF CACHE BOOL "" FORCE)
set(SEAL_USE_ZLIB OFF CACHE BOOL "" FORCE)
set(SEAL_USE_ZSTD OFF CACHE BOOL "" FORCE)
set(SEAL_USE_INTEL_HEXL OFF CACHE BOOL "" FORCE)
add_subdirectory(thirdparties/SEAL)

#-------------------Build only a static library--------------------
add_library(SAGE STATIC ${SAGE_SOURCE_FILES})
target_include_directories(SAGE PUBLIC src)
target_include_directories(SAGE PUBLIC thirdparties/SEAL/native/src)

target_link_libraries(SAGE seal)
add_subdirectory(test)
