cmake_minimum_required(VERSION 3.16)
project(mguard
    VERSION 1.0.0
    DESCRIPTION "Memory Guard Shim - LD_PRELOAD library for memory error detection"
    LANGUAGES C
)

# C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Build type defaults
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Options
option(MGUARD_BUILD_TESTS "Build test programs" ON)

# Add cmake/ to module path
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Find required packages
find_package(Threads REQUIRED)

# Check for MADV_GUARD_INSTALL (Linux 6.13+)
include(CheckSymbolExists)
check_symbol_exists(MADV_GUARD_INSTALL "sys/mman.h" HAVE_MADV_GUARD_INSTALL)
if(NOT HAVE_MADV_GUARD_INSTALL)
    message(STATUS "MADV_GUARD_INSTALL not found in headers - defining fallback values (requires Linux 6.13+ at runtime)")
endif()

# Generate config header
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/include/mguard/config.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/include/mguard/config.h"
    @ONLY
)

# Add subdirectories
add_subdirectory(src)

if(MGUARD_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Installation rules
include(GNUInstallDirs)
install(TARGETS mguard
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
