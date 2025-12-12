# Source files
set(MGUARD_SOURCES
    mguard.c
    config.c
    registry.c
    quarantine.c
    interpose.c
    guard.c
    report.c
)

# Create shared library
add_library(mguard SHARED ${MGUARD_SOURCES})

# Include directories
target_include_directories(mguard
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/../include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# Compile options
target_compile_options(mguard PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Werror=implicit-function-declaration
    $<$<CONFIG:Release>:-O2>
    $<$<CONFIG:Debug>:-O0 -g>
)

# Position independent code
set_target_properties(mguard PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
)

# Link libraries
target_link_libraries(mguard
    PRIVATE
        ${CMAKE_DL_LIBS}
        Threads::Threads
)
