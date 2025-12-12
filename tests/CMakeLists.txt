# Integration tests (use LD_PRELOAD)
# These tests trigger errors that mguard should detect
# Detection tests use a wrapper script for CI compatibility

# Detection test - uses wrapper script to check for expected output
function(add_mguard_test name expected_pattern)
    add_executable(test_${name} test_${name}.c)

    add_test(
        NAME ${name}_detected
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/check_detection.sh
                $<TARGET_FILE:test_${name}>
                "${expected_pattern}"
    )
    set_tests_properties(${name}_detected PROPERTIES
        ENVIRONMENT "LD_PRELOAD=$<TARGET_FILE:mguard>;MGUARD_ENABLED=1;MGUARD_VERBOSE=1"
    )
endfunction()

# Special test for underflow - needs MGUARD_PROTECT_BELOW=1
function(add_mguard_underflow_test name expected_pattern)
    add_executable(test_${name} test_${name}.c)

    add_test(
        NAME ${name}_detected
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/check_detection.sh
                $<TARGET_FILE:test_${name}>
                "${expected_pattern}"
    )
    set_tests_properties(${name}_detected PROPERTIES
        ENVIRONMENT "LD_PRELOAD=$<TARGET_FILE:mguard>;MGUARD_ENABLED=1;MGUARD_PROTECT_BELOW=1;MGUARD_VERBOSE=1"
    )
endfunction()

# Safe test - runs with mguard but shouldn't crash
function(add_mguard_safe_test name)
    add_executable(test_${name} test_${name}.c)

    add_test(
        NAME ${name}
        COMMAND test_${name}
    )
    set_tests_properties(${name} PROPERTIES
        ENVIRONMENT "LD_PRELOAD=$<TARGET_FILE:mguard>;MGUARD_ENABLED=1;MGUARD_VERBOSE=1"
    )
endfunction()

# Safe test with pthread linking
function(add_mguard_safe_test_pthread name)
    add_executable(test_${name} test_${name}.c)
    target_link_libraries(test_${name} PRIVATE pthread)

    add_test(
        NAME ${name}
        COMMAND test_${name}
    )
    set_tests_properties(${name} PROPERTIES
        ENVIRONMENT "LD_PRELOAD=$<TARGET_FILE:mguard>;MGUARD_ENABLED=1;MGUARD_VERBOSE=1"
        TIMEOUT 120
    )
endfunction()

# ============================================================================
# Detection tests - these should trigger mguard error detection and crash
# ============================================================================

# Basic detection tests
add_mguard_test(overflow "MGUARD: Buffer overflow")
add_mguard_underflow_test(underflow "MGUARD: Buffer underflow")
add_mguard_test(uaf "MGUARD: Use-after-free")
add_mguard_test(double_free "MGUARD: Double-free")
add_mguard_test(mmap_overflow "MGUARD: Buffer overflow")

# Off-by-one overflow tests (may be detected immediately or on free)
add_mguard_test(overflow_offbyone "MGUARD: Buffer overflow")
add_mguard_test(overflow_aligned "MGUARD: Buffer overflow")
add_mguard_test(overflow_large "MGUARD: Buffer overflow")
add_mguard_test(mmap_offbyone "MGUARD: Buffer overflow")
add_mguard_test(overflow_calloc "MGUARD: Buffer overflow")
add_mguard_test(overflow_realloc "MGUARD: Buffer overflow")

# Realloc of freed pointer
add_mguard_test(realloc_freed "MGUARD: Realloc of freed")

# ============================================================================
# Safe tests - these should pass without crashing
# ============================================================================

# Basic functionality tests
add_mguard_safe_test(basic)
add_mguard_safe_test(aligned)
add_mguard_safe_test(mmap_basic)

# Edge case tests
add_mguard_safe_test(edge_cases)
add_mguard_safe_test(large_alloc)
add_mguard_safe_test(realloc)
add_mguard_safe_test(calloc)
add_mguard_safe_test(mmap_edge)

# Quarantine behavior tests
add_mguard_safe_test(quarantine)

# Stress and concurrency tests (needs pthread)
add_mguard_safe_test_pthread(stress)
