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

# Safe test with underflow protection enabled
function(add_mguard_underflow_safe_test name)
    add_executable(test_${name} test_${name}.c)

    add_test(
        NAME ${name}
        COMMAND test_${name}
    )
    set_tests_properties(${name} PROPERTIES
        ENVIRONMENT "LD_PRELOAD=$<TARGET_FILE:mguard>;MGUARD_ENABLED=1;MGUARD_PROTECT_BELOW=1;MGUARD_VERBOSE=1"
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

# Safe disabled-mode test - runs with mguard preloaded but disabled
function(add_mguard_disabled_test name)
    add_executable(test_${name} test_${name}.c)
    target_link_libraries(test_${name} PRIVATE pthread)

    add_test(
        NAME ${name}
        COMMAND test_${name}
    )
    set_tests_properties(${name} PROPERTIES
        ENVIRONMENT "LD_PRELOAD=$<TARGET_FILE:mguard>;MGUARD_ENABLED=0"
    )
endfunction()

# Detection test that emulates JVM-style handler chaining and needs pthread.
function(add_mguard_jvm_pthread_test name expected_pattern)
    add_executable(test_${name} test_${name}.c)
    target_link_libraries(test_${name} PRIVATE pthread)

    add_test(
        NAME ${name}_detected
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/check_detection.sh
                $<TARGET_FILE:test_${name}>
                "${expected_pattern}"
    )
    set_tests_properties(${name}_detected PROPERTIES
        ENVIRONMENT "LD_PRELOAD=$<TARGET_FILE:mguard>;MGUARD_ENABLED=1;MGUARD_JVM=1;MGUARD_VERBOSE=0"
        TIMEOUT 15
    )
endfunction()

function(add_mguard_pthread_test name expected_pattern)
    add_executable(test_${name} test_${name}.c)
    target_link_libraries(test_${name} PRIVATE pthread)

    add_test(
        NAME ${name}_detected
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/check_detection.sh
                $<TARGET_FILE:test_${name}>
                "${expected_pattern}"
    )
    set_tests_properties(${name}_detected PROPERTIES
        ENVIRONMENT "LD_PRELOAD=$<TARGET_FILE:mguard>;MGUARD_ENABLED=1;MGUARD_VERBOSE=1"
        TIMEOUT 15
    )
endfunction()

function(add_mguard_bootstrap_calloc_test)
    add_library(test_bootstrap_calloc_probe SHARED test_bootstrap_calloc_probe.c)
    add_executable(test_bootstrap_calloc_main test_bootstrap_calloc_main.c)

    add_test(
        NAME bootstrap_calloc_overflow
        COMMAND test_bootstrap_calloc_main
    )
    set_tests_properties(bootstrap_calloc_overflow PROPERTIES
        ENVIRONMENT "LD_PRELOAD=$<TARGET_FILE:mguard>:$<TARGET_FILE:test_bootstrap_calloc_probe>;MGUARD_ENABLED=1;MGUARD_VERBOSE=0"
    )
endfunction()

# ============================================================================
# Detection tests - these should trigger mguard error detection and crash
# ============================================================================

# Basic detection tests
add_mguard_test(overflow "MGUARD: Buffer overflow")
add_mguard_underflow_test(underflow "MGUARD: Buffer underflow")
add_mguard_underflow_test(underflow_aligned "MGUARD: Buffer underflow")
add_mguard_test(uaf "MGUARD: Use-after-free")
add_mguard_test(double_free "MGUARD: Double-free")
add_mguard_pthread_test(concurrent_double_free "MGUARD: Double-free")
add_mguard_test(mmap_overflow "MGUARD: Buffer overflow")
add_mguard_underflow_test(mmap_underflow "MGUARD: Buffer underflow")
add_mguard_underflow_test(mmap_file_underflow "MGUARD: Buffer underflow")
add_mguard_test(chain_then_overflow "MGUARD: Buffer overflow")
add_mguard_jvm_pthread_test(threaded_signal_reentry "MGUARD: Buffer overflow")

# Off-by-one overflow tests (may be detected immediately or on free)
add_mguard_test(overflow_offbyone "MGUARD: Buffer overflow")
add_mguard_test(overflow_aligned "MGUARD: Buffer overflow")
add_mguard_test(overflow_large "MGUARD: Buffer overflow")
add_mguard_test(mmap_offbyone "MGUARD: Buffer overflow")
add_mguard_test(overflow_calloc "MGUARD: Buffer overflow")
add_mguard_test(overflow_realloc "MGUARD: Buffer overflow")
add_mguard_underflow_test(protect_below_malloc_tail "MGUARD: Buffer overflow")

# Realloc of freed pointer
add_mguard_test(realloc_freed "MGUARD: Realloc of freed")

# ============================================================================
# Safe tests - these should pass without crashing
# ============================================================================

# Basic functionality tests
add_mguard_safe_test(basic)
add_mguard_safe_test(aligned)
add_mguard_underflow_safe_test(aligned_protect_below)
add_mguard_safe_test(mmap_basic)
add_mguard_safe_test(mmap_partial)
add_test(NAME mmap_partial_protect_below COMMAND test_mmap_partial)
set_tests_properties(mmap_partial_protect_below PROPERTIES
    ENVIRONMENT "LD_PRELOAD=$<TARGET_FILE:mguard>;MGUARD_ENABLED=1;MGUARD_PROTECT_BELOW=1;MGUARD_VERBOSE=1"
)
add_mguard_safe_test(mremap_semantics)
add_mguard_underflow_safe_test(mmap_protect_below)

# Edge case tests
add_mguard_safe_test(edge_cases)
add_mguard_safe_test(large_alloc)
add_mguard_safe_test(huge_alloc)
add_mguard_safe_test(realloc)
add_mguard_safe_test(calloc)
add_mguard_safe_test(mmap_edge)

# Quarantine behavior tests
add_mguard_safe_test(quarantine)

# Signal handler chaining test
add_mguard_safe_test(chain)

# Disabled mode should delegate to libc while still preloaded
add_mguard_disabled_test(disabled)

# Stress and concurrency tests (needs pthread)
add_mguard_safe_test_pthread(stress)

# Bootstrap behavior tests
add_mguard_bootstrap_calloc_test()
