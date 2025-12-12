# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

mguard is a memory debugging LD_PRELOAD library for Linux that uses MADV_GUARD (kernel 6.13+) to detect memory errors: buffer overflows, underflows, use-after-free, and double-free.

## Build Commands

```bash
# Build
mkdir build && cd build
cmake ..
cmake --build .

# Run all tests
ctest

# Run single test
ctest -R overflow_detected --output-on-failure

# Run test binary directly with mguard
MGUARD_VERBOSE=1 LD_PRELOAD=./src/libmguard.so ./tests/test_basic
```

## Architecture

**Core Components (src/):**
- `interpose.c` - Main interposition: malloc/free/calloc/realloc/memalign/mmap/munmap/mremap. Contains bootstrap allocator for dlsym recursion.
- `registry.c` - Hash table tracking all allocations with per-bucket locking. Uses mmap'd entry pool to avoid malloc recursion.
- `quarantine.c` - Ring buffer holding freed allocations for use-after-free detection.
- `guard.c` - MADV_GUARD_INSTALL/REMOVE wrappers.
- `report.c` - Async-signal-safe error reporting and SIGSEGV/SIGBUS handlers.
- `config.c` - Environment variable parsing.

**Memory Layout (overflow detection mode):**
```
[pre_padding | user_data | post_padding | GUARD_PAGE]
```
User pointer positioned so overflow hits guard page. Pre/post padding filled with pattern (0xAA) checked on free.

**Key Design Decisions:**
- 16-byte alignment for malloc (SIMD compatibility) means small overflows land in padding, detected on free via pattern check
- Bootstrap buffer (256KB) handles allocations during dlsym initialization
- Thread-local `g_in_mguard` flag prevents recursion

## Environment Variables

- `MGUARD_ENABLED=0|1` - Enable/disable (default: 1)
- `MGUARD_PROTECT_BELOW=1` - Guard page before buffer (underflow detection)
- `MGUARD_QUARANTINE_MB=N` - Quarantine size in MB (default: 64)
- `MGUARD_VERBOSE=1` - Trace allocations to stderr
- `MGUARD_MIN_SIZE=N` - Skip guarding allocations smaller than N bytes

## Test Structure

Detection tests (`*_detected`) expect crashes - wrapped by `check_detection.sh` for CI.
Safe tests verify normal operations don't crash.
