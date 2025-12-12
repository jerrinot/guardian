# mguard

Memory guard library for Linux. Uses MADV_GUARD (kernel 6.13+) to detect buffer overflows, use-after-free, and double-free bugs.

## Requirements

- Linux kernel 6.13+
- CMake 3.16+
- GCC or Clang

## Build

```
mkdir build && cd build
cmake ..
make
```

## Usage

```
LD_PRELOAD=./libmguard.so ./your_program
```

Environment variables:
- `MGUARD_ENABLED=0` - disable
- `MGUARD_VERBOSE=1` - trace allocations
- `MGUARD_QUARANTINE_MB=64` - quarantine size for UAF detection
- `MGUARD_PROTECT_BELOW=1` - detect underflows instead of overflows
- `MGUARD_MIN_SIZE=N` - skip allocations smaller than N bytes

## How it works

Each allocation gets a guard page. Overflows hit the guard page and trigger SIGSEGV with diagnostic output.

Freed memory goes to quarantine: instead of releasing immediately, mguard marks it inaccessible and holds it in a ring buffer. If your program accesses freed memory, it crashes with "Use-after-free detected". Without quarantine, freed memory gets reused immediately and bugs go unnoticed. Old entries are released when quarantine fills up (default 64MB).

## License

MIT
