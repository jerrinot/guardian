# mguard correctness audit

Findings from a multi-agent review of `src/` focused on correctness. Each
finding is self-contained: a downstream agent should be able to read one
section and either dismiss the issue, classify it (e.g. duplicate / wontfix /
needs-design), or implement a fix without re-deriving the analysis.

Conventions:
- File:line citations are against the current `main` branch
  (`0d3b3e1`).
- Severity reflects user-visible impact, not effort to fix.
- "Trigger" sections describe a concrete input/sequence that exercises the
  bug; if you can't reproduce from it, the finding may be stale or wrong —
  please push back.

Tracking states (update both the index row and the per-finding `Status:`
line when changing state):

| State          | Meaning |
|----------------|---------|
| `open`         | Fresh from this audit. Not yet triaged. |
| `confirmed`    | Triaged and accepted as a real bug worth fixing. |
| `in-progress`  | Someone is actively working a fix (add who in the per-finding note). |
| `fixed`        | Patched in a commit/PR (add the SHA/PR # in the per-finding note). |
| `wontfix`      | Declined (add reason in the per-finding note: by-design / out-of-scope / accepted risk). |
| `duplicate`    | Same as another finding (add the `F#` it dupes in the per-finding note). |
| `needs-design` | Real bug but the fix requires a design decision before coding (note the open questions). |
| `invalid`      | Audit was wrong — bug doesn't exist (add a sentence on what was misread). |

---

## Index

| # | Status | Severity   | Area                | Title |
|---|--------|------------|---------------------|-------|
| F1  | fixed | critical | mmap            | `MGUARD_PROTECT_BELOW` totally broken for `mmap()` (size_t underflow + user data overlaps guard) |
| F2  | fixed | critical | signal-safety   | SIGSEGV/SIGBUS handler takes `pthread_mutex_t` |
| F3  | fixed | critical | concurrency     | Double-free / concurrent-free race in `free()` and `munmap()` |
| F4  | fixed | critical | signal-safety   | `in_sigsegv_handler` / `in_sigbus_handler` are process-global, not per-thread |
| F5  | fixed | serious  | concurrency     | Bootstrap allocator (`bootstrap_pos`) not thread-safe |
| F6  | fixed | serious  | malloc          | `calloc` bootstrap path lacks `nmemb * size` overflow check |
| F7  | fixed | serious  | mmap            | Partial `munmap()` silently unmaps the entire guarded region |
| F8  | fixed | serious  | mmap            | `mremap()` drops `MREMAP_FIXED` address and `MREMAP_MAYMOVE` semantics |
| F9  | fixed | serious  | mmap            | Anonymous `mmap()` default mode misses sub-16-byte overflows |
| F10 | fixed | serious  | malloc          | `memalign`/`posix_memalign`/`aligned_alloc`/`valloc` ignore `MGUARD_PROTECT_BELOW` |
| F11 | fixed | serious  | concurrency     | `realloc()` releases recursion guard mid-op; concurrent free of same `ptr` causes fault inside mguard |
| F12 | fixed | serious  | concurrency     | `g_mguard_initialized` is plain `int` (no acquire/release pairing with registry init) |
| F13 | fixed | serious  | malloc          | `aligned_alloc(alignment=0, size=0)` divides by zero |
| F14 | fixed | serious  | malloc/mmap     | No overflow check on `aligned + page_size` for huge requested sizes |
| F15 | fixed | serious  | concurrency     | `registry_insert` publishes new chain head without a release barrier |
| F16 | fixed | minor    | concurrency     | UAF detection window between `entry->magic = MAGIC_FREED` and `MADV_GUARD_INSTALL` |
| F17 | fixed | minor    | shutdown        | `quarantine_drain()` runs in destructor while other threads may still be live |
| F18 | fixed | minor    | malloc          | `realloc` of a bootstrap pointer reads past original allocation size |
| F19 | fixed | minor    | concurrency     | `load_warning_printed` not atomic |
| F20 | fixed | minor    | malloc          | malloc `MGUARD_PROTECT_BELOW` mode under-fills `post_padding` by up to 15 bytes |
| F21 | fixed | minor    | performance     | `free()` not-found path takes every bucket lock to print a TRACE |
| F22 | fixed | critical | disable-mode    | `MGUARD_ENABLED=0` leaves real libc symbols unresolved and routes through bootstrap/ENOSYS |
| F23 | fixed | serious  | mmap            | Anonymous `mmap()` returns non-page-aligned addresses |
| F24 | fixed | serious  | signal-safety   | Recoverable non-mguard SIGSEGV permanently disables mguard's SIGSEGV handler |
| F25 | fixed | minor    | tests           | mmap quarantine test is a false positive |

---

## F1. `MGUARD_PROTECT_BELOW` is completely broken for `mmap()` — `[critical]`

**Status**: `fixed` — fixed in the current working tree; covered by focused tests and full CTest.

**Files**: `src/interpose.c:618-645`

**Code in question** (`mmap()` anonymous, `protect_below` branch):

```c
if (g_config.protect_below) {
    user_ptr = (char *)base + page_size;
    /* Post-padding is between user data end and guard page */
    post_padding = aligned - page_size - length;
    if (post_padding > 0 && (prot & PROT_WRITE)) {
        memset((char *)user_ptr + length, g_config.fill_pattern, post_padding);
    }
}
...
/* Guard page at end */
void *guard_page = (char *)base + aligned;
if (guard_install(guard_page, page_size) != 0) { ... }
```

**Three independent bugs in this block:**

1. **No guard at the start.** Despite the `protect_below` branch name, no
   `guard_install` is performed on the leading page. The unconditional
   `guard_page = base + aligned` at line 639 always installs the guard at the
   end. Result: underflow detection is silently absent in this mode.

2. **`post_padding` is `size_t` and always underflows.** With
   `aligned = ALIGN_UP(length, page_size)` we have
   `aligned ≤ length + page_size - 1`, so `aligned - page_size ≤ length - 1 < length`,
   so `aligned - page_size - length` wraps to ~`SIZE_MAX` for every `length > 0`.
   Then `if (post_padding > 0 && (prot & PROT_WRITE))` is true → `memset` of
   ~`SIZE_MAX` bytes → segfault inside mguard.

3. **User data overlaps the guard page.** `user_ptr = base + page_size` and the
   guard is at `base + aligned`. If `length > aligned - page_size` (which is
   true for every non-zero length, since `aligned ≤ length + page_size - 1`),
   user data extends into the guard page. For `length = 4000, page_size = 4096`,
   `aligned = 4096`, so `user_ptr == guard_page` — the *first byte* of "user
   memory" faults on access.

**Trigger**: `MGUARD_PROTECT_BELOW=1 LD_PRELOAD=./libmguard.so <prog>` where the
program does any direct `mmap()` of a non-page-multiple length and `min_size`
is satisfied. With `PROT_WRITE` set, mguard itself crashes on the giant
`memset`. Without `PROT_WRITE`, the program crashes on first access.
This also reproduces with page-sized mappings: running the existing
`test_mmap_basic` binary under `MGUARD_PROTECT_BELOW=1` exits with SIGSEGV
before the test can print its own failure.

**Fix direction**: The branch needs to actually install a leading guard at
`base`, set `user_ptr = base + page_size`, and set `post_padding = aligned - length`
(the actual gap between user data end and end of mapping). The trailing
guard_install at line 639 must be conditional on `!protect_below`. Or
reserve `total = page_size + aligned + page_size` and have guards at both
ends like memalign-style; pick one design and make the math match.

---

## F2. SIGSEGV/SIGBUS handler is not async-signal-safe (takes `pthread_mutex_t`) — `[critical]`

**Status**: `fixed` — fixed in the current working tree; signal-path artifacts checked for unsafe internal PLT/TLS calls; full CTest passed.

**Files**: `src/report.c:164-257`, `src/registry.c:232-254`

**Code in question**:

```c
// report.c:181 (inside sigsegv_handler)
alloc_entry_t *entry = registry_lookup_containing(fault_addr);

// registry.c:232
alloc_entry_t *registry_lookup_containing(void *addr) {
    ...
    for (size_t i = 0; i < g_config.registry_buckets; i++) {
        pthread_mutex_lock(&bucket_locks[i]);    // NOT async-signal-safe
        ...
        pthread_mutex_unlock(&bucket_locks[i]);
    }
    ...
}
```

**Issue**: `pthread_mutex_lock` / `pthread_mutex_unlock` are not in the POSIX
async-signal-safe list (POSIX §2.4.3). Calling them from a signal handler is
undefined behavior. Concrete failure modes:

- If the faulting thread already held a bucket lock at the moment of the
  fault (e.g. the fault occurred while traversing or modifying a chain),
  the handler attempts to re-lock the same default `PTHREAD_MUTEX_NORMAL`
  → deadlock (undefined per POSIX but in practice a hang).
- The fault may have occurred *inside* `pthread_mutex_lock`, leaving futex /
  internal state inconsistent; a second `pthread_mutex_lock` from the same
  thread will deadlock or misbehave.
- Even when it doesn't deadlock, the syscall paths inside `pthread_mutex_*`
  are not designed to be reentrant from signal context.

This is the headline bug that makes mguard's crash reporter unreliable
precisely when it matters most.

**Trigger**: Any program that produces a guard-page fault while another
thread is concurrently inserting/looking up in the registry. Easier repro:
artificially set `MGUARD_BUCKETS=1` so every operation contends, run a
multi-threaded allocation workload, then trigger an overflow.

**Fix direction**: Make the handler-side walk lock-free. Concretely:
- Declare `buckets[]` as `_Atomic(alloc_entry_t *) *` (and `entry->next` atomic).
- In `registry_insert`, fill all fields, `atomic_thread_fence(memory_order_release)`,
  then atomic-store the new head with `memory_order_release`.
- In the handler, walk chains with `atomic_load_explicit(..., memory_order_acquire)`
  and do **not** take any mutex. Tolerate stale reads — entry pool chunks live
  for the process lifetime.
- Remove the `pthread_mutex_lock` loop from `registry_lookup_containing`,
  or split it into a "normal path" and "signal-safe path" variant. See also F15.

---

## F3. Double-free / concurrent-free race in `free()` and `munmap()` — `[critical]`

**Status**: `fixed` — fixed in the current working tree with bucket-lock claim; covered by double-free, concurrent double-free, stress, quarantine, and full CTest. Follow-up test coverage could add `MGUARD_QUARANTINE=0` and concurrent guarded `munmap()`.

**Files**: `src/interpose.c:270-322` (`free`), `src/interpose.c:670-705` (`munmap`)

**Code in question**:

```c
alloc_entry_t *entry = registry_lookup(ptr);   // takes/releases bucket lock
if (!entry) { ... }

// --- LOCK NOT HELD HERE ---
if (entry->magic == MAGIC_FREED) { report_double_free(...); }
if (!verify_padding(entry)) { report_overflow_on_free(...); }
entry->magic = MAGIC_FREED;

if (g_config.quarantine_entries > 0) {
    quarantine_add(entry);
} else {
    registry_remove(ptr);
    real_munmap(entry->real_addr, entry->real_size);
    registry_free_entry(entry);
}
```

**Issue**: `registry_lookup` releases the bucket lock before returning
(`registry.c:222, 227`). The magic check, padding check, magic store, and
quarantine/remove decisions all run without any lock. Two threads calling
`free(same_ptr)` (a buggy app's double-free, or a legitimate race in an
application that's the very kind of bug mguard exists to detect) both:

1. Look up the entry, both observe `MAGIC_ALIVE`.
2. Both pass `verify_padding`.
3. Both store `MAGIC_FREED` (idempotent — harmless on its own).
4. Both call `quarantine_add(entry)` → **the same entry is enqueued twice**
   in the ring buffer.
5. Later, when the ring evicts, `release_evict_batch` (`quarantine.c:85-95`)
   calls `registry_remove` twice (second is a no-op), `real_munmap` twice
   (second is a no-op on already-unmapped memory), and crucially
   `registry_free_entry` twice → the entry is pushed onto the pool free-list
   twice, creating a cycle. Next `registry_alloc_entry` walks into the
   cycle and hands out the same entry to two future allocations, silently
   corrupting registry state.

In the no-quarantine branch the symptom is more direct: thread A does
`real_munmap`; thread B then does `real_munmap` on already-unmapped memory
(EINVAL — silent loss) **and** calls `registry_free_entry` again → pool
free-list cycle.

**Trigger**: Two threads call `free(p)` (or `munmap(p, ...)`) on the same
pointer with quarantine enabled. Easiest synthetic repro: a tight `pthread`
loop where both threads `free` the same pointer.

**Fix direction**: Atomically CAS `entry->magic` from `MAGIC_ALIVE` to
`MAGIC_FREED` *before* the verify/quarantine path. CAS failure means another
thread won the race — that thread either succeeded (treat as a real
double-free against the now-quarantined entry: report it) or also lost
(impossible: exactly one thread CAS-succeeds). Make `magic` `_Atomic uint32_t`.
Mirror the change in `munmap()`. See also F11 for the related `realloc()` window.

---

## F4. `in_sigsegv_handler` / `in_sigbus_handler` are process-global — `[critical]`

**Status**: `fixed` — fixed in the current working tree; covered by focused signal-chain tests and full CTest.

**Files**: `src/report.c:13-15`

**Code in question**:

```c
/* Prevent re-entry when chaining to JVM handler that chains back to us */
static volatile sig_atomic_t in_sigsegv_handler = 0;
static volatile sig_atomic_t in_sigbus_handler = 0;
```

**Issue**: These flags are file-static (process-wide). If thread A is inside
the handler (set to 1 at `report.c:206`) and thread B faults concurrently,
B's handler returns early at `report.c:176-178` *without doing anything*.
The kernel restarts B's faulting instruction → infinite fault loop on B,
even though B's fault may be entirely unrelated to whatever A is reporting.

The comment "Prevent re-entry when chaining to JVM handler that chains back
to us" describes a same-thread reentry concern — the right primitive for
that is a TLS flag.

**Trigger**: Any program that produces two concurrent guard faults on
different threads. e.g. two threads each overflow their own buffer at the
same instant.

**Fix direction**: `static __thread volatile sig_atomic_t in_sigsegv_handler`.
Same for `in_sigbus_handler`. Note that `__thread` storage is initialized in
each thread's TLS area which is set up by the libc; it's safe to read/write
from a signal handler.

---

## F5. Bootstrap allocator (`bootstrap_pos`) is not thread-safe — `[serious]`

**Status**: `fixed` — fixed in the current working tree with a bounded CAS loop; covered by bootstrap calloc overflow, stress, disabled, and full CTest.

**Files**: `src/interpose.c:49-63`

**Code in question**:

```c
static char bootstrap_buf[262144];  /* 256KB */
static size_t bootstrap_pos = 0;

static void *bootstrap_alloc(size_t size) {
    size_t aligned = ALIGN_UP(size, MALLOC_ALIGNMENT);
    if (bootstrap_pos + aligned > sizeof(bootstrap_buf)) { ... }
    void *p = bootstrap_buf + bootstrap_pos;
    bootstrap_pos += aligned;             // RACE: read-modify-write, no atomic
    ...
}
```

**Issue**: Read-modify-write on `bootstrap_pos` without atomicity. Although
the constructor (`mguard.c:15`, priority 101) runs early, the bootstrap
path is reached *before* `mguard_init` resolves real symbols — and the very
allocations that hit this path come from `dlsym` itself, glibc TLS setup,
and other preloaded libraries. Some of these are known to spawn helper
threads (e.g. for TLS allocator init on certain glibc versions, or
GnuTLS/NSS initializers also using LD_PRELOAD). Two threads in
`bootstrap_alloc` simultaneously can read the same `bootstrap_pos`, both
get the same `p`, both advance — silent overlapping allocations that corrupt
each other.

**Trigger**: Hard to reliably reproduce because timing depends on which
libraries are loaded and which spawn early threads. The hazard is real but
latent.

**Fix direction**: `bootstrap_pos` as `_Atomic size_t` (or `atomic_size_t`),
use `atomic_fetch_add(&bootstrap_pos, aligned)` to claim a region. Handle
overflow by detecting the post-add value > buffer size (rare, but the
existing pre-check has the same TOCTOU bug).

---

## F6. `calloc` bootstrap path lacks `nmemb * size` overflow check — `[serious]`

**Status**: `fixed` — fixed in the current working tree; covered by bootstrap calloc overflow regression and full CTest.

**Files**: `src/interpose.c:324-329`

**Code in question**:

```c
void *calloc(size_t nmemb, size_t size) {
    /* Bootstrap path */
    if (!real_calloc) {
        size_t total = nmemb * size;          // wrap!
        return bootstrap_alloc(total);
    }
    ...
    if (__builtin_mul_overflow(nmemb, size, &total)) { ... }  // non-bootstrap path is correct
```

**Issue**: The non-bootstrap path uses `__builtin_mul_overflow`. The
bootstrap path multiplies into `size_t total` with no overflow check. A
caller (e.g. early-init code) doing `calloc(SIZE_MAX, 2)` gets a small
allocation but believes it received `SIZE_MAX * 2` bytes → buffer overflow
that mguard would normally have rejected.

**Trigger**: Any caller invoking `calloc(huge, huge)` before `dlsym`
resolution completes. In practice, hard to hit during normal init but
should still match the non-bootstrap behavior.

**Fix direction**: Move the overflow check above the bootstrap branch, or
duplicate it: `if (__builtin_mul_overflow(nmemb, size, &total)) return NULL;`
before calling `bootstrap_alloc(total)`.

---

## F7. Partial `munmap()` silently unmaps the entire guarded region — `[serious]`

**Status**: `fixed` — fixed in the current working tree by preserving `EINVAL` for zero-length/interior tracked `munmap()`, while supporting exact-base prefix unmaps by moving the registry entry to the remaining suffix; covered by `mmap_partial`, `mmap_partial_protect_below`, mmap-focused tests, and full CTest.

**Files**: `src/interpose.c:849-973`

**Code in question**:

```c
int munmap(void *addr, size_t length) {
    ...
    alloc_entry_t *entry = registry_lookup(addr);
    if (!entry) { return real_munmap(addr, length); }
    ...
    int result = real_munmap(entry->real_addr, entry->real_size);   // ignores `length`!
    ...
}
```

**Issue**: POSIX allows `munmap(addr, length)` where `length` is smaller
than the original mapping — the kernel splits the VMA and unmaps only the
requested range. mguard's interposer always unmaps `entry->real_size`,
which is `aligned + page_size`. A program that mmaps 16 pages and then
unmaps just the first 4 will instead lose all 16 + the guard. Many real
programs do partial unmaps (jemalloc, glibc's tcmalloc-style arenas, GC
runtimes, ring-buffer libraries).

There's also no handling for `munmap(addr+offset, len)` where `addr+offset`
is inside a tracked region — `registry_lookup` only matches exact
`user_addr`, so the call falls through to `real_munmap` and creates a hole
inside the tracked mapping while the registry still believes it's intact.
Subsequent `free`/`munmap` on the original `user_addr` then `real_munmap`s
a range with holes (harmless to the kernel, but `verify_padding` may
segfault reading unmapped pages).

**Trigger**: A program calls `mmap(NULL, 16*page_size, ...)` then
`munmap(base, 4*page_size)`. Or `munmap(base + page_size, page_size)`.
With mguard, the program now behaves nothing like it did under stock libc.
Another sharp case: `munmap(base, 0)` should fail with `EINVAL` and leave the
mapping alone, but the exact-address tracked path still removes the registry
entry and unmaps `entry->real_size`.

**Fix direction**: Either (a) detect partial unmap and forward to
`real_munmap` with the user-supplied range, removing the entry only if
length covers the whole user region, and update `entry->real_size`
accordingly; or (b) declare partial munmap unsupported and abort with a
clear diagnostic when detected. Option (a) is more correct but harder; (b)
is acceptable if documented in CLAUDE.md.

---

## F8. `mremap()` drops `MREMAP_FIXED` address and `MREMAP_MAYMOVE` semantics — `[serious]`

**Status**: `fixed` — fixed in the current working tree by failing unsupported tracked `mremap()` modes instead of silently changing semantics, supporting tracked file-backed remaps through guarded remap/release, accepting same-size tracked no-op remaps, rejecting interior tracked ranges before libc can mutate part of a guarded mapping, and claiming the old mapping during supported alloc-copy-release so concurrent releases cannot free/recycle the registry entry mid-`mremap`; covered by `mremap_semantics`, mmap-focused tests, and full CTest.

**Files**: `src/interpose.c:919-1059`

**Code in question**:

```c
void *new_address = NULL;
if (flags & MREMAP_FIXED) {
    va_list ap;
    va_start(ap, flags);
    new_address = va_arg(ap, void *);    // parsed but ...
    va_end(ap);
}
...
/* For tracked allocations, do alloc-copy-free instead of real mremap */
g_in_mguard = 0;

void *new_ptr = mmap(NULL, new_size, entry->prot, entry->flags, entry->fd, entry->offset);
//                  ^^^^ ... never used. new_address is discarded.
```

**Issue**: For tracked allocations, mremap is implemented as alloc-copy-free
through `mmap(NULL, ...)`. Two distinct semantic violations:

1. **`MREMAP_FIXED` is ignored.** Callers passing a target `new_address`
   expect the new mapping at exactly that address. With mguard, they get
   wherever the kernel decides.
2. **`MREMAP_MAYMOVE` is ignored.** Without `MREMAP_MAYMOVE`, the kernel is
   required to *fail with `-ENOMEM`* rather than move the mapping. mguard
   always moves. Code that depends on "fail rather than move" (a common
   pattern for in-place resize attempts) silently gets relocated.

3. **Dirty file-backed `MAP_PRIVATE` data is lost.** The code skips copying
   every file-backed mapping because "file content is already there"
   (`interpose.c:763-773`). That is false for private COW pages: a caller can
   write `p[0] = 'X'` to a private mapping, `mremap` it, and receive a new
   mapping where `new_p[0]` is the original file byte, not `'X'`.

Additionally for `MAP_SHARED` mappings the copy-and-replace pattern breaks
cross-process visibility: other processes that mapped the same fd/region
will see the original region disappear when mguard unmaps it.

**Trigger**: Any caller of `mremap(..., MREMAP_FIXED, addr)` or
`mremap(..., 0 /*no MAYMOVE*/)`. e.g. some database engines, ring buffer
libs, virtual-memory allocators. For the file-backed data-loss variant:
create a file, map it `MAP_PRIVATE|PROT_READ|PROT_WRITE`, dirty a byte,
then `mremap`; the dirty byte should survive.

**Fix direction**: When `MREMAP_FIXED` is set, the new mapping must land at
`new_address`; the current alloc-copy-free model can't honour that without
a reservation+`MAP_FIXED` dance. Simplest path: fall through to `real_mremap`
for tracked entries when `MREMAP_FIXED` or `!MREMAP_MAYMOVE` is set, and
update the registry entry to point at the new location (re-installing the
guard page accordingly). Document that mguard's `mremap` support is
best-effort for the MAYMOVE case only.

---

## F9. Anonymous `mmap()` default mode misses sub-16-byte overflows — `[serious]`

**Status**: `fixed` — fixed in the current working tree; covered by mmap off-by-one regression and full CTest.

**Files**: `src/interpose.c:625-634, 91-118` (`verify_padding`)

**Code in question**:

```c
} else {
    /* Byte-level detection */
    size_t effective = ALIGN_UP(length, MALLOC_ALIGNMENT);
    pre_padding = aligned - effective;
    user_ptr = (char *)base + pre_padding;
    /* Fill pre-padding */
    if (pre_padding > 0 && (prot & PROT_WRITE)) {
        memset(base, g_config.fill_pattern, pre_padding);
    }
}
// post_padding is NEVER set in this branch.
```

**Issue**: For anonymous mmap in default (overflow) mode, only `pre_padding`
is computed and filled. `post_padding` stays at its initializer (0). The
actual gap between user data end and the guard page is
`aligned - length - pre_padding = aligned - length - (aligned - effective)
= effective - length`, which is 0..15 bytes. Those bytes are kernel-zero,
not `0xAA`. On `munmap`, `verify_padding` (`interpose.c:108`) skips the
post-side because `entry->post_padding == 0`. So a 1..15-byte overflow past
the requested `length` of a non-page-multiple anonymous mmap goes
undetected.

(Contrast: `malloc()` correctly sets `post_padding = effective - size` at
`interpose.c:223`. This regression is mmap-only.)

**Trigger**: Direct `mmap(NULL, 4000, PROT_RW, MAP_ANON|MAP_PRIVATE, -1, 0)`,
then write to byte offset 4001..4015. mguard reports nothing.

**Fix direction**: Compute and fill `post_padding = effective - length` and
write it into `entry->post_padding` before calling `register_alloc`. Mirror
the malloc layout.

---

## F10. `memalign` family ignores `MGUARD_PROTECT_BELOW` — `[serious]`

**Status**: `fixed` — fixed in the current working tree by placing the leading guard immediately before the aligned user pointer; covered by `underflow_aligned`, `aligned_protect_below`, aligned/huge tests, and full CTest.

**Files**: `src/interpose.c:406-522`

**Code in question** (`memalign()` has no `protect_below` branch):

```c
void *memalign(size_t alignment, size_t size) {
    ...
    /* Guard page at end */
    void *guard_page = (char *)base + aligned;
    ...
}
```

`posix_memalign`, `aligned_alloc`, and `valloc` all funnel through `memalign`,
so they inherit the limitation.

**Issue**: Setting `MGUARD_PROTECT_BELOW=1` is documented (in CLAUDE.md) as
"Guard page before buffer (underflow detection)". For allocations going
through the memalign family, the flag has no effect — the guard always
goes at the end. A program designed to catch underflow on page-aligned
buffers (a common case for I/O code, ring buffers, JITs) will silently
fail to detect underflow.

**Trigger**: `MGUARD_PROTECT_BELOW=1` + a program using `posix_memalign` or
`aligned_alloc` or `valloc`, plus a write at byte `[-1]` of the returned
buffer. No detection.

**Fix direction**: Add a `protect_below` branch to `memalign` analogous to
malloc's. Note that aligned addresses inside the writable region complicate
the layout: `ALIGN_UP(base + page_size, alignment)` must land within the
mapping. Easiest is to over-reserve `total = page_size + aligned + alignment`,
put the guard at `base`, choose `user_addr = ALIGN_UP(base + page_size, alignment)`,
and treat the post region as padding.

---

## F11. `realloc()` releases recursion guard mid-op; concurrent free of same `ptr` faults inside mguard — `[serious]`

**Status**: `fixed` — fixed in the current working tree with a bucket-lock realloc claim, transient `MAGIC_REALLOCING` state, allocation-failure restore, and direct old-entry release after copy; covered by realloc-focused tests, stress, full CTest, and focused subagent review.

**Files**: `src/interpose.c:376-403`

**Code in question**:

```c
alloc_entry_t *entry = registry_lookup(ptr);
...
if (entry->magic != MAGIC_ALIVE) { report_realloc_freed(...); }

g_in_mguard = 0;                          // <-- recursion guard cleared

void *new_ptr = malloc(size);             // may take a long time (mmap + guard_install)
if (!new_ptr) return NULL;

memcpy(new_ptr, ptr, MIN(entry->user_size, size));  // <-- reads from `ptr`

free(ptr);                                 // <-- releases via normal path
```

**Issue**: Between clearing `g_in_mguard` and the trailing `free(ptr)`,
another thread can call `free(ptr)` on the same pointer (a UAF in the
application; or a double-free; or a thread-confusion bug — exactly the kind
of bug mguard exists to detect). That sibling `free` will:
1. Mark the entry `MAGIC_FREED` and quarantine it (per F3, racy but assume
   one thread wins);
2. `quarantine_add` runs `MADV_GUARD_INSTALL` over the real region,
   including the user pages.

When the realloc thread then performs the `memcpy(new_ptr, ptr, ...)`,
reads from the now-guarded pages trigger SIGSEGV *inside mguard's own
`realloc`*, producing a confusing report ("buffer underflow inside realloc")
that obscures the underlying application bug.

**Trigger**: Two threads share a heap pointer. Thread A calls
`realloc(p, ...)`. Thread B calls `free(p)`. Order them so that B's
`quarantine_add` runs between A's `g_in_mguard = 0` and A's `memcpy`.

**Fix direction**: Transition `entry->magic` to a transient state
(`MAGIC_REALLOCING = 0xA11CE002`?) under the bucket lock with CAS, do the
copy, then transition to `MAGIC_FREED` and release. Other threads that
observe the transient state report "concurrent free/realloc race detected"
and abort. Couples tightly with the F3 fix.

---

## F12. `g_mguard_initialized` is plain `int` — `[serious]`

**Status**: `fixed` — fixed in the current working tree by making `g_mguard_initialized` an atomic release/acquire publication flag; all interposer read sites use an acquire helper, focused init/stress tests passed, full CTest passed, and focused subagent review found no blockers.

**Files**: `src/mguard.c:10, 17, 28, 54`; read sites in `src/interpose.c:161, 262, 369, 408, 542, 664, 723`

**Code in question**:

```c
// mguard.c
int g_mguard_initialized = 0;
...
// after configuring buckets, quarantine, signal handlers:
g_mguard_initialized = 1;

// interpose.c (read from arbitrary threads)
if (g_in_mguard || !g_mguard_initialized || !g_config.enabled) { ... }
```

**Issue**: `g_mguard_initialized` is a plain `int` written by the init
thread after `registry_init` populates `buckets[]` and `quarantine_init`
populates `quarantine.ring`. Other threads read `g_mguard_initialized`
with no synchronization. On weakly-ordered architectures (aarch64 — and the
project documentation mentions arm64 page sizes), a reader can observe
`g_mguard_initialized == 1` while still seeing the pre-init `buckets` and
`quarantine.ring` (both NULL). The reader then enters the slow path and
dereferences `buckets[bucket]` → segfault inside `registry_lookup`.

Constructor-time `init` *usually* runs before app threads, but other
preloaded libraries and dynamic loader paths can spawn threads before
priority-101 constructors finish.

**Trigger**: Hard to reproduce on x86 (strong memory model). aarch64 with
an `LD_PRELOAD` chain that also spawns a thread in an earlier constructor.

**Fix direction**: `_Atomic int g_mguard_initialized`, store with
`memory_order_release` in `mguard_init`, load with `memory_order_acquire`
at every read site. Or use `pthread_once` for the init path.

---

## F13. `aligned_alloc(alignment=0, size=0)` divides by zero — `[serious]`

**Status**: `fixed` — fixed in the current working tree; covered by aligned allocation regression and full CTest.

**Files**: `src/interpose.c:507-517`

**Code in question**:

```c
void *aligned_alloc(size_t alignment, size_t size) {
    /* aligned_alloc requires size to be multiple of alignment */
    if (size % alignment != 0) {           // <-- alignment == 0 → SIGFPE
        ...
    }
    void *ptr = memalign(alignment, size);
    ...
}
```

**Issue**: No check that `alignment != 0` before the modulo. The C11 standard
says `aligned_alloc` with an unsupported alignment is undefined behaviour,
but glibc rejects it cleanly with `EINVAL`. mguard crashes the process.

Additionally there's no check that `alignment` is a power of two (also a
C11 requirement). `memalign` itself doesn't validate `alignment` either
(`interpose.c:406`) — only `posix_memalign` does (`interpose.c:491`).

**Trigger**: `aligned_alloc(0, 0)` — easy to hit accidentally or via
fuzzing.

**Fix direction**: Validate `alignment` at the top of `aligned_alloc` and
`memalign`: must be non-zero, power of two, and (for `aligned_alloc`)
`size` must be a multiple of `alignment`. Return `NULL`/`EINVAL` per the
spec.

---

## F14. No overflow check on `aligned + page_size` for huge requested sizes — `[serious]`

**Status**: `fixed` — fixed in the current working tree; covered by huge allocation regression and full CTest.

**Files**: `src/interpose.c:188-190` (malloc), `:333-340` (calloc), `:395` (realloc), `:432-436` (memalign), `:496`, `:514`, `:560-561` (mmap)

**Code in question** (malloc):

```c
size_t effective = ALIGN_UP(size, MALLOC_ALIGNMENT);
size_t aligned = ALIGN_UP(effective, page_size);
size_t total = aligned + page_size;       // wrap!
```

**Issue**: `ALIGN_UP(x, a) = ((x + a - 1) & ~(a - 1))`. For `size` near
`SIZE_MAX`, the `x + a - 1` step wraps to a small value; `aligned` ends up
tiny and the subsequent `mmap(total, ...)` succeeds with a small mapping.
The caller, believing they received their requested huge size, writes far
past the end.

Memalign has the same issue at `padded = size + alignment`, then `aligned
= ALIGN_UP(effective, page_size)`. `posix_memalign` and `aligned_alloc`
both funnel through that same unchecked path, so their apparent validation
does not protect against a huge `size`.

`calloc` only checks `nmemb * size` overflow; `calloc(1, SIZE_MAX - 8)` still
delegates to `malloc(total)` and hits the same layout wrap. Guarded `realloc`
inherits the same bug through `malloc(size)` before copying the old contents.

**Trigger**: `malloc(SIZE_MAX - 4095)` or `memalign(huge, huge)`. The real
allocator would return NULL; mguard returns a tiny but valid pointer, or
crashes while preparing padding. Locally, a tiny program that called
`malloc(SIZE_MAX - 8)` under the current preload exited with SIGSEGV before
printing; expected behavior is `NULL` with `errno = ENOMEM`.

**Fix direction**: Use `__builtin_add_overflow` / `__builtin_mul_overflow`
to compute `effective`, `aligned`, `total`. On overflow set `errno = ENOMEM`
and return NULL.

---

## F15. `registry_insert` publishes new chain head without a release barrier — `[serious]`

**Status**: `fixed` — fixed in the current working tree; signal-path artifacts checked for release/acquire publication and local calls; full CTest passed.

**Files**: `src/registry.c:186-211`

**Code in question**:

```c
size_t bucket = hash_addr(entry->user_addr);

pthread_mutex_lock(&bucket_locks[bucket]);
entry->next = buckets[bucket];
buckets[bucket] = entry;
...
pthread_mutex_unlock(&bucket_locks[bucket]);
```

**Issue**: The mutex provides happens-before for *other mutex holders*. But
the signal handler walks chains without holding the mutex (or *should*, per
F2's fix); and even today, on weakly-ordered hardware, readers that
fast-path through the structure without locking are not safe.

Concretely: the writer fills `entry->user_addr`, `entry->magic`,
`entry->real_addr`, etc. in `register_alloc` (`interpose.c:133-144`) — plain
stores. Then it calls `registry_insert`, which under the mutex stores
`buckets[bucket] = entry`. Without an explicit release fence between the
field stores and the head publication, a concurrent lock-free reader on
another CPU can observe `buckets[bucket] == entry` while `entry->user_addr`
is still its previous value (the pool was zeroed when allocated, so likely
NULL) → reader dereferences NULL or stale fields.

Today this is masked because all readers also lock. But (a) the signal
handler path must become lock-free (F2), and (b) even with locks, removing
this hazard up-front is correct and cheap.

**Trigger**: aarch64 / Power, lock-free reader (post-F2 fix). On x86 the
hazard is largely masked by TSO.

**Fix direction**: Declare `buckets` as `_Atomic(alloc_entry_t *) *` and
`entry->next` as atomic. In `registry_insert`, fill `entry->next` with an
atomic-store-release, then atomic-store-release the new head. Pair with
acquire loads in any lock-free reader. Documented design contract: any
field of `alloc_entry_t` reachable from `buckets[]` must be set before the
release-store on `buckets[bucket]`.

---

## F16. UAF detection window between `entry->magic = MAGIC_FREED` and `MADV_GUARD_INSTALL` — `[minor]`

**Status**: `fixed` — fixed in the current working tree by using `MAGIC_FREEING` as the claimed release state, installing the guard before publishing `MAGIC_FREED`, and treating guarded `MAGIC_FREEING` user faults as UAF; focused UAF/double-free/quarantine/realloc/stress tests, full CTest, and focused subagent re-review passed.

**Files**: `src/interpose.c:302, 312`; `src/quarantine.c:107`

**Code in question**:

```c
// interpose.c:302
entry->magic = MAGIC_FREED;
if (g_config.quarantine_entries > 0) {
    quarantine_add(entry);     // <-- not yet guarded
} else { ... }

// quarantine.c:107 (inside quarantine_add)
guard_install(entry->real_addr, entry->real_size);
```

**Issue**: There's a small window where `magic == MAGIC_FREED` but the
pages are not yet `MADV_GUARD_INSTALL`'d. A racing thread with a stale
pointer can read/write the memory without faulting. A subsequent
SIGSEGV-handler lookup of the same address would correctly report UAF
*if* the thread reads after the guard install, but a touch during the
window is silently allowed.

This is inherent to "set magic, then guard": you can't atomically combine
a memory store and a syscall. The window is short (~one syscall) and
involves a fundamentally racy app bug — but worth noting.

**Trigger**: Two threads, A calls `free(p)`, B touches `*p` between A's
`magic = MAGIC_FREED` store and the kernel's installation of the guard.
Single-byte touches will not be detected.

**Fix direction**: Reorder to `guard_install` first, then store
`MAGIC_FREED`. Note: this depends on F3's CAS being in place, otherwise
two threads can both call `guard_install` and both call
`quarantine_add` — but the existing race on `quarantine_add` is already F3.
Order-fix is cheap once F3 lands.

---

## F17. `quarantine_drain()` runs in destructor while other threads may still be live — `[minor]`

**Status**: `fixed` — fixed in the current working tree by removing the destructor `quarantine_drain()` path and letting the kernel reclaim guarded mappings at process exit; quarantine/stress/disabled focused tests, full CTest, and focused subagent review passed.

**Files**: `src/mguard.c:57-67`, `src/quarantine.c:132-145`

**Code in question**:

```c
__attribute__((destructor))
static void mguard_fini(void) {
    if (!g_mguard_initialized || !g_config.enabled) return;
    ...
    quarantine_drain();
}
```

`quarantine_drain` calls `release_evict_batch` which calls `registry_remove`,
`real_munmap`, and `registry_free_entry` for every quarantined entry.

**Issue**: Destructors run during process exit but the system does not
join other threads first. If a sibling thread is mid-`free()` (the
quarantined entry it added moments ago is what we're now releasing), or
mid-`malloc()`-which-allocates-a-new-pool-entry, the operations race.

In practice, process exit usually means "let the kernel clean it all up" —
the only reason to drain is to release virtual address back to the kernel
that the kernel was about to reclaim anyway. So the cost of the bug is
small (occasional confusing crashes at exit when atexit handlers in the
app are still running).

**Trigger**: Any multi-threaded app exiting while other threads are still
working in mguard paths. Most visible when the app exits via `_exit()`
soon after an mguard fault report, racing the destructor.

**Fix direction**: Either remove `quarantine_drain()` from the destructor
(let the kernel reclaim everything on exit), or guard the entire mguard
fast path with a "shutting_down" flag that makes new ops fall through to
real_*.

---

## F18. `realloc` of a bootstrap pointer reads past original allocation — `[minor]`

**Status**: `fixed` — fixed in the current working tree by making nonzero `realloc()` of bootstrap pointers fail with `ENOMEM` instead of copying an unknown size; bootstrap/realloc/disabled/stress focused tests, full CTest, and focused subagent review passed.

**Files**: `src/interpose.c:358-365`

**Code in question**:

```c
/* Bootstrap pointers can't be reallocated properly */
if (is_bootstrap_ptr(ptr)) {
    void *new_ptr = malloc(size);
    if (new_ptr) {
        /* Copy what we can - we don't know original size */
        memcpy(new_ptr, ptr, size);     // <-- may exceed original allocation
    }
    ...
}
```

**Issue**: Bootstrap allocations don't record their size. `realloc` copies
`size` bytes regardless. If `size > original_alloc_size`, the `memcpy` reads
past the original bootstrap allocation into adjacent bootstrap entries
(still within `bootstrap_buf`, so no segfault — but the copied trailing
bytes are some other early-init buffer's data). The new buffer contains
garbage past the original logical end.

**Trigger**: Any caller that `realloc`s a pointer that was originally
returned from `bootstrap_alloc`. Real-world: rare, because bootstrap
allocations belong to libraries (libdl, libpthread internals) that don't
typically realloc them — but possible.

**Fix direction**: Either record bootstrap allocation sizes alongside
`bootstrap_pos` (turn `bootstrap_buf` into a tiny bump allocator that also
stores per-allocation size headers) or refuse to realloc bootstrap pointers
(`return NULL; errno = ENOMEM`). The former is correct; the latter is
simpler and matches the "bootstrap path is best-effort" spirit.

---

## F19. `load_warning_printed` is not atomic — `[minor]`

**Status**: `fixed` — fixed in the current working tree with an atomic warning-once exchange; stress and full CTest passed.

**Files**: `src/registry.c:78, 205-210`

**Code in question**:

```c
static int load_warning_printed;
...
if (!load_warning_printed && chain_len > REGISTRY_LOAD_WARN_THRESHOLD) {
    load_warning_printed = 1;
    fprintf(stderr, "[mguard] WARNING: ...\n");
}
```

**Issue**: Two threads can both see `load_warning_printed == 0` and both
print the warning. Cosmetic, not a correctness bug, but trivial to fix.

**Fix direction**: `static atomic_int load_warning_printed = 0;` and
`if (chain_len > THRESHOLD && atomic_exchange(&load_warning_printed, 1) == 0) { fprintf(...); }`.

---

## F20. malloc `MGUARD_PROTECT_BELOW` mode under-fills `post_padding` by up to 15 bytes — `[minor]`

**Status**: `fixed` — fixed in the current working tree by using `aligned - size` for protect-below malloc tail padding; covered by a new corrupt-last-tail-byte regression, underflow/off-by-one focused tests, full CTest, and focused subagent review.

**Files**: `src/interpose.c:207-215`

**Code in question**:

```c
if (g_config.protect_below) {
    guard_page = base;
    user_ptr = (char *)base + page_size;
    /* Fill padding after user data */
    post_padding = aligned - effective;          // <-- not the actual gap
    if (post_padding > 0) {
        memset((char *)user_ptr + size, g_config.fill_pattern, post_padding);
    }
}
```

**Issue**: The writable region in protect-below mode is `[base + page_size,
base + page_size + aligned)`. User data is at `[user_ptr, user_ptr + size)`.
The actual gap to the end of the writable region is `aligned - size`. The
code fills `aligned - effective = aligned - ALIGN_UP(size, 16)`, which is
up to 15 bytes shorter. The last 0..15 bytes of the writable region are
*not* filled and not checked. A pathological overflow that lands only in
those final bytes is undetected.

In practice that means a tiny overflow of e.g. exactly the right size to
skip the post-padding pattern check is missed — unusual.

(Default overflow mode is fine: layout math at `interpose.c:216-231` is
correct; user data abuts the guard page.)

**Fix direction**: `post_padding = aligned - size` (the true gap), and
keep `effective` only for figuring out where to place `user_ptr` (which
isn't needed in protect-below mode since `user_ptr` is page-aligned).

---

## F21. `free()` not-found path takes every bucket lock to print a TRACE — `[minor, performance]`

**Status**: `fixed` — fixed in the current working tree by gating the expensive free-not-found containing-address scan behind `MGUARD_VERBOSE`; double-free/stress focused tests and full CTest passed. The `munmap()` containing scan remains because it enforces partial-`munmap()` rejection.

**Files**: `src/interpose.c:273-285`

**Code in question**:

```c
alloc_entry_t *entry = registry_lookup(ptr);
if (!entry) {
    /* Not our allocation - check if it's inside one of ours (bug detection) */
    alloc_entry_t *containing = registry_lookup_containing(ptr);   // <-- O(buckets×chain), all locks
    if (containing) { TRACE(...); }
    else { TRACE(...); }
    g_in_mguard = 0;
    real_free(ptr);
    return;
}
```

**Issue**: Every `free()` on a pointer mguard doesn't own (e.g. a pointer
from the original libc heap, used as a comparison/sentinel, or anything
returned before mguard initialized) takes `g_config.registry_buckets`
(default 65536) mutexes in sequence, just to populate a TRACE message that
is discarded unless `MGUARD_VERBOSE=1` is set. Heavy contention spike under
multi-threaded workloads with lots of "stray" pointers.

**Fix direction**: Gate `registry_lookup_containing` behind
`if (g_config.verbose)` — the result is only used for trace output.

---

## F22. `MGUARD_ENABLED=0` leaves real libc symbols unresolved — `[critical]`

**Status**: `fixed` — fixed in the current working tree; covered by disabled-mode regression and full CTest.

**Files**: `README.md:25-27`, `src/mguard.c:27-33`, `src/interpose.c:154-158, 526-530`

**Code in question**:

```c
// mguard.c
if (!g_config.enabled) {
    g_mguard_initialized = 1;
    return;                         // interpose_init() was not called
}

// interpose.c
void *malloc(size_t size) {
    if (!real_malloc) {
        return bootstrap_alloc(size);
    }
    ...
}

void *mmap(...) {
    if (!real_mmap) {
        errno = ENOSYS;
        return MAP_FAILED;
    }
    ...
}
```

**Issue**: README advertises `MGUARD_ENABLED=0` as a disable switch. But the
constructor returns before resolving the real libc functions. The interposed
symbols are still active through `LD_PRELOAD`, so disabled mode is not a
pass-through mode:

- `malloc`/`calloc` route into the fixed 256 KiB bootstrap buffer forever.
- `free` on bootstrap pointers is ignored.
- `mmap` fails with `ENOSYS` because `real_mmap == NULL`.

This can make a supposedly disabled preload more dangerous than the enabled
mode.

**Trigger**: `MGUARD_ENABLED=0 LD_PRELOAD=./libmguard.so ./tests/test_mmap_basic`
fails immediately because anonymous `mmap` returns `MAP_FAILED`. Running the
existing stress test under the same environment exhausts the bootstrap buffer
and aborts in glibc thread-stack allocation.

**Fix direction**: Always call `interpose_init()` before the enabled check, so
disabled mode can delegate to real libc. Keep registry/quarantine/report
initialization behind the enabled check.

---

## F23. Anonymous `mmap()` returns non-page-aligned addresses — `[serious]`

**Status**: `fixed` — fixed in the current working tree by returning page-aligned anonymous mmap bases in default mode, retaining trailing padding checks, and accepting original or page-rounded lengths for tracked `munmap()`/`mremap()`; mmap/mremap focused tests, full CTest, and focused subagent re-review passed.

**Files**: `src/interpose.c:625-634`, `tests/test_mmap_edge.c:324-326`

**Code in question**:

```c
size_t effective = ALIGN_UP(length, MALLOC_ALIGNMENT);
pre_padding = aligned - effective;
user_ptr = (char *)base + pre_padding;
```

**Issue**: The kernel `mmap()` ABI returns a page-aligned mapping base. mguard
returns `base + pre_padding` for anonymous mappings in default mode, and the
test suite explicitly accepts non-page-aligned mmap results. That breaks real
callers that pass the returned address to `mprotect`, `msync`, `madvise`,
`munmap` with subranges, page-table walkers, JITs, or VM allocators.

This is distinct from F9. F9 is about missed sub-16-byte overflow detection
inside the current shifted-pointer design. This finding is that the shifted
pointer itself violates `mmap`'s contract.

**Trigger**:

```c
void *p = mmap(NULL, 1000, PROT_READ|PROT_WRITE,
               MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
assert((uintptr_t)p % sysconf(_SC_PAGESIZE) == 0);
```

Under mguard today, the assertion can fail.

**Fix direction**: Do not return shifted pointers from `mmap`. Either keep
anonymous mmap page-granular (page-aligned base, trailing guard page, no
byte-precise detection for sub-page overflows), or document and expose a
separate non-mmap API for byte-precise guarded regions.

---

## F24. Recoverable non-mguard SIGSEGV disables future mguard reports — `[serious]`

**Status**: `fixed` — fixed in the current working tree; covered by signal-chain regressions and full CTest.

**Files**: `src/report.c:187-189, 328-330`, `tests/test_chain.c:28-36`

**Code in question**:

```c
// report.c
if (!entry) {
    chain_handler(&old_sigsegv_action, sig, info, ucontext);
    return;
}
...
sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
sigaction(SIGSEGV, &sa, &old_sigsegv_action);
```

**Issue**: `SA_RESETHAND` resets the SIGSEGV disposition before the handler
knows whether the fault belongs to mguard. If the fault is not in
mguard-managed memory, mguard chains to the previous handler. If that previous
handler recovers, as `tests/test_chain.c` intentionally does with
`siglongjmp`, mguard's handler is no longer installed. The next real guard-page
fault becomes a plain SIGSEGV with no `MGUARD:` report.

**Trigger**: Extend `tests/test_chain.c` so that after
`trigger_non_mguard_fault()` returns, it allocates a guarded buffer and writes
into the guard page. Expected: mguard diagnostic. With the current
`SA_RESETHAND` setup, the process can terminate without mguard reporting.

**Fix direction**: Remove `SA_RESETHAND`, or reinstall mguard's handler before
chaining non-owned faults to a recoverable previous handler. The JVM comment in
`report_init` should be rechecked: current JVM mode skips installing mguard's
handler in `mguard_init`, so `SA_RESETHAND` is not buying the documented JVM
behavior in that mode.

---

## F25. mmap quarantine test is a false positive — `[minor]`

**Status**: `fixed` — fixed in the current working tree by removing the false-positive mmap quarantine case from the heap quarantine test; mmap lifetime remains covered by mmap tests, and quarantine/mmap focused tests plus full CTest passed.

**Files**: `tests/test_quarantine.c:219-237`, `src/interpose.c:694-699`

**Code in question**:

```c
// tests/test_quarantine.c
munmap(p, 4096);

/* mmap'd regions should also be quarantined */
if (causes_segfault(saved)) {
    PASS();
}

// interpose.c
entry->magic = MAGIC_FREED;
registry_remove(addr);
int result = real_munmap(entry->real_addr, entry->real_size);
registry_free_entry(entry);
```

**Issue**: The test claims to verify mmap quarantine, but `munmap()` removes
the entry and unmaps the backing region immediately. A later access segfaults
because the address is unmapped, not because it is quarantined or still
registered as a freed guarded allocation. The test passes even if mmap
quarantine does not exist.

**Trigger**: Run the existing `quarantine` test. Test 8 passes on a plain
unmapped-address segfault; it does not check for `MGUARD: Use-after-free`,
double-`munmap` detection, or registry retention.

**Fix direction**: Decide whether mmap regions are supposed to be quarantined.
If yes, implement the same retention/reporting semantics as `free()`. If no,
rename or remove this test case and keep mmap lifetime separate from heap
quarantine.

---

## Categories the audit found clean (don't fix what isn't broken)

The following were specifically examined and look correct:

- Default (overflow-mode) malloc layout math (`interpose.c:216-231`):
  `user_ptr` is 16-byte aligned, user data abuts the guard page exactly.
- `guard_install` ordering: always called *before* the user pointer is
  returned (`interpose.c:235, 450, 640`).
- `calloc` zero-init does not clobber `0xAA` padding (`interpose.c:340`
  zeros only `total = nmemb*size`, not the padding region).
- `realloc`'s implicit `free(old)` (`interpose.c:401`) does run
  `verify_padding` — overflow on the source buffer is still detected.
- VA accounting on quarantine eviction (`quarantine.c:91-94`) unmaps the
  full `real_size`; no permanent address-space leak.
- 16/64 KiB page systems (aarch64) handled via `sysconf(_SC_PAGESIZE)` at
  `config.c`. Note the resulting VA waste is large (~128 GiB for a 1M-entry
  quarantine on 64 KiB pages); not a correctness bug, but worth
  documenting.

---

## Suggested fix order

If a fixer wants a prioritized roadmap:

1. **F22** (`MGUARD_ENABLED=0`) — single-file fix, and disables must be
   trustworthy before any other testing mode.
2. **F1** (mmap protect_below total breakage) — single-file fix, no
   coordination needed, biggest user-visible blast radius.
3. **F4 + F24** (signal reentry/reset behavior) — same file, low mechanical
   risk but important for report reliability.
4. **F13** (`aligned_alloc(0, 0)`) — single-file, trivial.
5. **F6** (calloc bootstrap overflow) — single-file, trivial.
6. **F14** (size overflow checks) — single-file, mechanical.
7. **F9** (mmap missing post_padding) — single-file.
8. **F2 + F15** (signal-safety + publication ordering) — these are coupled;
   make `registry_insert` use atomic publication, then convert
   `registry_lookup_containing` to a lock-free walker, then remove the
   mutex calls from the signal handler.
9. **F3 + F11** (concurrent-free CAS) — coupled; introduce atomic `magic`
   with a transient `MAGIC_REALLOCING` state.
10. **F5, F12, F19** (atomic flags) — mechanical.
11. **F7, F8, F23** (mmap ABI / partial munmap / mremap semantics) — design
    decision needed: "support accurately" vs. "decline with diagnostics".
12. **F10** (memalign + protect_below) — design follows F1.
13. **F25** (test false positive) — fix once the intended mmap quarantine
    contract is decided.
14. **F16, F17, F18, F20, F21** — minor cleanup.
