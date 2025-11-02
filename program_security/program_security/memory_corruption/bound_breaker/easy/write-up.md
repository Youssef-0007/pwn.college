**Problem (short):** the program reads an integer `n` (stored at `[rbp-0x44]`) and does `cmp eax, 0x2e` followed by `jle` (signed ≤). A negative value like `-50` passes that signed check, but later the same `n` is used as the `size` argument to `read()` — where it ends up treated as a large unsigned length. This lets an attacker request a huge read and overflow the buffer.

**Concrete illustration**

1. Decimal `-50` as 32-bit two’s-complement:

   * `-50` → 32-bit: `0xFFFFFFCE`.

2. How the check lets it through:

   * `cmp eax, 0x2e` + `jle` is a *signed* comparison. Since `eax` contains `0xFFFFFFCE` which, interpreted as signed 32-bit, is `-50`, the CPU sees `-50 <= 46` → **true**, so the code continues.

3. How it becomes a large unsigned size for `read()`:

   * Later the value is copied into the register used for `read`’s length argument. If that copy/sign/zero-extension is done in a way that results in the sign being extended to 64 bits (or treated as an unsigned `size_t`), the 32-bit `0xFFFFFFCE` becomes `0xFFFFFFFFFFFFFFCE` (64-bit), which as an unsigned size is `2^64 - 50` — a huge length. Even if some ABI operations zero-extend 32→64 bits producing `0x00000000FFFFFFCE`, that still corresponds to `4294967246` — also huge. Either way, the net effect is the kernel sees a very large length, not the intended small positive 46-ish value.

4. Why that’s exploitable:

   * The program expects a small positive `n` and will `read()` `n` bytes into a fixed buffer. If `read()` is given a very large `size`, the attacker can cause far more bytes to be written than the buffer can hold, enabling an overflow.

**Short example numbers**

* `-50` (signed) → stored 32-bit `0xFFFFFFCE`.
* Signed compare: `-50 <= 46` → *true* → pass check.
* As unsigned 64-bit: `0xFFFFFFFFFFFFFFCE` → `18446744073709551566` (effectively huge).
* Or zero-extended 32→64: `0x00000000FFFFFFCE` → `4294967246` (still large).

**Mitigations (practical & small)**

1. Reject negative values explicitly:

   * `if (n < 0) reject;`  — use a signed check early.

2. Use unsigned types for sizes and compare unsignedly:

   * Store input into an `unsigned`/`size_t` and check with unsigned comparison (`if (n > MAX) reject;`), or use `cmp` + `ja`/`jae` (unsigned jump) in assembly.

3. Normalize and clamp before using in `read()`:

   * Convert to `size_t` safely and cap: `size_t len = (n < 0) ? 0 : (size_t)n; if (len > MAX_ALLOWED) reject;`

4. Use safe input functions that accept a maximum length directly:

   * Prefer `fgets(buf, sizeof buf, stdin)` or `read_exact(fd, buf, sizeof buf)` where caller controls the maximum, not user input.

5. Check the sign bit in assembly (tiny & efficient):

   * test `eax, eax` ; js reject   — this rejects negative `eax` quickly before any unsigned use.

**Minimal C example showing a safe check**

```c
ssize_t n_signed;
if (scanf("%zd", &n_signed) != 1) error();
if (n_signed < 0) { puts("negative size"); exit(1); }
size_t n = (size_t) n_signed;
if (n > MAX_LEN) { puts("too big"); exit(1); }
ssize_t r = read(0, buf, n);
```

**Summary:** the root cause is a *mismatch* between a signed comparison (allowing negative inputs) and later interpretation of that same value as an unsigned size. Fixes are simple: reject negatives, use unsigned types consistently for lengths, and always clamp to a safe maximum before performing reads/writes.
