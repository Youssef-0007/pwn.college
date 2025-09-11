# 📸 `cimg-screenshots-2` Write-up

**Category:** Reverse Engineering + Binary Exploitation
**Platform:** pwn.college (Integrated Security)
**Goal:** Execute `win()` to print the flag

---

## 🔍 Challenge Overview

We are given an ELF binary named `integration-cimg-screenshot-win`, and our objective is to trigger the hidden `win()` function to print the contents of `/flag`.

A quick `checksec` showed:

```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
FORTIFY:  Enabled
SHSTK:    Enabled
IBT:      Enabled
Stripped: No
```

---

## 🧠 Key Concepts Practiced

* Stack-based buffer overflows
* Function pointer overwrites
* Reverse engineering control flow
* Controlled partial return address overwriting
* Validating jump destinations under character filtering
* Identifying safe stack setup before syscalls

---

## 🧩 Challenge Analysis

We decompiled the binary and discovered:

* The main input entry point is via `handle_1337()`, which reads from a memory address `param_1 + 0x10`.
* We assumed that a buffer overflow in the logic of sprite loading and framebuffer manipulation lets us overwrite a return address (e.g., from `handle_1337`) and hijack execution flow.

The `win()` function is very large and repeats logic to:

1. Attempt to open `/flag`
2. If successful, read its content into a buffer
3. Write the content to stdout

```c
int fd = open("/flag", O_RDONLY);
read(fd, buffer, 0x100);
write(1, buffer, bytes_read);
```

But due to its complexity, not all blocks inside `win()` are safe to jump into.

---

## 🚨 The Subtle Trap

In many blocks of `win()`, the `read()` syscall writes into the address stored in `$rbp`. If `$rbp` is not initialized (e.g., when jumping into `win()` manually), this results in a crash.

### Example bad path:

```asm
mov rsi, rbp     ; <--- rbp is garbage here
call read        ; ⛔ crash
```

---

## ✅ The Correct Path

We found a block at `0x402e26` that performs:

```asm
open("/flag")
mov edx, 0x100
mov rsi, rbp
call read
...
mov rbp, rsp     ; ✅ SAFE BUFFER SETUP
mov rsi, rbp
call write
```

This sequence prints the contents of the flag file **after safely resetting `$rbp` to the stack pointer**.

---

## 🧪 Exploitation Strategy

1. **Overflow a return address** in the program using controlled input.
2. **Overwrite the least significant two bytes** of the return address using printable characters (to pass filters in functions like `handle_3`).
3. Point it to a valid mid-function instruction inside `win()` — specifically, we chose:

   ```
   0x402e26
   ```

   This begins a block where:

   * `$rbp` is reset before `write()`
   * A clean `read()`/`write()` cycle is established
4. When executed, this prints the flag multiple times.

---

## 📦 Payload Example (Conceptual)

Assuming you control a buffer in memory that overflows into the return address (e.g., via sprite/framebuffer logic):

```python
payload = b"A" * offset
payload += p64(0x402e26)   # Must be passed in chunks that meet character constraints
```

In our case, we used partial overwrite logic to control just the lower bytes of RIP (since the binary is **non-PIE**, base address is fixed at `0x400000`).

---

## 🧠 Lessons Learned

* Not all `win()` entry points are safe — jumping into the middle of a function requires **setup awareness**, especially when registers like `$rbp` are used as memory targets.
* Even when you can overwrite return addresses, filters (e.g., only printable characters) may require **partial overwrites** or **encoding tricks**.
* Reverse engineering stack setup is crucial before redirecting execution.
* Understanding syscall calling conventions and the binary's logic lets you exploit without complex heap tricks like tcache poisoning.

---

## 🏁 Conclusion

Despite being marketed as an "entry-level" challenge, `cimg-screenshots-2` is a **great test of combining reverse engineering with subtle exploitation techniques**. The core lesson is understanding *where* in a function you're allowed to jump — and how stack/register states matter in real-world exploitation.
