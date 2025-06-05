from pwn import *
import sys

def strxor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

def main():
    # Original and target commands
    sleep = b"sleep"
    flag = b"flag!"
    
    # padd both of sleep and flag for block size 16 bytes
    sleep_padded = sleep + b"\x0b" * 11
    flag_padded = flag + b"\x0b" * 11

    # Compute the XOR difference between commands
    sleep_xor_flag = strxor(sleep_padded, flag_padded)

    # Start the dispatcher to get the original ciphertext
    dispatcher = process('/challenge/dispatcher')
    dispatcher.recvuntil(b'TASK: ')
    ciphertext_hex = dispatcher.recvline().strip().decode()
    ciphertext = bytes.fromhex(ciphertext_hex)
    dispatcher.close()

    # Extract original IV
    original_iv = ciphertext[:16]
    original_ciphertext = ciphertext[16:]

    # Start the worker process
    worker = process('/challenge/worker')

    # Compute the malicious ciphertext
    new_iv = strxor(original_iv, sleep_xor_flag)
    malicious_ciphertext = new_iv + original_ciphertext

    # Send the malicious task directly to worker
    worker.sendline(b'TASK: ' + malicious_ciphertext.hex().encode())

    # Get the flag
    worker.interactive()

    worker.close()

if __name__ == '__main__':
    main()
