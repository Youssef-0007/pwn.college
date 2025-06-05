from pwn import *
import sys

def strxor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

def main():
    # Original and target commands
    P = b"sleep"
    P_prime = b"flag!"
    
    # Compute the XOR difference between commands
    P_xor_P_prime = strxor(P, P_prime)

    # Start the dispatcher to get the original ciphertext
    dispatcher = process('/challenge/dispatcher')
    dispatcher.recvuntil(b'TASK: ')
    original_ciphertext_hex = dispatcher.recvline().strip().decode()
    original_ciphertext = bytes.fromhex(original_ciphertext_hex)
    dispatcher.close()

    # Start the worker process
    worker = process('/challenge/worker')

    # Compute the malicious ciphertext
    malicious_ciphertext = strxor(original_ciphertext, P_xor_P_prime)

    # Send the malicious task directly to worker
    worker.sendline(b'TASK: ' + malicious_ciphertext.hex().encode())

    # Get the flag
    worker.interactive()

if __name__ == '__main__':
    main()
