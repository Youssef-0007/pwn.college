
/challenge/integration-cimg-screenshot-win:     file format elf64-x86-64


Disassembly of section .init:

0000000000401000 <_init>:
  401000:	f3 0f 1e fa          	endbr64
  401004:	48 83 ec 08          	sub    rsp,0x8
  401008:	48 8b 05 e9 2f 01 00 	mov    rax,QWORD PTR [rip+0x12fe9]        # 413ff8 <__gmon_start__>
  40100f:	48 85 c0             	test   rax,rax
  401012:	74 02                	je     401016 <_init+0x16>
  401014:	ff d0                	call   rax
  401016:	48 83 c4 08          	add    rsp,0x8
  40101a:	c3                   	ret

Disassembly of section .plt:

0000000000401020 <.plt>:
  401020:	ff 35 22 2f 01 00    	push   QWORD PTR [rip+0x12f22]        # 413f48 <_GLOBAL_OFFSET_TABLE_+0x8>
  401026:	f2 ff 25 23 2f 01 00 	bnd jmp QWORD PTR [rip+0x12f23]        # 413f50 <_GLOBAL_OFFSET_TABLE_+0x10>
  40102d:	0f 1f 00             	nop    DWORD PTR [rax]
  401030:	f3 0f 1e fa          	endbr64
  401034:	68 00 00 00 00       	push   0x0
  401039:	f2 e9 e1 ff ff ff    	bnd jmp 401020 <.plt>
  40103f:	90                   	nop
  401040:	f3 0f 1e fa          	endbr64
  401044:	68 01 00 00 00       	push   0x1
  401049:	f2 e9 d1 ff ff ff    	bnd jmp 401020 <.plt>
  40104f:	90                   	nop
  401050:	f3 0f 1e fa          	endbr64
  401054:	68 02 00 00 00       	push   0x2
  401059:	f2 e9 c1 ff ff ff    	bnd jmp 401020 <.plt>
  40105f:	90                   	nop
  401060:	f3 0f 1e fa          	endbr64
  401064:	68 03 00 00 00       	push   0x3
  401069:	f2 e9 b1 ff ff ff    	bnd jmp 401020 <.plt>
  40106f:	90                   	nop
  401070:	f3 0f 1e fa          	endbr64
  401074:	68 04 00 00 00       	push   0x4
  401079:	f2 e9 a1 ff ff ff    	bnd jmp 401020 <.plt>
  40107f:	90                   	nop
  401080:	f3 0f 1e fa          	endbr64
  401084:	68 05 00 00 00       	push   0x5
  401089:	f2 e9 91 ff ff ff    	bnd jmp 401020 <.plt>
  40108f:	90                   	nop
  401090:	f3 0f 1e fa          	endbr64
  401094:	68 06 00 00 00       	push   0x6
  401099:	f2 e9 81 ff ff ff    	bnd jmp 401020 <.plt>
  40109f:	90                   	nop
  4010a0:	f3 0f 1e fa          	endbr64
  4010a4:	68 07 00 00 00       	push   0x7
  4010a9:	f2 e9 71 ff ff ff    	bnd jmp 401020 <.plt>
  4010af:	90                   	nop
  4010b0:	f3 0f 1e fa          	endbr64
  4010b4:	68 08 00 00 00       	push   0x8
  4010b9:	f2 e9 61 ff ff ff    	bnd jmp 401020 <.plt>
  4010bf:	90                   	nop
  4010c0:	f3 0f 1e fa          	endbr64
  4010c4:	68 09 00 00 00       	push   0x9
  4010c9:	f2 e9 51 ff ff ff    	bnd jmp 401020 <.plt>
  4010cf:	90                   	nop
  4010d0:	f3 0f 1e fa          	endbr64
  4010d4:	68 0a 00 00 00       	push   0xa
  4010d9:	f2 e9 41 ff ff ff    	bnd jmp 401020 <.plt>
  4010df:	90                   	nop
  4010e0:	f3 0f 1e fa          	endbr64
  4010e4:	68 0b 00 00 00       	push   0xb
  4010e9:	f2 e9 31 ff ff ff    	bnd jmp 401020 <.plt>
  4010ef:	90                   	nop
  4010f0:	f3 0f 1e fa          	endbr64
  4010f4:	68 0c 00 00 00       	push   0xc
  4010f9:	f2 e9 21 ff ff ff    	bnd jmp 401020 <.plt>
  4010ff:	90                   	nop
  401100:	f3 0f 1e fa          	endbr64
  401104:	68 0d 00 00 00       	push   0xd
  401109:	f2 e9 11 ff ff ff    	bnd jmp 401020 <.plt>
  40110f:	90                   	nop
  401110:	f3 0f 1e fa          	endbr64
  401114:	68 0e 00 00 00       	push   0xe
  401119:	f2 e9 01 ff ff ff    	bnd jmp 401020 <.plt>
  40111f:	90                   	nop
  401120:	f3 0f 1e fa          	endbr64
  401124:	68 0f 00 00 00       	push   0xf
  401129:	f2 e9 f1 fe ff ff    	bnd jmp 401020 <.plt>
  40112f:	90                   	nop
  401130:	f3 0f 1e fa          	endbr64
  401134:	68 10 00 00 00       	push   0x10
  401139:	f2 e9 e1 fe ff ff    	bnd jmp 401020 <.plt>
  40113f:	90                   	nop
  401140:	f3 0f 1e fa          	endbr64
  401144:	68 11 00 00 00       	push   0x11
  401149:	f2 e9 d1 fe ff ff    	bnd jmp 401020 <.plt>
  40114f:	90                   	nop
  401150:	f3 0f 1e fa          	endbr64
  401154:	68 12 00 00 00       	push   0x12
  401159:	f2 e9 c1 fe ff ff    	bnd jmp 401020 <.plt>
  40115f:	90                   	nop

Disassembly of section .plt.sec:

0000000000401160 <__snprintf_chk@plt>:
  401160:	f3 0f 1e fa          	endbr64
  401164:	f2 ff 25 ed 2d 01 00 	bnd jmp QWORD PTR [rip+0x12ded]        # 413f58 <__snprintf_chk@GLIBC_2.3.4>
  40116b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000401170 <free@plt>:
  401170:	f3 0f 1e fa          	endbr64
  401174:	f2 ff 25 e5 2d 01 00 	bnd jmp QWORD PTR [rip+0x12de5]        # 413f60 <free@GLIBC_2.2.5>
  40117b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000401180 <__errno_location@plt>:
  401180:	f3 0f 1e fa          	endbr64
  401184:	f2 ff 25 dd 2d 01 00 	bnd jmp QWORD PTR [rip+0x12ddd]        # 413f68 <__errno_location@GLIBC_2.2.5>
  40118b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000401190 <puts@plt>:
  401190:	f3 0f 1e fa          	endbr64
  401194:	f2 ff 25 d5 2d 01 00 	bnd jmp QWORD PTR [rip+0x12dd5]        # 413f70 <puts@GLIBC_2.2.5>
  40119b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004011a0 <write@plt>:
  4011a0:	f3 0f 1e fa          	endbr64
  4011a4:	f2 ff 25 cd 2d 01 00 	bnd jmp QWORD PTR [rip+0x12dcd]        # 413f78 <write@GLIBC_2.2.5>
  4011ab:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004011b0 <dup2@plt>:
  4011b0:	f3 0f 1e fa          	endbr64
  4011b4:	f2 ff 25 c5 2d 01 00 	bnd jmp QWORD PTR [rip+0x12dc5]        # 413f80 <dup2@GLIBC_2.2.5>
  4011bb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004011c0 <nanosleep@plt>:
  4011c0:	f3 0f 1e fa          	endbr64
  4011c4:	f2 ff 25 bd 2d 01 00 	bnd jmp QWORD PTR [rip+0x12dbd]        # 413f88 <nanosleep@GLIBC_2.2.5>
  4011cb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004011d0 <fputs@plt>:
  4011d0:	f3 0f 1e fa          	endbr64
  4011d4:	f2 ff 25 b5 2d 01 00 	bnd jmp QWORD PTR [rip+0x12db5]        # 413f90 <fputs@GLIBC_2.2.5>
  4011db:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004011e0 <geteuid@plt>:
  4011e0:	f3 0f 1e fa          	endbr64
  4011e4:	f2 ff 25 ad 2d 01 00 	bnd jmp QWORD PTR [rip+0x12dad]        # 413f98 <geteuid@GLIBC_2.2.5>
  4011eb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

00000000004011f0 <fputc@plt>:
  4011f0:	f3 0f 1e fa          	endbr64
  4011f4:	f2 ff 25 a5 2d 01 00 	bnd jmp QWORD PTR [rip+0x12da5]        # 413fa0 <fputc@GLIBC_2.2.5>
  4011fb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000401200 <read@plt>:
  401200:	f3 0f 1e fa          	endbr64
  401204:	f2 ff 25 9d 2d 01 00 	bnd jmp QWORD PTR [rip+0x12d9d]        # 413fa8 <read@GLIBC_2.2.5>
  40120b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000401210 <strcmp@plt>:
  401210:	f3 0f 1e fa          	endbr64
  401214:	f2 ff 25 95 2d 01 00 	bnd jmp QWORD PTR [rip+0x12d95]        # 413fb0 <strcmp@GLIBC_2.2.5>
  40121b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000401220 <malloc@plt>:
  401220:	f3 0f 1e fa          	endbr64
  401224:	f2 ff 25 8d 2d 01 00 	bnd jmp QWORD PTR [rip+0x12d8d]        # 413fb8 <malloc@GLIBC_2.2.5>
  40122b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000401230 <__printf_chk@plt>:
  401230:	f3 0f 1e fa          	endbr64
  401234:	f2 ff 25 85 2d 01 00 	bnd jmp QWORD PTR [rip+0x12d85]        # 413fc0 <__printf_chk@GLIBC_2.3.4>
  40123b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000401240 <setvbuf@plt>:
  401240:	f3 0f 1e fa          	endbr64
  401244:	f2 ff 25 7d 2d 01 00 	bnd jmp QWORD PTR [rip+0x12d7d]        # 413fc8 <setvbuf@GLIBC_2.2.5>
  40124b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000401250 <open@plt>:
  401250:	f3 0f 1e fa          	endbr64
  401254:	f2 ff 25 75 2d 01 00 	bnd jmp QWORD PTR [rip+0x12d75]        # 413fd0 <open@GLIBC_2.2.5>
  40125b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000401260 <exit@plt>:
  401260:	f3 0f 1e fa          	endbr64
  401264:	f2 ff 25 6d 2d 01 00 	bnd jmp QWORD PTR [rip+0x12d6d]        # 413fd8 <exit@GLIBC_2.2.5>
  40126b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000401270 <__fprintf_chk@plt>:
  401270:	f3 0f 1e fa          	endbr64
  401274:	f2 ff 25 65 2d 01 00 	bnd jmp QWORD PTR [rip+0x12d65]        # 413fe0 <__fprintf_chk@GLIBC_2.3.4>
  40127b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000401280 <strerror@plt>:
  401280:	f3 0f 1e fa          	endbr64
  401284:	f2 ff 25 5d 2d 01 00 	bnd jmp QWORD PTR [rip+0x12d5d]        # 413fe8 <strerror@GLIBC_2.2.5>
  40128b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

Disassembly of section .text:

0000000000401290 <disable_buffering>:
  401290:	f3 0f 1e fa          	endbr64
  401294:	50                   	push   rax
  401295:	48 8b 3d 94 2d 01 00 	mov    rdi,QWORD PTR [rip+0x12d94]        # 414030 <stdin@GLIBC_2.2.5>
  40129c:	31 c9                	xor    ecx,ecx
  40129e:	ba 02 00 00 00       	mov    edx,0x2
  4012a3:	31 f6                	xor    esi,esi
  4012a5:	e8 96 ff ff ff       	call   401240 <setvbuf@plt>
  4012aa:	48 8b 3d 6f 2d 01 00 	mov    rdi,QWORD PTR [rip+0x12d6f]        # 414020 <stdout@GLIBC_2.2.5>
  4012b1:	b9 01 00 00 00       	mov    ecx,0x1
  4012b6:	31 f6                	xor    esi,esi
  4012b8:	ba 02 00 00 00       	mov    edx,0x2
  4012bd:	41 58                	pop    r8
  4012bf:	e9 7c ff ff ff       	jmp    401240 <setvbuf@plt>

00000000004012c4 <main>:
  4012c4:	f3 0f 1e fa          	endbr64
  4012c8:	41 54                	push   r12
  4012ca:	55                   	push   rbp
  4012cb:	53                   	push   rbx
  4012cc:	48 81 ec 00 10 00 00 	sub    rsp,0x1000
  4012d3:	48 83 0c 24 00       	or     QWORD PTR [rsp],0x0
  4012d8:	48 83 ec 20          	sub    rsp,0x20
  4012dc:	31 c0                	xor    eax,eax
  4012de:	b9 06 04 00 00       	mov    ecx,0x406
  4012e3:	41 89 f8             	mov    r8d,edi
  4012e6:	48 8d 7c 24 08       	lea    rdi,[rsp+0x8]
  4012eb:	48 8d 6c 24 08       	lea    rbp,[rsp+0x8]
  4012f0:	f3 ab                	rep stos DWORD PTR es:[rdi],eax
  4012f2:	41 ff c8             	dec    r8d
  4012f5:	7e 4f                	jle    401346 <main+0x82>
  4012f7:	4c 8b 66 08          	mov    r12,QWORD PTR [rsi+0x8]
  4012fb:	48 83 c9 ff          	or     rcx,0xffffffffffffffff
  4012ff:	48 8d 35 34 10 01 00 	lea    rsi,[rip+0x11034]        # 41233a <_IO_stdin_used+0x33a>
  401306:	4c 89 e7             	mov    rdi,r12
  401309:	f2 ae                	repnz scas al,BYTE PTR es:[rdi]
  40130b:	48 f7 d1             	not    rcx
  40130e:	49 8d 7c 0c fa       	lea    rdi,[r12+rcx*1-0x6]
  401313:	e8 f8 fe ff ff       	call   401210 <strcmp@plt>
  401318:	85 c0                	test   eax,eax
  40131a:	74 15                	je     401331 <main+0x6d>
  40131c:	48 8d 35 1d 10 01 00 	lea    rsi,[rip+0x1101d]        # 412340 <_IO_stdin_used+0x340>
  401323:	bf 01 00 00 00       	mov    edi,0x1
  401328:	31 c0                	xor    eax,eax
  40132a:	e8 01 ff ff ff       	call   401230 <__printf_chk@plt>
  40132f:	eb 45                	jmp    401376 <main+0xb2>
  401331:	31 f6                	xor    esi,esi
  401333:	4c 89 e7             	mov    rdi,r12
  401336:	31 c0                	xor    eax,eax
  401338:	e8 13 ff ff ff       	call   401250 <open@plt>
  40133d:	31 f6                	xor    esi,esi
  40133f:	89 c7                	mov    edi,eax
  401341:	e8 6a fe ff ff       	call   4011b0 <dup2@plt>
  401346:	41 83 c8 ff          	or     r8d,0xffffffff
  40134a:	31 ff                	xor    edi,edi
  40134c:	48 8d 0d 11 10 01 00 	lea    rcx,[rip+0x11011]        # 412364 <_IO_stdin_used+0x364>
  401353:	48 89 ee             	mov    rsi,rbp
  401356:	ba 0c 00 00 00       	mov    edx,0xc
  40135b:	e8 0e fe 00 00       	call   41116e <read_exact>
  401360:	81 7c 24 08 63 49 4d 	cmp    DWORD PTR [rsp+0x8],0x474d4963
  401367:	47 
  401368:	74 14                	je     40137e <main+0xba>
  40136a:	48 8d 3d 16 10 01 00 	lea    rdi,[rip+0x11016]        # 412387 <_IO_stdin_used+0x387>
  401371:	e8 1a fe ff ff       	call   401190 <puts@plt>
  401376:	83 cf ff             	or     edi,0xffffffff
  401379:	e8 e2 fe ff ff       	call   401260 <exit@plt>
  40137e:	66 83 7c 24 0c 04    	cmp    WORD PTR [rsp+0xc],0x4
  401384:	48 8d 3d 19 10 01 00 	lea    rdi,[rip+0x11019]        # 4123a4 <_IO_stdin_used+0x3a4>
  40138b:	75 e4                	jne    401371 <main+0xad>
  40138d:	48 89 ef             	mov    rdi,rbp
  401390:	48 8d 1d 75 10 01 00 	lea    rbx,[rip+0x11075]        # 41240c <_IO_stdin_used+0x40c>
  401397:	e8 93 06 01 00       	call   411a2f <initialize_framebuffer>
  40139c:	8b 44 24 10          	mov    eax,DWORD PTR [rsp+0x10]
  4013a0:	8d 50 ff             	lea    edx,[rax-0x1]
  4013a3:	89 54 24 10          	mov    DWORD PTR [rsp+0x10],edx
  4013a7:	85 c0                	test   eax,eax
  4013a9:	0f 84 be 00 00 00    	je     40146d <main+0x1a9>
  4013af:	48 8d 74 24 06       	lea    rsi,[rsp+0x6]
  4013b4:	41 83 c8 ff          	or     r8d,0xffffffff
  4013b8:	ba 02 00 00 00       	mov    edx,0x2
  4013bd:	31 ff                	xor    edi,edi
  4013bf:	48 8d 0d fa 0f 01 00 	lea    rcx,[rip+0x10ffa]        # 4123c0 <_IO_stdin_used+0x3c0>
  4013c6:	e8 a3 fd 00 00       	call   41116e <read_exact>
  4013cb:	0f b7 4c 24 06       	movzx  ecx,WORD PTR [rsp+0x6]
  4013d0:	66 83 f9 07          	cmp    cx,0x7
  4013d4:	77 1a                	ja     4013f0 <main+0x12c>
  4013d6:	66 85 c9             	test   cx,cx
  4013d9:	74 73                	je     40144e <main+0x18a>
  4013db:	ff c9                	dec    ecx
  4013dd:	66 83 f9 06          	cmp    cx,0x6
  4013e1:	77 66                	ja     401449 <main+0x185>
  4013e3:	0f b7 c9             	movzx  ecx,cx
  4013e6:	48 63 04 8b          	movsxd rax,DWORD PTR [rbx+rcx*4]
  4013ea:	48 01 d8             	add    rax,rbx
  4013ed:	3e ff e0             	notrack jmp rax
  4013f0:	66 81 f9 39 05       	cmp    cx,0x539
  4013f5:	75 57                	jne    40144e <main+0x18a>
  4013f7:	48 89 ef             	mov    rdi,rbp
  4013fa:	e8 55 04 01 00       	call   411854 <handle_1337>
  4013ff:	eb 9b                	jmp    40139c <main+0xd8>
  401401:	48 89 ef             	mov    rdi,rbp
  401404:	e8 b5 fd 00 00       	call   4111be <handle_1>
  401409:	eb 91                	jmp    40139c <main+0xd8>
  40140b:	48 89 ef             	mov    rdi,rbp
  40140e:	e8 08 ff 00 00       	call   41131b <handle_2>
  401413:	eb 87                	jmp    40139c <main+0xd8>
  401415:	48 89 ef             	mov    rdi,rbp
  401418:	e8 de 00 01 00       	call   4114fb <handle_3>
  40141d:	e9 7a ff ff ff       	jmp    40139c <main+0xd8>
  401422:	48 89 ef             	mov    rdi,rbp
  401425:	e8 fd 01 01 00       	call   411627 <handle_4>
  40142a:	e9 6d ff ff ff       	jmp    40139c <main+0xd8>
  40142f:	48 89 ef             	mov    rdi,rbp
  401432:	e8 a4 05 01 00       	call   4119db <handle_6>
  401437:	e9 60 ff ff ff       	jmp    40139c <main+0xd8>
  40143c:	48 89 ef             	mov    rdi,rbp
  40143f:	e8 e2 04 01 00       	call   411926 <handle_7>
  401444:	e9 53 ff ff ff       	jmp    40139c <main+0xd8>
  401449:	b9 05 00 00 00       	mov    ecx,0x5
  40144e:	48 8b 3d eb 2b 01 00 	mov    rdi,QWORD PTR [rip+0x12beb]        # 414040 <stderr@GLIBC_2.2.5>
  401455:	48 8d 15 8b 0f 01 00 	lea    rdx,[rip+0x10f8b]        # 4123e7 <_IO_stdin_used+0x3e7>
  40145c:	be 01 00 00 00       	mov    esi,0x1
  401461:	31 c0                	xor    eax,eax
  401463:	e8 08 fe ff ff       	call   401270 <__fprintf_chk@plt>
  401468:	e9 09 ff ff ff       	jmp    401376 <main+0xb2>
  40146d:	48 89 ef             	mov    rdi,rbp
  401470:	31 f6                	xor    esi,esi
  401472:	e8 03 05 01 00       	call   41197a <display>
  401477:	48 81 c4 20 10 00 00 	add    rsp,0x1020
  40147e:	31 c0                	xor    eax,eax
  401480:	5b                   	pop    rbx
  401481:	5d                   	pop    rbp
  401482:	41 5c                	pop    r12
  401484:	c3                   	ret
  401485:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  40148c:	00 00 00 
  40148f:	90                   	nop

0000000000401490 <_start>:
  401490:	f3 0f 1e fa          	endbr64
  401494:	31 ed                	xor    ebp,ebp
  401496:	49 89 d1             	mov    r9,rdx
  401499:	5e                   	pop    rsi
  40149a:	48 89 e2             	mov    rdx,rsp
  40149d:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
  4014a1:	50                   	push   rax
  4014a2:	54                   	push   rsp
  4014a3:	49 c7 c0 60 1b 41 00 	mov    r8,0x411b60
  4014aa:	48 c7 c1 f0 1a 41 00 	mov    rcx,0x411af0
  4014b1:	48 c7 c7 c4 12 40 00 	mov    rdi,0x4012c4
  4014b8:	ff 15 32 2b 01 00    	call   QWORD PTR [rip+0x12b32]        # 413ff0 <__libc_start_main@GLIBC_2.2.5>
  4014be:	f4                   	hlt
  4014bf:	90                   	nop

00000000004014c0 <_dl_relocate_static_pie>:
  4014c0:	f3 0f 1e fa          	endbr64
  4014c4:	c3                   	ret
  4014c5:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  4014cc:	00 00 00 
  4014cf:	90                   	nop

00000000004014d0 <deregister_tm_clones>:
  4014d0:	b8 10 40 41 00       	mov    eax,0x414010
  4014d5:	48 3d 10 40 41 00    	cmp    rax,0x414010
  4014db:	74 13                	je     4014f0 <deregister_tm_clones+0x20>
  4014dd:	b8 00 00 00 00       	mov    eax,0x0
  4014e2:	48 85 c0             	test   rax,rax
  4014e5:	74 09                	je     4014f0 <deregister_tm_clones+0x20>
  4014e7:	bf 10 40 41 00       	mov    edi,0x414010
  4014ec:	ff e0                	jmp    rax
  4014ee:	66 90                	xchg   ax,ax
  4014f0:	c3                   	ret
  4014f1:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  4014f8:	00 00 00 00 
  4014fc:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000401500 <register_tm_clones>:
  401500:	be 10 40 41 00       	mov    esi,0x414010
  401505:	48 81 ee 10 40 41 00 	sub    rsi,0x414010
  40150c:	48 89 f0             	mov    rax,rsi
  40150f:	48 c1 ee 3f          	shr    rsi,0x3f
  401513:	48 c1 f8 03          	sar    rax,0x3
  401517:	48 01 c6             	add    rsi,rax
  40151a:	48 d1 fe             	sar    rsi,1
  40151d:	74 11                	je     401530 <register_tm_clones+0x30>
  40151f:	b8 00 00 00 00       	mov    eax,0x0
  401524:	48 85 c0             	test   rax,rax
  401527:	74 07                	je     401530 <register_tm_clones+0x30>
  401529:	bf 10 40 41 00       	mov    edi,0x414010
  40152e:	ff e0                	jmp    rax
  401530:	c3                   	ret
  401531:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  401538:	00 00 00 00 
  40153c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000401540 <__do_global_dtors_aux>:
  401540:	f3 0f 1e fa          	endbr64
  401544:	80 3d fd 2a 01 00 00 	cmp    BYTE PTR [rip+0x12afd],0x0        # 414048 <completed.8061>
  40154b:	75 13                	jne    401560 <__do_global_dtors_aux+0x20>
  40154d:	55                   	push   rbp
  40154e:	48 89 e5             	mov    rbp,rsp
  401551:	e8 7a ff ff ff       	call   4014d0 <deregister_tm_clones>
  401556:	c6 05 eb 2a 01 00 01 	mov    BYTE PTR [rip+0x12aeb],0x1        # 414048 <completed.8061>
  40155d:	5d                   	pop    rbp
  40155e:	c3                   	ret
  40155f:	90                   	nop
  401560:	c3                   	ret
  401561:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  401568:	00 00 00 00 
  40156c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000401570 <frame_dummy>:
  401570:	f3 0f 1e fa          	endbr64
  401574:	eb 8a                	jmp    401500 <register_tm_clones>

0000000000401576 <win>:
  401576:	f3 0f 1e fa          	endbr64
  40157a:	55                   	push   rbp
  40157b:	31 f6                	xor    esi,esi
  40157d:	31 c0                	xor    eax,eax
  40157f:	48 8d 3d 7e 0a 01 00 	lea    rdi,[rip+0x10a7e]        # 412004 <_IO_stdin_used+0x4>
  401586:	48 81 ec 00 01 00 00 	sub    rsp,0x100
  40158d:	e8 be fc ff ff       	call   401250 <open@plt>
  401592:	85 c0                	test   eax,eax
  401594:	79 4b                	jns    4015e1 <win+0x6b>
  401596:	e8 e5 fb ff ff       	call   401180 <__errno_location@plt>
  40159b:	8b 38                	mov    edi,DWORD PTR [rax]
  40159d:	e8 de fc ff ff       	call   401280 <strerror@plt>
  4015a2:	48 8d 35 61 0a 01 00 	lea    rsi,[rip+0x10a61]        # 41200a <_IO_stdin_used+0xa>
  4015a9:	bf 01 00 00 00       	mov    edi,0x1
  4015ae:	48 89 c2             	mov    rdx,rax
  4015b1:	31 c0                	xor    eax,eax
  4015b3:	e8 78 fc ff ff       	call   401230 <__printf_chk@plt>
  4015b8:	e8 23 fc ff ff       	call   4011e0 <geteuid@plt>
  4015bd:	85 c0                	test   eax,eax
  4015bf:	74 18                	je     4015d9 <win+0x63>
  4015c1:	48 8d 3d 6c 0a 01 00 	lea    rdi,[rip+0x10a6c]        # 412034 <_IO_stdin_used+0x34>
  4015c8:	e8 c3 fb ff ff       	call   401190 <puts@plt>
  4015cd:	48 8d 3d 83 0a 01 00 	lea    rdi,[rip+0x10a83]        # 412057 <_IO_stdin_used+0x57>
  4015d4:	e8 b7 fb ff ff       	call   401190 <puts@plt>
  4015d9:	83 cf ff             	or     edi,0xffffffff
  4015dc:	e8 7f fc ff ff       	call   401260 <exit@plt>
  4015e1:	48 89 e5             	mov    rbp,rsp
  4015e4:	89 c7                	mov    edi,eax
  4015e6:	ba 00 01 00 00       	mov    edx,0x100
  4015eb:	48 89 ee             	mov    rsi,rbp
  4015ee:	e8 0d fc ff ff       	call   401200 <read@plt>
  4015f3:	85 c0                	test   eax,eax
  4015f5:	7f 2a                	jg     401621 <win+0xab>
  4015f7:	e8 84 fb ff ff       	call   401180 <__errno_location@plt>
  4015fc:	8b 38                	mov    edi,DWORD PTR [rax]
  4015fe:	e8 7d fc ff ff       	call   401280 <strerror@plt>
  401603:	bf 01 00 00 00       	mov    edi,0x1
  401608:	48 8d 35 9a 0a 01 00 	lea    rsi,[rip+0x10a9a]        # 4120a9 <_IO_stdin_used+0xa9>
  40160f:	48 89 c2             	mov    rdx,rax
  401612:	31 c0                	xor    eax,eax
  401614:	e8 17 fc ff ff       	call   401230 <__printf_chk@plt>
  401619:	83 cf ff             	or     edi,0xffffffff
  40161c:	e8 3f fc ff ff       	call   401260 <exit@plt>
  401621:	48 63 d0             	movsxd rdx,eax
  401624:	48 89 ee             	mov    rsi,rbp
  401627:	bf 01 00 00 00       	mov    edi,0x1
  40162c:	e8 6f fb ff ff       	call   4011a0 <write@plt>
  401631:	48 8d 3d 1c 0b 01 00 	lea    rdi,[rip+0x10b1c]        # 412154 <_IO_stdin_used+0x154>
  401638:	e8 53 fb ff ff       	call   401190 <puts@plt>
  40163d:	48 8d 3d c0 09 01 00 	lea    rdi,[rip+0x109c0]        # 412004 <_IO_stdin_used+0x4>
  401644:	31 f6                	xor    esi,esi
  401646:	31 c0                	xor    eax,eax
  401648:	e8 03 fc ff ff       	call   401250 <open@plt>
  40164d:	89 c7                	mov    edi,eax
  40164f:	85 c0                	test   eax,eax
  401651:	79 34                	jns    401687 <win+0x111>
  401653:	e8 28 fb ff ff       	call   401180 <__errno_location@plt>
  401658:	8b 38                	mov    edi,DWORD PTR [rax]
  40165a:	e8 21 fc ff ff       	call   401280 <strerror@plt>
  40165f:	48 8d 35 a4 09 01 00 	lea    rsi,[rip+0x109a4]        # 41200a <_IO_stdin_used+0xa>
  401666:	bf 01 00 00 00       	mov    edi,0x1
  40166b:	48 89 c2             	mov    rdx,rax
  40166e:	31 c0                	xor    eax,eax
  401670:	e8 bb fb ff ff       	call   401230 <__printf_chk@plt>
  401675:	e8 66 fb ff ff       	call   4011e0 <geteuid@plt>
  40167a:	85 c0                	test   eax,eax
  40167c:	0f 84 57 ff ff ff    	je     4015d9 <win+0x63>
  401682:	e9 3a ff ff ff       	jmp    4015c1 <win+0x4b>
  401687:	ba 00 01 00 00       	mov    edx,0x100
  40168c:	48 89 ee             	mov    rsi,rbp
  40168f:	e8 6c fb ff ff       	call   401200 <read@plt>
  401694:	85 c0                	test   eax,eax
  401696:	7f 2a                	jg     4016c2 <win+0x14c>
  401698:	e8 e3 fa ff ff       	call   401180 <__errno_location@plt>
  40169d:	8b 38                	mov    edi,DWORD PTR [rax]
  40169f:	e8 dc fb ff ff       	call   401280 <strerror@plt>
  4016a4:	bf 01 00 00 00       	mov    edi,0x1
  4016a9:	48 8d 35 f9 09 01 00 	lea    rsi,[rip+0x109f9]        # 4120a9 <_IO_stdin_used+0xa9>
  4016b0:	48 89 c2             	mov    rdx,rax
  4016b3:	31 c0                	xor    eax,eax
  4016b5:	e8 76 fb ff ff       	call   401230 <__printf_chk@plt>
  4016ba:	83 cf ff             	or     edi,0xffffffff
  4016bd:	e8 9e fb ff ff       	call   401260 <exit@plt>
  4016c2:	48 63 d0             	movsxd rdx,eax
  4016c5:	48 89 ee             	mov    rsi,rbp
  4016c8:	bf 01 00 00 00       	mov    edi,0x1
  4016cd:	e8 ce fa ff ff       	call   4011a0 <write@plt>
  4016d2:	48 8d 3d 7b 0a 01 00 	lea    rdi,[rip+0x10a7b]        # 412154 <_IO_stdin_used+0x154>
  4016d9:	e8 b2 fa ff ff       	call   401190 <puts@plt>
  4016de:	48 8d 3d 1f 09 01 00 	lea    rdi,[rip+0x1091f]        # 412004 <_IO_stdin_used+0x4>
  4016e5:	31 f6                	xor    esi,esi
  4016e7:	31 c0                	xor    eax,eax
  4016e9:	e8 62 fb ff ff       	call   401250 <open@plt>
  4016ee:	89 c7                	mov    edi,eax
  4016f0:	85 c0                	test   eax,eax
  4016f2:	79 34                	jns    401728 <win+0x1b2>
  4016f4:	e8 87 fa ff ff       	call   401180 <__errno_location@plt>
  4016f9:	8b 38                	mov    edi,DWORD PTR [rax]
  4016fb:	e8 80 fb ff ff       	call   401280 <strerror@plt>
  401700:	48 8d 35 03 09 01 00 	lea    rsi,[rip+0x10903]        # 41200a <_IO_stdin_used+0xa>
  401707:	bf 01 00 00 00       	mov    edi,0x1
  40170c:	48 89 c2             	mov    rdx,rax
  40170f:	31 c0                	xor    eax,eax
  401711:	e8 1a fb ff ff       	call   401230 <__printf_chk@plt>
  401716:	e8 c5 fa ff ff       	call   4011e0 <geteuid@plt>
  40171b:	85 c0                	test   eax,eax
  40171d:	0f 84 b6 fe ff ff    	je     4015d9 <win+0x63>
  401723:	e9 99 fe ff ff       	jmp    4015c1 <win+0x4b>
  401728:	ba 00 01 00 00       	mov    edx,0x100
  40172d:	48 89 ee             	mov    rsi,rbp
  401730:	e8 cb fa ff ff       	call   401200 <read@plt>
  401735:	85 c0                	test   eax,eax
  401737:	7f 2a                	jg     401763 <win+0x1ed>
  401739:	e8 42 fa ff ff       	call   401180 <__errno_location@plt>
  40173e:	8b 38                	mov    edi,DWORD PTR [rax]
  401740:	e8 3b fb ff ff       	call   401280 <strerror@plt>
  401745:	bf 01 00 00 00       	mov    edi,0x1
  40174a:	48 8d 35 58 09 01 00 	lea    rsi,[rip+0x10958]        # 4120a9 <_IO_stdin_used+0xa9>
  401751:	48 89 c2             	mov    rdx,rax
  401754:	31 c0                	xor    eax,eax
  401756:	e8 d5 fa ff ff       	call   401230 <__printf_chk@plt>
  40175b:	83 cf ff             	or     edi,0xffffffff
  40175e:	e8 fd fa ff ff       	call   401260 <exit@plt>
  401763:	48 63 d0             	movsxd rdx,eax
  401766:	48 89 ee             	mov    rsi,rbp
  401769:	bf 01 00 00 00       	mov    edi,0x1
  40176e:	e8 2d fa ff ff       	call   4011a0 <write@plt>
  401773:	48 8d 3d da 09 01 00 	lea    rdi,[rip+0x109da]        # 412154 <_IO_stdin_used+0x154>
  40177a:	e8 11 fa ff ff       	call   401190 <puts@plt>
  40177f:	48 8d 3d 7e 08 01 00 	lea    rdi,[rip+0x1087e]        # 412004 <_IO_stdin_used+0x4>
  401786:	31 f6                	xor    esi,esi
  401788:	31 c0                	xor    eax,eax
  40178a:	e8 c1 fa ff ff       	call   401250 <open@plt>
  40178f:	89 c7                	mov    edi,eax
  401791:	85 c0                	test   eax,eax
  401793:	79 34                	jns    4017c9 <win+0x253>
  401795:	e8 e6 f9 ff ff       	call   401180 <__errno_location@plt>
  40179a:	8b 38                	mov    edi,DWORD PTR [rax]
  40179c:	e8 df fa ff ff       	call   401280 <strerror@plt>
  4017a1:	48 8d 35 62 08 01 00 	lea    rsi,[rip+0x10862]        # 41200a <_IO_stdin_used+0xa>
  4017a8:	bf 01 00 00 00       	mov    edi,0x1
  4017ad:	48 89 c2             	mov    rdx,rax
  4017b0:	31 c0                	xor    eax,eax
  4017b2:	e8 79 fa ff ff       	call   401230 <__printf_chk@plt>
  4017b7:	e8 24 fa ff ff       	call   4011e0 <geteuid@plt>
  4017bc:	85 c0                	test   eax,eax
  4017be:	0f 84 15 fe ff ff    	je     4015d9 <win+0x63>
  4017c4:	e9 f8 fd ff ff       	jmp    4015c1 <win+0x4b>
  4017c9:	ba 00 01 00 00       	mov    edx,0x100
  4017ce:	48 89 ee             	mov    rsi,rbp
  4017d1:	e8 2a fa ff ff       	call   401200 <read@plt>
  4017d6:	85 c0                	test   eax,eax
  4017d8:	7f 2a                	jg     401804 <win+0x28e>
  4017da:	e8 a1 f9 ff ff       	call   401180 <__errno_location@plt>
  4017df:	8b 38                	mov    edi,DWORD PTR [rax]
  4017e1:	e8 9a fa ff ff       	call   401280 <strerror@plt>
  4017e6:	bf 01 00 00 00       	mov    edi,0x1
  4017eb:	48 8d 35 b7 08 01 00 	lea    rsi,[rip+0x108b7]        # 4120a9 <_IO_stdin_used+0xa9>
  4017f2:	48 89 c2             	mov    rdx,rax
  4017f5:	31 c0                	xor    eax,eax
  4017f7:	e8 34 fa ff ff       	call   401230 <__printf_chk@plt>
  4017fc:	83 cf ff             	or     edi,0xffffffff
  4017ff:	e8 5c fa ff ff       	call   401260 <exit@plt>
  401804:	48 63 d0             	movsxd rdx,eax
  401807:	48 89 ee             	mov    rsi,rbp
  40180a:	bf 01 00 00 00       	mov    edi,0x1
  40180f:	e8 8c f9 ff ff       	call   4011a0 <write@plt>
  401814:	48 8d 3d 39 09 01 00 	lea    rdi,[rip+0x10939]        # 412154 <_IO_stdin_used+0x154>
  40181b:	e8 70 f9 ff ff       	call   401190 <puts@plt>
  401820:	48 8d 3d dd 07 01 00 	lea    rdi,[rip+0x107dd]        # 412004 <_IO_stdin_used+0x4>
  401827:	31 f6                	xor    esi,esi
  401829:	31 c0                	xor    eax,eax
  40182b:	e8 20 fa ff ff       	call   401250 <open@plt>
  401830:	89 c7                	mov    edi,eax
  401832:	85 c0                	test   eax,eax
  401834:	79 34                	jns    40186a <win+0x2f4>
  401836:	e8 45 f9 ff ff       	call   401180 <__errno_location@plt>
  40183b:	8b 38                	mov    edi,DWORD PTR [rax]
  40183d:	e8 3e fa ff ff       	call   401280 <strerror@plt>
  401842:	48 8d 35 c1 07 01 00 	lea    rsi,[rip+0x107c1]        # 41200a <_IO_stdin_used+0xa>
  401849:	bf 01 00 00 00       	mov    edi,0x1
  40184e:	48 89 c2             	mov    rdx,rax
  401851:	31 c0                	xor    eax,eax
  401853:	e8 d8 f9 ff ff       	call   401230 <__printf_chk@plt>
  401858:	e8 83 f9 ff ff       	call   4011e0 <geteuid@plt>
  40185d:	85 c0                	test   eax,eax
  40185f:	0f 84 74 fd ff ff    	je     4015d9 <win+0x63>
  401865:	e9 57 fd ff ff       	jmp    4015c1 <win+0x4b>
  40186a:	ba 00 01 00 00       	mov    edx,0x100
  40186f:	48 89 ee             	mov    rsi,rbp
  401872:	e8 89 f9 ff ff       	call   401200 <read@plt>
  401877:	85 c0                	test   eax,eax
  401879:	7f 2a                	jg     4018a5 <win+0x32f>
  40187b:	e8 00 f9 ff ff       	call   401180 <__errno_location@plt>
  401880:	8b 38                	mov    edi,DWORD PTR [rax]
  401882:	e8 f9 f9 ff ff       	call   401280 <strerror@plt>
  401887:	bf 01 00 00 00       	mov    edi,0x1
  40188c:	48 8d 35 16 08 01 00 	lea    rsi,[rip+0x10816]        # 4120a9 <_IO_stdin_used+0xa9>
  401893:	48 89 c2             	mov    rdx,rax
  401896:	31 c0                	xor    eax,eax
  401898:	e8 93 f9 ff ff       	call   401230 <__printf_chk@plt>
  40189d:	83 cf ff             	or     edi,0xffffffff
  4018a0:	e8 bb f9 ff ff       	call   401260 <exit@plt>
  4018a5:	48 63 d0             	movsxd rdx,eax
  4018a8:	48 89 ee             	mov    rsi,rbp
  4018ab:	bf 01 00 00 00       	mov    edi,0x1
  4018b0:	e8 eb f8 ff ff       	call   4011a0 <write@plt>
  4018b5:	48 8d 3d 98 08 01 00 	lea    rdi,[rip+0x10898]        # 412154 <_IO_stdin_used+0x154>
  4018bc:	e8 cf f8 ff ff       	call   401190 <puts@plt>
  4018c1:	48 8d 3d 3c 07 01 00 	lea    rdi,[rip+0x1073c]        # 412004 <_IO_stdin_used+0x4>
  4018c8:	31 f6                	xor    esi,esi
  4018ca:	31 c0                	xor    eax,eax
  4018cc:	e8 7f f9 ff ff       	call   401250 <open@plt>
  4018d1:	89 c7                	mov    edi,eax
  4018d3:	85 c0                	test   eax,eax
  4018d5:	79 34                	jns    40190b <win+0x395>
  4018d7:	e8 a4 f8 ff ff       	call   401180 <__errno_location@plt>
  4018dc:	8b 38                	mov    edi,DWORD PTR [rax]
  4018de:	e8 9d f9 ff ff       	call   401280 <strerror@plt>
  4018e3:	48 8d 35 20 07 01 00 	lea    rsi,[rip+0x10720]        # 41200a <_IO_stdin_used+0xa>
  4018ea:	bf 01 00 00 00       	mov    edi,0x1
  4018ef:	48 89 c2             	mov    rdx,rax
  4018f2:	31 c0                	xor    eax,eax
  4018f4:	e8 37 f9 ff ff       	call   401230 <__printf_chk@plt>
  4018f9:	e8 e2 f8 ff ff       	call   4011e0 <geteuid@plt>
  4018fe:	85 c0                	test   eax,eax
  401900:	0f 84 d3 fc ff ff    	je     4015d9 <win+0x63>
  401906:	e9 b6 fc ff ff       	jmp    4015c1 <win+0x4b>
  40190b:	ba 00 01 00 00       	mov    edx,0x100
  401910:	48 89 ee             	mov    rsi,rbp
  401913:	e8 e8 f8 ff ff       	call   401200 <read@plt>
  401918:	85 c0                	test   eax,eax
  40191a:	7f 2a                	jg     401946 <win+0x3d0>
  40191c:	e8 5f f8 ff ff       	call   401180 <__errno_location@plt>
  401921:	8b 38                	mov    edi,DWORD PTR [rax]
  401923:	e8 58 f9 ff ff       	call   401280 <strerror@plt>
  401928:	bf 01 00 00 00       	mov    edi,0x1
  40192d:	48 8d 35 75 07 01 00 	lea    rsi,[rip+0x10775]        # 4120a9 <_IO_stdin_used+0xa9>
  401934:	48 89 c2             	mov    rdx,rax
  401937:	31 c0                	xor    eax,eax
  401939:	e8 f2 f8 ff ff       	call   401230 <__printf_chk@plt>
  40193e:	83 cf ff             	or     edi,0xffffffff
  401941:	e8 1a f9 ff ff       	call   401260 <exit@plt>
  401946:	48 63 d0             	movsxd rdx,eax
  401949:	48 89 ee             	mov    rsi,rbp
  40194c:	bf 01 00 00 00       	mov    edi,0x1
  401951:	e8 4a f8 ff ff       	call   4011a0 <write@plt>
  401956:	48 8d 3d f7 07 01 00 	lea    rdi,[rip+0x107f7]        # 412154 <_IO_stdin_used+0x154>
  40195d:	e8 2e f8 ff ff       	call   401190 <puts@plt>
  401962:	48 8d 3d 9b 06 01 00 	lea    rdi,[rip+0x1069b]        # 412004 <_IO_stdin_used+0x4>
  401969:	31 f6                	xor    esi,esi
  40196b:	31 c0                	xor    eax,eax
  40196d:	e8 de f8 ff ff       	call   401250 <open@plt>
  401972:	89 c7                	mov    edi,eax
  401974:	85 c0                	test   eax,eax
  401976:	79 34                	jns    4019ac <win+0x436>
  401978:	e8 03 f8 ff ff       	call   401180 <__errno_location@plt>
  40197d:	8b 38                	mov    edi,DWORD PTR [rax]
  40197f:	e8 fc f8 ff ff       	call   401280 <strerror@plt>
  401984:	48 8d 35 7f 06 01 00 	lea    rsi,[rip+0x1067f]        # 41200a <_IO_stdin_used+0xa>
  40198b:	bf 01 00 00 00       	mov    edi,0x1
  401990:	48 89 c2             	mov    rdx,rax
  401993:	31 c0                	xor    eax,eax
  401995:	e8 96 f8 ff ff       	call   401230 <__printf_chk@plt>
  40199a:	e8 41 f8 ff ff       	call   4011e0 <geteuid@plt>
  40199f:	85 c0                	test   eax,eax
  4019a1:	0f 84 32 fc ff ff    	je     4015d9 <win+0x63>
  4019a7:	e9 15 fc ff ff       	jmp    4015c1 <win+0x4b>
  4019ac:	ba 00 01 00 00       	mov    edx,0x100
  4019b1:	48 89 ee             	mov    rsi,rbp
  4019b4:	e8 47 f8 ff ff       	call   401200 <read@plt>
  4019b9:	85 c0                	test   eax,eax
  4019bb:	7f 2a                	jg     4019e7 <win+0x471>
  4019bd:	e8 be f7 ff ff       	call   401180 <__errno_location@plt>
  4019c2:	8b 38                	mov    edi,DWORD PTR [rax]
  4019c4:	e8 b7 f8 ff ff       	call   401280 <strerror@plt>
  4019c9:	bf 01 00 00 00       	mov    edi,0x1
  4019ce:	48 8d 35 d4 06 01 00 	lea    rsi,[rip+0x106d4]        # 4120a9 <_IO_stdin_used+0xa9>
  4019d5:	48 89 c2             	mov    rdx,rax
  4019d8:	31 c0                	xor    eax,eax
  4019da:	e8 51 f8 ff ff       	call   401230 <__printf_chk@plt>
  4019df:	83 cf ff             	or     edi,0xffffffff
  4019e2:	e8 79 f8 ff ff       	call   401260 <exit@plt>
  4019e7:	48 63 d0             	movsxd rdx,eax
  4019ea:	48 89 ee             	mov    rsi,rbp
  4019ed:	bf 01 00 00 00       	mov    edi,0x1
  4019f2:	e8 a9 f7 ff ff       	call   4011a0 <write@plt>
  4019f7:	48 8d 3d 56 07 01 00 	lea    rdi,[rip+0x10756]        # 412154 <_IO_stdin_used+0x154>
  4019fe:	e8 8d f7 ff ff       	call   401190 <puts@plt>
  401a03:	48 8d 3d fa 05 01 00 	lea    rdi,[rip+0x105fa]        # 412004 <_IO_stdin_used+0x4>
  401a0a:	31 f6                	xor    esi,esi
  401a0c:	31 c0                	xor    eax,eax
  401a0e:	e8 3d f8 ff ff       	call   401250 <open@plt>
  401a13:	89 c7                	mov    edi,eax
  401a15:	85 c0                	test   eax,eax
  401a17:	79 34                	jns    401a4d <win+0x4d7>
  401a19:	e8 62 f7 ff ff       	call   401180 <__errno_location@plt>
  401a1e:	8b 38                	mov    edi,DWORD PTR [rax]
  401a20:	e8 5b f8 ff ff       	call   401280 <strerror@plt>
  401a25:	48 8d 35 de 05 01 00 	lea    rsi,[rip+0x105de]        # 41200a <_IO_stdin_used+0xa>
  401a2c:	bf 01 00 00 00       	mov    edi,0x1
  401a31:	48 89 c2             	mov    rdx,rax
  401a34:	31 c0                	xor    eax,eax
  401a36:	e8 f5 f7 ff ff       	call   401230 <__printf_chk@plt>
  401a3b:	e8 a0 f7 ff ff       	call   4011e0 <geteuid@plt>
  401a40:	85 c0                	test   eax,eax
  401a42:	0f 84 91 fb ff ff    	je     4015d9 <win+0x63>
  401a48:	e9 74 fb ff ff       	jmp    4015c1 <win+0x4b>
  401a4d:	ba 00 01 00 00       	mov    edx,0x100
  401a52:	48 89 ee             	mov    rsi,rbp
  401a55:	e8 a6 f7 ff ff       	call   401200 <read@plt>
  401a5a:	85 c0                	test   eax,eax
  401a5c:	7f 2a                	jg     401a88 <win+0x512>
  401a5e:	e8 1d f7 ff ff       	call   401180 <__errno_location@plt>
  401a63:	8b 38                	mov    edi,DWORD PTR [rax]
  401a65:	e8 16 f8 ff ff       	call   401280 <strerror@plt>
  401a6a:	bf 01 00 00 00       	mov    edi,0x1
  401a6f:	48 8d 35 33 06 01 00 	lea    rsi,[rip+0x10633]        # 4120a9 <_IO_stdin_used+0xa9>
  401a76:	48 89 c2             	mov    rdx,rax
  401a79:	31 c0                	xor    eax,eax
  401a7b:	e8 b0 f7 ff ff       	call   401230 <__printf_chk@plt>
  401a80:	83 cf ff             	or     edi,0xffffffff
  401a83:	e8 d8 f7 ff ff       	call   401260 <exit@plt>
  401a88:	48 63 d0             	movsxd rdx,eax
  401a8b:	48 89 ee             	mov    rsi,rbp
  401a8e:	bf 01 00 00 00       	mov    edi,0x1
  401a93:	e8 08 f7 ff ff       	call   4011a0 <write@plt>
  401a98:	48 8d 3d b5 06 01 00 	lea    rdi,[rip+0x106b5]        # 412154 <_IO_stdin_used+0x154>
  401a9f:	e8 ec f6 ff ff       	call   401190 <puts@plt>
  401aa4:	48 8d 3d 59 05 01 00 	lea    rdi,[rip+0x10559]        # 412004 <_IO_stdin_used+0x4>
  401aab:	31 f6                	xor    esi,esi
  401aad:	31 c0                	xor    eax,eax
  401aaf:	e8 9c f7 ff ff       	call   401250 <open@plt>
  401ab4:	89 c7                	mov    edi,eax
  401ab6:	85 c0                	test   eax,eax
  401ab8:	79 34                	jns    401aee <win+0x578>
  401aba:	e8 c1 f6 ff ff       	call   401180 <__errno_location@plt>
  401abf:	8b 38                	mov    edi,DWORD PTR [rax]
  401ac1:	e8 ba f7 ff ff       	call   401280 <strerror@plt>
  401ac6:	48 8d 35 3d 05 01 00 	lea    rsi,[rip+0x1053d]        # 41200a <_IO_stdin_used+0xa>
  401acd:	bf 01 00 00 00       	mov    edi,0x1
  401ad2:	48 89 c2             	mov    rdx,rax
  401ad5:	31 c0                	xor    eax,eax
  401ad7:	e8 54 f7 ff ff       	call   401230 <__printf_chk@plt>
  401adc:	e8 ff f6 ff ff       	call   4011e0 <geteuid@plt>
  401ae1:	85 c0                	test   eax,eax
  401ae3:	0f 84 f0 fa ff ff    	je     4015d9 <win+0x63>
  401ae9:	e9 d3 fa ff ff       	jmp    4015c1 <win+0x4b>
  401aee:	ba 00 01 00 00       	mov    edx,0x100
  401af3:	48 89 ee             	mov    rsi,rbp
  401af6:	e8 05 f7 ff ff       	call   401200 <read@plt>
  401afb:	85 c0                	test   eax,eax
  401afd:	7f 2a                	jg     401b29 <win+0x5b3>
  401aff:	e8 7c f6 ff ff       	call   401180 <__errno_location@plt>
  401b04:	8b 38                	mov    edi,DWORD PTR [rax]
  401b06:	e8 75 f7 ff ff       	call   401280 <strerror@plt>
  401b0b:	bf 01 00 00 00       	mov    edi,0x1
  401b10:	48 8d 35 92 05 01 00 	lea    rsi,[rip+0x10592]        # 4120a9 <_IO_stdin_used+0xa9>
  401b17:	48 89 c2             	mov    rdx,rax
  401b1a:	31 c0                	xor    eax,eax
  401b1c:	e8 0f f7 ff ff       	call   401230 <__printf_chk@plt>
  401b21:	83 cf ff             	or     edi,0xffffffff
  401b24:	e8 37 f7 ff ff       	call   401260 <exit@plt>
  401b29:	48 63 d0             	movsxd rdx,eax
  401b2c:	48 89 ee             	mov    rsi,rbp
  401b2f:	bf 01 00 00 00       	mov    edi,0x1
  401b34:	e8 67 f6 ff ff       	call   4011a0 <write@plt>
  401b39:	48 8d 3d 14 06 01 00 	lea    rdi,[rip+0x10614]        # 412154 <_IO_stdin_used+0x154>
  401b40:	e8 4b f6 ff ff       	call   401190 <puts@plt>
  401b45:	48 8d 3d b8 04 01 00 	lea    rdi,[rip+0x104b8]        # 412004 <_IO_stdin_used+0x4>
  401b4c:	31 f6                	xor    esi,esi
  401b4e:	31 c0                	xor    eax,eax
  401b50:	e8 fb f6 ff ff       	call   401250 <open@plt>
  401b55:	89 c7                	mov    edi,eax
  401b57:	85 c0                	test   eax,eax
  401b59:	79 34                	jns    401b8f <win+0x619>
  401b5b:	e8 20 f6 ff ff       	call   401180 <__errno_location@plt>
  401b60:	8b 38                	mov    edi,DWORD PTR [rax]
  401b62:	e8 19 f7 ff ff       	call   401280 <strerror@plt>
  401b67:	48 8d 35 9c 04 01 00 	lea    rsi,[rip+0x1049c]        # 41200a <_IO_stdin_used+0xa>
  401b6e:	bf 01 00 00 00       	mov    edi,0x1
  401b73:	48 89 c2             	mov    rdx,rax
  401b76:	31 c0                	xor    eax,eax
  401b78:	e8 b3 f6 ff ff       	call   401230 <__printf_chk@plt>
  401b7d:	e8 5e f6 ff ff       	call   4011e0 <geteuid@plt>
  401b82:	85 c0                	test   eax,eax
  401b84:	0f 84 4f fa ff ff    	je     4015d9 <win+0x63>
  401b8a:	e9 32 fa ff ff       	jmp    4015c1 <win+0x4b>
  401b8f:	ba 00 01 00 00       	mov    edx,0x100
  401b94:	48 89 ee             	mov    rsi,rbp
  401b97:	e8 64 f6 ff ff       	call   401200 <read@plt>
  401b9c:	85 c0                	test   eax,eax
  401b9e:	7f 2a                	jg     401bca <win+0x654>
  401ba0:	e8 db f5 ff ff       	call   401180 <__errno_location@plt>
  401ba5:	8b 38                	mov    edi,DWORD PTR [rax]
  401ba7:	e8 d4 f6 ff ff       	call   401280 <strerror@plt>
  401bac:	bf 01 00 00 00       	mov    edi,0x1
  401bb1:	48 8d 35 f1 04 01 00 	lea    rsi,[rip+0x104f1]        # 4120a9 <_IO_stdin_used+0xa9>
  401bb8:	48 89 c2             	mov    rdx,rax
  401bbb:	31 c0                	xor    eax,eax
  401bbd:	e8 6e f6 ff ff       	call   401230 <__printf_chk@plt>
  401bc2:	83 cf ff             	or     edi,0xffffffff
  401bc5:	e8 96 f6 ff ff       	call   401260 <exit@plt>
  401bca:	48 63 d0             	movsxd rdx,eax
  401bcd:	48 89 ee             	mov    rsi,rbp
  401bd0:	bf 01 00 00 00       	mov    edi,0x1
  401bd5:	e8 c6 f5 ff ff       	call   4011a0 <write@plt>
  401bda:	48 8d 3d 73 05 01 00 	lea    rdi,[rip+0x10573]        # 412154 <_IO_stdin_used+0x154>
  401be1:	e8 aa f5 ff ff       	call   401190 <puts@plt>
  401be6:	48 8d 3d 17 04 01 00 	lea    rdi,[rip+0x10417]        # 412004 <_IO_stdin_used+0x4>
  401bed:	31 f6                	xor    esi,esi
  401bef:	31 c0                	xor    eax,eax
  401bf1:	e8 5a f6 ff ff       	call   401250 <open@plt>
  401bf6:	89 c7                	mov    edi,eax
  401bf8:	85 c0                	test   eax,eax
  401bfa:	79 34                	jns    401c30 <win+0x6ba>
  401bfc:	e8 7f f5 ff ff       	call   401180 <__errno_location@plt>
  401c01:	8b 38                	mov    edi,DWORD PTR [rax]
  401c03:	e8 78 f6 ff ff       	call   401280 <strerror@plt>
  401c08:	48 8d 35 fb 03 01 00 	lea    rsi,[rip+0x103fb]        # 41200a <_IO_stdin_used+0xa>
  401c0f:	bf 01 00 00 00       	mov    edi,0x1
  401c14:	48 89 c2             	mov    rdx,rax
  401c17:	31 c0                	xor    eax,eax
  401c19:	e8 12 f6 ff ff       	call   401230 <__printf_chk@plt>
  401c1e:	e8 bd f5 ff ff       	call   4011e0 <geteuid@plt>
  401c23:	85 c0                	test   eax,eax
  401c25:	0f 84 ae f9 ff ff    	je     4015d9 <win+0x63>
  401c2b:	e9 91 f9 ff ff       	jmp    4015c1 <win+0x4b>
  401c30:	ba 00 01 00 00       	mov    edx,0x100
  401c35:	48 89 ee             	mov    rsi,rbp
  401c38:	e8 c3 f5 ff ff       	call   401200 <read@plt>
  401c3d:	85 c0                	test   eax,eax
  401c3f:	7f 2a                	jg     401c6b <win+0x6f5>
  401c41:	e8 3a f5 ff ff       	call   401180 <__errno_location@plt>
  401c46:	8b 38                	mov    edi,DWORD PTR [rax]
  401c48:	e8 33 f6 ff ff       	call   401280 <strerror@plt>
  401c4d:	bf 01 00 00 00       	mov    edi,0x1
  401c52:	48 8d 35 50 04 01 00 	lea    rsi,[rip+0x10450]        # 4120a9 <_IO_stdin_used+0xa9>
  401c59:	48 89 c2             	mov    rdx,rax
  401c5c:	31 c0                	xor    eax,eax
  401c5e:	e8 cd f5 ff ff       	call   401230 <__printf_chk@plt>
  401c63:	83 cf ff             	or     edi,0xffffffff
  401c66:	e8 f5 f5 ff ff       	call   401260 <exit@plt>
  401c6b:	48 63 d0             	movsxd rdx,eax
  401c6e:	48 89 ee             	mov    rsi,rbp
  401c71:	bf 01 00 00 00       	mov    edi,0x1
  401c76:	e8 25 f5 ff ff       	call   4011a0 <write@plt>
  401c7b:	48 8d 3d d2 04 01 00 	lea    rdi,[rip+0x104d2]        # 412154 <_IO_stdin_used+0x154>
  401c82:	e8 09 f5 ff ff       	call   401190 <puts@plt>
  401c87:	48 8d 3d 76 03 01 00 	lea    rdi,[rip+0x10376]        # 412004 <_IO_stdin_used+0x4>
  401c8e:	31 f6                	xor    esi,esi
  401c90:	31 c0                	xor    eax,eax
  401c92:	e8 b9 f5 ff ff       	call   401250 <open@plt>
  401c97:	89 c7                	mov    edi,eax
  401c99:	85 c0                	test   eax,eax
  401c9b:	79 34                	jns    401cd1 <win+0x75b>
  401c9d:	e8 de f4 ff ff       	call   401180 <__errno_location@plt>
  401ca2:	8b 38                	mov    edi,DWORD PTR [rax]
  401ca4:	e8 d7 f5 ff ff       	call   401280 <strerror@plt>
  401ca9:	48 8d 35 5a 03 01 00 	lea    rsi,[rip+0x1035a]        # 41200a <_IO_stdin_used+0xa>
  401cb0:	bf 01 00 00 00       	mov    edi,0x1
  401cb5:	48 89 c2             	mov    rdx,rax
  401cb8:	31 c0                	xor    eax,eax
  401cba:	e8 71 f5 ff ff       	call   401230 <__printf_chk@plt>
  401cbf:	e8 1c f5 ff ff       	call   4011e0 <geteuid@plt>
  401cc4:	85 c0                	test   eax,eax
  401cc6:	0f 84 0d f9 ff ff    	je     4015d9 <win+0x63>
  401ccc:	e9 f0 f8 ff ff       	jmp    4015c1 <win+0x4b>
  401cd1:	ba 00 01 00 00       	mov    edx,0x100
  401cd6:	48 89 ee             	mov    rsi,rbp
  401cd9:	e8 22 f5 ff ff       	call   401200 <read@plt>
  401cde:	85 c0                	test   eax,eax
  401ce0:	7f 2a                	jg     401d0c <win+0x796>
  401ce2:	e8 99 f4 ff ff       	call   401180 <__errno_location@plt>
  401ce7:	8b 38                	mov    edi,DWORD PTR [rax]
  401ce9:	e8 92 f5 ff ff       	call   401280 <strerror@plt>
  401cee:	bf 01 00 00 00       	mov    edi,0x1
  401cf3:	48 8d 35 af 03 01 00 	lea    rsi,[rip+0x103af]        # 4120a9 <_IO_stdin_used+0xa9>
  401cfa:	48 89 c2             	mov    rdx,rax
  401cfd:	31 c0                	xor    eax,eax
  401cff:	e8 2c f5 ff ff       	call   401230 <__printf_chk@plt>
  401d04:	83 cf ff             	or     edi,0xffffffff
  401d07:	e8 54 f5 ff ff       	call   401260 <exit@plt>
  401d0c:	48 63 d0             	movsxd rdx,eax
  401d0f:	48 89 ee             	mov    rsi,rbp
  401d12:	bf 01 00 00 00       	mov    edi,0x1
  401d17:	e8 84 f4 ff ff       	call   4011a0 <write@plt>
  401d1c:	48 8d 3d 31 04 01 00 	lea    rdi,[rip+0x10431]        # 412154 <_IO_stdin_used+0x154>
  401d23:	e8 68 f4 ff ff       	call   401190 <puts@plt>
  401d28:	48 8d 3d d5 02 01 00 	lea    rdi,[rip+0x102d5]        # 412004 <_IO_stdin_used+0x4>
  401d2f:	31 f6                	xor    esi,esi
  401d31:	31 c0                	xor    eax,eax
  401d33:	e8 18 f5 ff ff       	call   401250 <open@plt>
  401d38:	89 c7                	mov    edi,eax
  401d3a:	85 c0                	test   eax,eax
  401d3c:	79 34                	jns    401d72 <win+0x7fc>
  401d3e:	e8 3d f4 ff ff       	call   401180 <__errno_location@plt>
  401d43:	8b 38                	mov    edi,DWORD PTR [rax]
  401d45:	e8 36 f5 ff ff       	call   401280 <strerror@plt>
  401d4a:	48 8d 35 b9 02 01 00 	lea    rsi,[rip+0x102b9]        # 41200a <_IO_stdin_used+0xa>
  401d51:	bf 01 00 00 00       	mov    edi,0x1
  401d56:	48 89 c2             	mov    rdx,rax
  401d59:	31 c0                	xor    eax,eax
  401d5b:	e8 d0 f4 ff ff       	call   401230 <__printf_chk@plt>
  401d60:	e8 7b f4 ff ff       	call   4011e0 <geteuid@plt>
  401d65:	85 c0                	test   eax,eax
  401d67:	0f 84 6c f8 ff ff    	je     4015d9 <win+0x63>
  401d6d:	e9 4f f8 ff ff       	jmp    4015c1 <win+0x4b>
  401d72:	ba 00 01 00 00       	mov    edx,0x100
  401d77:	48 89 ee             	mov    rsi,rbp
  401d7a:	e8 81 f4 ff ff       	call   401200 <read@plt>
  401d7f:	85 c0                	test   eax,eax
  401d81:	7f 2a                	jg     401dad <win+0x837>
  401d83:	e8 f8 f3 ff ff       	call   401180 <__errno_location@plt>
  401d88:	8b 38                	mov    edi,DWORD PTR [rax]
  401d8a:	e8 f1 f4 ff ff       	call   401280 <strerror@plt>
  401d8f:	bf 01 00 00 00       	mov    edi,0x1
  401d94:	48 8d 35 0e 03 01 00 	lea    rsi,[rip+0x1030e]        # 4120a9 <_IO_stdin_used+0xa9>
  401d9b:	48 89 c2             	mov    rdx,rax
  401d9e:	31 c0                	xor    eax,eax
  401da0:	e8 8b f4 ff ff       	call   401230 <__printf_chk@plt>
  401da5:	83 cf ff             	or     edi,0xffffffff
  401da8:	e8 b3 f4 ff ff       	call   401260 <exit@plt>
  401dad:	48 63 d0             	movsxd rdx,eax
  401db0:	48 89 ee             	mov    rsi,rbp
  401db3:	bf 01 00 00 00       	mov    edi,0x1
  401db8:	e8 e3 f3 ff ff       	call   4011a0 <write@plt>
  401dbd:	48 8d 3d 90 03 01 00 	lea    rdi,[rip+0x10390]        # 412154 <_IO_stdin_used+0x154>
  401dc4:	e8 c7 f3 ff ff       	call   401190 <puts@plt>
  401dc9:	48 8d 3d 34 02 01 00 	lea    rdi,[rip+0x10234]        # 412004 <_IO_stdin_used+0x4>
  401dd0:	31 f6                	xor    esi,esi
  401dd2:	31 c0                	xor    eax,eax
  401dd4:	e8 77 f4 ff ff       	call   401250 <open@plt>
  401dd9:	89 c7                	mov    edi,eax
  401ddb:	85 c0                	test   eax,eax
  401ddd:	79 34                	jns    401e13 <win+0x89d>
  401ddf:	e8 9c f3 ff ff       	call   401180 <__errno_location@plt>
  401de4:	8b 38                	mov    edi,DWORD PTR [rax]
  401de6:	e8 95 f4 ff ff       	call   401280 <strerror@plt>
  401deb:	48 8d 35 18 02 01 00 	lea    rsi,[rip+0x10218]        # 41200a <_IO_stdin_used+0xa>
  401df2:	bf 01 00 00 00       	mov    edi,0x1
  401df7:	48 89 c2             	mov    rdx,rax
  401dfa:	31 c0                	xor    eax,eax
  401dfc:	e8 2f f4 ff ff       	call   401230 <__printf_chk@plt>
  401e01:	e8 da f3 ff ff       	call   4011e0 <geteuid@plt>
  401e06:	85 c0                	test   eax,eax
  401e08:	0f 84 cb f7 ff ff    	je     4015d9 <win+0x63>
  401e0e:	e9 ae f7 ff ff       	jmp    4015c1 <win+0x4b>
  401e13:	ba 00 01 00 00       	mov    edx,0x100
  401e18:	48 89 ee             	mov    rsi,rbp
  401e1b:	e8 e0 f3 ff ff       	call   401200 <read@plt>
  401e20:	85 c0                	test   eax,eax
  401e22:	7f 2a                	jg     401e4e <win+0x8d8>
  401e24:	e8 57 f3 ff ff       	call   401180 <__errno_location@plt>
  401e29:	8b 38                	mov    edi,DWORD PTR [rax]
  401e2b:	e8 50 f4 ff ff       	call   401280 <strerror@plt>
  401e30:	bf 01 00 00 00       	mov    edi,0x1
  401e35:	48 8d 35 6d 02 01 00 	lea    rsi,[rip+0x1026d]        # 4120a9 <_IO_stdin_used+0xa9>
  401e3c:	48 89 c2             	mov    rdx,rax
  401e3f:	31 c0                	xor    eax,eax
  401e41:	e8 ea f3 ff ff       	call   401230 <__printf_chk@plt>
  401e46:	83 cf ff             	or     edi,0xffffffff
  401e49:	e8 12 f4 ff ff       	call   401260 <exit@plt>
  401e4e:	48 63 d0             	movsxd rdx,eax
  401e51:	48 89 ee             	mov    rsi,rbp
  401e54:	bf 01 00 00 00       	mov    edi,0x1
  401e59:	e8 42 f3 ff ff       	call   4011a0 <write@plt>
  401e5e:	48 8d 3d ef 02 01 00 	lea    rdi,[rip+0x102ef]        # 412154 <_IO_stdin_used+0x154>
  401e65:	e8 26 f3 ff ff       	call   401190 <puts@plt>
  401e6a:	48 8d 3d 93 01 01 00 	lea    rdi,[rip+0x10193]        # 412004 <_IO_stdin_used+0x4>
  401e71:	31 f6                	xor    esi,esi
  401e73:	31 c0                	xor    eax,eax
  401e75:	e8 d6 f3 ff ff       	call   401250 <open@plt>
  401e7a:	89 c7                	mov    edi,eax
  401e7c:	85 c0                	test   eax,eax
  401e7e:	79 34                	jns    401eb4 <win+0x93e>
  401e80:	e8 fb f2 ff ff       	call   401180 <__errno_location@plt>
  401e85:	8b 38                	mov    edi,DWORD PTR [rax]
  401e87:	e8 f4 f3 ff ff       	call   401280 <strerror@plt>
  401e8c:	48 8d 35 77 01 01 00 	lea    rsi,[rip+0x10177]        # 41200a <_IO_stdin_used+0xa>
  401e93:	bf 01 00 00 00       	mov    edi,0x1
  401e98:	48 89 c2             	mov    rdx,rax
  401e9b:	31 c0                	xor    eax,eax
  401e9d:	e8 8e f3 ff ff       	call   401230 <__printf_chk@plt>
  401ea2:	e8 39 f3 ff ff       	call   4011e0 <geteuid@plt>
  401ea7:	85 c0                	test   eax,eax
  401ea9:	0f 84 2a f7 ff ff    	je     4015d9 <win+0x63>
  401eaf:	e9 0d f7 ff ff       	jmp    4015c1 <win+0x4b>
  401eb4:	ba 00 01 00 00       	mov    edx,0x100
  401eb9:	48 89 ee             	mov    rsi,rbp
  401ebc:	e8 3f f3 ff ff       	call   401200 <read@plt>
  401ec1:	85 c0                	test   eax,eax
  401ec3:	7f 2a                	jg     401eef <win+0x979>
  401ec5:	e8 b6 f2 ff ff       	call   401180 <__errno_location@plt>
  401eca:	8b 38                	mov    edi,DWORD PTR [rax]
  401ecc:	e8 af f3 ff ff       	call   401280 <strerror@plt>
  401ed1:	bf 01 00 00 00       	mov    edi,0x1
  401ed6:	48 8d 35 cc 01 01 00 	lea    rsi,[rip+0x101cc]        # 4120a9 <_IO_stdin_used+0xa9>
  401edd:	48 89 c2             	mov    rdx,rax
  401ee0:	31 c0                	xor    eax,eax
  401ee2:	e8 49 f3 ff ff       	call   401230 <__printf_chk@plt>
  401ee7:	83 cf ff             	or     edi,0xffffffff
  401eea:	e8 71 f3 ff ff       	call   401260 <exit@plt>
  401eef:	48 63 d0             	movsxd rdx,eax
  401ef2:	48 89 ee             	mov    rsi,rbp
  401ef5:	bf 01 00 00 00       	mov    edi,0x1
  401efa:	e8 a1 f2 ff ff       	call   4011a0 <write@plt>
  401eff:	48 8d 3d 4e 02 01 00 	lea    rdi,[rip+0x1024e]        # 412154 <_IO_stdin_used+0x154>
  401f06:	e8 85 f2 ff ff       	call   401190 <puts@plt>
  401f0b:	48 8d 3d f2 00 01 00 	lea    rdi,[rip+0x100f2]        # 412004 <_IO_stdin_used+0x4>
  401f12:	31 f6                	xor    esi,esi
  401f14:	31 c0                	xor    eax,eax
  401f16:	e8 35 f3 ff ff       	call   401250 <open@plt>
  401f1b:	89 c7                	mov    edi,eax
  401f1d:	85 c0                	test   eax,eax
  401f1f:	79 34                	jns    401f55 <win+0x9df>
  401f21:	e8 5a f2 ff ff       	call   401180 <__errno_location@plt>
  401f26:	8b 38                	mov    edi,DWORD PTR [rax]
  401f28:	e8 53 f3 ff ff       	call   401280 <strerror@plt>
  401f2d:	48 8d 35 d6 00 01 00 	lea    rsi,[rip+0x100d6]        # 41200a <_IO_stdin_used+0xa>
  401f34:	bf 01 00 00 00       	mov    edi,0x1
  401f39:	48 89 c2             	mov    rdx,rax
  401f3c:	31 c0                	xor    eax,eax
  401f3e:	e8 ed f2 ff ff       	call   401230 <__printf_chk@plt>
  401f43:	e8 98 f2 ff ff       	call   4011e0 <geteuid@plt>
  401f48:	85 c0                	test   eax,eax
  401f4a:	0f 84 89 f6 ff ff    	je     4015d9 <win+0x63>
  401f50:	e9 6c f6 ff ff       	jmp    4015c1 <win+0x4b>
  401f55:	ba 00 01 00 00       	mov    edx,0x100
  401f5a:	48 89 ee             	mov    rsi,rbp
  401f5d:	e8 9e f2 ff ff       	call   401200 <read@plt>
  401f62:	85 c0                	test   eax,eax
  401f64:	7f 2a                	jg     401f90 <win+0xa1a>
  401f66:	e8 15 f2 ff ff       	call   401180 <__errno_location@plt>
  401f6b:	8b 38                	mov    edi,DWORD PTR [rax]
  401f6d:	e8 0e f3 ff ff       	call   401280 <strerror@plt>
  401f72:	bf 01 00 00 00       	mov    edi,0x1
  401f77:	48 8d 35 2b 01 01 00 	lea    rsi,[rip+0x1012b]        # 4120a9 <_IO_stdin_used+0xa9>
  401f7e:	48 89 c2             	mov    rdx,rax
  401f81:	31 c0                	xor    eax,eax
  401f83:	e8 a8 f2 ff ff       	call   401230 <__printf_chk@plt>
  401f88:	83 cf ff             	or     edi,0xffffffff
  401f8b:	e8 d0 f2 ff ff       	call   401260 <exit@plt>
  401f90:	48 63 d0             	movsxd rdx,eax
  401f93:	48 89 ee             	mov    rsi,rbp
  401f96:	bf 01 00 00 00       	mov    edi,0x1
  401f9b:	e8 00 f2 ff ff       	call   4011a0 <write@plt>
  401fa0:	48 8d 3d ad 01 01 00 	lea    rdi,[rip+0x101ad]        # 412154 <_IO_stdin_used+0x154>
  401fa7:	e8 e4 f1 ff ff       	call   401190 <puts@plt>
  401fac:	48 8d 3d 51 00 01 00 	lea    rdi,[rip+0x10051]        # 412004 <_IO_stdin_used+0x4>
  401fb3:	31 f6                	xor    esi,esi
  401fb5:	31 c0                	xor    eax,eax
  401fb7:	e8 94 f2 ff ff       	call   401250 <open@plt>
  401fbc:	89 c7                	mov    edi,eax
  401fbe:	85 c0                	test   eax,eax
  401fc0:	79 34                	jns    401ff6 <win+0xa80>
  401fc2:	e8 b9 f1 ff ff       	call   401180 <__errno_location@plt>
  401fc7:	8b 38                	mov    edi,DWORD PTR [rax]
  401fc9:	e8 b2 f2 ff ff       	call   401280 <strerror@plt>
  401fce:	48 8d 35 35 00 01 00 	lea    rsi,[rip+0x10035]        # 41200a <_IO_stdin_used+0xa>
  401fd5:	bf 01 00 00 00       	mov    edi,0x1
  401fda:	48 89 c2             	mov    rdx,rax
  401fdd:	31 c0                	xor    eax,eax
  401fdf:	e8 4c f2 ff ff       	call   401230 <__printf_chk@plt>
  401fe4:	e8 f7 f1 ff ff       	call   4011e0 <geteuid@plt>
  401fe9:	85 c0                	test   eax,eax
  401feb:	0f 84 e8 f5 ff ff    	je     4015d9 <win+0x63>
  401ff1:	e9 cb f5 ff ff       	jmp    4015c1 <win+0x4b>
  401ff6:	ba 00 01 00 00       	mov    edx,0x100
  401ffb:	48 89 ee             	mov    rsi,rbp
  401ffe:	e8 fd f1 ff ff       	call   401200 <read@plt>
  402003:	85 c0                	test   eax,eax
  402005:	7f 2a                	jg     402031 <win+0xabb>
  402007:	e8 74 f1 ff ff       	call   401180 <__errno_location@plt>
  40200c:	8b 38                	mov    edi,DWORD PTR [rax]
  40200e:	e8 6d f2 ff ff       	call   401280 <strerror@plt>
  402013:	bf 01 00 00 00       	mov    edi,0x1
  402018:	48 8d 35 8a 00 01 00 	lea    rsi,[rip+0x1008a]        # 4120a9 <_IO_stdin_used+0xa9>
  40201f:	48 89 c2             	mov    rdx,rax
  402022:	31 c0                	xor    eax,eax
  402024:	e8 07 f2 ff ff       	call   401230 <__printf_chk@plt>
  402029:	83 cf ff             	or     edi,0xffffffff
  40202c:	e8 2f f2 ff ff       	call   401260 <exit@plt>
  402031:	48 63 d0             	movsxd rdx,eax
  402034:	48 89 ee             	mov    rsi,rbp
  402037:	bf 01 00 00 00       	mov    edi,0x1
  40203c:	e8 5f f1 ff ff       	call   4011a0 <write@plt>
  402041:	48 8d 3d 0c 01 01 00 	lea    rdi,[rip+0x1010c]        # 412154 <_IO_stdin_used+0x154>
  402048:	e8 43 f1 ff ff       	call   401190 <puts@plt>
  40204d:	48 8d 3d b0 ff 00 00 	lea    rdi,[rip+0xffb0]        # 412004 <_IO_stdin_used+0x4>
  402054:	31 f6                	xor    esi,esi
  402056:	31 c0                	xor    eax,eax
  402058:	e8 f3 f1 ff ff       	call   401250 <open@plt>
  40205d:	89 c7                	mov    edi,eax
  40205f:	85 c0                	test   eax,eax
  402061:	79 34                	jns    402097 <win+0xb21>
  402063:	e8 18 f1 ff ff       	call   401180 <__errno_location@plt>
  402068:	8b 38                	mov    edi,DWORD PTR [rax]
  40206a:	e8 11 f2 ff ff       	call   401280 <strerror@plt>
  40206f:	48 8d 35 94 ff 00 00 	lea    rsi,[rip+0xff94]        # 41200a <_IO_stdin_used+0xa>
  402076:	bf 01 00 00 00       	mov    edi,0x1
  40207b:	48 89 c2             	mov    rdx,rax
  40207e:	31 c0                	xor    eax,eax
  402080:	e8 ab f1 ff ff       	call   401230 <__printf_chk@plt>
  402085:	e8 56 f1 ff ff       	call   4011e0 <geteuid@plt>
  40208a:	85 c0                	test   eax,eax
  40208c:	0f 84 47 f5 ff ff    	je     4015d9 <win+0x63>
  402092:	e9 2a f5 ff ff       	jmp    4015c1 <win+0x4b>
  402097:	ba 00 01 00 00       	mov    edx,0x100
  40209c:	48 89 ee             	mov    rsi,rbp
  40209f:	e8 5c f1 ff ff       	call   401200 <read@plt>
  4020a4:	85 c0                	test   eax,eax
  4020a6:	7f 2a                	jg     4020d2 <win+0xb5c>
  4020a8:	e8 d3 f0 ff ff       	call   401180 <__errno_location@plt>
  4020ad:	8b 38                	mov    edi,DWORD PTR [rax]
  4020af:	e8 cc f1 ff ff       	call   401280 <strerror@plt>
  4020b4:	bf 01 00 00 00       	mov    edi,0x1
  4020b9:	48 8d 35 e9 ff 00 00 	lea    rsi,[rip+0xffe9]        # 4120a9 <_IO_stdin_used+0xa9>
  4020c0:	48 89 c2             	mov    rdx,rax
  4020c3:	31 c0                	xor    eax,eax
  4020c5:	e8 66 f1 ff ff       	call   401230 <__printf_chk@plt>
  4020ca:	83 cf ff             	or     edi,0xffffffff
  4020cd:	e8 8e f1 ff ff       	call   401260 <exit@plt>
  4020d2:	48 63 d0             	movsxd rdx,eax
  4020d5:	48 89 ee             	mov    rsi,rbp
  4020d8:	bf 01 00 00 00       	mov    edi,0x1
  4020dd:	e8 be f0 ff ff       	call   4011a0 <write@plt>
  4020e2:	48 8d 3d 6b 00 01 00 	lea    rdi,[rip+0x1006b]        # 412154 <_IO_stdin_used+0x154>
  4020e9:	e8 a2 f0 ff ff       	call   401190 <puts@plt>
  4020ee:	48 8d 3d 0f ff 00 00 	lea    rdi,[rip+0xff0f]        # 412004 <_IO_stdin_used+0x4>
  4020f5:	31 f6                	xor    esi,esi
  4020f7:	31 c0                	xor    eax,eax
  4020f9:	e8 52 f1 ff ff       	call   401250 <open@plt>
  4020fe:	89 c7                	mov    edi,eax
  402100:	85 c0                	test   eax,eax
  402102:	79 34                	jns    402138 <win+0xbc2>
  402104:	e8 77 f0 ff ff       	call   401180 <__errno_location@plt>
  402109:	8b 38                	mov    edi,DWORD PTR [rax]
  40210b:	e8 70 f1 ff ff       	call   401280 <strerror@plt>
  402110:	48 8d 35 f3 fe 00 00 	lea    rsi,[rip+0xfef3]        # 41200a <_IO_stdin_used+0xa>
  402117:	bf 01 00 00 00       	mov    edi,0x1
  40211c:	48 89 c2             	mov    rdx,rax
  40211f:	31 c0                	xor    eax,eax
  402121:	e8 0a f1 ff ff       	call   401230 <__printf_chk@plt>
  402126:	e8 b5 f0 ff ff       	call   4011e0 <geteuid@plt>
  40212b:	85 c0                	test   eax,eax
  40212d:	0f 84 a6 f4 ff ff    	je     4015d9 <win+0x63>
  402133:	e9 89 f4 ff ff       	jmp    4015c1 <win+0x4b>
  402138:	ba 00 01 00 00       	mov    edx,0x100
  40213d:	48 89 ee             	mov    rsi,rbp
  402140:	e8 bb f0 ff ff       	call   401200 <read@plt>
  402145:	85 c0                	test   eax,eax
  402147:	7f 2a                	jg     402173 <win+0xbfd>
  402149:	e8 32 f0 ff ff       	call   401180 <__errno_location@plt>
  40214e:	8b 38                	mov    edi,DWORD PTR [rax]
  402150:	e8 2b f1 ff ff       	call   401280 <strerror@plt>
  402155:	bf 01 00 00 00       	mov    edi,0x1
  40215a:	48 8d 35 48 ff 00 00 	lea    rsi,[rip+0xff48]        # 4120a9 <_IO_stdin_used+0xa9>
  402161:	48 89 c2             	mov    rdx,rax
  402164:	31 c0                	xor    eax,eax
  402166:	e8 c5 f0 ff ff       	call   401230 <__printf_chk@plt>
  40216b:	83 cf ff             	or     edi,0xffffffff
  40216e:	e8 ed f0 ff ff       	call   401260 <exit@plt>
  402173:	48 63 d0             	movsxd rdx,eax
  402176:	48 89 ee             	mov    rsi,rbp
  402179:	bf 01 00 00 00       	mov    edi,0x1
  40217e:	e8 1d f0 ff ff       	call   4011a0 <write@plt>
  402183:	48 8d 3d ca ff 00 00 	lea    rdi,[rip+0xffca]        # 412154 <_IO_stdin_used+0x154>
  40218a:	e8 01 f0 ff ff       	call   401190 <puts@plt>
  40218f:	48 8d 3d 6e fe 00 00 	lea    rdi,[rip+0xfe6e]        # 412004 <_IO_stdin_used+0x4>
  402196:	31 f6                	xor    esi,esi
  402198:	31 c0                	xor    eax,eax
  40219a:	e8 b1 f0 ff ff       	call   401250 <open@plt>
  40219f:	89 c7                	mov    edi,eax
  4021a1:	85 c0                	test   eax,eax
  4021a3:	79 34                	jns    4021d9 <win+0xc63>
  4021a5:	e8 d6 ef ff ff       	call   401180 <__errno_location@plt>
  4021aa:	8b 38                	mov    edi,DWORD PTR [rax]
  4021ac:	e8 cf f0 ff ff       	call   401280 <strerror@plt>
  4021b1:	48 8d 35 52 fe 00 00 	lea    rsi,[rip+0xfe52]        # 41200a <_IO_stdin_used+0xa>
  4021b8:	bf 01 00 00 00       	mov    edi,0x1
  4021bd:	48 89 c2             	mov    rdx,rax
  4021c0:	31 c0                	xor    eax,eax
  4021c2:	e8 69 f0 ff ff       	call   401230 <__printf_chk@plt>
  4021c7:	e8 14 f0 ff ff       	call   4011e0 <geteuid@plt>
  4021cc:	85 c0                	test   eax,eax
  4021ce:	0f 84 05 f4 ff ff    	je     4015d9 <win+0x63>
  4021d4:	e9 e8 f3 ff ff       	jmp    4015c1 <win+0x4b>
  4021d9:	ba 00 01 00 00       	mov    edx,0x100
  4021de:	48 89 ee             	mov    rsi,rbp
  4021e1:	e8 1a f0 ff ff       	call   401200 <read@plt>
  4021e6:	85 c0                	test   eax,eax
  4021e8:	7f 2a                	jg     402214 <win+0xc9e>
  4021ea:	e8 91 ef ff ff       	call   401180 <__errno_location@plt>
  4021ef:	8b 38                	mov    edi,DWORD PTR [rax]
  4021f1:	e8 8a f0 ff ff       	call   401280 <strerror@plt>
  4021f6:	bf 01 00 00 00       	mov    edi,0x1
  4021fb:	48 8d 35 a7 fe 00 00 	lea    rsi,[rip+0xfea7]        # 4120a9 <_IO_stdin_used+0xa9>
  402202:	48 89 c2             	mov    rdx,rax
  402205:	31 c0                	xor    eax,eax
  402207:	e8 24 f0 ff ff       	call   401230 <__printf_chk@plt>
  40220c:	83 cf ff             	or     edi,0xffffffff
  40220f:	e8 4c f0 ff ff       	call   401260 <exit@plt>
  402214:	48 89 e5             	mov    rbp,rsp
  402217:	48 63 d0             	movsxd rdx,eax
  40221a:	bf 01 00 00 00       	mov    edi,0x1
  40221f:	48 89 ee             	mov    rsi,rbp
  402222:	e8 79 ef ff ff       	call   4011a0 <write@plt>
  402227:	48 8d 3d 26 ff 00 00 	lea    rdi,[rip+0xff26]        # 412154 <_IO_stdin_used+0x154>
  40222e:	e8 5d ef ff ff       	call   401190 <puts@plt>
  402233:	48 8d 3d ca fd 00 00 	lea    rdi,[rip+0xfdca]        # 412004 <_IO_stdin_used+0x4>
  40223a:	31 f6                	xor    esi,esi
  40223c:	31 c0                	xor    eax,eax
  40223e:	e8 0d f0 ff ff       	call   401250 <open@plt>
  402243:	89 c7                	mov    edi,eax
  402245:	85 c0                	test   eax,eax
  402247:	79 34                	jns    40227d <win+0xd07>
  402249:	e8 32 ef ff ff       	call   401180 <__errno_location@plt>
  40224e:	8b 38                	mov    edi,DWORD PTR [rax]
  402250:	e8 2b f0 ff ff       	call   401280 <strerror@plt>
  402255:	48 8d 35 ae fd 00 00 	lea    rsi,[rip+0xfdae]        # 41200a <_IO_stdin_used+0xa>
  40225c:	bf 01 00 00 00       	mov    edi,0x1
  402261:	48 89 c2             	mov    rdx,rax
  402264:	31 c0                	xor    eax,eax
  402266:	e8 c5 ef ff ff       	call   401230 <__printf_chk@plt>
  40226b:	e8 70 ef ff ff       	call   4011e0 <geteuid@plt>
  402270:	85 c0                	test   eax,eax
  402272:	0f 84 61 f3 ff ff    	je     4015d9 <win+0x63>
  402278:	e9 44 f3 ff ff       	jmp    4015c1 <win+0x4b>
  40227d:	ba 00 01 00 00       	mov    edx,0x100
  402282:	48 89 ee             	mov    rsi,rbp
  402285:	e8 76 ef ff ff       	call   401200 <read@plt>
  40228a:	85 c0                	test   eax,eax
  40228c:	7f 2a                	jg     4022b8 <win+0xd42>
  40228e:	e8 ed ee ff ff       	call   401180 <__errno_location@plt>
  402293:	8b 38                	mov    edi,DWORD PTR [rax]
  402295:	e8 e6 ef ff ff       	call   401280 <strerror@plt>
  40229a:	bf 01 00 00 00       	mov    edi,0x1
  40229f:	48 8d 35 03 fe 00 00 	lea    rsi,[rip+0xfe03]        # 4120a9 <_IO_stdin_used+0xa9>
  4022a6:	48 89 c2             	mov    rdx,rax
  4022a9:	31 c0                	xor    eax,eax
  4022ab:	e8 80 ef ff ff       	call   401230 <__printf_chk@plt>
  4022b0:	83 cf ff             	or     edi,0xffffffff
  4022b3:	e8 a8 ef ff ff       	call   401260 <exit@plt>
  4022b8:	48 63 d0             	movsxd rdx,eax
  4022bb:	48 89 ee             	mov    rsi,rbp
  4022be:	bf 01 00 00 00       	mov    edi,0x1
  4022c3:	e8 d8 ee ff ff       	call   4011a0 <write@plt>
  4022c8:	48 8d 3d 85 fe 00 00 	lea    rdi,[rip+0xfe85]        # 412154 <_IO_stdin_used+0x154>
  4022cf:	e8 bc ee ff ff       	call   401190 <puts@plt>
  4022d4:	48 8d 3d 29 fd 00 00 	lea    rdi,[rip+0xfd29]        # 412004 <_IO_stdin_used+0x4>
  4022db:	31 f6                	xor    esi,esi
  4022dd:	31 c0                	xor    eax,eax
  4022df:	e8 6c ef ff ff       	call   401250 <open@plt>
  4022e4:	89 c7                	mov    edi,eax
  4022e6:	85 c0                	test   eax,eax
  4022e8:	79 34                	jns    40231e <win+0xda8>
  4022ea:	e8 91 ee ff ff       	call   401180 <__errno_location@plt>
  4022ef:	8b 38                	mov    edi,DWORD PTR [rax]
  4022f1:	e8 8a ef ff ff       	call   401280 <strerror@plt>
  4022f6:	48 8d 35 0d fd 00 00 	lea    rsi,[rip+0xfd0d]        # 41200a <_IO_stdin_used+0xa>
  4022fd:	bf 01 00 00 00       	mov    edi,0x1
  402302:	48 89 c2             	mov    rdx,rax
  402305:	31 c0                	xor    eax,eax
  402307:	e8 24 ef ff ff       	call   401230 <__printf_chk@plt>
  40230c:	e8 cf ee ff ff       	call   4011e0 <geteuid@plt>
  402311:	85 c0                	test   eax,eax
  402313:	0f 84 c0 f2 ff ff    	je     4015d9 <win+0x63>
  402319:	e9 a3 f2 ff ff       	jmp    4015c1 <win+0x4b>
  40231e:	ba 00 01 00 00       	mov    edx,0x100
  402323:	48 89 ee             	mov    rsi,rbp
  402326:	e8 d5 ee ff ff       	call   401200 <read@plt>
  40232b:	85 c0                	test   eax,eax
  40232d:	7f 2a                	jg     402359 <win+0xde3>
  40232f:	e8 4c ee ff ff       	call   401180 <__errno_location@plt>
  402334:	8b 38                	mov    edi,DWORD PTR [rax]
  402336:	e8 45 ef ff ff       	call   401280 <strerror@plt>
  40233b:	bf 01 00 00 00       	mov    edi,0x1
  402340:	48 8d 35 62 fd 00 00 	lea    rsi,[rip+0xfd62]        # 4120a9 <_IO_stdin_used+0xa9>
  402347:	48 89 c2             	mov    rdx,rax
  40234a:	31 c0                	xor    eax,eax
  40234c:	e8 df ee ff ff       	call   401230 <__printf_chk@plt>
  402351:	83 cf ff             	or     edi,0xffffffff
  402354:	e8 07 ef ff ff       	call   401260 <exit@plt>
  402359:	48 63 d0             	movsxd rdx,eax
  40235c:	48 89 ee             	mov    rsi,rbp
  40235f:	bf 01 00 00 00       	mov    edi,0x1
  402364:	e8 37 ee ff ff       	call   4011a0 <write@plt>
  402369:	48 8d 3d e4 fd 00 00 	lea    rdi,[rip+0xfde4]        # 412154 <_IO_stdin_used+0x154>
  402370:	e8 1b ee ff ff       	call   401190 <puts@plt>
  402375:	48 8d 3d 88 fc 00 00 	lea    rdi,[rip+0xfc88]        # 412004 <_IO_stdin_used+0x4>
  40237c:	31 f6                	xor    esi,esi
  40237e:	31 c0                	xor    eax,eax
  402380:	e8 cb ee ff ff       	call   401250 <open@plt>
  402385:	89 c7                	mov    edi,eax
  402387:	85 c0                	test   eax,eax
  402389:	79 34                	jns    4023bf <win+0xe49>
  40238b:	e8 f0 ed ff ff       	call   401180 <__errno_location@plt>
  402390:	8b 38                	mov    edi,DWORD PTR [rax]
  402392:	e8 e9 ee ff ff       	call   401280 <strerror@plt>
  402397:	48 8d 35 6c fc 00 00 	lea    rsi,[rip+0xfc6c]        # 41200a <_IO_stdin_used+0xa>
  40239e:	bf 01 00 00 00       	mov    edi,0x1
  4023a3:	48 89 c2             	mov    rdx,rax
  4023a6:	31 c0                	xor    eax,eax
  4023a8:	e8 83 ee ff ff       	call   401230 <__printf_chk@plt>
  4023ad:	e8 2e ee ff ff       	call   4011e0 <geteuid@plt>
  4023b2:	85 c0                	test   eax,eax
  4023b4:	0f 84 1f f2 ff ff    	je     4015d9 <win+0x63>
  4023ba:	e9 02 f2 ff ff       	jmp    4015c1 <win+0x4b>
  4023bf:	ba 00 01 00 00       	mov    edx,0x100
  4023c4:	48 89 ee             	mov    rsi,rbp
  4023c7:	e8 34 ee ff ff       	call   401200 <read@plt>
  4023cc:	85 c0                	test   eax,eax
  4023ce:	7f 2a                	jg     4023fa <win+0xe84>
  4023d0:	e8 ab ed ff ff       	call   401180 <__errno_location@plt>
  4023d5:	8b 38                	mov    edi,DWORD PTR [rax]
  4023d7:	e8 a4 ee ff ff       	call   401280 <strerror@plt>
  4023dc:	bf 01 00 00 00       	mov    edi,0x1
  4023e1:	48 8d 35 c1 fc 00 00 	lea    rsi,[rip+0xfcc1]        # 4120a9 <_IO_stdin_used+0xa9>
  4023e8:	48 89 c2             	mov    rdx,rax
  4023eb:	31 c0                	xor    eax,eax
  4023ed:	e8 3e ee ff ff       	call   401230 <__printf_chk@plt>
  4023f2:	83 cf ff             	or     edi,0xffffffff
  4023f5:	e8 66 ee ff ff       	call   401260 <exit@plt>
  4023fa:	48 63 d0             	movsxd rdx,eax
  4023fd:	48 89 ee             	mov    rsi,rbp
  402400:	bf 01 00 00 00       	mov    edi,0x1
  402405:	e8 96 ed ff ff       	call   4011a0 <write@plt>
  40240a:	48 8d 3d 43 fd 00 00 	lea    rdi,[rip+0xfd43]        # 412154 <_IO_stdin_used+0x154>
  402411:	e8 7a ed ff ff       	call   401190 <puts@plt>
  402416:	48 8d 3d e7 fb 00 00 	lea    rdi,[rip+0xfbe7]        # 412004 <_IO_stdin_used+0x4>
  40241d:	31 f6                	xor    esi,esi
  40241f:	31 c0                	xor    eax,eax
  402421:	e8 2a ee ff ff       	call   401250 <open@plt>
  402426:	89 c7                	mov    edi,eax
  402428:	85 c0                	test   eax,eax
  40242a:	79 34                	jns    402460 <win+0xeea>
  40242c:	e8 4f ed ff ff       	call   401180 <__errno_location@plt>
  402431:	8b 38                	mov    edi,DWORD PTR [rax]
  402433:	e8 48 ee ff ff       	call   401280 <strerror@plt>
  402438:	48 8d 35 cb fb 00 00 	lea    rsi,[rip+0xfbcb]        # 41200a <_IO_stdin_used+0xa>
  40243f:	bf 01 00 00 00       	mov    edi,0x1
  402444:	48 89 c2             	mov    rdx,rax
  402447:	31 c0                	xor    eax,eax
  402449:	e8 e2 ed ff ff       	call   401230 <__printf_chk@plt>
  40244e:	e8 8d ed ff ff       	call   4011e0 <geteuid@plt>
  402453:	85 c0                	test   eax,eax
  402455:	0f 84 7e f1 ff ff    	je     4015d9 <win+0x63>
  40245b:	e9 61 f1 ff ff       	jmp    4015c1 <win+0x4b>
  402460:	ba 00 01 00 00       	mov    edx,0x100
  402465:	48 89 ee             	mov    rsi,rbp
  402468:	e8 93 ed ff ff       	call   401200 <read@plt>
  40246d:	85 c0                	test   eax,eax
  40246f:	7f 2a                	jg     40249b <win+0xf25>
  402471:	e8 0a ed ff ff       	call   401180 <__errno_location@plt>
  402476:	8b 38                	mov    edi,DWORD PTR [rax]
  402478:	e8 03 ee ff ff       	call   401280 <strerror@plt>
  40247d:	bf 01 00 00 00       	mov    edi,0x1
  402482:	48 8d 35 20 fc 00 00 	lea    rsi,[rip+0xfc20]        # 4120a9 <_IO_stdin_used+0xa9>
  402489:	48 89 c2             	mov    rdx,rax
  40248c:	31 c0                	xor    eax,eax
  40248e:	e8 9d ed ff ff       	call   401230 <__printf_chk@plt>
  402493:	83 cf ff             	or     edi,0xffffffff
  402496:	e8 c5 ed ff ff       	call   401260 <exit@plt>
  40249b:	48 63 d0             	movsxd rdx,eax
  40249e:	48 89 ee             	mov    rsi,rbp
  4024a1:	bf 01 00 00 00       	mov    edi,0x1
  4024a6:	e8 f5 ec ff ff       	call   4011a0 <write@plt>
  4024ab:	48 8d 3d a2 fc 00 00 	lea    rdi,[rip+0xfca2]        # 412154 <_IO_stdin_used+0x154>
  4024b2:	e8 d9 ec ff ff       	call   401190 <puts@plt>
  4024b7:	48 8d 3d 46 fb 00 00 	lea    rdi,[rip+0xfb46]        # 412004 <_IO_stdin_used+0x4>
  4024be:	31 f6                	xor    esi,esi
  4024c0:	31 c0                	xor    eax,eax
  4024c2:	e8 89 ed ff ff       	call   401250 <open@plt>
  4024c7:	89 c7                	mov    edi,eax
  4024c9:	85 c0                	test   eax,eax
  4024cb:	79 34                	jns    402501 <win+0xf8b>
  4024cd:	e8 ae ec ff ff       	call   401180 <__errno_location@plt>
  4024d2:	8b 38                	mov    edi,DWORD PTR [rax]
  4024d4:	e8 a7 ed ff ff       	call   401280 <strerror@plt>
  4024d9:	48 8d 35 2a fb 00 00 	lea    rsi,[rip+0xfb2a]        # 41200a <_IO_stdin_used+0xa>
  4024e0:	bf 01 00 00 00       	mov    edi,0x1
  4024e5:	48 89 c2             	mov    rdx,rax
  4024e8:	31 c0                	xor    eax,eax
  4024ea:	e8 41 ed ff ff       	call   401230 <__printf_chk@plt>
  4024ef:	e8 ec ec ff ff       	call   4011e0 <geteuid@plt>
  4024f4:	85 c0                	test   eax,eax
  4024f6:	0f 84 dd f0 ff ff    	je     4015d9 <win+0x63>
  4024fc:	e9 c0 f0 ff ff       	jmp    4015c1 <win+0x4b>
  402501:	ba 00 01 00 00       	mov    edx,0x100
  402506:	48 89 ee             	mov    rsi,rbp
  402509:	e8 f2 ec ff ff       	call   401200 <read@plt>
  40250e:	85 c0                	test   eax,eax
  402510:	7f 2a                	jg     40253c <win+0xfc6>
  402512:	e8 69 ec ff ff       	call   401180 <__errno_location@plt>
  402517:	8b 38                	mov    edi,DWORD PTR [rax]
  402519:	e8 62 ed ff ff       	call   401280 <strerror@plt>
  40251e:	bf 01 00 00 00       	mov    edi,0x1
  402523:	48 8d 35 7f fb 00 00 	lea    rsi,[rip+0xfb7f]        # 4120a9 <_IO_stdin_used+0xa9>
  40252a:	48 89 c2             	mov    rdx,rax
  40252d:	31 c0                	xor    eax,eax
  40252f:	e8 fc ec ff ff       	call   401230 <__printf_chk@plt>
  402534:	83 cf ff             	or     edi,0xffffffff
  402537:	e8 24 ed ff ff       	call   401260 <exit@plt>
  40253c:	48 63 d0             	movsxd rdx,eax
  40253f:	48 89 ee             	mov    rsi,rbp
  402542:	bf 01 00 00 00       	mov    edi,0x1
  402547:	e8 54 ec ff ff       	call   4011a0 <write@plt>
  40254c:	48 8d 3d 01 fc 00 00 	lea    rdi,[rip+0xfc01]        # 412154 <_IO_stdin_used+0x154>
  402553:	e8 38 ec ff ff       	call   401190 <puts@plt>
  402558:	48 8d 3d a5 fa 00 00 	lea    rdi,[rip+0xfaa5]        # 412004 <_IO_stdin_used+0x4>
  40255f:	31 f6                	xor    esi,esi
  402561:	31 c0                	xor    eax,eax
  402563:	e8 e8 ec ff ff       	call   401250 <open@plt>
  402568:	89 c7                	mov    edi,eax
  40256a:	85 c0                	test   eax,eax
  40256c:	79 34                	jns    4025a2 <win+0x102c>
  40256e:	e8 0d ec ff ff       	call   401180 <__errno_location@plt>
  402573:	8b 38                	mov    edi,DWORD PTR [rax]
  402575:	e8 06 ed ff ff       	call   401280 <strerror@plt>
  40257a:	48 8d 35 89 fa 00 00 	lea    rsi,[rip+0xfa89]        # 41200a <_IO_stdin_used+0xa>
  402581:	bf 01 00 00 00       	mov    edi,0x1
  402586:	48 89 c2             	mov    rdx,rax
  402589:	31 c0                	xor    eax,eax
  40258b:	e8 a0 ec ff ff       	call   401230 <__printf_chk@plt>
  402590:	e8 4b ec ff ff       	call   4011e0 <geteuid@plt>
  402595:	85 c0                	test   eax,eax
  402597:	0f 84 3c f0 ff ff    	je     4015d9 <win+0x63>
  40259d:	e9 1f f0 ff ff       	jmp    4015c1 <win+0x4b>
  4025a2:	ba 00 01 00 00       	mov    edx,0x100
  4025a7:	48 89 ee             	mov    rsi,rbp
  4025aa:	e8 51 ec ff ff       	call   401200 <read@plt>
  4025af:	85 c0                	test   eax,eax
  4025b1:	7f 2a                	jg     4025dd <win+0x1067>
  4025b3:	e8 c8 eb ff ff       	call   401180 <__errno_location@plt>
  4025b8:	8b 38                	mov    edi,DWORD PTR [rax]
  4025ba:	e8 c1 ec ff ff       	call   401280 <strerror@plt>
  4025bf:	bf 01 00 00 00       	mov    edi,0x1
  4025c4:	48 8d 35 de fa 00 00 	lea    rsi,[rip+0xfade]        # 4120a9 <_IO_stdin_used+0xa9>
  4025cb:	48 89 c2             	mov    rdx,rax
  4025ce:	31 c0                	xor    eax,eax
  4025d0:	e8 5b ec ff ff       	call   401230 <__printf_chk@plt>
  4025d5:	83 cf ff             	or     edi,0xffffffff
  4025d8:	e8 83 ec ff ff       	call   401260 <exit@plt>
  4025dd:	48 63 d0             	movsxd rdx,eax
  4025e0:	48 89 ee             	mov    rsi,rbp
  4025e3:	bf 01 00 00 00       	mov    edi,0x1
  4025e8:	e8 b3 eb ff ff       	call   4011a0 <write@plt>
  4025ed:	48 8d 3d 60 fb 00 00 	lea    rdi,[rip+0xfb60]        # 412154 <_IO_stdin_used+0x154>
  4025f4:	e8 97 eb ff ff       	call   401190 <puts@plt>
  4025f9:	48 8d 3d 04 fa 00 00 	lea    rdi,[rip+0xfa04]        # 412004 <_IO_stdin_used+0x4>
  402600:	31 f6                	xor    esi,esi
  402602:	31 c0                	xor    eax,eax
  402604:	e8 47 ec ff ff       	call   401250 <open@plt>
  402609:	89 c7                	mov    edi,eax
  40260b:	85 c0                	test   eax,eax
  40260d:	79 34                	jns    402643 <win+0x10cd>
  40260f:	e8 6c eb ff ff       	call   401180 <__errno_location@plt>
  402614:	8b 38                	mov    edi,DWORD PTR [rax]
  402616:	e8 65 ec ff ff       	call   401280 <strerror@plt>
  40261b:	48 8d 35 e8 f9 00 00 	lea    rsi,[rip+0xf9e8]        # 41200a <_IO_stdin_used+0xa>
  402622:	bf 01 00 00 00       	mov    edi,0x1
  402627:	48 89 c2             	mov    rdx,rax
  40262a:	31 c0                	xor    eax,eax
  40262c:	e8 ff eb ff ff       	call   401230 <__printf_chk@plt>
  402631:	e8 aa eb ff ff       	call   4011e0 <geteuid@plt>
  402636:	85 c0                	test   eax,eax
  402638:	0f 84 9b ef ff ff    	je     4015d9 <win+0x63>
  40263e:	e9 7e ef ff ff       	jmp    4015c1 <win+0x4b>
  402643:	ba 00 01 00 00       	mov    edx,0x100
  402648:	48 89 ee             	mov    rsi,rbp
  40264b:	e8 b0 eb ff ff       	call   401200 <read@plt>
  402650:	85 c0                	test   eax,eax
  402652:	7f 2a                	jg     40267e <win+0x1108>
  402654:	e8 27 eb ff ff       	call   401180 <__errno_location@plt>
  402659:	8b 38                	mov    edi,DWORD PTR [rax]
  40265b:	e8 20 ec ff ff       	call   401280 <strerror@plt>
  402660:	bf 01 00 00 00       	mov    edi,0x1
  402665:	48 8d 35 3d fa 00 00 	lea    rsi,[rip+0xfa3d]        # 4120a9 <_IO_stdin_used+0xa9>
  40266c:	48 89 c2             	mov    rdx,rax
  40266f:	31 c0                	xor    eax,eax
  402671:	e8 ba eb ff ff       	call   401230 <__printf_chk@plt>
  402676:	83 cf ff             	or     edi,0xffffffff
  402679:	e8 e2 eb ff ff       	call   401260 <exit@plt>
  40267e:	48 63 d0             	movsxd rdx,eax
  402681:	48 89 ee             	mov    rsi,rbp
  402684:	bf 01 00 00 00       	mov    edi,0x1
  402689:	e8 12 eb ff ff       	call   4011a0 <write@plt>
  40268e:	48 8d 3d bf fa 00 00 	lea    rdi,[rip+0xfabf]        # 412154 <_IO_stdin_used+0x154>
  402695:	e8 f6 ea ff ff       	call   401190 <puts@plt>
  40269a:	48 8d 3d 63 f9 00 00 	lea    rdi,[rip+0xf963]        # 412004 <_IO_stdin_used+0x4>
  4026a1:	31 f6                	xor    esi,esi
  4026a3:	31 c0                	xor    eax,eax
  4026a5:	e8 a6 eb ff ff       	call   401250 <open@plt>
  4026aa:	89 c7                	mov    edi,eax
  4026ac:	85 c0                	test   eax,eax
  4026ae:	79 34                	jns    4026e4 <win+0x116e>
  4026b0:	e8 cb ea ff ff       	call   401180 <__errno_location@plt>
  4026b5:	8b 38                	mov    edi,DWORD PTR [rax]
  4026b7:	e8 c4 eb ff ff       	call   401280 <strerror@plt>
  4026bc:	48 8d 35 47 f9 00 00 	lea    rsi,[rip+0xf947]        # 41200a <_IO_stdin_used+0xa>
  4026c3:	bf 01 00 00 00       	mov    edi,0x1
  4026c8:	48 89 c2             	mov    rdx,rax
  4026cb:	31 c0                	xor    eax,eax
  4026cd:	e8 5e eb ff ff       	call   401230 <__printf_chk@plt>
  4026d2:	e8 09 eb ff ff       	call   4011e0 <geteuid@plt>
  4026d7:	85 c0                	test   eax,eax
  4026d9:	0f 84 fa ee ff ff    	je     4015d9 <win+0x63>
  4026df:	e9 dd ee ff ff       	jmp    4015c1 <win+0x4b>
  4026e4:	ba 00 01 00 00       	mov    edx,0x100
  4026e9:	48 89 ee             	mov    rsi,rbp
  4026ec:	e8 0f eb ff ff       	call   401200 <read@plt>
  4026f1:	85 c0                	test   eax,eax
  4026f3:	7f 2a                	jg     40271f <win+0x11a9>
  4026f5:	e8 86 ea ff ff       	call   401180 <__errno_location@plt>
  4026fa:	8b 38                	mov    edi,DWORD PTR [rax]
  4026fc:	e8 7f eb ff ff       	call   401280 <strerror@plt>
  402701:	bf 01 00 00 00       	mov    edi,0x1
  402706:	48 8d 35 9c f9 00 00 	lea    rsi,[rip+0xf99c]        # 4120a9 <_IO_stdin_used+0xa9>
  40270d:	48 89 c2             	mov    rdx,rax
  402710:	31 c0                	xor    eax,eax
  402712:	e8 19 eb ff ff       	call   401230 <__printf_chk@plt>
  402717:	83 cf ff             	or     edi,0xffffffff
  40271a:	e8 41 eb ff ff       	call   401260 <exit@plt>
  40271f:	48 63 d0             	movsxd rdx,eax
  402722:	48 89 ee             	mov    rsi,rbp
  402725:	bf 01 00 00 00       	mov    edi,0x1
  40272a:	e8 71 ea ff ff       	call   4011a0 <write@plt>
  40272f:	48 8d 3d 1e fa 00 00 	lea    rdi,[rip+0xfa1e]        # 412154 <_IO_stdin_used+0x154>
  402736:	e8 55 ea ff ff       	call   401190 <puts@plt>
  40273b:	48 8d 3d c2 f8 00 00 	lea    rdi,[rip+0xf8c2]        # 412004 <_IO_stdin_used+0x4>
  402742:	31 f6                	xor    esi,esi
  402744:	31 c0                	xor    eax,eax
  402746:	e8 05 eb ff ff       	call   401250 <open@plt>
  40274b:	89 c7                	mov    edi,eax
  40274d:	85 c0                	test   eax,eax
  40274f:	79 34                	jns    402785 <win+0x120f>
  402751:	e8 2a ea ff ff       	call   401180 <__errno_location@plt>
  402756:	8b 38                	mov    edi,DWORD PTR [rax]
  402758:	e8 23 eb ff ff       	call   401280 <strerror@plt>
  40275d:	48 8d 35 a6 f8 00 00 	lea    rsi,[rip+0xf8a6]        # 41200a <_IO_stdin_used+0xa>
  402764:	bf 01 00 00 00       	mov    edi,0x1
  402769:	48 89 c2             	mov    rdx,rax
  40276c:	31 c0                	xor    eax,eax
  40276e:	e8 bd ea ff ff       	call   401230 <__printf_chk@plt>
  402773:	e8 68 ea ff ff       	call   4011e0 <geteuid@plt>
  402778:	85 c0                	test   eax,eax
  40277a:	0f 84 59 ee ff ff    	je     4015d9 <win+0x63>
  402780:	e9 3c ee ff ff       	jmp    4015c1 <win+0x4b>
  402785:	ba 00 01 00 00       	mov    edx,0x100
  40278a:	48 89 ee             	mov    rsi,rbp
  40278d:	e8 6e ea ff ff       	call   401200 <read@plt>
  402792:	85 c0                	test   eax,eax
  402794:	7f 2a                	jg     4027c0 <win+0x124a>
  402796:	e8 e5 e9 ff ff       	call   401180 <__errno_location@plt>
  40279b:	8b 38                	mov    edi,DWORD PTR [rax]
  40279d:	e8 de ea ff ff       	call   401280 <strerror@plt>
  4027a2:	bf 01 00 00 00       	mov    edi,0x1
  4027a7:	48 8d 35 fb f8 00 00 	lea    rsi,[rip+0xf8fb]        # 4120a9 <_IO_stdin_used+0xa9>
  4027ae:	48 89 c2             	mov    rdx,rax
  4027b1:	31 c0                	xor    eax,eax
  4027b3:	e8 78 ea ff ff       	call   401230 <__printf_chk@plt>
  4027b8:	83 cf ff             	or     edi,0xffffffff
  4027bb:	e8 a0 ea ff ff       	call   401260 <exit@plt>
  4027c0:	48 63 d0             	movsxd rdx,eax
  4027c3:	48 89 ee             	mov    rsi,rbp
  4027c6:	bf 01 00 00 00       	mov    edi,0x1
  4027cb:	e8 d0 e9 ff ff       	call   4011a0 <write@plt>
  4027d0:	48 8d 3d 7d f9 00 00 	lea    rdi,[rip+0xf97d]        # 412154 <_IO_stdin_used+0x154>
  4027d7:	e8 b4 e9 ff ff       	call   401190 <puts@plt>
  4027dc:	48 8d 3d 21 f8 00 00 	lea    rdi,[rip+0xf821]        # 412004 <_IO_stdin_used+0x4>
  4027e3:	31 f6                	xor    esi,esi
  4027e5:	31 c0                	xor    eax,eax
  4027e7:	e8 64 ea ff ff       	call   401250 <open@plt>
  4027ec:	89 c7                	mov    edi,eax
  4027ee:	85 c0                	test   eax,eax
  4027f0:	79 34                	jns    402826 <win+0x12b0>
  4027f2:	e8 89 e9 ff ff       	call   401180 <__errno_location@plt>
  4027f7:	8b 38                	mov    edi,DWORD PTR [rax]
  4027f9:	e8 82 ea ff ff       	call   401280 <strerror@plt>
  4027fe:	48 8d 35 05 f8 00 00 	lea    rsi,[rip+0xf805]        # 41200a <_IO_stdin_used+0xa>
  402805:	bf 01 00 00 00       	mov    edi,0x1
  40280a:	48 89 c2             	mov    rdx,rax
  40280d:	31 c0                	xor    eax,eax
  40280f:	e8 1c ea ff ff       	call   401230 <__printf_chk@plt>
  402814:	e8 c7 e9 ff ff       	call   4011e0 <geteuid@plt>
  402819:	85 c0                	test   eax,eax
  40281b:	0f 84 b8 ed ff ff    	je     4015d9 <win+0x63>
  402821:	e9 9b ed ff ff       	jmp    4015c1 <win+0x4b>
  402826:	ba 00 01 00 00       	mov    edx,0x100
  40282b:	48 89 ee             	mov    rsi,rbp
  40282e:	e8 cd e9 ff ff       	call   401200 <read@plt>
  402833:	85 c0                	test   eax,eax
  402835:	7f 2a                	jg     402861 <win+0x12eb>
  402837:	e8 44 e9 ff ff       	call   401180 <__errno_location@plt>
  40283c:	8b 38                	mov    edi,DWORD PTR [rax]
  40283e:	e8 3d ea ff ff       	call   401280 <strerror@plt>
  402843:	bf 01 00 00 00       	mov    edi,0x1
  402848:	48 8d 35 5a f8 00 00 	lea    rsi,[rip+0xf85a]        # 4120a9 <_IO_stdin_used+0xa9>
  40284f:	48 89 c2             	mov    rdx,rax
  402852:	31 c0                	xor    eax,eax
  402854:	e8 d7 e9 ff ff       	call   401230 <__printf_chk@plt>
  402859:	83 cf ff             	or     edi,0xffffffff
  40285c:	e8 ff e9 ff ff       	call   401260 <exit@plt>
  402861:	48 63 d0             	movsxd rdx,eax
  402864:	48 89 ee             	mov    rsi,rbp
  402867:	bf 01 00 00 00       	mov    edi,0x1
  40286c:	e8 2f e9 ff ff       	call   4011a0 <write@plt>
  402871:	48 8d 3d dc f8 00 00 	lea    rdi,[rip+0xf8dc]        # 412154 <_IO_stdin_used+0x154>
  402878:	e8 13 e9 ff ff       	call   401190 <puts@plt>
  40287d:	48 8d 3d 80 f7 00 00 	lea    rdi,[rip+0xf780]        # 412004 <_IO_stdin_used+0x4>
  402884:	31 f6                	xor    esi,esi
  402886:	31 c0                	xor    eax,eax
  402888:	e8 c3 e9 ff ff       	call   401250 <open@plt>
  40288d:	89 c7                	mov    edi,eax
  40288f:	85 c0                	test   eax,eax
  402891:	79 34                	jns    4028c7 <win+0x1351>
  402893:	e8 e8 e8 ff ff       	call   401180 <__errno_location@plt>
  402898:	8b 38                	mov    edi,DWORD PTR [rax]
  40289a:	e8 e1 e9 ff ff       	call   401280 <strerror@plt>
  40289f:	48 8d 35 64 f7 00 00 	lea    rsi,[rip+0xf764]        # 41200a <_IO_stdin_used+0xa>
  4028a6:	bf 01 00 00 00       	mov    edi,0x1
  4028ab:	48 89 c2             	mov    rdx,rax
  4028ae:	31 c0                	xor    eax,eax
  4028b0:	e8 7b e9 ff ff       	call   401230 <__printf_chk@plt>
  4028b5:	e8 26 e9 ff ff       	call   4011e0 <geteuid@plt>
  4028ba:	85 c0                	test   eax,eax
  4028bc:	0f 84 17 ed ff ff    	je     4015d9 <win+0x63>
  4028c2:	e9 fa ec ff ff       	jmp    4015c1 <win+0x4b>
  4028c7:	ba 00 01 00 00       	mov    edx,0x100
  4028cc:	48 89 ee             	mov    rsi,rbp
  4028cf:	e8 2c e9 ff ff       	call   401200 <read@plt>
  4028d4:	85 c0                	test   eax,eax
  4028d6:	7f 2a                	jg     402902 <win+0x138c>
  4028d8:	e8 a3 e8 ff ff       	call   401180 <__errno_location@plt>
  4028dd:	8b 38                	mov    edi,DWORD PTR [rax]
  4028df:	e8 9c e9 ff ff       	call   401280 <strerror@plt>
  4028e4:	bf 01 00 00 00       	mov    edi,0x1
  4028e9:	48 8d 35 b9 f7 00 00 	lea    rsi,[rip+0xf7b9]        # 4120a9 <_IO_stdin_used+0xa9>
  4028f0:	48 89 c2             	mov    rdx,rax
  4028f3:	31 c0                	xor    eax,eax
  4028f5:	e8 36 e9 ff ff       	call   401230 <__printf_chk@plt>
  4028fa:	83 cf ff             	or     edi,0xffffffff
  4028fd:	e8 5e e9 ff ff       	call   401260 <exit@plt>
  402902:	48 63 d0             	movsxd rdx,eax
  402905:	48 89 ee             	mov    rsi,rbp
  402908:	bf 01 00 00 00       	mov    edi,0x1
  40290d:	e8 8e e8 ff ff       	call   4011a0 <write@plt>
  402912:	48 8d 3d 3b f8 00 00 	lea    rdi,[rip+0xf83b]        # 412154 <_IO_stdin_used+0x154>
  402919:	e8 72 e8 ff ff       	call   401190 <puts@plt>
  40291e:	48 8d 3d df f6 00 00 	lea    rdi,[rip+0xf6df]        # 412004 <_IO_stdin_used+0x4>
  402925:	31 f6                	xor    esi,esi
  402927:	31 c0                	xor    eax,eax
  402929:	e8 22 e9 ff ff       	call   401250 <open@plt>
  40292e:	89 c7                	mov    edi,eax
  402930:	85 c0                	test   eax,eax
  402932:	79 34                	jns    402968 <win+0x13f2>
  402934:	e8 47 e8 ff ff       	call   401180 <__errno_location@plt>
  402939:	8b 38                	mov    edi,DWORD PTR [rax]
  40293b:	e8 40 e9 ff ff       	call   401280 <strerror@plt>
  402940:	48 8d 35 c3 f6 00 00 	lea    rsi,[rip+0xf6c3]        # 41200a <_IO_stdin_used+0xa>
  402947:	bf 01 00 00 00       	mov    edi,0x1
  40294c:	48 89 c2             	mov    rdx,rax
  40294f:	31 c0                	xor    eax,eax
  402951:	e8 da e8 ff ff       	call   401230 <__printf_chk@plt>
  402956:	e8 85 e8 ff ff       	call   4011e0 <geteuid@plt>
  40295b:	85 c0                	test   eax,eax
  40295d:	0f 84 76 ec ff ff    	je     4015d9 <win+0x63>
  402963:	e9 59 ec ff ff       	jmp    4015c1 <win+0x4b>
  402968:	ba 00 01 00 00       	mov    edx,0x100
  40296d:	48 89 ee             	mov    rsi,rbp
  402970:	e8 8b e8 ff ff       	call   401200 <read@plt>
  402975:	85 c0                	test   eax,eax
  402977:	7f 2a                	jg     4029a3 <win+0x142d>
  402979:	e8 02 e8 ff ff       	call   401180 <__errno_location@plt>
  40297e:	8b 38                	mov    edi,DWORD PTR [rax]
  402980:	e8 fb e8 ff ff       	call   401280 <strerror@plt>
  402985:	bf 01 00 00 00       	mov    edi,0x1
  40298a:	48 8d 35 18 f7 00 00 	lea    rsi,[rip+0xf718]        # 4120a9 <_IO_stdin_used+0xa9>
  402991:	48 89 c2             	mov    rdx,rax
  402994:	31 c0                	xor    eax,eax
  402996:	e8 95 e8 ff ff       	call   401230 <__printf_chk@plt>
  40299b:	83 cf ff             	or     edi,0xffffffff
  40299e:	e8 bd e8 ff ff       	call   401260 <exit@plt>
  4029a3:	48 63 d0             	movsxd rdx,eax
  4029a6:	48 89 ee             	mov    rsi,rbp
  4029a9:	bf 01 00 00 00       	mov    edi,0x1
  4029ae:	e8 ed e7 ff ff       	call   4011a0 <write@plt>
  4029b3:	48 8d 3d 9a f7 00 00 	lea    rdi,[rip+0xf79a]        # 412154 <_IO_stdin_used+0x154>
  4029ba:	e8 d1 e7 ff ff       	call   401190 <puts@plt>
  4029bf:	48 8d 3d 3e f6 00 00 	lea    rdi,[rip+0xf63e]        # 412004 <_IO_stdin_used+0x4>
  4029c6:	31 f6                	xor    esi,esi
  4029c8:	31 c0                	xor    eax,eax
  4029ca:	e8 81 e8 ff ff       	call   401250 <open@plt>
  4029cf:	89 c7                	mov    edi,eax
  4029d1:	85 c0                	test   eax,eax
  4029d3:	79 34                	jns    402a09 <win+0x1493>
  4029d5:	e8 a6 e7 ff ff       	call   401180 <__errno_location@plt>
  4029da:	8b 38                	mov    edi,DWORD PTR [rax]
  4029dc:	e8 9f e8 ff ff       	call   401280 <strerror@plt>
  4029e1:	48 8d 35 22 f6 00 00 	lea    rsi,[rip+0xf622]        # 41200a <_IO_stdin_used+0xa>
  4029e8:	bf 01 00 00 00       	mov    edi,0x1
  4029ed:	48 89 c2             	mov    rdx,rax
  4029f0:	31 c0                	xor    eax,eax
  4029f2:	e8 39 e8 ff ff       	call   401230 <__printf_chk@plt>
  4029f7:	e8 e4 e7 ff ff       	call   4011e0 <geteuid@plt>
  4029fc:	85 c0                	test   eax,eax
  4029fe:	0f 84 d5 eb ff ff    	je     4015d9 <win+0x63>
  402a04:	e9 b8 eb ff ff       	jmp    4015c1 <win+0x4b>
  402a09:	ba 00 01 00 00       	mov    edx,0x100
  402a0e:	48 89 ee             	mov    rsi,rbp
  402a11:	e8 ea e7 ff ff       	call   401200 <read@plt>
  402a16:	85 c0                	test   eax,eax
  402a18:	7f 2a                	jg     402a44 <win+0x14ce>
  402a1a:	e8 61 e7 ff ff       	call   401180 <__errno_location@plt>
  402a1f:	8b 38                	mov    edi,DWORD PTR [rax]
  402a21:	e8 5a e8 ff ff       	call   401280 <strerror@plt>
  402a26:	bf 01 00 00 00       	mov    edi,0x1
  402a2b:	48 8d 35 77 f6 00 00 	lea    rsi,[rip+0xf677]        # 4120a9 <_IO_stdin_used+0xa9>
  402a32:	48 89 c2             	mov    rdx,rax
  402a35:	31 c0                	xor    eax,eax
  402a37:	e8 f4 e7 ff ff       	call   401230 <__printf_chk@plt>
  402a3c:	83 cf ff             	or     edi,0xffffffff
  402a3f:	e8 1c e8 ff ff       	call   401260 <exit@plt>
  402a44:	48 63 d0             	movsxd rdx,eax
  402a47:	48 89 ee             	mov    rsi,rbp
  402a4a:	bf 01 00 00 00       	mov    edi,0x1
  402a4f:	e8 4c e7 ff ff       	call   4011a0 <write@plt>
  402a54:	48 8d 3d f9 f6 00 00 	lea    rdi,[rip+0xf6f9]        # 412154 <_IO_stdin_used+0x154>
  402a5b:	e8 30 e7 ff ff       	call   401190 <puts@plt>
  402a60:	48 8d 3d 9d f5 00 00 	lea    rdi,[rip+0xf59d]        # 412004 <_IO_stdin_used+0x4>
  402a67:	31 f6                	xor    esi,esi
  402a69:	31 c0                	xor    eax,eax
  402a6b:	e8 e0 e7 ff ff       	call   401250 <open@plt>
  402a70:	89 c7                	mov    edi,eax
  402a72:	85 c0                	test   eax,eax
  402a74:	79 34                	jns    402aaa <win+0x1534>
  402a76:	e8 05 e7 ff ff       	call   401180 <__errno_location@plt>
  402a7b:	8b 38                	mov    edi,DWORD PTR [rax]
  402a7d:	e8 fe e7 ff ff       	call   401280 <strerror@plt>
  402a82:	48 8d 35 81 f5 00 00 	lea    rsi,[rip+0xf581]        # 41200a <_IO_stdin_used+0xa>
  402a89:	bf 01 00 00 00       	mov    edi,0x1
  402a8e:	48 89 c2             	mov    rdx,rax
  402a91:	31 c0                	xor    eax,eax
  402a93:	e8 98 e7 ff ff       	call   401230 <__printf_chk@plt>
  402a98:	e8 43 e7 ff ff       	call   4011e0 <geteuid@plt>
  402a9d:	85 c0                	test   eax,eax
  402a9f:	0f 84 34 eb ff ff    	je     4015d9 <win+0x63>
  402aa5:	e9 17 eb ff ff       	jmp    4015c1 <win+0x4b>
  402aaa:	ba 00 01 00 00       	mov    edx,0x100
  402aaf:	48 89 ee             	mov    rsi,rbp
  402ab2:	e8 49 e7 ff ff       	call   401200 <read@plt>
  402ab7:	85 c0                	test   eax,eax
  402ab9:	7f 2a                	jg     402ae5 <win+0x156f>
  402abb:	e8 c0 e6 ff ff       	call   401180 <__errno_location@plt>
  402ac0:	8b 38                	mov    edi,DWORD PTR [rax]
  402ac2:	e8 b9 e7 ff ff       	call   401280 <strerror@plt>
  402ac7:	bf 01 00 00 00       	mov    edi,0x1
  402acc:	48 8d 35 d6 f5 00 00 	lea    rsi,[rip+0xf5d6]        # 4120a9 <_IO_stdin_used+0xa9>
  402ad3:	48 89 c2             	mov    rdx,rax
  402ad6:	31 c0                	xor    eax,eax
  402ad8:	e8 53 e7 ff ff       	call   401230 <__printf_chk@plt>
  402add:	83 cf ff             	or     edi,0xffffffff
  402ae0:	e8 7b e7 ff ff       	call   401260 <exit@plt>
  402ae5:	48 63 d0             	movsxd rdx,eax
  402ae8:	48 89 ee             	mov    rsi,rbp
  402aeb:	bf 01 00 00 00       	mov    edi,0x1
  402af0:	e8 ab e6 ff ff       	call   4011a0 <write@plt>
  402af5:	48 8d 3d 58 f6 00 00 	lea    rdi,[rip+0xf658]        # 412154 <_IO_stdin_used+0x154>
  402afc:	e8 8f e6 ff ff       	call   401190 <puts@plt>
  402b01:	48 8d 3d fc f4 00 00 	lea    rdi,[rip+0xf4fc]        # 412004 <_IO_stdin_used+0x4>
  402b08:	31 f6                	xor    esi,esi
  402b0a:	31 c0                	xor    eax,eax
  402b0c:	e8 3f e7 ff ff       	call   401250 <open@plt>
  402b11:	89 c7                	mov    edi,eax
  402b13:	85 c0                	test   eax,eax
  402b15:	79 34                	jns    402b4b <win+0x15d5>
  402b17:	e8 64 e6 ff ff       	call   401180 <__errno_location@plt>
  402b1c:	8b 38                	mov    edi,DWORD PTR [rax]
  402b1e:	e8 5d e7 ff ff       	call   401280 <strerror@plt>
  402b23:	48 8d 35 e0 f4 00 00 	lea    rsi,[rip+0xf4e0]        # 41200a <_IO_stdin_used+0xa>
  402b2a:	bf 01 00 00 00       	mov    edi,0x1
  402b2f:	48 89 c2             	mov    rdx,rax
  402b32:	31 c0                	xor    eax,eax
  402b34:	e8 f7 e6 ff ff       	call   401230 <__printf_chk@plt>
  402b39:	e8 a2 e6 ff ff       	call   4011e0 <geteuid@plt>
  402b3e:	85 c0                	test   eax,eax
  402b40:	0f 84 93 ea ff ff    	je     4015d9 <win+0x63>
  402b46:	e9 76 ea ff ff       	jmp    4015c1 <win+0x4b>
  402b4b:	ba 00 01 00 00       	mov    edx,0x100
  402b50:	48 89 ee             	mov    rsi,rbp
  402b53:	e8 a8 e6 ff ff       	call   401200 <read@plt>
  402b58:	85 c0                	test   eax,eax
  402b5a:	7f 2a                	jg     402b86 <win+0x1610>
  402b5c:	e8 1f e6 ff ff       	call   401180 <__errno_location@plt>
  402b61:	8b 38                	mov    edi,DWORD PTR [rax]
  402b63:	e8 18 e7 ff ff       	call   401280 <strerror@plt>
  402b68:	bf 01 00 00 00       	mov    edi,0x1
  402b6d:	48 8d 35 35 f5 00 00 	lea    rsi,[rip+0xf535]        # 4120a9 <_IO_stdin_used+0xa9>
  402b74:	48 89 c2             	mov    rdx,rax
  402b77:	31 c0                	xor    eax,eax
  402b79:	e8 b2 e6 ff ff       	call   401230 <__printf_chk@plt>
  402b7e:	83 cf ff             	or     edi,0xffffffff
  402b81:	e8 da e6 ff ff       	call   401260 <exit@plt>
  402b86:	48 63 d0             	movsxd rdx,eax
  402b89:	48 89 ee             	mov    rsi,rbp
  402b8c:	bf 01 00 00 00       	mov    edi,0x1
  402b91:	e8 0a e6 ff ff       	call   4011a0 <write@plt>
  402b96:	48 8d 3d b7 f5 00 00 	lea    rdi,[rip+0xf5b7]        # 412154 <_IO_stdin_used+0x154>
  402b9d:	e8 ee e5 ff ff       	call   401190 <puts@plt>
  402ba2:	48 8d 3d 5b f4 00 00 	lea    rdi,[rip+0xf45b]        # 412004 <_IO_stdin_used+0x4>
  402ba9:	31 f6                	xor    esi,esi
  402bab:	31 c0                	xor    eax,eax
  402bad:	e8 9e e6 ff ff       	call   401250 <open@plt>
  402bb2:	89 c7                	mov    edi,eax
  402bb4:	85 c0                	test   eax,eax
  402bb6:	79 34                	jns    402bec <win+0x1676>
  402bb8:	e8 c3 e5 ff ff       	call   401180 <__errno_location@plt>
  402bbd:	8b 38                	mov    edi,DWORD PTR [rax]
  402bbf:	e8 bc e6 ff ff       	call   401280 <strerror@plt>
  402bc4:	48 8d 35 3f f4 00 00 	lea    rsi,[rip+0xf43f]        # 41200a <_IO_stdin_used+0xa>
  402bcb:	bf 01 00 00 00       	mov    edi,0x1
  402bd0:	48 89 c2             	mov    rdx,rax
  402bd3:	31 c0                	xor    eax,eax
  402bd5:	e8 56 e6 ff ff       	call   401230 <__printf_chk@plt>
  402bda:	e8 01 e6 ff ff       	call   4011e0 <geteuid@plt>
  402bdf:	85 c0                	test   eax,eax
  402be1:	0f 84 f2 e9 ff ff    	je     4015d9 <win+0x63>
  402be7:	e9 d5 e9 ff ff       	jmp    4015c1 <win+0x4b>
  402bec:	ba 00 01 00 00       	mov    edx,0x100
  402bf1:	48 89 ee             	mov    rsi,rbp
  402bf4:	e8 07 e6 ff ff       	call   401200 <read@plt>
  402bf9:	85 c0                	test   eax,eax
  402bfb:	7f 2a                	jg     402c27 <win+0x16b1>
  402bfd:	e8 7e e5 ff ff       	call   401180 <__errno_location@plt>
  402c02:	8b 38                	mov    edi,DWORD PTR [rax]
  402c04:	e8 77 e6 ff ff       	call   401280 <strerror@plt>
  402c09:	bf 01 00 00 00       	mov    edi,0x1
  402c0e:	48 8d 35 94 f4 00 00 	lea    rsi,[rip+0xf494]        # 4120a9 <_IO_stdin_used+0xa9>
  402c15:	48 89 c2             	mov    rdx,rax
  402c18:	31 c0                	xor    eax,eax
  402c1a:	e8 11 e6 ff ff       	call   401230 <__printf_chk@plt>
  402c1f:	83 cf ff             	or     edi,0xffffffff
  402c22:	e8 39 e6 ff ff       	call   401260 <exit@plt>
  402c27:	48 63 d0             	movsxd rdx,eax
  402c2a:	48 89 ee             	mov    rsi,rbp
  402c2d:	bf 01 00 00 00       	mov    edi,0x1
  402c32:	e8 69 e5 ff ff       	call   4011a0 <write@plt>
  402c37:	48 8d 3d 16 f5 00 00 	lea    rdi,[rip+0xf516]        # 412154 <_IO_stdin_used+0x154>
  402c3e:	e8 4d e5 ff ff       	call   401190 <puts@plt>
  402c43:	48 8d 3d ba f3 00 00 	lea    rdi,[rip+0xf3ba]        # 412004 <_IO_stdin_used+0x4>
  402c4a:	31 f6                	xor    esi,esi
  402c4c:	31 c0                	xor    eax,eax
  402c4e:	e8 fd e5 ff ff       	call   401250 <open@plt>
  402c53:	89 c7                	mov    edi,eax
  402c55:	85 c0                	test   eax,eax
  402c57:	79 34                	jns    402c8d <win+0x1717>
  402c59:	e8 22 e5 ff ff       	call   401180 <__errno_location@plt>
  402c5e:	8b 38                	mov    edi,DWORD PTR [rax]
  402c60:	e8 1b e6 ff ff       	call   401280 <strerror@plt>
  402c65:	48 8d 35 9e f3 00 00 	lea    rsi,[rip+0xf39e]        # 41200a <_IO_stdin_used+0xa>
  402c6c:	bf 01 00 00 00       	mov    edi,0x1
  402c71:	48 89 c2             	mov    rdx,rax
  402c74:	31 c0                	xor    eax,eax
  402c76:	e8 b5 e5 ff ff       	call   401230 <__printf_chk@plt>
  402c7b:	e8 60 e5 ff ff       	call   4011e0 <geteuid@plt>
  402c80:	85 c0                	test   eax,eax
  402c82:	0f 84 51 e9 ff ff    	je     4015d9 <win+0x63>
  402c88:	e9 34 e9 ff ff       	jmp    4015c1 <win+0x4b>
  402c8d:	ba 00 01 00 00       	mov    edx,0x100
  402c92:	48 89 ee             	mov    rsi,rbp
  402c95:	e8 66 e5 ff ff       	call   401200 <read@plt>
  402c9a:	85 c0                	test   eax,eax
  402c9c:	7f 2a                	jg     402cc8 <win+0x1752>
  402c9e:	e8 dd e4 ff ff       	call   401180 <__errno_location@plt>
  402ca3:	8b 38                	mov    edi,DWORD PTR [rax]
  402ca5:	e8 d6 e5 ff ff       	call   401280 <strerror@plt>
  402caa:	bf 01 00 00 00       	mov    edi,0x1
  402caf:	48 8d 35 f3 f3 00 00 	lea    rsi,[rip+0xf3f3]        # 4120a9 <_IO_stdin_used+0xa9>
  402cb6:	48 89 c2             	mov    rdx,rax
  402cb9:	31 c0                	xor    eax,eax
  402cbb:	e8 70 e5 ff ff       	call   401230 <__printf_chk@plt>
  402cc0:	83 cf ff             	or     edi,0xffffffff
  402cc3:	e8 98 e5 ff ff       	call   401260 <exit@plt>
  402cc8:	48 63 d0             	movsxd rdx,eax
  402ccb:	48 89 ee             	mov    rsi,rbp
  402cce:	bf 01 00 00 00       	mov    edi,0x1
  402cd3:	e8 c8 e4 ff ff       	call   4011a0 <write@plt>
  402cd8:	48 8d 3d 75 f4 00 00 	lea    rdi,[rip+0xf475]        # 412154 <_IO_stdin_used+0x154>
  402cdf:	e8 ac e4 ff ff       	call   401190 <puts@plt>
  402ce4:	48 8d 3d 19 f3 00 00 	lea    rdi,[rip+0xf319]        # 412004 <_IO_stdin_used+0x4>
  402ceb:	31 f6                	xor    esi,esi
  402ced:	31 c0                	xor    eax,eax
  402cef:	e8 5c e5 ff ff       	call   401250 <open@plt>
  402cf4:	89 c7                	mov    edi,eax
  402cf6:	85 c0                	test   eax,eax
  402cf8:	79 34                	jns    402d2e <win+0x17b8>
  402cfa:	e8 81 e4 ff ff       	call   401180 <__errno_location@plt>
  402cff:	8b 38                	mov    edi,DWORD PTR [rax]
  402d01:	e8 7a e5 ff ff       	call   401280 <strerror@plt>
  402d06:	48 8d 35 fd f2 00 00 	lea    rsi,[rip+0xf2fd]        # 41200a <_IO_stdin_used+0xa>
  402d0d:	bf 01 00 00 00       	mov    edi,0x1
  402d12:	48 89 c2             	mov    rdx,rax
  402d15:	31 c0                	xor    eax,eax
  402d17:	e8 14 e5 ff ff       	call   401230 <__printf_chk@plt>
  402d1c:	e8 bf e4 ff ff       	call   4011e0 <geteuid@plt>
  402d21:	85 c0                	test   eax,eax
  402d23:	0f 84 b0 e8 ff ff    	je     4015d9 <win+0x63>
  402d29:	e9 93 e8 ff ff       	jmp    4015c1 <win+0x4b>
  402d2e:	ba 00 01 00 00       	mov    edx,0x100
  402d33:	48 89 ee             	mov    rsi,rbp
  402d36:	e8 c5 e4 ff ff       	call   401200 <read@plt>
  402d3b:	85 c0                	test   eax,eax
  402d3d:	7f 2a                	jg     402d69 <win+0x17f3>
  402d3f:	e8 3c e4 ff ff       	call   401180 <__errno_location@plt>
  402d44:	8b 38                	mov    edi,DWORD PTR [rax]
  402d46:	e8 35 e5 ff ff       	call   401280 <strerror@plt>
  402d4b:	bf 01 00 00 00       	mov    edi,0x1
  402d50:	48 8d 35 52 f3 00 00 	lea    rsi,[rip+0xf352]        # 4120a9 <_IO_stdin_used+0xa9>
  402d57:	48 89 c2             	mov    rdx,rax
  402d5a:	31 c0                	xor    eax,eax
  402d5c:	e8 cf e4 ff ff       	call   401230 <__printf_chk@plt>
  402d61:	83 cf ff             	or     edi,0xffffffff
  402d64:	e8 f7 e4 ff ff       	call   401260 <exit@plt>
  402d69:	48 63 d0             	movsxd rdx,eax
  402d6c:	48 89 ee             	mov    rsi,rbp
  402d6f:	bf 01 00 00 00       	mov    edi,0x1
  402d74:	e8 27 e4 ff ff       	call   4011a0 <write@plt>
  402d79:	48 8d 3d d4 f3 00 00 	lea    rdi,[rip+0xf3d4]        # 412154 <_IO_stdin_used+0x154>
  402d80:	e8 0b e4 ff ff       	call   401190 <puts@plt>
  402d85:	48 8d 3d 78 f2 00 00 	lea    rdi,[rip+0xf278]        # 412004 <_IO_stdin_used+0x4>
  402d8c:	31 f6                	xor    esi,esi
  402d8e:	31 c0                	xor    eax,eax
  402d90:	e8 bb e4 ff ff       	call   401250 <open@plt>
  402d95:	89 c7                	mov    edi,eax
  402d97:	85 c0                	test   eax,eax
  402d99:	79 34                	jns    402dcf <win+0x1859>
  402d9b:	e8 e0 e3 ff ff       	call   401180 <__errno_location@plt>
  402da0:	8b 38                	mov    edi,DWORD PTR [rax]
  402da2:	e8 d9 e4 ff ff       	call   401280 <strerror@plt>
  402da7:	48 8d 35 5c f2 00 00 	lea    rsi,[rip+0xf25c]        # 41200a <_IO_stdin_used+0xa>
  402dae:	bf 01 00 00 00       	mov    edi,0x1
  402db3:	48 89 c2             	mov    rdx,rax
  402db6:	31 c0                	xor    eax,eax
  402db8:	e8 73 e4 ff ff       	call   401230 <__printf_chk@plt>
  402dbd:	e8 1e e4 ff ff       	call   4011e0 <geteuid@plt>
  402dc2:	85 c0                	test   eax,eax
  402dc4:	0f 84 0f e8 ff ff    	je     4015d9 <win+0x63>
  402dca:	e9 f2 e7 ff ff       	jmp    4015c1 <win+0x4b>
  402dcf:	ba 00 01 00 00       	mov    edx,0x100
  402dd4:	48 89 ee             	mov    rsi,rbp
  402dd7:	e8 24 e4 ff ff       	call   401200 <read@plt>
  402ddc:	85 c0                	test   eax,eax
  402dde:	7f 2a                	jg     402e0a <win+0x1894>
  402de0:	e8 9b e3 ff ff       	call   401180 <__errno_location@plt>
  402de5:	8b 38                	mov    edi,DWORD PTR [rax]
  402de7:	e8 94 e4 ff ff       	call   401280 <strerror@plt>
  402dec:	bf 01 00 00 00       	mov    edi,0x1
  402df1:	48 8d 35 b1 f2 00 00 	lea    rsi,[rip+0xf2b1]        # 4120a9 <_IO_stdin_used+0xa9>
  402df8:	48 89 c2             	mov    rdx,rax
  402dfb:	31 c0                	xor    eax,eax
  402dfd:	e8 2e e4 ff ff       	call   401230 <__printf_chk@plt>
  402e02:	83 cf ff             	or     edi,0xffffffff
  402e05:	e8 56 e4 ff ff       	call   401260 <exit@plt>
  402e0a:	48 63 d0             	movsxd rdx,eax
  402e0d:	48 89 ee             	mov    rsi,rbp
  402e10:	bf 01 00 00 00       	mov    edi,0x1
  402e15:	e8 86 e3 ff ff       	call   4011a0 <write@plt>
  402e1a:	48 8d 3d 33 f3 00 00 	lea    rdi,[rip+0xf333]        # 412154 <_IO_stdin_used+0x154>
  402e21:	e8 6a e3 ff ff       	call   401190 <puts@plt>
  402e26:	48 8d 3d d7 f1 00 00 	lea    rdi,[rip+0xf1d7]        # 412004 <_IO_stdin_used+0x4>
  402e2d:	31 f6                	xor    esi,esi
  402e2f:	31 c0                	xor    eax,eax
  402e31:	e8 1a e4 ff ff       	call   401250 <open@plt>
  402e36:	89 c7                	mov    edi,eax
  402e38:	85 c0                	test   eax,eax
  402e3a:	79 34                	jns    402e70 <win+0x18fa>
  402e3c:	e8 3f e3 ff ff       	call   401180 <__errno_location@plt>
  402e41:	8b 38                	mov    edi,DWORD PTR [rax]
  402e43:	e8 38 e4 ff ff       	call   401280 <strerror@plt>
  402e48:	48 8d 35 bb f1 00 00 	lea    rsi,[rip+0xf1bb]        # 41200a <_IO_stdin_used+0xa>
  402e4f:	bf 01 00 00 00       	mov    edi,0x1
  402e54:	48 89 c2             	mov    rdx,rax
  402e57:	31 c0                	xor    eax,eax
  402e59:	e8 d2 e3 ff ff       	call   401230 <__printf_chk@plt>
  402e5e:	e8 7d e3 ff ff       	call   4011e0 <geteuid@plt>
  402e63:	85 c0                	test   eax,eax
  402e65:	0f 84 6e e7 ff ff    	je     4015d9 <win+0x63>
  402e6b:	e9 51 e7 ff ff       	jmp    4015c1 <win+0x4b>
  402e70:	ba 00 01 00 00       	mov    edx,0x100
  402e75:	48 89 ee             	mov    rsi,rbp
  402e78:	e8 83 e3 ff ff       	call   401200 <read@plt>
  402e7d:	85 c0                	test   eax,eax
  402e7f:	7f 2a                	jg     402eab <win+0x1935>
  402e81:	e8 fa e2 ff ff       	call   401180 <__errno_location@plt>
  402e86:	8b 38                	mov    edi,DWORD PTR [rax]
  402e88:	e8 f3 e3 ff ff       	call   401280 <strerror@plt>
  402e8d:	bf 01 00 00 00       	mov    edi,0x1
  402e92:	48 8d 35 10 f2 00 00 	lea    rsi,[rip+0xf210]        # 4120a9 <_IO_stdin_used+0xa9>
  402e99:	48 89 c2             	mov    rdx,rax
  402e9c:	31 c0                	xor    eax,eax
  402e9e:	e8 8d e3 ff ff       	call   401230 <__printf_chk@plt>
  402ea3:	83 cf ff             	or     edi,0xffffffff
  402ea6:	e8 b5 e3 ff ff       	call   401260 <exit@plt>
  402eab:	48 89 e5             	mov    rbp,rsp
  402eae:	48 63 d0             	movsxd rdx,eax
  402eb1:	bf 01 00 00 00       	mov    edi,0x1
  402eb6:	48 89 ee             	mov    rsi,rbp
  402eb9:	e8 e2 e2 ff ff       	call   4011a0 <write@plt>
  402ebe:	48 8d 3d 8f f2 00 00 	lea    rdi,[rip+0xf28f]        # 412154 <_IO_stdin_used+0x154>
  402ec5:	e8 c6 e2 ff ff       	call   401190 <puts@plt>
  402eca:	48 8d 3d 33 f1 00 00 	lea    rdi,[rip+0xf133]        # 412004 <_IO_stdin_used+0x4>
  402ed1:	31 f6                	xor    esi,esi
  402ed3:	31 c0                	xor    eax,eax
  402ed5:	e8 76 e3 ff ff       	call   401250 <open@plt>
  402eda:	89 c7                	mov    edi,eax
  402edc:	85 c0                	test   eax,eax
  402ede:	79 34                	jns    402f14 <win+0x199e>
  402ee0:	e8 9b e2 ff ff       	call   401180 <__errno_location@plt>
  402ee5:	8b 38                	mov    edi,DWORD PTR [rax]
  402ee7:	e8 94 e3 ff ff       	call   401280 <strerror@plt>
  402eec:	48 8d 35 17 f1 00 00 	lea    rsi,[rip+0xf117]        # 41200a <_IO_stdin_used+0xa>
  402ef3:	bf 01 00 00 00       	mov    edi,0x1
  402ef8:	48 89 c2             	mov    rdx,rax
  402efb:	31 c0                	xor    eax,eax
  402efd:	e8 2e e3 ff ff       	call   401230 <__printf_chk@plt>
  402f02:	e8 d9 e2 ff ff       	call   4011e0 <geteuid@plt>
  402f07:	85 c0                	test   eax,eax
  402f09:	0f 84 ca e6 ff ff    	je     4015d9 <win+0x63>
  402f0f:	e9 ad e6 ff ff       	jmp    4015c1 <win+0x4b>
  402f14:	ba 00 01 00 00       	mov    edx,0x100
  402f19:	48 89 ee             	mov    rsi,rbp
  402f1c:	e8 df e2 ff ff       	call   401200 <read@plt>
  402f21:	85 c0                	test   eax,eax
  402f23:	7f 2a                	jg     402f4f <win+0x19d9>
  402f25:	e8 56 e2 ff ff       	call   401180 <__errno_location@plt>
  402f2a:	8b 38                	mov    edi,DWORD PTR [rax]
  402f2c:	e8 4f e3 ff ff       	call   401280 <strerror@plt>
  402f31:	bf 01 00 00 00       	mov    edi,0x1
  402f36:	48 8d 35 6c f1 00 00 	lea    rsi,[rip+0xf16c]        # 4120a9 <_IO_stdin_used+0xa9>
  402f3d:	48 89 c2             	mov    rdx,rax
  402f40:	31 c0                	xor    eax,eax
  402f42:	e8 e9 e2 ff ff       	call   401230 <__printf_chk@plt>
  402f47:	83 cf ff             	or     edi,0xffffffff
  402f4a:	e8 11 e3 ff ff       	call   401260 <exit@plt>
  402f4f:	48 63 d0             	movsxd rdx,eax
  402f52:	48 89 ee             	mov    rsi,rbp
  402f55:	bf 01 00 00 00       	mov    edi,0x1
  402f5a:	e8 41 e2 ff ff       	call   4011a0 <write@plt>
  402f5f:	48 8d 3d ee f1 00 00 	lea    rdi,[rip+0xf1ee]        # 412154 <_IO_stdin_used+0x154>
  402f66:	e8 25 e2 ff ff       	call   401190 <puts@plt>
  402f6b:	48 8d 3d 92 f0 00 00 	lea    rdi,[rip+0xf092]        # 412004 <_IO_stdin_used+0x4>
  402f72:	31 f6                	xor    esi,esi
  402f74:	31 c0                	xor    eax,eax
  402f76:	e8 d5 e2 ff ff       	call   401250 <open@plt>
  402f7b:	89 c7                	mov    edi,eax
  402f7d:	85 c0                	test   eax,eax
  402f7f:	79 34                	jns    402fb5 <win+0x1a3f>
  402f81:	e8 fa e1 ff ff       	call   401180 <__errno_location@plt>
  402f86:	8b 38                	mov    edi,DWORD PTR [rax]
  402f88:	e8 f3 e2 ff ff       	call   401280 <strerror@plt>
  402f8d:	48 8d 35 76 f0 00 00 	lea    rsi,[rip+0xf076]        # 41200a <_IO_stdin_used+0xa>
  402f94:	bf 01 00 00 00       	mov    edi,0x1
  402f99:	48 89 c2             	mov    rdx,rax
  402f9c:	31 c0                	xor    eax,eax
  402f9e:	e8 8d e2 ff ff       	call   401230 <__printf_chk@plt>
  402fa3:	e8 38 e2 ff ff       	call   4011e0 <geteuid@plt>
  402fa8:	85 c0                	test   eax,eax
  402faa:	0f 84 29 e6 ff ff    	je     4015d9 <win+0x63>
  402fb0:	e9 0c e6 ff ff       	jmp    4015c1 <win+0x4b>
  402fb5:	ba 00 01 00 00       	mov    edx,0x100
  402fba:	48 89 ee             	mov    rsi,rbp
  402fbd:	e8 3e e2 ff ff       	call   401200 <read@plt>
  402fc2:	85 c0                	test   eax,eax
  402fc4:	7f 2a                	jg     402ff0 <win+0x1a7a>
  402fc6:	e8 b5 e1 ff ff       	call   401180 <__errno_location@plt>
  402fcb:	8b 38                	mov    edi,DWORD PTR [rax]
  402fcd:	e8 ae e2 ff ff       	call   401280 <strerror@plt>
  402fd2:	bf 01 00 00 00       	mov    edi,0x1
  402fd7:	48 8d 35 cb f0 00 00 	lea    rsi,[rip+0xf0cb]        # 4120a9 <_IO_stdin_used+0xa9>
  402fde:	48 89 c2             	mov    rdx,rax
  402fe1:	31 c0                	xor    eax,eax
  402fe3:	e8 48 e2 ff ff       	call   401230 <__printf_chk@plt>
  402fe8:	83 cf ff             	or     edi,0xffffffff
  402feb:	e8 70 e2 ff ff       	call   401260 <exit@plt>
  402ff0:	48 63 d0             	movsxd rdx,eax
  402ff3:	48 89 ee             	mov    rsi,rbp
  402ff6:	bf 01 00 00 00       	mov    edi,0x1
  402ffb:	e8 a0 e1 ff ff       	call   4011a0 <write@plt>
  403000:	48 8d 3d 4d f1 00 00 	lea    rdi,[rip+0xf14d]        # 412154 <_IO_stdin_used+0x154>
  403007:	e8 84 e1 ff ff       	call   401190 <puts@plt>
  40300c:	48 8d 3d f1 ef 00 00 	lea    rdi,[rip+0xeff1]        # 412004 <_IO_stdin_used+0x4>
  403013:	31 f6                	xor    esi,esi
  403015:	31 c0                	xor    eax,eax
  403017:	e8 34 e2 ff ff       	call   401250 <open@plt>
  40301c:	89 c7                	mov    edi,eax
  40301e:	85 c0                	test   eax,eax
  403020:	79 34                	jns    403056 <win+0x1ae0>
  403022:	e8 59 e1 ff ff       	call   401180 <__errno_location@plt>
  403027:	8b 38                	mov    edi,DWORD PTR [rax]
  403029:	e8 52 e2 ff ff       	call   401280 <strerror@plt>
  40302e:	48 8d 35 d5 ef 00 00 	lea    rsi,[rip+0xefd5]        # 41200a <_IO_stdin_used+0xa>
  403035:	bf 01 00 00 00       	mov    edi,0x1
  40303a:	48 89 c2             	mov    rdx,rax
  40303d:	31 c0                	xor    eax,eax
  40303f:	e8 ec e1 ff ff       	call   401230 <__printf_chk@plt>
  403044:	e8 97 e1 ff ff       	call   4011e0 <geteuid@plt>
  403049:	85 c0                	test   eax,eax
  40304b:	0f 84 88 e5 ff ff    	je     4015d9 <win+0x63>
  403051:	e9 6b e5 ff ff       	jmp    4015c1 <win+0x4b>
  403056:	ba 00 01 00 00       	mov    edx,0x100
  40305b:	48 89 ee             	mov    rsi,rbp
  40305e:	e8 9d e1 ff ff       	call   401200 <read@plt>
  403063:	85 c0                	test   eax,eax
  403065:	7f 2a                	jg     403091 <win+0x1b1b>
  403067:	e8 14 e1 ff ff       	call   401180 <__errno_location@plt>
  40306c:	8b 38                	mov    edi,DWORD PTR [rax]
  40306e:	e8 0d e2 ff ff       	call   401280 <strerror@plt>
  403073:	bf 01 00 00 00       	mov    edi,0x1
  403078:	48 8d 35 2a f0 00 00 	lea    rsi,[rip+0xf02a]        # 4120a9 <_IO_stdin_used+0xa9>
  40307f:	48 89 c2             	mov    rdx,rax
  403082:	31 c0                	xor    eax,eax
  403084:	e8 a7 e1 ff ff       	call   401230 <__printf_chk@plt>
  403089:	83 cf ff             	or     edi,0xffffffff
  40308c:	e8 cf e1 ff ff       	call   401260 <exit@plt>
  403091:	48 63 d0             	movsxd rdx,eax
  403094:	48 89 ee             	mov    rsi,rbp
  403097:	bf 01 00 00 00       	mov    edi,0x1
  40309c:	e8 ff e0 ff ff       	call   4011a0 <write@plt>
  4030a1:	48 8d 3d ac f0 00 00 	lea    rdi,[rip+0xf0ac]        # 412154 <_IO_stdin_used+0x154>
  4030a8:	e8 e3 e0 ff ff       	call   401190 <puts@plt>
  4030ad:	48 8d 3d 50 ef 00 00 	lea    rdi,[rip+0xef50]        # 412004 <_IO_stdin_used+0x4>
  4030b4:	31 f6                	xor    esi,esi
  4030b6:	31 c0                	xor    eax,eax
  4030b8:	e8 93 e1 ff ff       	call   401250 <open@plt>
  4030bd:	89 c7                	mov    edi,eax
  4030bf:	85 c0                	test   eax,eax
  4030c1:	79 34                	jns    4030f7 <win+0x1b81>
  4030c3:	e8 b8 e0 ff ff       	call   401180 <__errno_location@plt>
  4030c8:	8b 38                	mov    edi,DWORD PTR [rax]
  4030ca:	e8 b1 e1 ff ff       	call   401280 <strerror@plt>
  4030cf:	48 8d 35 34 ef 00 00 	lea    rsi,[rip+0xef34]        # 41200a <_IO_stdin_used+0xa>
  4030d6:	bf 01 00 00 00       	mov    edi,0x1
  4030db:	48 89 c2             	mov    rdx,rax
  4030de:	31 c0                	xor    eax,eax
  4030e0:	e8 4b e1 ff ff       	call   401230 <__printf_chk@plt>
  4030e5:	e8 f6 e0 ff ff       	call   4011e0 <geteuid@plt>
  4030ea:	85 c0                	test   eax,eax
  4030ec:	0f 84 e7 e4 ff ff    	je     4015d9 <win+0x63>
  4030f2:	e9 ca e4 ff ff       	jmp    4015c1 <win+0x4b>
  4030f7:	ba 00 01 00 00       	mov    edx,0x100
  4030fc:	48 89 ee             	mov    rsi,rbp
  4030ff:	e8 fc e0 ff ff       	call   401200 <read@plt>
  403104:	85 c0                	test   eax,eax
  403106:	7f 2a                	jg     403132 <win+0x1bbc>
  403108:	e8 73 e0 ff ff       	call   401180 <__errno_location@plt>
  40310d:	8b 38                	mov    edi,DWORD PTR [rax]
  40310f:	e8 6c e1 ff ff       	call   401280 <strerror@plt>
  403114:	bf 01 00 00 00       	mov    edi,0x1
  403119:	48 8d 35 89 ef 00 00 	lea    rsi,[rip+0xef89]        # 4120a9 <_IO_stdin_used+0xa9>
  403120:	48 89 c2             	mov    rdx,rax
  403123:	31 c0                	xor    eax,eax
  403125:	e8 06 e1 ff ff       	call   401230 <__printf_chk@plt>
  40312a:	83 cf ff             	or     edi,0xffffffff
  40312d:	e8 2e e1 ff ff       	call   401260 <exit@plt>
  403132:	48 63 d0             	movsxd rdx,eax
  403135:	48 89 ee             	mov    rsi,rbp
  403138:	bf 01 00 00 00       	mov    edi,0x1
  40313d:	e8 5e e0 ff ff       	call   4011a0 <write@plt>
  403142:	48 8d 3d 0b f0 00 00 	lea    rdi,[rip+0xf00b]        # 412154 <_IO_stdin_used+0x154>
  403149:	e8 42 e0 ff ff       	call   401190 <puts@plt>
  40314e:	48 8d 3d af ee 00 00 	lea    rdi,[rip+0xeeaf]        # 412004 <_IO_stdin_used+0x4>
  403155:	31 f6                	xor    esi,esi
  403157:	31 c0                	xor    eax,eax
  403159:	e8 f2 e0 ff ff       	call   401250 <open@plt>
  40315e:	89 c7                	mov    edi,eax
  403160:	85 c0                	test   eax,eax
  403162:	79 34                	jns    403198 <win+0x1c22>
  403164:	e8 17 e0 ff ff       	call   401180 <__errno_location@plt>
  403169:	8b 38                	mov    edi,DWORD PTR [rax]
  40316b:	e8 10 e1 ff ff       	call   401280 <strerror@plt>
  403170:	48 8d 35 93 ee 00 00 	lea    rsi,[rip+0xee93]        # 41200a <_IO_stdin_used+0xa>
  403177:	bf 01 00 00 00       	mov    edi,0x1
  40317c:	48 89 c2             	mov    rdx,rax
  40317f:	31 c0                	xor    eax,eax
  403181:	e8 aa e0 ff ff       	call   401230 <__printf_chk@plt>
  403186:	e8 55 e0 ff ff       	call   4011e0 <geteuid@plt>
  40318b:	85 c0                	test   eax,eax
  40318d:	0f 84 46 e4 ff ff    	je     4015d9 <win+0x63>
  403193:	e9 29 e4 ff ff       	jmp    4015c1 <win+0x4b>
  403198:	ba 00 01 00 00       	mov    edx,0x100
  40319d:	48 89 ee             	mov    rsi,rbp
  4031a0:	e8 5b e0 ff ff       	call   401200 <read@plt>
  4031a5:	85 c0                	test   eax,eax
  4031a7:	7f 2a                	jg     4031d3 <win+0x1c5d>
  4031a9:	e8 d2 df ff ff       	call   401180 <__errno_location@plt>
  4031ae:	8b 38                	mov    edi,DWORD PTR [rax]
  4031b0:	e8 cb e0 ff ff       	call   401280 <strerror@plt>
  4031b5:	bf 01 00 00 00       	mov    edi,0x1
  4031ba:	48 8d 35 e8 ee 00 00 	lea    rsi,[rip+0xeee8]        # 4120a9 <_IO_stdin_used+0xa9>
  4031c1:	48 89 c2             	mov    rdx,rax
  4031c4:	31 c0                	xor    eax,eax
  4031c6:	e8 65 e0 ff ff       	call   401230 <__printf_chk@plt>
  4031cb:	83 cf ff             	or     edi,0xffffffff
  4031ce:	e8 8d e0 ff ff       	call   401260 <exit@plt>
  4031d3:	48 63 d0             	movsxd rdx,eax
  4031d6:	48 89 ee             	mov    rsi,rbp
  4031d9:	bf 01 00 00 00       	mov    edi,0x1
  4031de:	e8 bd df ff ff       	call   4011a0 <write@plt>
  4031e3:	48 8d 3d 6a ef 00 00 	lea    rdi,[rip+0xef6a]        # 412154 <_IO_stdin_used+0x154>
  4031ea:	e8 a1 df ff ff       	call   401190 <puts@plt>
  4031ef:	48 8d 3d 0e ee 00 00 	lea    rdi,[rip+0xee0e]        # 412004 <_IO_stdin_used+0x4>
  4031f6:	31 f6                	xor    esi,esi
  4031f8:	31 c0                	xor    eax,eax
  4031fa:	e8 51 e0 ff ff       	call   401250 <open@plt>
  4031ff:	89 c7                	mov    edi,eax
  403201:	85 c0                	test   eax,eax
  403203:	79 34                	jns    403239 <win+0x1cc3>
  403205:	e8 76 df ff ff       	call   401180 <__errno_location@plt>
  40320a:	8b 38                	mov    edi,DWORD PTR [rax]
  40320c:	e8 6f e0 ff ff       	call   401280 <strerror@plt>
  403211:	48 8d 35 f2 ed 00 00 	lea    rsi,[rip+0xedf2]        # 41200a <_IO_stdin_used+0xa>
  403218:	bf 01 00 00 00       	mov    edi,0x1
  40321d:	48 89 c2             	mov    rdx,rax
  403220:	31 c0                	xor    eax,eax
  403222:	e8 09 e0 ff ff       	call   401230 <__printf_chk@plt>
  403227:	e8 b4 df ff ff       	call   4011e0 <geteuid@plt>
  40322c:	85 c0                	test   eax,eax
  40322e:	0f 84 a5 e3 ff ff    	je     4015d9 <win+0x63>
  403234:	e9 88 e3 ff ff       	jmp    4015c1 <win+0x4b>
  403239:	ba 00 01 00 00       	mov    edx,0x100
  40323e:	48 89 ee             	mov    rsi,rbp
  403241:	e8 ba df ff ff       	call   401200 <read@plt>
  403246:	85 c0                	test   eax,eax
  403248:	7f 2a                	jg     403274 <win+0x1cfe>
  40324a:	e8 31 df ff ff       	call   401180 <__errno_location@plt>
  40324f:	8b 38                	mov    edi,DWORD PTR [rax]
  403251:	e8 2a e0 ff ff       	call   401280 <strerror@plt>
  403256:	bf 01 00 00 00       	mov    edi,0x1
  40325b:	48 8d 35 47 ee 00 00 	lea    rsi,[rip+0xee47]        # 4120a9 <_IO_stdin_used+0xa9>
  403262:	48 89 c2             	mov    rdx,rax
  403265:	31 c0                	xor    eax,eax
  403267:	e8 c4 df ff ff       	call   401230 <__printf_chk@plt>
  40326c:	83 cf ff             	or     edi,0xffffffff
  40326f:	e8 ec df ff ff       	call   401260 <exit@plt>
  403274:	48 63 d0             	movsxd rdx,eax
  403277:	48 89 ee             	mov    rsi,rbp
  40327a:	bf 01 00 00 00       	mov    edi,0x1
  40327f:	e8 1c df ff ff       	call   4011a0 <write@plt>
  403284:	48 8d 3d c9 ee 00 00 	lea    rdi,[rip+0xeec9]        # 412154 <_IO_stdin_used+0x154>
  40328b:	e8 00 df ff ff       	call   401190 <puts@plt>
  403290:	48 8d 3d 6d ed 00 00 	lea    rdi,[rip+0xed6d]        # 412004 <_IO_stdin_used+0x4>
  403297:	31 f6                	xor    esi,esi
  403299:	31 c0                	xor    eax,eax
  40329b:	e8 b0 df ff ff       	call   401250 <open@plt>
  4032a0:	89 c7                	mov    edi,eax
  4032a2:	85 c0                	test   eax,eax
  4032a4:	79 34                	jns    4032da <win+0x1d64>
  4032a6:	e8 d5 de ff ff       	call   401180 <__errno_location@plt>
  4032ab:	8b 38                	mov    edi,DWORD PTR [rax]
  4032ad:	e8 ce df ff ff       	call   401280 <strerror@plt>
  4032b2:	48 8d 35 51 ed 00 00 	lea    rsi,[rip+0xed51]        # 41200a <_IO_stdin_used+0xa>
  4032b9:	bf 01 00 00 00       	mov    edi,0x1
  4032be:	48 89 c2             	mov    rdx,rax
  4032c1:	31 c0                	xor    eax,eax
  4032c3:	e8 68 df ff ff       	call   401230 <__printf_chk@plt>
  4032c8:	e8 13 df ff ff       	call   4011e0 <geteuid@plt>
  4032cd:	85 c0                	test   eax,eax
  4032cf:	0f 84 04 e3 ff ff    	je     4015d9 <win+0x63>
  4032d5:	e9 e7 e2 ff ff       	jmp    4015c1 <win+0x4b>
  4032da:	ba 00 01 00 00       	mov    edx,0x100
  4032df:	48 89 ee             	mov    rsi,rbp
  4032e2:	e8 19 df ff ff       	call   401200 <read@plt>
  4032e7:	85 c0                	test   eax,eax
  4032e9:	7f 2a                	jg     403315 <win+0x1d9f>
  4032eb:	e8 90 de ff ff       	call   401180 <__errno_location@plt>
  4032f0:	8b 38                	mov    edi,DWORD PTR [rax]
  4032f2:	e8 89 df ff ff       	call   401280 <strerror@plt>
  4032f7:	bf 01 00 00 00       	mov    edi,0x1
  4032fc:	48 8d 35 a6 ed 00 00 	lea    rsi,[rip+0xeda6]        # 4120a9 <_IO_stdin_used+0xa9>
  403303:	48 89 c2             	mov    rdx,rax
  403306:	31 c0                	xor    eax,eax
  403308:	e8 23 df ff ff       	call   401230 <__printf_chk@plt>
  40330d:	83 cf ff             	or     edi,0xffffffff
  403310:	e8 4b df ff ff       	call   401260 <exit@plt>
  403315:	48 63 d0             	movsxd rdx,eax
  403318:	48 89 ee             	mov    rsi,rbp
  40331b:	bf 01 00 00 00       	mov    edi,0x1
  403320:	e8 7b de ff ff       	call   4011a0 <write@plt>
  403325:	48 8d 3d 28 ee 00 00 	lea    rdi,[rip+0xee28]        # 412154 <_IO_stdin_used+0x154>
  40332c:	e8 5f de ff ff       	call   401190 <puts@plt>
  403331:	48 8d 3d cc ec 00 00 	lea    rdi,[rip+0xeccc]        # 412004 <_IO_stdin_used+0x4>
  403338:	31 f6                	xor    esi,esi
  40333a:	31 c0                	xor    eax,eax
  40333c:	e8 0f df ff ff       	call   401250 <open@plt>
  403341:	89 c7                	mov    edi,eax
  403343:	85 c0                	test   eax,eax
  403345:	79 34                	jns    40337b <win+0x1e05>
  403347:	e8 34 de ff ff       	call   401180 <__errno_location@plt>
  40334c:	8b 38                	mov    edi,DWORD PTR [rax]
  40334e:	e8 2d df ff ff       	call   401280 <strerror@plt>
  403353:	48 8d 35 b0 ec 00 00 	lea    rsi,[rip+0xecb0]        # 41200a <_IO_stdin_used+0xa>
  40335a:	bf 01 00 00 00       	mov    edi,0x1
  40335f:	48 89 c2             	mov    rdx,rax
  403362:	31 c0                	xor    eax,eax
  403364:	e8 c7 de ff ff       	call   401230 <__printf_chk@plt>
  403369:	e8 72 de ff ff       	call   4011e0 <geteuid@plt>
  40336e:	85 c0                	test   eax,eax
  403370:	0f 84 63 e2 ff ff    	je     4015d9 <win+0x63>
  403376:	e9 46 e2 ff ff       	jmp    4015c1 <win+0x4b>
  40337b:	ba 00 01 00 00       	mov    edx,0x100
  403380:	48 89 ee             	mov    rsi,rbp
  403383:	e8 78 de ff ff       	call   401200 <read@plt>
  403388:	85 c0                	test   eax,eax
  40338a:	7f 2a                	jg     4033b6 <win+0x1e40>
  40338c:	e8 ef dd ff ff       	call   401180 <__errno_location@plt>
  403391:	8b 38                	mov    edi,DWORD PTR [rax]
  403393:	e8 e8 de ff ff       	call   401280 <strerror@plt>
  403398:	bf 01 00 00 00       	mov    edi,0x1
  40339d:	48 8d 35 05 ed 00 00 	lea    rsi,[rip+0xed05]        # 4120a9 <_IO_stdin_used+0xa9>
  4033a4:	48 89 c2             	mov    rdx,rax
  4033a7:	31 c0                	xor    eax,eax
  4033a9:	e8 82 de ff ff       	call   401230 <__printf_chk@plt>
  4033ae:	83 cf ff             	or     edi,0xffffffff
  4033b1:	e8 aa de ff ff       	call   401260 <exit@plt>
  4033b6:	48 63 d0             	movsxd rdx,eax
  4033b9:	48 89 ee             	mov    rsi,rbp
  4033bc:	bf 01 00 00 00       	mov    edi,0x1
  4033c1:	e8 da dd ff ff       	call   4011a0 <write@plt>
  4033c6:	48 8d 3d 87 ed 00 00 	lea    rdi,[rip+0xed87]        # 412154 <_IO_stdin_used+0x154>
  4033cd:	e8 be dd ff ff       	call   401190 <puts@plt>
  4033d2:	48 8d 3d 2b ec 00 00 	lea    rdi,[rip+0xec2b]        # 412004 <_IO_stdin_used+0x4>
  4033d9:	31 f6                	xor    esi,esi
  4033db:	31 c0                	xor    eax,eax
  4033dd:	e8 6e de ff ff       	call   401250 <open@plt>
  4033e2:	89 c7                	mov    edi,eax
  4033e4:	85 c0                	test   eax,eax
  4033e6:	79 34                	jns    40341c <win+0x1ea6>
  4033e8:	e8 93 dd ff ff       	call   401180 <__errno_location@plt>
  4033ed:	8b 38                	mov    edi,DWORD PTR [rax]
  4033ef:	e8 8c de ff ff       	call   401280 <strerror@plt>
  4033f4:	48 8d 35 0f ec 00 00 	lea    rsi,[rip+0xec0f]        # 41200a <_IO_stdin_used+0xa>
  4033fb:	bf 01 00 00 00       	mov    edi,0x1
  403400:	48 89 c2             	mov    rdx,rax
  403403:	31 c0                	xor    eax,eax
  403405:	e8 26 de ff ff       	call   401230 <__printf_chk@plt>
  40340a:	e8 d1 dd ff ff       	call   4011e0 <geteuid@plt>
  40340f:	85 c0                	test   eax,eax
  403411:	0f 84 c2 e1 ff ff    	je     4015d9 <win+0x63>
  403417:	e9 a5 e1 ff ff       	jmp    4015c1 <win+0x4b>
  40341c:	ba 00 01 00 00       	mov    edx,0x100
  403421:	48 89 ee             	mov    rsi,rbp
  403424:	e8 d7 dd ff ff       	call   401200 <read@plt>
  403429:	85 c0                	test   eax,eax
  40342b:	7f 2a                	jg     403457 <win+0x1ee1>
  40342d:	e8 4e dd ff ff       	call   401180 <__errno_location@plt>
  403432:	8b 38                	mov    edi,DWORD PTR [rax]
  403434:	e8 47 de ff ff       	call   401280 <strerror@plt>
  403439:	bf 01 00 00 00       	mov    edi,0x1
  40343e:	48 8d 35 64 ec 00 00 	lea    rsi,[rip+0xec64]        # 4120a9 <_IO_stdin_used+0xa9>
  403445:	48 89 c2             	mov    rdx,rax
  403448:	31 c0                	xor    eax,eax
  40344a:	e8 e1 dd ff ff       	call   401230 <__printf_chk@plt>
  40344f:	83 cf ff             	or     edi,0xffffffff
  403452:	e8 09 de ff ff       	call   401260 <exit@plt>
  403457:	48 63 d0             	movsxd rdx,eax
  40345a:	48 89 ee             	mov    rsi,rbp
  40345d:	bf 01 00 00 00       	mov    edi,0x1
  403462:	e8 39 dd ff ff       	call   4011a0 <write@plt>
  403467:	48 8d 3d e6 ec 00 00 	lea    rdi,[rip+0xece6]        # 412154 <_IO_stdin_used+0x154>
  40346e:	e8 1d dd ff ff       	call   401190 <puts@plt>
  403473:	48 8d 3d 8a eb 00 00 	lea    rdi,[rip+0xeb8a]        # 412004 <_IO_stdin_used+0x4>
  40347a:	31 f6                	xor    esi,esi
  40347c:	31 c0                	xor    eax,eax
  40347e:	e8 cd dd ff ff       	call   401250 <open@plt>
  403483:	89 c7                	mov    edi,eax
  403485:	85 c0                	test   eax,eax
  403487:	79 34                	jns    4034bd <win+0x1f47>
  403489:	e8 f2 dc ff ff       	call   401180 <__errno_location@plt>
  40348e:	8b 38                	mov    edi,DWORD PTR [rax]
  403490:	e8 eb dd ff ff       	call   401280 <strerror@plt>
  403495:	48 8d 35 6e eb 00 00 	lea    rsi,[rip+0xeb6e]        # 41200a <_IO_stdin_used+0xa>
  40349c:	bf 01 00 00 00       	mov    edi,0x1
  4034a1:	48 89 c2             	mov    rdx,rax
  4034a4:	31 c0                	xor    eax,eax
  4034a6:	e8 85 dd ff ff       	call   401230 <__printf_chk@plt>
  4034ab:	e8 30 dd ff ff       	call   4011e0 <geteuid@plt>
  4034b0:	85 c0                	test   eax,eax
  4034b2:	0f 84 21 e1 ff ff    	je     4015d9 <win+0x63>
  4034b8:	e9 04 e1 ff ff       	jmp    4015c1 <win+0x4b>
  4034bd:	ba 00 01 00 00       	mov    edx,0x100
  4034c2:	48 89 ee             	mov    rsi,rbp
  4034c5:	e8 36 dd ff ff       	call   401200 <read@plt>
  4034ca:	85 c0                	test   eax,eax
  4034cc:	7f 2a                	jg     4034f8 <win+0x1f82>
  4034ce:	e8 ad dc ff ff       	call   401180 <__errno_location@plt>
  4034d3:	8b 38                	mov    edi,DWORD PTR [rax]
  4034d5:	e8 a6 dd ff ff       	call   401280 <strerror@plt>
  4034da:	bf 01 00 00 00       	mov    edi,0x1
  4034df:	48 8d 35 c3 eb 00 00 	lea    rsi,[rip+0xebc3]        # 4120a9 <_IO_stdin_used+0xa9>
  4034e6:	48 89 c2             	mov    rdx,rax
  4034e9:	31 c0                	xor    eax,eax
  4034eb:	e8 40 dd ff ff       	call   401230 <__printf_chk@plt>
  4034f0:	83 cf ff             	or     edi,0xffffffff
  4034f3:	e8 68 dd ff ff       	call   401260 <exit@plt>
  4034f8:	48 63 d0             	movsxd rdx,eax
  4034fb:	48 89 ee             	mov    rsi,rbp
  4034fe:	bf 01 00 00 00       	mov    edi,0x1
  403503:	e8 98 dc ff ff       	call   4011a0 <write@plt>
  403508:	48 8d 3d 45 ec 00 00 	lea    rdi,[rip+0xec45]        # 412154 <_IO_stdin_used+0x154>
  40350f:	e8 7c dc ff ff       	call   401190 <puts@plt>
  403514:	48 8d 3d e9 ea 00 00 	lea    rdi,[rip+0xeae9]        # 412004 <_IO_stdin_used+0x4>
  40351b:	31 f6                	xor    esi,esi
  40351d:	31 c0                	xor    eax,eax
  40351f:	e8 2c dd ff ff       	call   401250 <open@plt>
  403524:	89 c7                	mov    edi,eax
  403526:	85 c0                	test   eax,eax
  403528:	79 34                	jns    40355e <win+0x1fe8>
  40352a:	e8 51 dc ff ff       	call   401180 <__errno_location@plt>
  40352f:	8b 38                	mov    edi,DWORD PTR [rax]
  403531:	e8 4a dd ff ff       	call   401280 <strerror@plt>
  403536:	48 8d 35 cd ea 00 00 	lea    rsi,[rip+0xeacd]        # 41200a <_IO_stdin_used+0xa>
  40353d:	bf 01 00 00 00       	mov    edi,0x1
  403542:	48 89 c2             	mov    rdx,rax
  403545:	31 c0                	xor    eax,eax
  403547:	e8 e4 dc ff ff       	call   401230 <__printf_chk@plt>
  40354c:	e8 8f dc ff ff       	call   4011e0 <geteuid@plt>
  403551:	85 c0                	test   eax,eax
  403553:	0f 84 80 e0 ff ff    	je     4015d9 <win+0x63>
  403559:	e9 63 e0 ff ff       	jmp    4015c1 <win+0x4b>
  40355e:	ba 00 01 00 00       	mov    edx,0x100
  403563:	48 89 ee             	mov    rsi,rbp
  403566:	e8 95 dc ff ff       	call   401200 <read@plt>
  40356b:	85 c0                	test   eax,eax
  40356d:	7f 2a                	jg     403599 <win+0x2023>
  40356f:	e8 0c dc ff ff       	call   401180 <__errno_location@plt>
  403574:	8b 38                	mov    edi,DWORD PTR [rax]
  403576:	e8 05 dd ff ff       	call   401280 <strerror@plt>
  40357b:	bf 01 00 00 00       	mov    edi,0x1
  403580:	48 8d 35 22 eb 00 00 	lea    rsi,[rip+0xeb22]        # 4120a9 <_IO_stdin_used+0xa9>
  403587:	48 89 c2             	mov    rdx,rax
  40358a:	31 c0                	xor    eax,eax
  40358c:	e8 9f dc ff ff       	call   401230 <__printf_chk@plt>
  403591:	83 cf ff             	or     edi,0xffffffff
  403594:	e8 c7 dc ff ff       	call   401260 <exit@plt>
  403599:	48 63 d0             	movsxd rdx,eax
  40359c:	48 89 ee             	mov    rsi,rbp
  40359f:	bf 01 00 00 00       	mov    edi,0x1
  4035a4:	e8 f7 db ff ff       	call   4011a0 <write@plt>
  4035a9:	48 8d 3d a4 eb 00 00 	lea    rdi,[rip+0xeba4]        # 412154 <_IO_stdin_used+0x154>
  4035b0:	e8 db db ff ff       	call   401190 <puts@plt>
  4035b5:	48 8d 3d 48 ea 00 00 	lea    rdi,[rip+0xea48]        # 412004 <_IO_stdin_used+0x4>
  4035bc:	31 f6                	xor    esi,esi
  4035be:	31 c0                	xor    eax,eax
  4035c0:	e8 8b dc ff ff       	call   401250 <open@plt>
  4035c5:	89 c7                	mov    edi,eax
  4035c7:	85 c0                	test   eax,eax
  4035c9:	79 34                	jns    4035ff <win+0x2089>
  4035cb:	e8 b0 db ff ff       	call   401180 <__errno_location@plt>
  4035d0:	8b 38                	mov    edi,DWORD PTR [rax]
  4035d2:	e8 a9 dc ff ff       	call   401280 <strerror@plt>
  4035d7:	48 8d 35 2c ea 00 00 	lea    rsi,[rip+0xea2c]        # 41200a <_IO_stdin_used+0xa>
  4035de:	bf 01 00 00 00       	mov    edi,0x1
  4035e3:	48 89 c2             	mov    rdx,rax
  4035e6:	31 c0                	xor    eax,eax
  4035e8:	e8 43 dc ff ff       	call   401230 <__printf_chk@plt>
  4035ed:	e8 ee db ff ff       	call   4011e0 <geteuid@plt>
  4035f2:	85 c0                	test   eax,eax
  4035f4:	0f 84 df df ff ff    	je     4015d9 <win+0x63>
  4035fa:	e9 c2 df ff ff       	jmp    4015c1 <win+0x4b>
  4035ff:	ba 00 01 00 00       	mov    edx,0x100
  403604:	48 89 ee             	mov    rsi,rbp
  403607:	e8 f4 db ff ff       	call   401200 <read@plt>
  40360c:	85 c0                	test   eax,eax
  40360e:	7f 2a                	jg     40363a <win+0x20c4>
  403610:	e8 6b db ff ff       	call   401180 <__errno_location@plt>
  403615:	8b 38                	mov    edi,DWORD PTR [rax]
  403617:	e8 64 dc ff ff       	call   401280 <strerror@plt>
  40361c:	bf 01 00 00 00       	mov    edi,0x1
  403621:	48 8d 35 81 ea 00 00 	lea    rsi,[rip+0xea81]        # 4120a9 <_IO_stdin_used+0xa9>
  403628:	48 89 c2             	mov    rdx,rax
  40362b:	31 c0                	xor    eax,eax
  40362d:	e8 fe db ff ff       	call   401230 <__printf_chk@plt>
  403632:	83 cf ff             	or     edi,0xffffffff
  403635:	e8 26 dc ff ff       	call   401260 <exit@plt>
  40363a:	48 63 d0             	movsxd rdx,eax
  40363d:	48 89 ee             	mov    rsi,rbp
  403640:	bf 01 00 00 00       	mov    edi,0x1
  403645:	e8 56 db ff ff       	call   4011a0 <write@plt>
  40364a:	48 8d 3d 03 eb 00 00 	lea    rdi,[rip+0xeb03]        # 412154 <_IO_stdin_used+0x154>
  403651:	e8 3a db ff ff       	call   401190 <puts@plt>
  403656:	48 8d 3d a7 e9 00 00 	lea    rdi,[rip+0xe9a7]        # 412004 <_IO_stdin_used+0x4>
  40365d:	31 f6                	xor    esi,esi
  40365f:	31 c0                	xor    eax,eax
  403661:	e8 ea db ff ff       	call   401250 <open@plt>
  403666:	89 c7                	mov    edi,eax
  403668:	85 c0                	test   eax,eax
  40366a:	79 34                	jns    4036a0 <win+0x212a>
  40366c:	e8 0f db ff ff       	call   401180 <__errno_location@plt>
  403671:	8b 38                	mov    edi,DWORD PTR [rax]
  403673:	e8 08 dc ff ff       	call   401280 <strerror@plt>
  403678:	48 8d 35 8b e9 00 00 	lea    rsi,[rip+0xe98b]        # 41200a <_IO_stdin_used+0xa>
  40367f:	bf 01 00 00 00       	mov    edi,0x1
  403684:	48 89 c2             	mov    rdx,rax
  403687:	31 c0                	xor    eax,eax
  403689:	e8 a2 db ff ff       	call   401230 <__printf_chk@plt>
  40368e:	e8 4d db ff ff       	call   4011e0 <geteuid@plt>
  403693:	85 c0                	test   eax,eax
  403695:	0f 84 3e df ff ff    	je     4015d9 <win+0x63>
  40369b:	e9 21 df ff ff       	jmp    4015c1 <win+0x4b>
  4036a0:	ba 00 01 00 00       	mov    edx,0x100
  4036a5:	48 89 ee             	mov    rsi,rbp
  4036a8:	e8 53 db ff ff       	call   401200 <read@plt>
  4036ad:	85 c0                	test   eax,eax
  4036af:	7f 2a                	jg     4036db <win+0x2165>
  4036b1:	e8 ca da ff ff       	call   401180 <__errno_location@plt>
  4036b6:	8b 38                	mov    edi,DWORD PTR [rax]
  4036b8:	e8 c3 db ff ff       	call   401280 <strerror@plt>
  4036bd:	bf 01 00 00 00       	mov    edi,0x1
  4036c2:	48 8d 35 e0 e9 00 00 	lea    rsi,[rip+0xe9e0]        # 4120a9 <_IO_stdin_used+0xa9>
  4036c9:	48 89 c2             	mov    rdx,rax
  4036cc:	31 c0                	xor    eax,eax
  4036ce:	e8 5d db ff ff       	call   401230 <__printf_chk@plt>
  4036d3:	83 cf ff             	or     edi,0xffffffff
  4036d6:	e8 85 db ff ff       	call   401260 <exit@plt>
  4036db:	48 63 d0             	movsxd rdx,eax
  4036de:	48 89 ee             	mov    rsi,rbp
  4036e1:	bf 01 00 00 00       	mov    edi,0x1
  4036e6:	e8 b5 da ff ff       	call   4011a0 <write@plt>
  4036eb:	48 8d 3d 62 ea 00 00 	lea    rdi,[rip+0xea62]        # 412154 <_IO_stdin_used+0x154>
  4036f2:	e8 99 da ff ff       	call   401190 <puts@plt>
  4036f7:	48 8d 3d 06 e9 00 00 	lea    rdi,[rip+0xe906]        # 412004 <_IO_stdin_used+0x4>
  4036fe:	31 f6                	xor    esi,esi
  403700:	31 c0                	xor    eax,eax
  403702:	e8 49 db ff ff       	call   401250 <open@plt>
  403707:	89 c7                	mov    edi,eax
  403709:	85 c0                	test   eax,eax
  40370b:	79 34                	jns    403741 <win+0x21cb>
  40370d:	e8 6e da ff ff       	call   401180 <__errno_location@plt>
  403712:	8b 38                	mov    edi,DWORD PTR [rax]
  403714:	e8 67 db ff ff       	call   401280 <strerror@plt>
  403719:	48 8d 35 ea e8 00 00 	lea    rsi,[rip+0xe8ea]        # 41200a <_IO_stdin_used+0xa>
  403720:	bf 01 00 00 00       	mov    edi,0x1
  403725:	48 89 c2             	mov    rdx,rax
  403728:	31 c0                	xor    eax,eax
  40372a:	e8 01 db ff ff       	call   401230 <__printf_chk@plt>
  40372f:	e8 ac da ff ff       	call   4011e0 <geteuid@plt>
  403734:	85 c0                	test   eax,eax
  403736:	0f 84 9d de ff ff    	je     4015d9 <win+0x63>
  40373c:	e9 80 de ff ff       	jmp    4015c1 <win+0x4b>
  403741:	ba 00 01 00 00       	mov    edx,0x100
  403746:	48 89 ee             	mov    rsi,rbp
  403749:	e8 b2 da ff ff       	call   401200 <read@plt>
  40374e:	85 c0                	test   eax,eax
  403750:	7f 2a                	jg     40377c <win+0x2206>
  403752:	e8 29 da ff ff       	call   401180 <__errno_location@plt>
  403757:	8b 38                	mov    edi,DWORD PTR [rax]
  403759:	e8 22 db ff ff       	call   401280 <strerror@plt>
  40375e:	bf 01 00 00 00       	mov    edi,0x1
  403763:	48 8d 35 3f e9 00 00 	lea    rsi,[rip+0xe93f]        # 4120a9 <_IO_stdin_used+0xa9>
  40376a:	48 89 c2             	mov    rdx,rax
  40376d:	31 c0                	xor    eax,eax
  40376f:	e8 bc da ff ff       	call   401230 <__printf_chk@plt>
  403774:	83 cf ff             	or     edi,0xffffffff
  403777:	e8 e4 da ff ff       	call   401260 <exit@plt>
  40377c:	48 63 d0             	movsxd rdx,eax
  40377f:	48 89 ee             	mov    rsi,rbp
  403782:	bf 01 00 00 00       	mov    edi,0x1
  403787:	e8 14 da ff ff       	call   4011a0 <write@plt>
  40378c:	48 8d 3d c1 e9 00 00 	lea    rdi,[rip+0xe9c1]        # 412154 <_IO_stdin_used+0x154>
  403793:	e8 f8 d9 ff ff       	call   401190 <puts@plt>
  403798:	48 8d 3d 65 e8 00 00 	lea    rdi,[rip+0xe865]        # 412004 <_IO_stdin_used+0x4>
  40379f:	31 f6                	xor    esi,esi
  4037a1:	31 c0                	xor    eax,eax
  4037a3:	e8 a8 da ff ff       	call   401250 <open@plt>
  4037a8:	89 c7                	mov    edi,eax
  4037aa:	85 c0                	test   eax,eax
  4037ac:	79 34                	jns    4037e2 <win+0x226c>
  4037ae:	e8 cd d9 ff ff       	call   401180 <__errno_location@plt>
  4037b3:	8b 38                	mov    edi,DWORD PTR [rax]
  4037b5:	e8 c6 da ff ff       	call   401280 <strerror@plt>
  4037ba:	48 8d 35 49 e8 00 00 	lea    rsi,[rip+0xe849]        # 41200a <_IO_stdin_used+0xa>
  4037c1:	bf 01 00 00 00       	mov    edi,0x1
  4037c6:	48 89 c2             	mov    rdx,rax
  4037c9:	31 c0                	xor    eax,eax
  4037cb:	e8 60 da ff ff       	call   401230 <__printf_chk@plt>
  4037d0:	e8 0b da ff ff       	call   4011e0 <geteuid@plt>
  4037d5:	85 c0                	test   eax,eax
  4037d7:	0f 84 fc dd ff ff    	je     4015d9 <win+0x63>
  4037dd:	e9 df dd ff ff       	jmp    4015c1 <win+0x4b>
  4037e2:	ba 00 01 00 00       	mov    edx,0x100
  4037e7:	48 89 ee             	mov    rsi,rbp
  4037ea:	e8 11 da ff ff       	call   401200 <read@plt>
  4037ef:	85 c0                	test   eax,eax
  4037f1:	7f 2a                	jg     40381d <win+0x22a7>
  4037f3:	e8 88 d9 ff ff       	call   401180 <__errno_location@plt>
  4037f8:	8b 38                	mov    edi,DWORD PTR [rax]
  4037fa:	e8 81 da ff ff       	call   401280 <strerror@plt>
  4037ff:	bf 01 00 00 00       	mov    edi,0x1
  403804:	48 8d 35 9e e8 00 00 	lea    rsi,[rip+0xe89e]        # 4120a9 <_IO_stdin_used+0xa9>
  40380b:	48 89 c2             	mov    rdx,rax
  40380e:	31 c0                	xor    eax,eax
  403810:	e8 1b da ff ff       	call   401230 <__printf_chk@plt>
  403815:	83 cf ff             	or     edi,0xffffffff
  403818:	e8 43 da ff ff       	call   401260 <exit@plt>
  40381d:	48 63 d0             	movsxd rdx,eax
  403820:	48 89 ee             	mov    rsi,rbp
  403823:	bf 01 00 00 00       	mov    edi,0x1
  403828:	e8 73 d9 ff ff       	call   4011a0 <write@plt>
  40382d:	48 8d 3d 20 e9 00 00 	lea    rdi,[rip+0xe920]        # 412154 <_IO_stdin_used+0x154>
  403834:	e8 57 d9 ff ff       	call   401190 <puts@plt>
  403839:	48 8d 3d c4 e7 00 00 	lea    rdi,[rip+0xe7c4]        # 412004 <_IO_stdin_used+0x4>
  403840:	31 f6                	xor    esi,esi
  403842:	31 c0                	xor    eax,eax
  403844:	e8 07 da ff ff       	call   401250 <open@plt>
  403849:	89 c7                	mov    edi,eax
  40384b:	85 c0                	test   eax,eax
  40384d:	79 34                	jns    403883 <win+0x230d>
  40384f:	e8 2c d9 ff ff       	call   401180 <__errno_location@plt>
  403854:	8b 38                	mov    edi,DWORD PTR [rax]
  403856:	e8 25 da ff ff       	call   401280 <strerror@plt>
  40385b:	48 8d 35 a8 e7 00 00 	lea    rsi,[rip+0xe7a8]        # 41200a <_IO_stdin_used+0xa>
  403862:	bf 01 00 00 00       	mov    edi,0x1
  403867:	48 89 c2             	mov    rdx,rax
  40386a:	31 c0                	xor    eax,eax
  40386c:	e8 bf d9 ff ff       	call   401230 <__printf_chk@plt>
  403871:	e8 6a d9 ff ff       	call   4011e0 <geteuid@plt>
  403876:	85 c0                	test   eax,eax
  403878:	0f 84 5b dd ff ff    	je     4015d9 <win+0x63>
  40387e:	e9 3e dd ff ff       	jmp    4015c1 <win+0x4b>
  403883:	ba 00 01 00 00       	mov    edx,0x100
  403888:	48 89 ee             	mov    rsi,rbp
  40388b:	e8 70 d9 ff ff       	call   401200 <read@plt>
  403890:	85 c0                	test   eax,eax
  403892:	7f 2a                	jg     4038be <win+0x2348>
  403894:	e8 e7 d8 ff ff       	call   401180 <__errno_location@plt>
  403899:	8b 38                	mov    edi,DWORD PTR [rax]
  40389b:	e8 e0 d9 ff ff       	call   401280 <strerror@plt>
  4038a0:	bf 01 00 00 00       	mov    edi,0x1
  4038a5:	48 8d 35 fd e7 00 00 	lea    rsi,[rip+0xe7fd]        # 4120a9 <_IO_stdin_used+0xa9>
  4038ac:	48 89 c2             	mov    rdx,rax
  4038af:	31 c0                	xor    eax,eax
  4038b1:	e8 7a d9 ff ff       	call   401230 <__printf_chk@plt>
  4038b6:	83 cf ff             	or     edi,0xffffffff
  4038b9:	e8 a2 d9 ff ff       	call   401260 <exit@plt>
  4038be:	48 63 d0             	movsxd rdx,eax
  4038c1:	48 89 ee             	mov    rsi,rbp
  4038c4:	bf 01 00 00 00       	mov    edi,0x1
  4038c9:	e8 d2 d8 ff ff       	call   4011a0 <write@plt>
  4038ce:	48 8d 3d 7f e8 00 00 	lea    rdi,[rip+0xe87f]        # 412154 <_IO_stdin_used+0x154>
  4038d5:	e8 b6 d8 ff ff       	call   401190 <puts@plt>
  4038da:	48 8d 3d 23 e7 00 00 	lea    rdi,[rip+0xe723]        # 412004 <_IO_stdin_used+0x4>
  4038e1:	31 f6                	xor    esi,esi
  4038e3:	31 c0                	xor    eax,eax
  4038e5:	e8 66 d9 ff ff       	call   401250 <open@plt>
  4038ea:	89 c7                	mov    edi,eax
  4038ec:	85 c0                	test   eax,eax
  4038ee:	79 34                	jns    403924 <win+0x23ae>
  4038f0:	e8 8b d8 ff ff       	call   401180 <__errno_location@plt>
  4038f5:	8b 38                	mov    edi,DWORD PTR [rax]
  4038f7:	e8 84 d9 ff ff       	call   401280 <strerror@plt>
  4038fc:	48 8d 35 07 e7 00 00 	lea    rsi,[rip+0xe707]        # 41200a <_IO_stdin_used+0xa>
  403903:	bf 01 00 00 00       	mov    edi,0x1
  403908:	48 89 c2             	mov    rdx,rax
  40390b:	31 c0                	xor    eax,eax
  40390d:	e8 1e d9 ff ff       	call   401230 <__printf_chk@plt>
  403912:	e8 c9 d8 ff ff       	call   4011e0 <geteuid@plt>
  403917:	85 c0                	test   eax,eax
  403919:	0f 84 ba dc ff ff    	je     4015d9 <win+0x63>
  40391f:	e9 9d dc ff ff       	jmp    4015c1 <win+0x4b>
  403924:	ba 00 01 00 00       	mov    edx,0x100
  403929:	48 89 ee             	mov    rsi,rbp
  40392c:	e8 cf d8 ff ff       	call   401200 <read@plt>
  403931:	85 c0                	test   eax,eax
  403933:	7f 2a                	jg     40395f <win+0x23e9>
  403935:	e8 46 d8 ff ff       	call   401180 <__errno_location@plt>
  40393a:	8b 38                	mov    edi,DWORD PTR [rax]
  40393c:	e8 3f d9 ff ff       	call   401280 <strerror@plt>
  403941:	bf 01 00 00 00       	mov    edi,0x1
  403946:	48 8d 35 5c e7 00 00 	lea    rsi,[rip+0xe75c]        # 4120a9 <_IO_stdin_used+0xa9>
  40394d:	48 89 c2             	mov    rdx,rax
  403950:	31 c0                	xor    eax,eax
  403952:	e8 d9 d8 ff ff       	call   401230 <__printf_chk@plt>
  403957:	83 cf ff             	or     edi,0xffffffff
  40395a:	e8 01 d9 ff ff       	call   401260 <exit@plt>
  40395f:	48 63 d0             	movsxd rdx,eax
  403962:	48 89 ee             	mov    rsi,rbp
  403965:	bf 01 00 00 00       	mov    edi,0x1
  40396a:	e8 31 d8 ff ff       	call   4011a0 <write@plt>
  40396f:	48 8d 3d de e7 00 00 	lea    rdi,[rip+0xe7de]        # 412154 <_IO_stdin_used+0x154>
  403976:	e8 15 d8 ff ff       	call   401190 <puts@plt>
  40397b:	48 8d 3d 82 e6 00 00 	lea    rdi,[rip+0xe682]        # 412004 <_IO_stdin_used+0x4>
  403982:	31 f6                	xor    esi,esi
  403984:	31 c0                	xor    eax,eax
  403986:	e8 c5 d8 ff ff       	call   401250 <open@plt>
  40398b:	89 c7                	mov    edi,eax
  40398d:	85 c0                	test   eax,eax
  40398f:	79 34                	jns    4039c5 <win+0x244f>
  403991:	e8 ea d7 ff ff       	call   401180 <__errno_location@plt>
  403996:	8b 38                	mov    edi,DWORD PTR [rax]
  403998:	e8 e3 d8 ff ff       	call   401280 <strerror@plt>
  40399d:	48 8d 35 66 e6 00 00 	lea    rsi,[rip+0xe666]        # 41200a <_IO_stdin_used+0xa>
  4039a4:	bf 01 00 00 00       	mov    edi,0x1
  4039a9:	48 89 c2             	mov    rdx,rax
  4039ac:	31 c0                	xor    eax,eax
  4039ae:	e8 7d d8 ff ff       	call   401230 <__printf_chk@plt>
  4039b3:	e8 28 d8 ff ff       	call   4011e0 <geteuid@plt>
  4039b8:	85 c0                	test   eax,eax
  4039ba:	0f 84 19 dc ff ff    	je     4015d9 <win+0x63>
  4039c0:	e9 fc db ff ff       	jmp    4015c1 <win+0x4b>
  4039c5:	ba 00 01 00 00       	mov    edx,0x100
  4039ca:	48 89 ee             	mov    rsi,rbp
  4039cd:	e8 2e d8 ff ff       	call   401200 <read@plt>
  4039d2:	85 c0                	test   eax,eax
  4039d4:	7f 2a                	jg     403a00 <win+0x248a>
  4039d6:	e8 a5 d7 ff ff       	call   401180 <__errno_location@plt>
  4039db:	8b 38                	mov    edi,DWORD PTR [rax]
  4039dd:	e8 9e d8 ff ff       	call   401280 <strerror@plt>
  4039e2:	bf 01 00 00 00       	mov    edi,0x1
  4039e7:	48 8d 35 bb e6 00 00 	lea    rsi,[rip+0xe6bb]        # 4120a9 <_IO_stdin_used+0xa9>
  4039ee:	48 89 c2             	mov    rdx,rax
  4039f1:	31 c0                	xor    eax,eax
  4039f3:	e8 38 d8 ff ff       	call   401230 <__printf_chk@plt>
  4039f8:	83 cf ff             	or     edi,0xffffffff
  4039fb:	e8 60 d8 ff ff       	call   401260 <exit@plt>
  403a00:	48 63 d0             	movsxd rdx,eax
  403a03:	48 89 ee             	mov    rsi,rbp
  403a06:	bf 01 00 00 00       	mov    edi,0x1
  403a0b:	e8 90 d7 ff ff       	call   4011a0 <write@plt>
  403a10:	48 8d 3d 3d e7 00 00 	lea    rdi,[rip+0xe73d]        # 412154 <_IO_stdin_used+0x154>
  403a17:	e8 74 d7 ff ff       	call   401190 <puts@plt>
  403a1c:	48 8d 3d e1 e5 00 00 	lea    rdi,[rip+0xe5e1]        # 412004 <_IO_stdin_used+0x4>
  403a23:	31 f6                	xor    esi,esi
  403a25:	31 c0                	xor    eax,eax
  403a27:	e8 24 d8 ff ff       	call   401250 <open@plt>
  403a2c:	89 c7                	mov    edi,eax
  403a2e:	85 c0                	test   eax,eax
  403a30:	79 34                	jns    403a66 <win+0x24f0>
  403a32:	e8 49 d7 ff ff       	call   401180 <__errno_location@plt>
  403a37:	8b 38                	mov    edi,DWORD PTR [rax]
  403a39:	e8 42 d8 ff ff       	call   401280 <strerror@plt>
  403a3e:	48 8d 35 c5 e5 00 00 	lea    rsi,[rip+0xe5c5]        # 41200a <_IO_stdin_used+0xa>
  403a45:	bf 01 00 00 00       	mov    edi,0x1
  403a4a:	48 89 c2             	mov    rdx,rax
  403a4d:	31 c0                	xor    eax,eax
  403a4f:	e8 dc d7 ff ff       	call   401230 <__printf_chk@plt>
  403a54:	e8 87 d7 ff ff       	call   4011e0 <geteuid@plt>
  403a59:	85 c0                	test   eax,eax
  403a5b:	0f 84 78 db ff ff    	je     4015d9 <win+0x63>
  403a61:	e9 5b db ff ff       	jmp    4015c1 <win+0x4b>
  403a66:	ba 00 01 00 00       	mov    edx,0x100
  403a6b:	48 89 ee             	mov    rsi,rbp
  403a6e:	e8 8d d7 ff ff       	call   401200 <read@plt>
  403a73:	85 c0                	test   eax,eax
  403a75:	7f 2a                	jg     403aa1 <win+0x252b>
  403a77:	e8 04 d7 ff ff       	call   401180 <__errno_location@plt>
  403a7c:	8b 38                	mov    edi,DWORD PTR [rax]
  403a7e:	e8 fd d7 ff ff       	call   401280 <strerror@plt>
  403a83:	bf 01 00 00 00       	mov    edi,0x1
  403a88:	48 8d 35 1a e6 00 00 	lea    rsi,[rip+0xe61a]        # 4120a9 <_IO_stdin_used+0xa9>
  403a8f:	48 89 c2             	mov    rdx,rax
  403a92:	31 c0                	xor    eax,eax
  403a94:	e8 97 d7 ff ff       	call   401230 <__printf_chk@plt>
  403a99:	83 cf ff             	or     edi,0xffffffff
  403a9c:	e8 bf d7 ff ff       	call   401260 <exit@plt>
  403aa1:	48 63 d0             	movsxd rdx,eax
  403aa4:	48 89 ee             	mov    rsi,rbp
  403aa7:	bf 01 00 00 00       	mov    edi,0x1
  403aac:	e8 ef d6 ff ff       	call   4011a0 <write@plt>
  403ab1:	48 8d 3d 9c e6 00 00 	lea    rdi,[rip+0xe69c]        # 412154 <_IO_stdin_used+0x154>
  403ab8:	e8 d3 d6 ff ff       	call   401190 <puts@plt>
  403abd:	48 8d 3d 40 e5 00 00 	lea    rdi,[rip+0xe540]        # 412004 <_IO_stdin_used+0x4>
  403ac4:	31 f6                	xor    esi,esi
  403ac6:	31 c0                	xor    eax,eax
  403ac8:	e8 83 d7 ff ff       	call   401250 <open@plt>
  403acd:	89 c7                	mov    edi,eax
  403acf:	85 c0                	test   eax,eax
  403ad1:	79 34                	jns    403b07 <win+0x2591>
  403ad3:	e8 a8 d6 ff ff       	call   401180 <__errno_location@plt>
  403ad8:	8b 38                	mov    edi,DWORD PTR [rax]
  403ada:	e8 a1 d7 ff ff       	call   401280 <strerror@plt>
  403adf:	48 8d 35 24 e5 00 00 	lea    rsi,[rip+0xe524]        # 41200a <_IO_stdin_used+0xa>
  403ae6:	bf 01 00 00 00       	mov    edi,0x1
  403aeb:	48 89 c2             	mov    rdx,rax
  403aee:	31 c0                	xor    eax,eax
  403af0:	e8 3b d7 ff ff       	call   401230 <__printf_chk@plt>
  403af5:	e8 e6 d6 ff ff       	call   4011e0 <geteuid@plt>
  403afa:	85 c0                	test   eax,eax
  403afc:	0f 84 d7 da ff ff    	je     4015d9 <win+0x63>
  403b02:	e9 ba da ff ff       	jmp    4015c1 <win+0x4b>
  403b07:	ba 00 01 00 00       	mov    edx,0x100
  403b0c:	48 89 ee             	mov    rsi,rbp
  403b0f:	e8 ec d6 ff ff       	call   401200 <read@plt>
  403b14:	85 c0                	test   eax,eax
  403b16:	7f 2a                	jg     403b42 <win+0x25cc>
  403b18:	e8 63 d6 ff ff       	call   401180 <__errno_location@plt>
  403b1d:	8b 38                	mov    edi,DWORD PTR [rax]
  403b1f:	e8 5c d7 ff ff       	call   401280 <strerror@plt>
  403b24:	bf 01 00 00 00       	mov    edi,0x1
  403b29:	48 8d 35 79 e5 00 00 	lea    rsi,[rip+0xe579]        # 4120a9 <_IO_stdin_used+0xa9>
  403b30:	48 89 c2             	mov    rdx,rax
  403b33:	31 c0                	xor    eax,eax
  403b35:	e8 f6 d6 ff ff       	call   401230 <__printf_chk@plt>
  403b3a:	83 cf ff             	or     edi,0xffffffff
  403b3d:	e8 1e d7 ff ff       	call   401260 <exit@plt>
  403b42:	48 89 e5             	mov    rbp,rsp
  403b45:	48 63 d0             	movsxd rdx,eax
  403b48:	bf 01 00 00 00       	mov    edi,0x1
  403b4d:	48 89 ee             	mov    rsi,rbp
  403b50:	e8 4b d6 ff ff       	call   4011a0 <write@plt>
  403b55:	48 8d 3d f8 e5 00 00 	lea    rdi,[rip+0xe5f8]        # 412154 <_IO_stdin_used+0x154>
  403b5c:	e8 2f d6 ff ff       	call   401190 <puts@plt>
  403b61:	48 8d 3d 9c e4 00 00 	lea    rdi,[rip+0xe49c]        # 412004 <_IO_stdin_used+0x4>
  403b68:	31 f6                	xor    esi,esi
  403b6a:	31 c0                	xor    eax,eax
  403b6c:	e8 df d6 ff ff       	call   401250 <open@plt>
  403b71:	89 c7                	mov    edi,eax
  403b73:	85 c0                	test   eax,eax
  403b75:	79 34                	jns    403bab <win+0x2635>
  403b77:	e8 04 d6 ff ff       	call   401180 <__errno_location@plt>
  403b7c:	8b 38                	mov    edi,DWORD PTR [rax]
  403b7e:	e8 fd d6 ff ff       	call   401280 <strerror@plt>
  403b83:	48 8d 35 80 e4 00 00 	lea    rsi,[rip+0xe480]        # 41200a <_IO_stdin_used+0xa>
  403b8a:	bf 01 00 00 00       	mov    edi,0x1
  403b8f:	48 89 c2             	mov    rdx,rax
  403b92:	31 c0                	xor    eax,eax
  403b94:	e8 97 d6 ff ff       	call   401230 <__printf_chk@plt>
  403b99:	e8 42 d6 ff ff       	call   4011e0 <geteuid@plt>
  403b9e:	85 c0                	test   eax,eax
  403ba0:	0f 84 33 da ff ff    	je     4015d9 <win+0x63>
  403ba6:	e9 16 da ff ff       	jmp    4015c1 <win+0x4b>
  403bab:	ba 00 01 00 00       	mov    edx,0x100
  403bb0:	48 89 ee             	mov    rsi,rbp
  403bb3:	e8 48 d6 ff ff       	call   401200 <read@plt>
  403bb8:	85 c0                	test   eax,eax
  403bba:	7f 2a                	jg     403be6 <win+0x2670>
  403bbc:	e8 bf d5 ff ff       	call   401180 <__errno_location@plt>
  403bc1:	8b 38                	mov    edi,DWORD PTR [rax]
  403bc3:	e8 b8 d6 ff ff       	call   401280 <strerror@plt>
  403bc8:	bf 01 00 00 00       	mov    edi,0x1
  403bcd:	48 8d 35 d5 e4 00 00 	lea    rsi,[rip+0xe4d5]        # 4120a9 <_IO_stdin_used+0xa9>
  403bd4:	48 89 c2             	mov    rdx,rax
  403bd7:	31 c0                	xor    eax,eax
  403bd9:	e8 52 d6 ff ff       	call   401230 <__printf_chk@plt>
  403bde:	83 cf ff             	or     edi,0xffffffff
  403be1:	e8 7a d6 ff ff       	call   401260 <exit@plt>
  403be6:	48 63 d0             	movsxd rdx,eax
  403be9:	48 89 ee             	mov    rsi,rbp
  403bec:	bf 01 00 00 00       	mov    edi,0x1
  403bf1:	e8 aa d5 ff ff       	call   4011a0 <write@plt>
  403bf6:	48 8d 3d 57 e5 00 00 	lea    rdi,[rip+0xe557]        # 412154 <_IO_stdin_used+0x154>
  403bfd:	e8 8e d5 ff ff       	call   401190 <puts@plt>
  403c02:	48 8d 3d fb e3 00 00 	lea    rdi,[rip+0xe3fb]        # 412004 <_IO_stdin_used+0x4>
  403c09:	31 f6                	xor    esi,esi
  403c0b:	31 c0                	xor    eax,eax
  403c0d:	e8 3e d6 ff ff       	call   401250 <open@plt>
  403c12:	89 c7                	mov    edi,eax
  403c14:	85 c0                	test   eax,eax
  403c16:	79 34                	jns    403c4c <win+0x26d6>
  403c18:	e8 63 d5 ff ff       	call   401180 <__errno_location@plt>
  403c1d:	8b 38                	mov    edi,DWORD PTR [rax]
  403c1f:	e8 5c d6 ff ff       	call   401280 <strerror@plt>
  403c24:	48 8d 35 df e3 00 00 	lea    rsi,[rip+0xe3df]        # 41200a <_IO_stdin_used+0xa>
  403c2b:	bf 01 00 00 00       	mov    edi,0x1
  403c30:	48 89 c2             	mov    rdx,rax
  403c33:	31 c0                	xor    eax,eax
  403c35:	e8 f6 d5 ff ff       	call   401230 <__printf_chk@plt>
  403c3a:	e8 a1 d5 ff ff       	call   4011e0 <geteuid@plt>
  403c3f:	85 c0                	test   eax,eax
  403c41:	0f 84 92 d9 ff ff    	je     4015d9 <win+0x63>
  403c47:	e9 75 d9 ff ff       	jmp    4015c1 <win+0x4b>
  403c4c:	ba 00 01 00 00       	mov    edx,0x100
  403c51:	48 89 ee             	mov    rsi,rbp
  403c54:	e8 a7 d5 ff ff       	call   401200 <read@plt>
  403c59:	85 c0                	test   eax,eax
  403c5b:	7f 2a                	jg     403c87 <win+0x2711>
  403c5d:	e8 1e d5 ff ff       	call   401180 <__errno_location@plt>
  403c62:	8b 38                	mov    edi,DWORD PTR [rax]
  403c64:	e8 17 d6 ff ff       	call   401280 <strerror@plt>
  403c69:	bf 01 00 00 00       	mov    edi,0x1
  403c6e:	48 8d 35 34 e4 00 00 	lea    rsi,[rip+0xe434]        # 4120a9 <_IO_stdin_used+0xa9>
  403c75:	48 89 c2             	mov    rdx,rax
  403c78:	31 c0                	xor    eax,eax
  403c7a:	e8 b1 d5 ff ff       	call   401230 <__printf_chk@plt>
  403c7f:	83 cf ff             	or     edi,0xffffffff
  403c82:	e8 d9 d5 ff ff       	call   401260 <exit@plt>
  403c87:	48 63 d0             	movsxd rdx,eax
  403c8a:	48 89 ee             	mov    rsi,rbp
  403c8d:	bf 01 00 00 00       	mov    edi,0x1
  403c92:	e8 09 d5 ff ff       	call   4011a0 <write@plt>
  403c97:	48 8d 3d b6 e4 00 00 	lea    rdi,[rip+0xe4b6]        # 412154 <_IO_stdin_used+0x154>
  403c9e:	e8 ed d4 ff ff       	call   401190 <puts@plt>
  403ca3:	48 8d 3d 5a e3 00 00 	lea    rdi,[rip+0xe35a]        # 412004 <_IO_stdin_used+0x4>
  403caa:	31 f6                	xor    esi,esi
  403cac:	31 c0                	xor    eax,eax
  403cae:	e8 9d d5 ff ff       	call   401250 <open@plt>
  403cb3:	89 c7                	mov    edi,eax
  403cb5:	85 c0                	test   eax,eax
  403cb7:	79 34                	jns    403ced <win+0x2777>
  403cb9:	e8 c2 d4 ff ff       	call   401180 <__errno_location@plt>
  403cbe:	8b 38                	mov    edi,DWORD PTR [rax]
  403cc0:	e8 bb d5 ff ff       	call   401280 <strerror@plt>
  403cc5:	48 8d 35 3e e3 00 00 	lea    rsi,[rip+0xe33e]        # 41200a <_IO_stdin_used+0xa>
  403ccc:	bf 01 00 00 00       	mov    edi,0x1
  403cd1:	48 89 c2             	mov    rdx,rax
  403cd4:	31 c0                	xor    eax,eax
  403cd6:	e8 55 d5 ff ff       	call   401230 <__printf_chk@plt>
  403cdb:	e8 00 d5 ff ff       	call   4011e0 <geteuid@plt>
  403ce0:	85 c0                	test   eax,eax
  403ce2:	0f 84 f1 d8 ff ff    	je     4015d9 <win+0x63>
  403ce8:	e9 d4 d8 ff ff       	jmp    4015c1 <win+0x4b>
  403ced:	ba 00 01 00 00       	mov    edx,0x100
  403cf2:	48 89 ee             	mov    rsi,rbp
  403cf5:	e8 06 d5 ff ff       	call   401200 <read@plt>
  403cfa:	85 c0                	test   eax,eax
  403cfc:	7f 2a                	jg     403d28 <win+0x27b2>
  403cfe:	e8 7d d4 ff ff       	call   401180 <__errno_location@plt>
  403d03:	8b 38                	mov    edi,DWORD PTR [rax]
  403d05:	e8 76 d5 ff ff       	call   401280 <strerror@plt>
  403d0a:	bf 01 00 00 00       	mov    edi,0x1
  403d0f:	48 8d 35 93 e3 00 00 	lea    rsi,[rip+0xe393]        # 4120a9 <_IO_stdin_used+0xa9>
  403d16:	48 89 c2             	mov    rdx,rax
  403d19:	31 c0                	xor    eax,eax
  403d1b:	e8 10 d5 ff ff       	call   401230 <__printf_chk@plt>
  403d20:	83 cf ff             	or     edi,0xffffffff
  403d23:	e8 38 d5 ff ff       	call   401260 <exit@plt>
  403d28:	48 63 d0             	movsxd rdx,eax
  403d2b:	48 89 ee             	mov    rsi,rbp
  403d2e:	bf 01 00 00 00       	mov    edi,0x1
  403d33:	e8 68 d4 ff ff       	call   4011a0 <write@plt>
  403d38:	48 8d 3d 15 e4 00 00 	lea    rdi,[rip+0xe415]        # 412154 <_IO_stdin_used+0x154>
  403d3f:	e8 4c d4 ff ff       	call   401190 <puts@plt>
  403d44:	48 8d 3d b9 e2 00 00 	lea    rdi,[rip+0xe2b9]        # 412004 <_IO_stdin_used+0x4>
  403d4b:	31 f6                	xor    esi,esi
  403d4d:	31 c0                	xor    eax,eax
  403d4f:	e8 fc d4 ff ff       	call   401250 <open@plt>
  403d54:	89 c7                	mov    edi,eax
  403d56:	85 c0                	test   eax,eax
  403d58:	79 34                	jns    403d8e <win+0x2818>
  403d5a:	e8 21 d4 ff ff       	call   401180 <__errno_location@plt>
  403d5f:	8b 38                	mov    edi,DWORD PTR [rax]
  403d61:	e8 1a d5 ff ff       	call   401280 <strerror@plt>
  403d66:	48 8d 35 9d e2 00 00 	lea    rsi,[rip+0xe29d]        # 41200a <_IO_stdin_used+0xa>
  403d6d:	bf 01 00 00 00       	mov    edi,0x1
  403d72:	48 89 c2             	mov    rdx,rax
  403d75:	31 c0                	xor    eax,eax
  403d77:	e8 b4 d4 ff ff       	call   401230 <__printf_chk@plt>
  403d7c:	e8 5f d4 ff ff       	call   4011e0 <geteuid@plt>
  403d81:	85 c0                	test   eax,eax
  403d83:	0f 84 50 d8 ff ff    	je     4015d9 <win+0x63>
  403d89:	e9 33 d8 ff ff       	jmp    4015c1 <win+0x4b>
  403d8e:	ba 00 01 00 00       	mov    edx,0x100
  403d93:	48 89 ee             	mov    rsi,rbp
  403d96:	e8 65 d4 ff ff       	call   401200 <read@plt>
  403d9b:	85 c0                	test   eax,eax
  403d9d:	7f 2a                	jg     403dc9 <win+0x2853>
  403d9f:	e8 dc d3 ff ff       	call   401180 <__errno_location@plt>
  403da4:	8b 38                	mov    edi,DWORD PTR [rax]
  403da6:	e8 d5 d4 ff ff       	call   401280 <strerror@plt>
  403dab:	bf 01 00 00 00       	mov    edi,0x1
  403db0:	48 8d 35 f2 e2 00 00 	lea    rsi,[rip+0xe2f2]        # 4120a9 <_IO_stdin_used+0xa9>
  403db7:	48 89 c2             	mov    rdx,rax
  403dba:	31 c0                	xor    eax,eax
  403dbc:	e8 6f d4 ff ff       	call   401230 <__printf_chk@plt>
  403dc1:	83 cf ff             	or     edi,0xffffffff
  403dc4:	e8 97 d4 ff ff       	call   401260 <exit@plt>
  403dc9:	48 63 d0             	movsxd rdx,eax
  403dcc:	48 89 ee             	mov    rsi,rbp
  403dcf:	bf 01 00 00 00       	mov    edi,0x1
  403dd4:	e8 c7 d3 ff ff       	call   4011a0 <write@plt>
  403dd9:	48 8d 3d 74 e3 00 00 	lea    rdi,[rip+0xe374]        # 412154 <_IO_stdin_used+0x154>
  403de0:	e8 ab d3 ff ff       	call   401190 <puts@plt>
  403de5:	48 8d 3d 18 e2 00 00 	lea    rdi,[rip+0xe218]        # 412004 <_IO_stdin_used+0x4>
  403dec:	31 f6                	xor    esi,esi
  403dee:	31 c0                	xor    eax,eax
  403df0:	e8 5b d4 ff ff       	call   401250 <open@plt>
  403df5:	89 c7                	mov    edi,eax
  403df7:	85 c0                	test   eax,eax
  403df9:	79 34                	jns    403e2f <win+0x28b9>
  403dfb:	e8 80 d3 ff ff       	call   401180 <__errno_location@plt>
  403e00:	8b 38                	mov    edi,DWORD PTR [rax]
  403e02:	e8 79 d4 ff ff       	call   401280 <strerror@plt>
  403e07:	48 8d 35 fc e1 00 00 	lea    rsi,[rip+0xe1fc]        # 41200a <_IO_stdin_used+0xa>
  403e0e:	bf 01 00 00 00       	mov    edi,0x1
  403e13:	48 89 c2             	mov    rdx,rax
  403e16:	31 c0                	xor    eax,eax
  403e18:	e8 13 d4 ff ff       	call   401230 <__printf_chk@plt>
  403e1d:	e8 be d3 ff ff       	call   4011e0 <geteuid@plt>
  403e22:	85 c0                	test   eax,eax
  403e24:	0f 84 af d7 ff ff    	je     4015d9 <win+0x63>
  403e2a:	e9 92 d7 ff ff       	jmp    4015c1 <win+0x4b>
  403e2f:	ba 00 01 00 00       	mov    edx,0x100
  403e34:	48 89 ee             	mov    rsi,rbp
  403e37:	e8 c4 d3 ff ff       	call   401200 <read@plt>
  403e3c:	85 c0                	test   eax,eax
  403e3e:	7f 2a                	jg     403e6a <win+0x28f4>
  403e40:	e8 3b d3 ff ff       	call   401180 <__errno_location@plt>
  403e45:	8b 38                	mov    edi,DWORD PTR [rax]
  403e47:	e8 34 d4 ff ff       	call   401280 <strerror@plt>
  403e4c:	bf 01 00 00 00       	mov    edi,0x1
  403e51:	48 8d 35 51 e2 00 00 	lea    rsi,[rip+0xe251]        # 4120a9 <_IO_stdin_used+0xa9>
  403e58:	48 89 c2             	mov    rdx,rax
  403e5b:	31 c0                	xor    eax,eax
  403e5d:	e8 ce d3 ff ff       	call   401230 <__printf_chk@plt>
  403e62:	83 cf ff             	or     edi,0xffffffff
  403e65:	e8 f6 d3 ff ff       	call   401260 <exit@plt>
  403e6a:	48 63 d0             	movsxd rdx,eax
  403e6d:	48 89 ee             	mov    rsi,rbp
  403e70:	bf 01 00 00 00       	mov    edi,0x1
  403e75:	e8 26 d3 ff ff       	call   4011a0 <write@plt>
  403e7a:	48 8d 3d d3 e2 00 00 	lea    rdi,[rip+0xe2d3]        # 412154 <_IO_stdin_used+0x154>
  403e81:	e8 0a d3 ff ff       	call   401190 <puts@plt>
  403e86:	48 8d 3d 77 e1 00 00 	lea    rdi,[rip+0xe177]        # 412004 <_IO_stdin_used+0x4>
  403e8d:	31 f6                	xor    esi,esi
  403e8f:	31 c0                	xor    eax,eax
  403e91:	e8 ba d3 ff ff       	call   401250 <open@plt>
  403e96:	89 c7                	mov    edi,eax
  403e98:	85 c0                	test   eax,eax
  403e9a:	79 34                	jns    403ed0 <win+0x295a>
  403e9c:	e8 df d2 ff ff       	call   401180 <__errno_location@plt>
  403ea1:	8b 38                	mov    edi,DWORD PTR [rax]
  403ea3:	e8 d8 d3 ff ff       	call   401280 <strerror@plt>
  403ea8:	48 8d 35 5b e1 00 00 	lea    rsi,[rip+0xe15b]        # 41200a <_IO_stdin_used+0xa>
  403eaf:	bf 01 00 00 00       	mov    edi,0x1
  403eb4:	48 89 c2             	mov    rdx,rax
  403eb7:	31 c0                	xor    eax,eax
  403eb9:	e8 72 d3 ff ff       	call   401230 <__printf_chk@plt>
  403ebe:	e8 1d d3 ff ff       	call   4011e0 <geteuid@plt>
  403ec3:	85 c0                	test   eax,eax
  403ec5:	0f 84 0e d7 ff ff    	je     4015d9 <win+0x63>
  403ecb:	e9 f1 d6 ff ff       	jmp    4015c1 <win+0x4b>
  403ed0:	ba 00 01 00 00       	mov    edx,0x100
  403ed5:	48 89 ee             	mov    rsi,rbp
  403ed8:	e8 23 d3 ff ff       	call   401200 <read@plt>
  403edd:	85 c0                	test   eax,eax
  403edf:	7f 2a                	jg     403f0b <win+0x2995>
  403ee1:	e8 9a d2 ff ff       	call   401180 <__errno_location@plt>
  403ee6:	8b 38                	mov    edi,DWORD PTR [rax]
  403ee8:	e8 93 d3 ff ff       	call   401280 <strerror@plt>
  403eed:	bf 01 00 00 00       	mov    edi,0x1
  403ef2:	48 8d 35 b0 e1 00 00 	lea    rsi,[rip+0xe1b0]        # 4120a9 <_IO_stdin_used+0xa9>
  403ef9:	48 89 c2             	mov    rdx,rax
  403efc:	31 c0                	xor    eax,eax
  403efe:	e8 2d d3 ff ff       	call   401230 <__printf_chk@plt>
  403f03:	83 cf ff             	or     edi,0xffffffff
  403f06:	e8 55 d3 ff ff       	call   401260 <exit@plt>
  403f0b:	48 63 d0             	movsxd rdx,eax
  403f0e:	48 89 ee             	mov    rsi,rbp
  403f11:	bf 01 00 00 00       	mov    edi,0x1
  403f16:	e8 85 d2 ff ff       	call   4011a0 <write@plt>
  403f1b:	48 8d 3d 32 e2 00 00 	lea    rdi,[rip+0xe232]        # 412154 <_IO_stdin_used+0x154>
  403f22:	e8 69 d2 ff ff       	call   401190 <puts@plt>
  403f27:	48 8d 3d d6 e0 00 00 	lea    rdi,[rip+0xe0d6]        # 412004 <_IO_stdin_used+0x4>
  403f2e:	31 f6                	xor    esi,esi
  403f30:	31 c0                	xor    eax,eax
  403f32:	e8 19 d3 ff ff       	call   401250 <open@plt>
  403f37:	89 c7                	mov    edi,eax
  403f39:	85 c0                	test   eax,eax
  403f3b:	79 34                	jns    403f71 <win+0x29fb>
  403f3d:	e8 3e d2 ff ff       	call   401180 <__errno_location@plt>
  403f42:	8b 38                	mov    edi,DWORD PTR [rax]
  403f44:	e8 37 d3 ff ff       	call   401280 <strerror@plt>
  403f49:	48 8d 35 ba e0 00 00 	lea    rsi,[rip+0xe0ba]        # 41200a <_IO_stdin_used+0xa>
  403f50:	bf 01 00 00 00       	mov    edi,0x1
  403f55:	48 89 c2             	mov    rdx,rax
  403f58:	31 c0                	xor    eax,eax
  403f5a:	e8 d1 d2 ff ff       	call   401230 <__printf_chk@plt>
  403f5f:	e8 7c d2 ff ff       	call   4011e0 <geteuid@plt>
  403f64:	85 c0                	test   eax,eax
  403f66:	0f 84 6d d6 ff ff    	je     4015d9 <win+0x63>
  403f6c:	e9 50 d6 ff ff       	jmp    4015c1 <win+0x4b>
  403f71:	ba 00 01 00 00       	mov    edx,0x100
  403f76:	48 89 ee             	mov    rsi,rbp
  403f79:	e8 82 d2 ff ff       	call   401200 <read@plt>
  403f7e:	85 c0                	test   eax,eax
  403f80:	7f 2a                	jg     403fac <win+0x2a36>
  403f82:	e8 f9 d1 ff ff       	call   401180 <__errno_location@plt>
  403f87:	8b 38                	mov    edi,DWORD PTR [rax]
  403f89:	e8 f2 d2 ff ff       	call   401280 <strerror@plt>
  403f8e:	bf 01 00 00 00       	mov    edi,0x1
  403f93:	48 8d 35 0f e1 00 00 	lea    rsi,[rip+0xe10f]        # 4120a9 <_IO_stdin_used+0xa9>
  403f9a:	48 89 c2             	mov    rdx,rax
  403f9d:	31 c0                	xor    eax,eax
  403f9f:	e8 8c d2 ff ff       	call   401230 <__printf_chk@plt>
  403fa4:	83 cf ff             	or     edi,0xffffffff
  403fa7:	e8 b4 d2 ff ff       	call   401260 <exit@plt>
  403fac:	48 63 d0             	movsxd rdx,eax
  403faf:	48 89 ee             	mov    rsi,rbp
  403fb2:	bf 01 00 00 00       	mov    edi,0x1
  403fb7:	e8 e4 d1 ff ff       	call   4011a0 <write@plt>
  403fbc:	48 8d 3d 91 e1 00 00 	lea    rdi,[rip+0xe191]        # 412154 <_IO_stdin_used+0x154>
  403fc3:	e8 c8 d1 ff ff       	call   401190 <puts@plt>
  403fc8:	48 8d 3d 35 e0 00 00 	lea    rdi,[rip+0xe035]        # 412004 <_IO_stdin_used+0x4>
  403fcf:	31 f6                	xor    esi,esi
  403fd1:	31 c0                	xor    eax,eax
  403fd3:	e8 78 d2 ff ff       	call   401250 <open@plt>
  403fd8:	89 c7                	mov    edi,eax
  403fda:	85 c0                	test   eax,eax
  403fdc:	79 34                	jns    404012 <win+0x2a9c>
  403fde:	e8 9d d1 ff ff       	call   401180 <__errno_location@plt>
  403fe3:	8b 38                	mov    edi,DWORD PTR [rax]
  403fe5:	e8 96 d2 ff ff       	call   401280 <strerror@plt>
  403fea:	48 8d 35 19 e0 00 00 	lea    rsi,[rip+0xe019]        # 41200a <_IO_stdin_used+0xa>
  403ff1:	bf 01 00 00 00       	mov    edi,0x1
  403ff6:	48 89 c2             	mov    rdx,rax
  403ff9:	31 c0                	xor    eax,eax
  403ffb:	e8 30 d2 ff ff       	call   401230 <__printf_chk@plt>
  404000:	e8 db d1 ff ff       	call   4011e0 <geteuid@plt>
  404005:	85 c0                	test   eax,eax
  404007:	0f 84 cc d5 ff ff    	je     4015d9 <win+0x63>
  40400d:	e9 af d5 ff ff       	jmp    4015c1 <win+0x4b>
  404012:	ba 00 01 00 00       	mov    edx,0x100
  404017:	48 89 ee             	mov    rsi,rbp
  40401a:	e8 e1 d1 ff ff       	call   401200 <read@plt>
  40401f:	85 c0                	test   eax,eax
  404021:	7f 2a                	jg     40404d <win+0x2ad7>
  404023:	e8 58 d1 ff ff       	call   401180 <__errno_location@plt>
  404028:	8b 38                	mov    edi,DWORD PTR [rax]
  40402a:	e8 51 d2 ff ff       	call   401280 <strerror@plt>
  40402f:	bf 01 00 00 00       	mov    edi,0x1
  404034:	48 8d 35 6e e0 00 00 	lea    rsi,[rip+0xe06e]        # 4120a9 <_IO_stdin_used+0xa9>
  40403b:	48 89 c2             	mov    rdx,rax
  40403e:	31 c0                	xor    eax,eax
  404040:	e8 eb d1 ff ff       	call   401230 <__printf_chk@plt>
  404045:	83 cf ff             	or     edi,0xffffffff
  404048:	e8 13 d2 ff ff       	call   401260 <exit@plt>
  40404d:	48 63 d0             	movsxd rdx,eax
  404050:	48 89 ee             	mov    rsi,rbp
  404053:	bf 01 00 00 00       	mov    edi,0x1
  404058:	e8 43 d1 ff ff       	call   4011a0 <write@plt>
  40405d:	48 8d 3d f0 e0 00 00 	lea    rdi,[rip+0xe0f0]        # 412154 <_IO_stdin_used+0x154>
  404064:	e8 27 d1 ff ff       	call   401190 <puts@plt>
  404069:	48 8d 3d 94 df 00 00 	lea    rdi,[rip+0xdf94]        # 412004 <_IO_stdin_used+0x4>
  404070:	31 f6                	xor    esi,esi
  404072:	31 c0                	xor    eax,eax
  404074:	e8 d7 d1 ff ff       	call   401250 <open@plt>
  404079:	89 c7                	mov    edi,eax
  40407b:	85 c0                	test   eax,eax
  40407d:	79 34                	jns    4040b3 <win+0x2b3d>
  40407f:	e8 fc d0 ff ff       	call   401180 <__errno_location@plt>
  404084:	8b 38                	mov    edi,DWORD PTR [rax]
  404086:	e8 f5 d1 ff ff       	call   401280 <strerror@plt>
  40408b:	48 8d 35 78 df 00 00 	lea    rsi,[rip+0xdf78]        # 41200a <_IO_stdin_used+0xa>
  404092:	bf 01 00 00 00       	mov    edi,0x1
  404097:	48 89 c2             	mov    rdx,rax
  40409a:	31 c0                	xor    eax,eax
  40409c:	e8 8f d1 ff ff       	call   401230 <__printf_chk@plt>
  4040a1:	e8 3a d1 ff ff       	call   4011e0 <geteuid@plt>
  4040a6:	85 c0                	test   eax,eax
  4040a8:	0f 84 2b d5 ff ff    	je     4015d9 <win+0x63>
  4040ae:	e9 0e d5 ff ff       	jmp    4015c1 <win+0x4b>
  4040b3:	ba 00 01 00 00       	mov    edx,0x100
  4040b8:	48 89 ee             	mov    rsi,rbp
  4040bb:	e8 40 d1 ff ff       	call   401200 <read@plt>
  4040c0:	85 c0                	test   eax,eax
  4040c2:	7f 2a                	jg     4040ee <win+0x2b78>
  4040c4:	e8 b7 d0 ff ff       	call   401180 <__errno_location@plt>
  4040c9:	8b 38                	mov    edi,DWORD PTR [rax]
  4040cb:	e8 b0 d1 ff ff       	call   401280 <strerror@plt>
  4040d0:	bf 01 00 00 00       	mov    edi,0x1
  4040d5:	48 8d 35 cd df 00 00 	lea    rsi,[rip+0xdfcd]        # 4120a9 <_IO_stdin_used+0xa9>
  4040dc:	48 89 c2             	mov    rdx,rax
  4040df:	31 c0                	xor    eax,eax
  4040e1:	e8 4a d1 ff ff       	call   401230 <__printf_chk@plt>
  4040e6:	83 cf ff             	or     edi,0xffffffff
  4040e9:	e8 72 d1 ff ff       	call   401260 <exit@plt>
  4040ee:	48 63 d0             	movsxd rdx,eax
  4040f1:	48 89 ee             	mov    rsi,rbp
  4040f4:	bf 01 00 00 00       	mov    edi,0x1
  4040f9:	e8 a2 d0 ff ff       	call   4011a0 <write@plt>
  4040fe:	48 8d 3d 4f e0 00 00 	lea    rdi,[rip+0xe04f]        # 412154 <_IO_stdin_used+0x154>
  404105:	e8 86 d0 ff ff       	call   401190 <puts@plt>
  40410a:	48 8d 3d f3 de 00 00 	lea    rdi,[rip+0xdef3]        # 412004 <_IO_stdin_used+0x4>
  404111:	31 f6                	xor    esi,esi
  404113:	31 c0                	xor    eax,eax
  404115:	e8 36 d1 ff ff       	call   401250 <open@plt>
  40411a:	89 c7                	mov    edi,eax
  40411c:	85 c0                	test   eax,eax
  40411e:	79 34                	jns    404154 <win+0x2bde>
  404120:	e8 5b d0 ff ff       	call   401180 <__errno_location@plt>
  404125:	8b 38                	mov    edi,DWORD PTR [rax]
  404127:	e8 54 d1 ff ff       	call   401280 <strerror@plt>
  40412c:	48 8d 35 d7 de 00 00 	lea    rsi,[rip+0xded7]        # 41200a <_IO_stdin_used+0xa>
  404133:	bf 01 00 00 00       	mov    edi,0x1
  404138:	48 89 c2             	mov    rdx,rax
  40413b:	31 c0                	xor    eax,eax
  40413d:	e8 ee d0 ff ff       	call   401230 <__printf_chk@plt>
  404142:	e8 99 d0 ff ff       	call   4011e0 <geteuid@plt>
  404147:	85 c0                	test   eax,eax
  404149:	0f 84 8a d4 ff ff    	je     4015d9 <win+0x63>
  40414f:	e9 6d d4 ff ff       	jmp    4015c1 <win+0x4b>
  404154:	ba 00 01 00 00       	mov    edx,0x100
  404159:	48 89 ee             	mov    rsi,rbp
  40415c:	e8 9f d0 ff ff       	call   401200 <read@plt>
  404161:	85 c0                	test   eax,eax
  404163:	7f 2a                	jg     40418f <win+0x2c19>
  404165:	e8 16 d0 ff ff       	call   401180 <__errno_location@plt>
  40416a:	8b 38                	mov    edi,DWORD PTR [rax]
  40416c:	e8 0f d1 ff ff       	call   401280 <strerror@plt>
  404171:	bf 01 00 00 00       	mov    edi,0x1
  404176:	48 8d 35 2c df 00 00 	lea    rsi,[rip+0xdf2c]        # 4120a9 <_IO_stdin_used+0xa9>
  40417d:	48 89 c2             	mov    rdx,rax
  404180:	31 c0                	xor    eax,eax
  404182:	e8 a9 d0 ff ff       	call   401230 <__printf_chk@plt>
  404187:	83 cf ff             	or     edi,0xffffffff
  40418a:	e8 d1 d0 ff ff       	call   401260 <exit@plt>
  40418f:	48 63 d0             	movsxd rdx,eax
  404192:	48 89 ee             	mov    rsi,rbp
  404195:	bf 01 00 00 00       	mov    edi,0x1
  40419a:	e8 01 d0 ff ff       	call   4011a0 <write@plt>
  40419f:	48 8d 3d ae df 00 00 	lea    rdi,[rip+0xdfae]        # 412154 <_IO_stdin_used+0x154>
  4041a6:	e8 e5 cf ff ff       	call   401190 <puts@plt>
  4041ab:	48 8d 3d 52 de 00 00 	lea    rdi,[rip+0xde52]        # 412004 <_IO_stdin_used+0x4>
  4041b2:	31 f6                	xor    esi,esi
  4041b4:	31 c0                	xor    eax,eax
  4041b6:	e8 95 d0 ff ff       	call   401250 <open@plt>
  4041bb:	89 c7                	mov    edi,eax
  4041bd:	85 c0                	test   eax,eax
  4041bf:	79 34                	jns    4041f5 <win+0x2c7f>
  4041c1:	e8 ba cf ff ff       	call   401180 <__errno_location@plt>
  4041c6:	8b 38                	mov    edi,DWORD PTR [rax]
  4041c8:	e8 b3 d0 ff ff       	call   401280 <strerror@plt>
  4041cd:	48 8d 35 36 de 00 00 	lea    rsi,[rip+0xde36]        # 41200a <_IO_stdin_used+0xa>
  4041d4:	bf 01 00 00 00       	mov    edi,0x1
  4041d9:	48 89 c2             	mov    rdx,rax
  4041dc:	31 c0                	xor    eax,eax
  4041de:	e8 4d d0 ff ff       	call   401230 <__printf_chk@plt>
  4041e3:	e8 f8 cf ff ff       	call   4011e0 <geteuid@plt>
  4041e8:	85 c0                	test   eax,eax
  4041ea:	0f 84 e9 d3 ff ff    	je     4015d9 <win+0x63>
  4041f0:	e9 cc d3 ff ff       	jmp    4015c1 <win+0x4b>
  4041f5:	ba 00 01 00 00       	mov    edx,0x100
  4041fa:	48 89 ee             	mov    rsi,rbp
  4041fd:	e8 fe cf ff ff       	call   401200 <read@plt>
  404202:	85 c0                	test   eax,eax
  404204:	7f 2a                	jg     404230 <win+0x2cba>
  404206:	e8 75 cf ff ff       	call   401180 <__errno_location@plt>
  40420b:	8b 38                	mov    edi,DWORD PTR [rax]
  40420d:	e8 6e d0 ff ff       	call   401280 <strerror@plt>
  404212:	bf 01 00 00 00       	mov    edi,0x1
  404217:	48 8d 35 8b de 00 00 	lea    rsi,[rip+0xde8b]        # 4120a9 <_IO_stdin_used+0xa9>
  40421e:	48 89 c2             	mov    rdx,rax
  404221:	31 c0                	xor    eax,eax
  404223:	e8 08 d0 ff ff       	call   401230 <__printf_chk@plt>
  404228:	83 cf ff             	or     edi,0xffffffff
  40422b:	e8 30 d0 ff ff       	call   401260 <exit@plt>
  404230:	48 63 d0             	movsxd rdx,eax
  404233:	48 89 ee             	mov    rsi,rbp
  404236:	bf 01 00 00 00       	mov    edi,0x1
  40423b:	e8 60 cf ff ff       	call   4011a0 <write@plt>
  404240:	48 8d 3d 0d df 00 00 	lea    rdi,[rip+0xdf0d]        # 412154 <_IO_stdin_used+0x154>
  404247:	e8 44 cf ff ff       	call   401190 <puts@plt>
  40424c:	48 8d 3d b1 dd 00 00 	lea    rdi,[rip+0xddb1]        # 412004 <_IO_stdin_used+0x4>
  404253:	31 f6                	xor    esi,esi
  404255:	31 c0                	xor    eax,eax
  404257:	e8 f4 cf ff ff       	call   401250 <open@plt>
  40425c:	89 c7                	mov    edi,eax
  40425e:	85 c0                	test   eax,eax
  404260:	79 34                	jns    404296 <win+0x2d20>
  404262:	e8 19 cf ff ff       	call   401180 <__errno_location@plt>
  404267:	8b 38                	mov    edi,DWORD PTR [rax]
  404269:	e8 12 d0 ff ff       	call   401280 <strerror@plt>
  40426e:	48 8d 35 95 dd 00 00 	lea    rsi,[rip+0xdd95]        # 41200a <_IO_stdin_used+0xa>
  404275:	bf 01 00 00 00       	mov    edi,0x1
  40427a:	48 89 c2             	mov    rdx,rax
  40427d:	31 c0                	xor    eax,eax
  40427f:	e8 ac cf ff ff       	call   401230 <__printf_chk@plt>
  404284:	e8 57 cf ff ff       	call   4011e0 <geteuid@plt>
  404289:	85 c0                	test   eax,eax
  40428b:	0f 84 48 d3 ff ff    	je     4015d9 <win+0x63>
  404291:	e9 2b d3 ff ff       	jmp    4015c1 <win+0x4b>
  404296:	ba 00 01 00 00       	mov    edx,0x100
  40429b:	48 89 ee             	mov    rsi,rbp
  40429e:	e8 5d cf ff ff       	call   401200 <read@plt>
  4042a3:	85 c0                	test   eax,eax
  4042a5:	7f 2a                	jg     4042d1 <win+0x2d5b>
  4042a7:	e8 d4 ce ff ff       	call   401180 <__errno_location@plt>
  4042ac:	8b 38                	mov    edi,DWORD PTR [rax]
  4042ae:	e8 cd cf ff ff       	call   401280 <strerror@plt>
  4042b3:	bf 01 00 00 00       	mov    edi,0x1
  4042b8:	48 8d 35 ea dd 00 00 	lea    rsi,[rip+0xddea]        # 4120a9 <_IO_stdin_used+0xa9>
  4042bf:	48 89 c2             	mov    rdx,rax
  4042c2:	31 c0                	xor    eax,eax
  4042c4:	e8 67 cf ff ff       	call   401230 <__printf_chk@plt>
  4042c9:	83 cf ff             	or     edi,0xffffffff
  4042cc:	e8 8f cf ff ff       	call   401260 <exit@plt>
  4042d1:	48 63 d0             	movsxd rdx,eax
  4042d4:	48 89 ee             	mov    rsi,rbp
  4042d7:	bf 01 00 00 00       	mov    edi,0x1
  4042dc:	e8 bf ce ff ff       	call   4011a0 <write@plt>
  4042e1:	48 8d 3d 6c de 00 00 	lea    rdi,[rip+0xde6c]        # 412154 <_IO_stdin_used+0x154>
  4042e8:	e8 a3 ce ff ff       	call   401190 <puts@plt>
  4042ed:	48 8d 3d 10 dd 00 00 	lea    rdi,[rip+0xdd10]        # 412004 <_IO_stdin_used+0x4>
  4042f4:	31 f6                	xor    esi,esi
  4042f6:	31 c0                	xor    eax,eax
  4042f8:	e8 53 cf ff ff       	call   401250 <open@plt>
  4042fd:	89 c7                	mov    edi,eax
  4042ff:	85 c0                	test   eax,eax
  404301:	79 34                	jns    404337 <win+0x2dc1>
  404303:	e8 78 ce ff ff       	call   401180 <__errno_location@plt>
  404308:	8b 38                	mov    edi,DWORD PTR [rax]
  40430a:	e8 71 cf ff ff       	call   401280 <strerror@plt>
  40430f:	48 8d 35 f4 dc 00 00 	lea    rsi,[rip+0xdcf4]        # 41200a <_IO_stdin_used+0xa>
  404316:	bf 01 00 00 00       	mov    edi,0x1
  40431b:	48 89 c2             	mov    rdx,rax
  40431e:	31 c0                	xor    eax,eax
  404320:	e8 0b cf ff ff       	call   401230 <__printf_chk@plt>
  404325:	e8 b6 ce ff ff       	call   4011e0 <geteuid@plt>
  40432a:	85 c0                	test   eax,eax
  40432c:	0f 84 a7 d2 ff ff    	je     4015d9 <win+0x63>
  404332:	e9 8a d2 ff ff       	jmp    4015c1 <win+0x4b>
  404337:	ba 00 01 00 00       	mov    edx,0x100
  40433c:	48 89 ee             	mov    rsi,rbp
  40433f:	e8 bc ce ff ff       	call   401200 <read@plt>
  404344:	85 c0                	test   eax,eax
  404346:	7f 2a                	jg     404372 <win+0x2dfc>
  404348:	e8 33 ce ff ff       	call   401180 <__errno_location@plt>
  40434d:	8b 38                	mov    edi,DWORD PTR [rax]
  40434f:	e8 2c cf ff ff       	call   401280 <strerror@plt>
  404354:	bf 01 00 00 00       	mov    edi,0x1
  404359:	48 8d 35 49 dd 00 00 	lea    rsi,[rip+0xdd49]        # 4120a9 <_IO_stdin_used+0xa9>
  404360:	48 89 c2             	mov    rdx,rax
  404363:	31 c0                	xor    eax,eax
  404365:	e8 c6 ce ff ff       	call   401230 <__printf_chk@plt>
  40436a:	83 cf ff             	or     edi,0xffffffff
  40436d:	e8 ee ce ff ff       	call   401260 <exit@plt>
  404372:	48 63 d0             	movsxd rdx,eax
  404375:	48 89 ee             	mov    rsi,rbp
  404378:	bf 01 00 00 00       	mov    edi,0x1
  40437d:	e8 1e ce ff ff       	call   4011a0 <write@plt>
  404382:	48 8d 3d cb dd 00 00 	lea    rdi,[rip+0xddcb]        # 412154 <_IO_stdin_used+0x154>
  404389:	e8 02 ce ff ff       	call   401190 <puts@plt>
  40438e:	48 8d 3d 6f dc 00 00 	lea    rdi,[rip+0xdc6f]        # 412004 <_IO_stdin_used+0x4>
  404395:	31 f6                	xor    esi,esi
  404397:	31 c0                	xor    eax,eax
  404399:	e8 b2 ce ff ff       	call   401250 <open@plt>
  40439e:	89 c7                	mov    edi,eax
  4043a0:	85 c0                	test   eax,eax
  4043a2:	79 34                	jns    4043d8 <win+0x2e62>
  4043a4:	e8 d7 cd ff ff       	call   401180 <__errno_location@plt>
  4043a9:	8b 38                	mov    edi,DWORD PTR [rax]
  4043ab:	e8 d0 ce ff ff       	call   401280 <strerror@plt>
  4043b0:	48 8d 35 53 dc 00 00 	lea    rsi,[rip+0xdc53]        # 41200a <_IO_stdin_used+0xa>
  4043b7:	bf 01 00 00 00       	mov    edi,0x1
  4043bc:	48 89 c2             	mov    rdx,rax
  4043bf:	31 c0                	xor    eax,eax
  4043c1:	e8 6a ce ff ff       	call   401230 <__printf_chk@plt>
  4043c6:	e8 15 ce ff ff       	call   4011e0 <geteuid@plt>
  4043cb:	85 c0                	test   eax,eax
  4043cd:	0f 84 06 d2 ff ff    	je     4015d9 <win+0x63>
  4043d3:	e9 e9 d1 ff ff       	jmp    4015c1 <win+0x4b>
  4043d8:	ba 00 01 00 00       	mov    edx,0x100
  4043dd:	48 89 ee             	mov    rsi,rbp
  4043e0:	e8 1b ce ff ff       	call   401200 <read@plt>
  4043e5:	85 c0                	test   eax,eax
  4043e7:	7f 2a                	jg     404413 <win+0x2e9d>
  4043e9:	e8 92 cd ff ff       	call   401180 <__errno_location@plt>
  4043ee:	8b 38                	mov    edi,DWORD PTR [rax]
  4043f0:	e8 8b ce ff ff       	call   401280 <strerror@plt>
  4043f5:	bf 01 00 00 00       	mov    edi,0x1
  4043fa:	48 8d 35 a8 dc 00 00 	lea    rsi,[rip+0xdca8]        # 4120a9 <_IO_stdin_used+0xa9>
  404401:	48 89 c2             	mov    rdx,rax
  404404:	31 c0                	xor    eax,eax
  404406:	e8 25 ce ff ff       	call   401230 <__printf_chk@plt>
  40440b:	83 cf ff             	or     edi,0xffffffff
  40440e:	e8 4d ce ff ff       	call   401260 <exit@plt>
  404413:	48 63 d0             	movsxd rdx,eax
  404416:	48 89 ee             	mov    rsi,rbp
  404419:	bf 01 00 00 00       	mov    edi,0x1
  40441e:	e8 7d cd ff ff       	call   4011a0 <write@plt>
  404423:	48 8d 3d 2a dd 00 00 	lea    rdi,[rip+0xdd2a]        # 412154 <_IO_stdin_used+0x154>
  40442a:	e8 61 cd ff ff       	call   401190 <puts@plt>
  40442f:	48 8d 3d ce db 00 00 	lea    rdi,[rip+0xdbce]        # 412004 <_IO_stdin_used+0x4>
  404436:	31 f6                	xor    esi,esi
  404438:	31 c0                	xor    eax,eax
  40443a:	e8 11 ce ff ff       	call   401250 <open@plt>
  40443f:	89 c7                	mov    edi,eax
  404441:	85 c0                	test   eax,eax
  404443:	79 34                	jns    404479 <win+0x2f03>
  404445:	e8 36 cd ff ff       	call   401180 <__errno_location@plt>
  40444a:	8b 38                	mov    edi,DWORD PTR [rax]
  40444c:	e8 2f ce ff ff       	call   401280 <strerror@plt>
  404451:	48 8d 35 b2 db 00 00 	lea    rsi,[rip+0xdbb2]        # 41200a <_IO_stdin_used+0xa>
  404458:	bf 01 00 00 00       	mov    edi,0x1
  40445d:	48 89 c2             	mov    rdx,rax
  404460:	31 c0                	xor    eax,eax
  404462:	e8 c9 cd ff ff       	call   401230 <__printf_chk@plt>
  404467:	e8 74 cd ff ff       	call   4011e0 <geteuid@plt>
  40446c:	85 c0                	test   eax,eax
  40446e:	0f 84 65 d1 ff ff    	je     4015d9 <win+0x63>
  404474:	e9 48 d1 ff ff       	jmp    4015c1 <win+0x4b>
  404479:	ba 00 01 00 00       	mov    edx,0x100
  40447e:	48 89 ee             	mov    rsi,rbp
  404481:	e8 7a cd ff ff       	call   401200 <read@plt>
  404486:	85 c0                	test   eax,eax
  404488:	7f 2a                	jg     4044b4 <win+0x2f3e>
  40448a:	e8 f1 cc ff ff       	call   401180 <__errno_location@plt>
  40448f:	8b 38                	mov    edi,DWORD PTR [rax]
  404491:	e8 ea cd ff ff       	call   401280 <strerror@plt>
  404496:	bf 01 00 00 00       	mov    edi,0x1
  40449b:	48 8d 35 07 dc 00 00 	lea    rsi,[rip+0xdc07]        # 4120a9 <_IO_stdin_used+0xa9>
  4044a2:	48 89 c2             	mov    rdx,rax
  4044a5:	31 c0                	xor    eax,eax
  4044a7:	e8 84 cd ff ff       	call   401230 <__printf_chk@plt>
  4044ac:	83 cf ff             	or     edi,0xffffffff
  4044af:	e8 ac cd ff ff       	call   401260 <exit@plt>
  4044b4:	48 63 d0             	movsxd rdx,eax
  4044b7:	48 89 ee             	mov    rsi,rbp
  4044ba:	bf 01 00 00 00       	mov    edi,0x1
  4044bf:	e8 dc cc ff ff       	call   4011a0 <write@plt>
  4044c4:	48 8d 3d 89 dc 00 00 	lea    rdi,[rip+0xdc89]        # 412154 <_IO_stdin_used+0x154>
  4044cb:	e8 c0 cc ff ff       	call   401190 <puts@plt>
  4044d0:	48 8d 3d 2d db 00 00 	lea    rdi,[rip+0xdb2d]        # 412004 <_IO_stdin_used+0x4>
  4044d7:	31 f6                	xor    esi,esi
  4044d9:	31 c0                	xor    eax,eax
  4044db:	e8 70 cd ff ff       	call   401250 <open@plt>
  4044e0:	89 c7                	mov    edi,eax
  4044e2:	85 c0                	test   eax,eax
  4044e4:	79 34                	jns    40451a <win+0x2fa4>
  4044e6:	e8 95 cc ff ff       	call   401180 <__errno_location@plt>
  4044eb:	8b 38                	mov    edi,DWORD PTR [rax]
  4044ed:	e8 8e cd ff ff       	call   401280 <strerror@plt>
  4044f2:	48 8d 35 11 db 00 00 	lea    rsi,[rip+0xdb11]        # 41200a <_IO_stdin_used+0xa>
  4044f9:	bf 01 00 00 00       	mov    edi,0x1
  4044fe:	48 89 c2             	mov    rdx,rax
  404501:	31 c0                	xor    eax,eax
  404503:	e8 28 cd ff ff       	call   401230 <__printf_chk@plt>
  404508:	e8 d3 cc ff ff       	call   4011e0 <geteuid@plt>
  40450d:	85 c0                	test   eax,eax
  40450f:	0f 84 c4 d0 ff ff    	je     4015d9 <win+0x63>
  404515:	e9 a7 d0 ff ff       	jmp    4015c1 <win+0x4b>
  40451a:	ba 00 01 00 00       	mov    edx,0x100
  40451f:	48 89 ee             	mov    rsi,rbp
  404522:	e8 d9 cc ff ff       	call   401200 <read@plt>
  404527:	85 c0                	test   eax,eax
  404529:	7f 2a                	jg     404555 <win+0x2fdf>
  40452b:	e8 50 cc ff ff       	call   401180 <__errno_location@plt>
  404530:	8b 38                	mov    edi,DWORD PTR [rax]
  404532:	e8 49 cd ff ff       	call   401280 <strerror@plt>
  404537:	bf 01 00 00 00       	mov    edi,0x1
  40453c:	48 8d 35 66 db 00 00 	lea    rsi,[rip+0xdb66]        # 4120a9 <_IO_stdin_used+0xa9>
  404543:	48 89 c2             	mov    rdx,rax
  404546:	31 c0                	xor    eax,eax
  404548:	e8 e3 cc ff ff       	call   401230 <__printf_chk@plt>
  40454d:	83 cf ff             	or     edi,0xffffffff
  404550:	e8 0b cd ff ff       	call   401260 <exit@plt>
  404555:	48 63 d0             	movsxd rdx,eax
  404558:	48 89 ee             	mov    rsi,rbp
  40455b:	bf 01 00 00 00       	mov    edi,0x1
  404560:	e8 3b cc ff ff       	call   4011a0 <write@plt>
  404565:	48 8d 3d e8 db 00 00 	lea    rdi,[rip+0xdbe8]        # 412154 <_IO_stdin_used+0x154>
  40456c:	e8 1f cc ff ff       	call   401190 <puts@plt>
  404571:	48 8d 3d 8c da 00 00 	lea    rdi,[rip+0xda8c]        # 412004 <_IO_stdin_used+0x4>
  404578:	31 f6                	xor    esi,esi
  40457a:	31 c0                	xor    eax,eax
  40457c:	e8 cf cc ff ff       	call   401250 <open@plt>
  404581:	89 c7                	mov    edi,eax
  404583:	85 c0                	test   eax,eax
  404585:	79 34                	jns    4045bb <win+0x3045>
  404587:	e8 f4 cb ff ff       	call   401180 <__errno_location@plt>
  40458c:	8b 38                	mov    edi,DWORD PTR [rax]
  40458e:	e8 ed cc ff ff       	call   401280 <strerror@plt>
  404593:	48 8d 35 70 da 00 00 	lea    rsi,[rip+0xda70]        # 41200a <_IO_stdin_used+0xa>
  40459a:	bf 01 00 00 00       	mov    edi,0x1
  40459f:	48 89 c2             	mov    rdx,rax
  4045a2:	31 c0                	xor    eax,eax
  4045a4:	e8 87 cc ff ff       	call   401230 <__printf_chk@plt>
  4045a9:	e8 32 cc ff ff       	call   4011e0 <geteuid@plt>
  4045ae:	85 c0                	test   eax,eax
  4045b0:	0f 84 23 d0 ff ff    	je     4015d9 <win+0x63>
  4045b6:	e9 06 d0 ff ff       	jmp    4015c1 <win+0x4b>
  4045bb:	ba 00 01 00 00       	mov    edx,0x100
  4045c0:	48 89 ee             	mov    rsi,rbp
  4045c3:	e8 38 cc ff ff       	call   401200 <read@plt>
  4045c8:	85 c0                	test   eax,eax
  4045ca:	7f 2a                	jg     4045f6 <win+0x3080>
  4045cc:	e8 af cb ff ff       	call   401180 <__errno_location@plt>
  4045d1:	8b 38                	mov    edi,DWORD PTR [rax]
  4045d3:	e8 a8 cc ff ff       	call   401280 <strerror@plt>
  4045d8:	bf 01 00 00 00       	mov    edi,0x1
  4045dd:	48 8d 35 c5 da 00 00 	lea    rsi,[rip+0xdac5]        # 4120a9 <_IO_stdin_used+0xa9>
  4045e4:	48 89 c2             	mov    rdx,rax
  4045e7:	31 c0                	xor    eax,eax
  4045e9:	e8 42 cc ff ff       	call   401230 <__printf_chk@plt>
  4045ee:	83 cf ff             	or     edi,0xffffffff
  4045f1:	e8 6a cc ff ff       	call   401260 <exit@plt>
  4045f6:	48 63 d0             	movsxd rdx,eax
  4045f9:	48 89 ee             	mov    rsi,rbp
  4045fc:	bf 01 00 00 00       	mov    edi,0x1
  404601:	e8 9a cb ff ff       	call   4011a0 <write@plt>
  404606:	48 8d 3d 47 db 00 00 	lea    rdi,[rip+0xdb47]        # 412154 <_IO_stdin_used+0x154>
  40460d:	e8 7e cb ff ff       	call   401190 <puts@plt>
  404612:	48 8d 3d eb d9 00 00 	lea    rdi,[rip+0xd9eb]        # 412004 <_IO_stdin_used+0x4>
  404619:	31 f6                	xor    esi,esi
  40461b:	31 c0                	xor    eax,eax
  40461d:	e8 2e cc ff ff       	call   401250 <open@plt>
  404622:	89 c7                	mov    edi,eax
  404624:	85 c0                	test   eax,eax
  404626:	79 34                	jns    40465c <win+0x30e6>
  404628:	e8 53 cb ff ff       	call   401180 <__errno_location@plt>
  40462d:	8b 38                	mov    edi,DWORD PTR [rax]
  40462f:	e8 4c cc ff ff       	call   401280 <strerror@plt>
  404634:	48 8d 35 cf d9 00 00 	lea    rsi,[rip+0xd9cf]        # 41200a <_IO_stdin_used+0xa>
  40463b:	bf 01 00 00 00       	mov    edi,0x1
  404640:	48 89 c2             	mov    rdx,rax
  404643:	31 c0                	xor    eax,eax
  404645:	e8 e6 cb ff ff       	call   401230 <__printf_chk@plt>
  40464a:	e8 91 cb ff ff       	call   4011e0 <geteuid@plt>
  40464f:	85 c0                	test   eax,eax
  404651:	0f 84 82 cf ff ff    	je     4015d9 <win+0x63>
  404657:	e9 65 cf ff ff       	jmp    4015c1 <win+0x4b>
  40465c:	ba 00 01 00 00       	mov    edx,0x100
  404661:	48 89 ee             	mov    rsi,rbp
  404664:	e8 97 cb ff ff       	call   401200 <read@plt>
  404669:	85 c0                	test   eax,eax
  40466b:	7f 2a                	jg     404697 <win+0x3121>
  40466d:	e8 0e cb ff ff       	call   401180 <__errno_location@plt>
  404672:	8b 38                	mov    edi,DWORD PTR [rax]
  404674:	e8 07 cc ff ff       	call   401280 <strerror@plt>
  404679:	bf 01 00 00 00       	mov    edi,0x1
  40467e:	48 8d 35 24 da 00 00 	lea    rsi,[rip+0xda24]        # 4120a9 <_IO_stdin_used+0xa9>
  404685:	48 89 c2             	mov    rdx,rax
  404688:	31 c0                	xor    eax,eax
  40468a:	e8 a1 cb ff ff       	call   401230 <__printf_chk@plt>
  40468f:	83 cf ff             	or     edi,0xffffffff
  404692:	e8 c9 cb ff ff       	call   401260 <exit@plt>
  404697:	48 63 d0             	movsxd rdx,eax
  40469a:	48 89 ee             	mov    rsi,rbp
  40469d:	bf 01 00 00 00       	mov    edi,0x1
  4046a2:	e8 f9 ca ff ff       	call   4011a0 <write@plt>
  4046a7:	48 8d 3d a6 da 00 00 	lea    rdi,[rip+0xdaa6]        # 412154 <_IO_stdin_used+0x154>
  4046ae:	e8 dd ca ff ff       	call   401190 <puts@plt>
  4046b3:	48 8d 3d 4a d9 00 00 	lea    rdi,[rip+0xd94a]        # 412004 <_IO_stdin_used+0x4>
  4046ba:	31 f6                	xor    esi,esi
  4046bc:	31 c0                	xor    eax,eax
  4046be:	e8 8d cb ff ff       	call   401250 <open@plt>
  4046c3:	89 c7                	mov    edi,eax
  4046c5:	85 c0                	test   eax,eax
  4046c7:	79 34                	jns    4046fd <win+0x3187>
  4046c9:	e8 b2 ca ff ff       	call   401180 <__errno_location@plt>
  4046ce:	8b 38                	mov    edi,DWORD PTR [rax]
  4046d0:	e8 ab cb ff ff       	call   401280 <strerror@plt>
  4046d5:	48 8d 35 2e d9 00 00 	lea    rsi,[rip+0xd92e]        # 41200a <_IO_stdin_used+0xa>
  4046dc:	bf 01 00 00 00       	mov    edi,0x1
  4046e1:	48 89 c2             	mov    rdx,rax
  4046e4:	31 c0                	xor    eax,eax
  4046e6:	e8 45 cb ff ff       	call   401230 <__printf_chk@plt>
  4046eb:	e8 f0 ca ff ff       	call   4011e0 <geteuid@plt>
  4046f0:	85 c0                	test   eax,eax
  4046f2:	0f 84 e1 ce ff ff    	je     4015d9 <win+0x63>
  4046f8:	e9 c4 ce ff ff       	jmp    4015c1 <win+0x4b>
  4046fd:	ba 00 01 00 00       	mov    edx,0x100
  404702:	48 89 ee             	mov    rsi,rbp
  404705:	e8 f6 ca ff ff       	call   401200 <read@plt>
  40470a:	85 c0                	test   eax,eax
  40470c:	7f 2a                	jg     404738 <win+0x31c2>
  40470e:	e8 6d ca ff ff       	call   401180 <__errno_location@plt>
  404713:	8b 38                	mov    edi,DWORD PTR [rax]
  404715:	e8 66 cb ff ff       	call   401280 <strerror@plt>
  40471a:	bf 01 00 00 00       	mov    edi,0x1
  40471f:	48 8d 35 83 d9 00 00 	lea    rsi,[rip+0xd983]        # 4120a9 <_IO_stdin_used+0xa9>
  404726:	48 89 c2             	mov    rdx,rax
  404729:	31 c0                	xor    eax,eax
  40472b:	e8 00 cb ff ff       	call   401230 <__printf_chk@plt>
  404730:	83 cf ff             	or     edi,0xffffffff
  404733:	e8 28 cb ff ff       	call   401260 <exit@plt>
  404738:	48 63 d0             	movsxd rdx,eax
  40473b:	48 89 ee             	mov    rsi,rbp
  40473e:	bf 01 00 00 00       	mov    edi,0x1
  404743:	e8 58 ca ff ff       	call   4011a0 <write@plt>
  404748:	48 8d 3d 05 da 00 00 	lea    rdi,[rip+0xda05]        # 412154 <_IO_stdin_used+0x154>
  40474f:	e8 3c ca ff ff       	call   401190 <puts@plt>
  404754:	48 8d 3d a9 d8 00 00 	lea    rdi,[rip+0xd8a9]        # 412004 <_IO_stdin_used+0x4>
  40475b:	31 f6                	xor    esi,esi
  40475d:	31 c0                	xor    eax,eax
  40475f:	e8 ec ca ff ff       	call   401250 <open@plt>
  404764:	89 c7                	mov    edi,eax
  404766:	85 c0                	test   eax,eax
  404768:	79 34                	jns    40479e <win+0x3228>
  40476a:	e8 11 ca ff ff       	call   401180 <__errno_location@plt>
  40476f:	8b 38                	mov    edi,DWORD PTR [rax]
  404771:	e8 0a cb ff ff       	call   401280 <strerror@plt>
  404776:	48 8d 35 8d d8 00 00 	lea    rsi,[rip+0xd88d]        # 41200a <_IO_stdin_used+0xa>
  40477d:	bf 01 00 00 00       	mov    edi,0x1
  404782:	48 89 c2             	mov    rdx,rax
  404785:	31 c0                	xor    eax,eax
  404787:	e8 a4 ca ff ff       	call   401230 <__printf_chk@plt>
  40478c:	e8 4f ca ff ff       	call   4011e0 <geteuid@plt>
  404791:	85 c0                	test   eax,eax
  404793:	0f 84 40 ce ff ff    	je     4015d9 <win+0x63>
  404799:	e9 23 ce ff ff       	jmp    4015c1 <win+0x4b>
  40479e:	ba 00 01 00 00       	mov    edx,0x100
  4047a3:	48 89 ee             	mov    rsi,rbp
  4047a6:	e8 55 ca ff ff       	call   401200 <read@plt>
  4047ab:	85 c0                	test   eax,eax
  4047ad:	7f 2a                	jg     4047d9 <win+0x3263>
  4047af:	e8 cc c9 ff ff       	call   401180 <__errno_location@plt>
  4047b4:	8b 38                	mov    edi,DWORD PTR [rax]
  4047b6:	e8 c5 ca ff ff       	call   401280 <strerror@plt>
  4047bb:	bf 01 00 00 00       	mov    edi,0x1
  4047c0:	48 8d 35 e2 d8 00 00 	lea    rsi,[rip+0xd8e2]        # 4120a9 <_IO_stdin_used+0xa9>
  4047c7:	48 89 c2             	mov    rdx,rax
  4047ca:	31 c0                	xor    eax,eax
  4047cc:	e8 5f ca ff ff       	call   401230 <__printf_chk@plt>
  4047d1:	83 cf ff             	or     edi,0xffffffff
  4047d4:	e8 87 ca ff ff       	call   401260 <exit@plt>
  4047d9:	48 89 e5             	mov    rbp,rsp
  4047dc:	48 63 d0             	movsxd rdx,eax
  4047df:	bf 01 00 00 00       	mov    edi,0x1
  4047e4:	48 89 ee             	mov    rsi,rbp
  4047e7:	e8 b4 c9 ff ff       	call   4011a0 <write@plt>
  4047ec:	48 8d 3d 61 d9 00 00 	lea    rdi,[rip+0xd961]        # 412154 <_IO_stdin_used+0x154>
  4047f3:	e8 98 c9 ff ff       	call   401190 <puts@plt>
  4047f8:	48 8d 3d 05 d8 00 00 	lea    rdi,[rip+0xd805]        # 412004 <_IO_stdin_used+0x4>
  4047ff:	31 f6                	xor    esi,esi
  404801:	31 c0                	xor    eax,eax
  404803:	e8 48 ca ff ff       	call   401250 <open@plt>
  404808:	89 c7                	mov    edi,eax
  40480a:	85 c0                	test   eax,eax
  40480c:	79 34                	jns    404842 <win+0x32cc>
  40480e:	e8 6d c9 ff ff       	call   401180 <__errno_location@plt>
  404813:	8b 38                	mov    edi,DWORD PTR [rax]
  404815:	e8 66 ca ff ff       	call   401280 <strerror@plt>
  40481a:	48 8d 35 e9 d7 00 00 	lea    rsi,[rip+0xd7e9]        # 41200a <_IO_stdin_used+0xa>
  404821:	bf 01 00 00 00       	mov    edi,0x1
  404826:	48 89 c2             	mov    rdx,rax
  404829:	31 c0                	xor    eax,eax
  40482b:	e8 00 ca ff ff       	call   401230 <__printf_chk@plt>
  404830:	e8 ab c9 ff ff       	call   4011e0 <geteuid@plt>
  404835:	85 c0                	test   eax,eax
  404837:	0f 84 9c cd ff ff    	je     4015d9 <win+0x63>
  40483d:	e9 7f cd ff ff       	jmp    4015c1 <win+0x4b>
  404842:	ba 00 01 00 00       	mov    edx,0x100
  404847:	48 89 ee             	mov    rsi,rbp
  40484a:	e8 b1 c9 ff ff       	call   401200 <read@plt>
  40484f:	85 c0                	test   eax,eax
  404851:	7f 2a                	jg     40487d <win+0x3307>
  404853:	e8 28 c9 ff ff       	call   401180 <__errno_location@plt>
  404858:	8b 38                	mov    edi,DWORD PTR [rax]
  40485a:	e8 21 ca ff ff       	call   401280 <strerror@plt>
  40485f:	bf 01 00 00 00       	mov    edi,0x1
  404864:	48 8d 35 3e d8 00 00 	lea    rsi,[rip+0xd83e]        # 4120a9 <_IO_stdin_used+0xa9>
  40486b:	48 89 c2             	mov    rdx,rax
  40486e:	31 c0                	xor    eax,eax
  404870:	e8 bb c9 ff ff       	call   401230 <__printf_chk@plt>
  404875:	83 cf ff             	or     edi,0xffffffff
  404878:	e8 e3 c9 ff ff       	call   401260 <exit@plt>
  40487d:	48 63 d0             	movsxd rdx,eax
  404880:	48 89 ee             	mov    rsi,rbp
  404883:	bf 01 00 00 00       	mov    edi,0x1
  404888:	e8 13 c9 ff ff       	call   4011a0 <write@plt>
  40488d:	48 8d 3d c0 d8 00 00 	lea    rdi,[rip+0xd8c0]        # 412154 <_IO_stdin_used+0x154>
  404894:	e8 f7 c8 ff ff       	call   401190 <puts@plt>
  404899:	48 8d 3d 64 d7 00 00 	lea    rdi,[rip+0xd764]        # 412004 <_IO_stdin_used+0x4>
  4048a0:	31 f6                	xor    esi,esi
  4048a2:	31 c0                	xor    eax,eax
  4048a4:	e8 a7 c9 ff ff       	call   401250 <open@plt>
  4048a9:	89 c7                	mov    edi,eax
  4048ab:	85 c0                	test   eax,eax
  4048ad:	79 34                	jns    4048e3 <win+0x336d>
  4048af:	e8 cc c8 ff ff       	call   401180 <__errno_location@plt>
  4048b4:	8b 38                	mov    edi,DWORD PTR [rax]
  4048b6:	e8 c5 c9 ff ff       	call   401280 <strerror@plt>
  4048bb:	48 8d 35 48 d7 00 00 	lea    rsi,[rip+0xd748]        # 41200a <_IO_stdin_used+0xa>
  4048c2:	bf 01 00 00 00       	mov    edi,0x1
  4048c7:	48 89 c2             	mov    rdx,rax
  4048ca:	31 c0                	xor    eax,eax
  4048cc:	e8 5f c9 ff ff       	call   401230 <__printf_chk@plt>
  4048d1:	e8 0a c9 ff ff       	call   4011e0 <geteuid@plt>
  4048d6:	85 c0                	test   eax,eax
  4048d8:	0f 84 fb cc ff ff    	je     4015d9 <win+0x63>
  4048de:	e9 de cc ff ff       	jmp    4015c1 <win+0x4b>
  4048e3:	ba 00 01 00 00       	mov    edx,0x100
  4048e8:	48 89 ee             	mov    rsi,rbp
  4048eb:	e8 10 c9 ff ff       	call   401200 <read@plt>
  4048f0:	85 c0                	test   eax,eax
  4048f2:	7f 2a                	jg     40491e <win+0x33a8>
  4048f4:	e8 87 c8 ff ff       	call   401180 <__errno_location@plt>
  4048f9:	8b 38                	mov    edi,DWORD PTR [rax]
  4048fb:	e8 80 c9 ff ff       	call   401280 <strerror@plt>
  404900:	bf 01 00 00 00       	mov    edi,0x1
  404905:	48 8d 35 9d d7 00 00 	lea    rsi,[rip+0xd79d]        # 4120a9 <_IO_stdin_used+0xa9>
  40490c:	48 89 c2             	mov    rdx,rax
  40490f:	31 c0                	xor    eax,eax
  404911:	e8 1a c9 ff ff       	call   401230 <__printf_chk@plt>
  404916:	83 cf ff             	or     edi,0xffffffff
  404919:	e8 42 c9 ff ff       	call   401260 <exit@plt>
  40491e:	48 63 d0             	movsxd rdx,eax
  404921:	48 89 ee             	mov    rsi,rbp
  404924:	bf 01 00 00 00       	mov    edi,0x1
  404929:	e8 72 c8 ff ff       	call   4011a0 <write@plt>
  40492e:	48 8d 3d 1f d8 00 00 	lea    rdi,[rip+0xd81f]        # 412154 <_IO_stdin_used+0x154>
  404935:	e8 56 c8 ff ff       	call   401190 <puts@plt>
  40493a:	48 8d 3d c3 d6 00 00 	lea    rdi,[rip+0xd6c3]        # 412004 <_IO_stdin_used+0x4>
  404941:	31 f6                	xor    esi,esi
  404943:	31 c0                	xor    eax,eax
  404945:	e8 06 c9 ff ff       	call   401250 <open@plt>
  40494a:	89 c7                	mov    edi,eax
  40494c:	85 c0                	test   eax,eax
  40494e:	79 34                	jns    404984 <win+0x340e>
  404950:	e8 2b c8 ff ff       	call   401180 <__errno_location@plt>
  404955:	8b 38                	mov    edi,DWORD PTR [rax]
  404957:	e8 24 c9 ff ff       	call   401280 <strerror@plt>
  40495c:	48 8d 35 a7 d6 00 00 	lea    rsi,[rip+0xd6a7]        # 41200a <_IO_stdin_used+0xa>
  404963:	bf 01 00 00 00       	mov    edi,0x1
  404968:	48 89 c2             	mov    rdx,rax
  40496b:	31 c0                	xor    eax,eax
  40496d:	e8 be c8 ff ff       	call   401230 <__printf_chk@plt>
  404972:	e8 69 c8 ff ff       	call   4011e0 <geteuid@plt>
  404977:	85 c0                	test   eax,eax
  404979:	0f 84 5a cc ff ff    	je     4015d9 <win+0x63>
  40497f:	e9 3d cc ff ff       	jmp    4015c1 <win+0x4b>
  404984:	ba 00 01 00 00       	mov    edx,0x100
  404989:	48 89 ee             	mov    rsi,rbp
  40498c:	e8 6f c8 ff ff       	call   401200 <read@plt>
  404991:	85 c0                	test   eax,eax
  404993:	7f 2a                	jg     4049bf <win+0x3449>
  404995:	e8 e6 c7 ff ff       	call   401180 <__errno_location@plt>
  40499a:	8b 38                	mov    edi,DWORD PTR [rax]
  40499c:	e8 df c8 ff ff       	call   401280 <strerror@plt>
  4049a1:	bf 01 00 00 00       	mov    edi,0x1
  4049a6:	48 8d 35 fc d6 00 00 	lea    rsi,[rip+0xd6fc]        # 4120a9 <_IO_stdin_used+0xa9>
  4049ad:	48 89 c2             	mov    rdx,rax
  4049b0:	31 c0                	xor    eax,eax
  4049b2:	e8 79 c8 ff ff       	call   401230 <__printf_chk@plt>
  4049b7:	83 cf ff             	or     edi,0xffffffff
  4049ba:	e8 a1 c8 ff ff       	call   401260 <exit@plt>
  4049bf:	48 63 d0             	movsxd rdx,eax
  4049c2:	48 89 ee             	mov    rsi,rbp
  4049c5:	bf 01 00 00 00       	mov    edi,0x1
  4049ca:	e8 d1 c7 ff ff       	call   4011a0 <write@plt>
  4049cf:	48 8d 3d 7e d7 00 00 	lea    rdi,[rip+0xd77e]        # 412154 <_IO_stdin_used+0x154>
  4049d6:	e8 b5 c7 ff ff       	call   401190 <puts@plt>
  4049db:	48 8d 3d 22 d6 00 00 	lea    rdi,[rip+0xd622]        # 412004 <_IO_stdin_used+0x4>
  4049e2:	31 f6                	xor    esi,esi
  4049e4:	31 c0                	xor    eax,eax
  4049e6:	e8 65 c8 ff ff       	call   401250 <open@plt>
  4049eb:	89 c7                	mov    edi,eax
  4049ed:	85 c0                	test   eax,eax
  4049ef:	79 34                	jns    404a25 <win+0x34af>
  4049f1:	e8 8a c7 ff ff       	call   401180 <__errno_location@plt>
  4049f6:	8b 38                	mov    edi,DWORD PTR [rax]
  4049f8:	e8 83 c8 ff ff       	call   401280 <strerror@plt>
  4049fd:	48 8d 35 06 d6 00 00 	lea    rsi,[rip+0xd606]        # 41200a <_IO_stdin_used+0xa>
  404a04:	bf 01 00 00 00       	mov    edi,0x1
  404a09:	48 89 c2             	mov    rdx,rax
  404a0c:	31 c0                	xor    eax,eax
  404a0e:	e8 1d c8 ff ff       	call   401230 <__printf_chk@plt>
  404a13:	e8 c8 c7 ff ff       	call   4011e0 <geteuid@plt>
  404a18:	85 c0                	test   eax,eax
  404a1a:	0f 84 b9 cb ff ff    	je     4015d9 <win+0x63>
  404a20:	e9 9c cb ff ff       	jmp    4015c1 <win+0x4b>
  404a25:	ba 00 01 00 00       	mov    edx,0x100
  404a2a:	48 89 ee             	mov    rsi,rbp
  404a2d:	e8 ce c7 ff ff       	call   401200 <read@plt>
  404a32:	85 c0                	test   eax,eax
  404a34:	7f 2a                	jg     404a60 <win+0x34ea>
  404a36:	e8 45 c7 ff ff       	call   401180 <__errno_location@plt>
  404a3b:	8b 38                	mov    edi,DWORD PTR [rax]
  404a3d:	e8 3e c8 ff ff       	call   401280 <strerror@plt>
  404a42:	bf 01 00 00 00       	mov    edi,0x1
  404a47:	48 8d 35 5b d6 00 00 	lea    rsi,[rip+0xd65b]        # 4120a9 <_IO_stdin_used+0xa9>
  404a4e:	48 89 c2             	mov    rdx,rax
  404a51:	31 c0                	xor    eax,eax
  404a53:	e8 d8 c7 ff ff       	call   401230 <__printf_chk@plt>
  404a58:	83 cf ff             	or     edi,0xffffffff
  404a5b:	e8 00 c8 ff ff       	call   401260 <exit@plt>
  404a60:	48 63 d0             	movsxd rdx,eax
  404a63:	48 89 ee             	mov    rsi,rbp
  404a66:	bf 01 00 00 00       	mov    edi,0x1
  404a6b:	e8 30 c7 ff ff       	call   4011a0 <write@plt>
  404a70:	48 8d 3d dd d6 00 00 	lea    rdi,[rip+0xd6dd]        # 412154 <_IO_stdin_used+0x154>
  404a77:	e8 14 c7 ff ff       	call   401190 <puts@plt>
  404a7c:	48 8d 3d 81 d5 00 00 	lea    rdi,[rip+0xd581]        # 412004 <_IO_stdin_used+0x4>
  404a83:	31 f6                	xor    esi,esi
  404a85:	31 c0                	xor    eax,eax
  404a87:	e8 c4 c7 ff ff       	call   401250 <open@plt>
  404a8c:	89 c7                	mov    edi,eax
  404a8e:	85 c0                	test   eax,eax
  404a90:	79 34                	jns    404ac6 <win+0x3550>
  404a92:	e8 e9 c6 ff ff       	call   401180 <__errno_location@plt>
  404a97:	8b 38                	mov    edi,DWORD PTR [rax]
  404a99:	e8 e2 c7 ff ff       	call   401280 <strerror@plt>
  404a9e:	48 8d 35 65 d5 00 00 	lea    rsi,[rip+0xd565]        # 41200a <_IO_stdin_used+0xa>
  404aa5:	bf 01 00 00 00       	mov    edi,0x1
  404aaa:	48 89 c2             	mov    rdx,rax
  404aad:	31 c0                	xor    eax,eax
  404aaf:	e8 7c c7 ff ff       	call   401230 <__printf_chk@plt>
  404ab4:	e8 27 c7 ff ff       	call   4011e0 <geteuid@plt>
  404ab9:	85 c0                	test   eax,eax
  404abb:	0f 84 18 cb ff ff    	je     4015d9 <win+0x63>
  404ac1:	e9 fb ca ff ff       	jmp    4015c1 <win+0x4b>
  404ac6:	ba 00 01 00 00       	mov    edx,0x100
  404acb:	48 89 ee             	mov    rsi,rbp
  404ace:	e8 2d c7 ff ff       	call   401200 <read@plt>
  404ad3:	85 c0                	test   eax,eax
  404ad5:	7f 2a                	jg     404b01 <win+0x358b>
  404ad7:	e8 a4 c6 ff ff       	call   401180 <__errno_location@plt>
  404adc:	8b 38                	mov    edi,DWORD PTR [rax]
  404ade:	e8 9d c7 ff ff       	call   401280 <strerror@plt>
  404ae3:	bf 01 00 00 00       	mov    edi,0x1
  404ae8:	48 8d 35 ba d5 00 00 	lea    rsi,[rip+0xd5ba]        # 4120a9 <_IO_stdin_used+0xa9>
  404aef:	48 89 c2             	mov    rdx,rax
  404af2:	31 c0                	xor    eax,eax
  404af4:	e8 37 c7 ff ff       	call   401230 <__printf_chk@plt>
  404af9:	83 cf ff             	or     edi,0xffffffff
  404afc:	e8 5f c7 ff ff       	call   401260 <exit@plt>
  404b01:	48 63 d0             	movsxd rdx,eax
  404b04:	48 89 ee             	mov    rsi,rbp
  404b07:	bf 01 00 00 00       	mov    edi,0x1
  404b0c:	e8 8f c6 ff ff       	call   4011a0 <write@plt>
  404b11:	48 8d 3d 3c d6 00 00 	lea    rdi,[rip+0xd63c]        # 412154 <_IO_stdin_used+0x154>
  404b18:	e8 73 c6 ff ff       	call   401190 <puts@plt>
  404b1d:	48 8d 3d e0 d4 00 00 	lea    rdi,[rip+0xd4e0]        # 412004 <_IO_stdin_used+0x4>
  404b24:	31 f6                	xor    esi,esi
  404b26:	31 c0                	xor    eax,eax
  404b28:	e8 23 c7 ff ff       	call   401250 <open@plt>
  404b2d:	89 c7                	mov    edi,eax
  404b2f:	85 c0                	test   eax,eax
  404b31:	79 34                	jns    404b67 <win+0x35f1>
  404b33:	e8 48 c6 ff ff       	call   401180 <__errno_location@plt>
  404b38:	8b 38                	mov    edi,DWORD PTR [rax]
  404b3a:	e8 41 c7 ff ff       	call   401280 <strerror@plt>
  404b3f:	48 8d 35 c4 d4 00 00 	lea    rsi,[rip+0xd4c4]        # 41200a <_IO_stdin_used+0xa>
  404b46:	bf 01 00 00 00       	mov    edi,0x1
  404b4b:	48 89 c2             	mov    rdx,rax
  404b4e:	31 c0                	xor    eax,eax
  404b50:	e8 db c6 ff ff       	call   401230 <__printf_chk@plt>
  404b55:	e8 86 c6 ff ff       	call   4011e0 <geteuid@plt>
  404b5a:	85 c0                	test   eax,eax
  404b5c:	0f 84 77 ca ff ff    	je     4015d9 <win+0x63>
  404b62:	e9 5a ca ff ff       	jmp    4015c1 <win+0x4b>
  404b67:	ba 00 01 00 00       	mov    edx,0x100
  404b6c:	48 89 ee             	mov    rsi,rbp
  404b6f:	e8 8c c6 ff ff       	call   401200 <read@plt>
  404b74:	85 c0                	test   eax,eax
  404b76:	7f 2a                	jg     404ba2 <win+0x362c>
  404b78:	e8 03 c6 ff ff       	call   401180 <__errno_location@plt>
  404b7d:	8b 38                	mov    edi,DWORD PTR [rax]
  404b7f:	e8 fc c6 ff ff       	call   401280 <strerror@plt>
  404b84:	bf 01 00 00 00       	mov    edi,0x1
  404b89:	48 8d 35 19 d5 00 00 	lea    rsi,[rip+0xd519]        # 4120a9 <_IO_stdin_used+0xa9>
  404b90:	48 89 c2             	mov    rdx,rax
  404b93:	31 c0                	xor    eax,eax
  404b95:	e8 96 c6 ff ff       	call   401230 <__printf_chk@plt>
  404b9a:	83 cf ff             	or     edi,0xffffffff
  404b9d:	e8 be c6 ff ff       	call   401260 <exit@plt>
  404ba2:	48 63 d0             	movsxd rdx,eax
  404ba5:	48 89 ee             	mov    rsi,rbp
  404ba8:	bf 01 00 00 00       	mov    edi,0x1
  404bad:	e8 ee c5 ff ff       	call   4011a0 <write@plt>
  404bb2:	48 8d 3d 9b d5 00 00 	lea    rdi,[rip+0xd59b]        # 412154 <_IO_stdin_used+0x154>
  404bb9:	e8 d2 c5 ff ff       	call   401190 <puts@plt>
  404bbe:	48 8d 3d 3f d4 00 00 	lea    rdi,[rip+0xd43f]        # 412004 <_IO_stdin_used+0x4>
  404bc5:	31 f6                	xor    esi,esi
  404bc7:	31 c0                	xor    eax,eax
  404bc9:	e8 82 c6 ff ff       	call   401250 <open@plt>
  404bce:	89 c7                	mov    edi,eax
  404bd0:	85 c0                	test   eax,eax
  404bd2:	79 34                	jns    404c08 <win+0x3692>
  404bd4:	e8 a7 c5 ff ff       	call   401180 <__errno_location@plt>
  404bd9:	8b 38                	mov    edi,DWORD PTR [rax]
  404bdb:	e8 a0 c6 ff ff       	call   401280 <strerror@plt>
  404be0:	48 8d 35 23 d4 00 00 	lea    rsi,[rip+0xd423]        # 41200a <_IO_stdin_used+0xa>
  404be7:	bf 01 00 00 00       	mov    edi,0x1
  404bec:	48 89 c2             	mov    rdx,rax
  404bef:	31 c0                	xor    eax,eax
  404bf1:	e8 3a c6 ff ff       	call   401230 <__printf_chk@plt>
  404bf6:	e8 e5 c5 ff ff       	call   4011e0 <geteuid@plt>
  404bfb:	85 c0                	test   eax,eax
  404bfd:	0f 84 d6 c9 ff ff    	je     4015d9 <win+0x63>
  404c03:	e9 b9 c9 ff ff       	jmp    4015c1 <win+0x4b>
  404c08:	ba 00 01 00 00       	mov    edx,0x100
  404c0d:	48 89 ee             	mov    rsi,rbp
  404c10:	e8 eb c5 ff ff       	call   401200 <read@plt>
  404c15:	85 c0                	test   eax,eax
  404c17:	7f 2a                	jg     404c43 <win+0x36cd>
  404c19:	e8 62 c5 ff ff       	call   401180 <__errno_location@plt>
  404c1e:	8b 38                	mov    edi,DWORD PTR [rax]
  404c20:	e8 5b c6 ff ff       	call   401280 <strerror@plt>
  404c25:	bf 01 00 00 00       	mov    edi,0x1
  404c2a:	48 8d 35 78 d4 00 00 	lea    rsi,[rip+0xd478]        # 4120a9 <_IO_stdin_used+0xa9>
  404c31:	48 89 c2             	mov    rdx,rax
  404c34:	31 c0                	xor    eax,eax
  404c36:	e8 f5 c5 ff ff       	call   401230 <__printf_chk@plt>
  404c3b:	83 cf ff             	or     edi,0xffffffff
  404c3e:	e8 1d c6 ff ff       	call   401260 <exit@plt>
  404c43:	48 63 d0             	movsxd rdx,eax
  404c46:	48 89 ee             	mov    rsi,rbp
  404c49:	bf 01 00 00 00       	mov    edi,0x1
  404c4e:	e8 4d c5 ff ff       	call   4011a0 <write@plt>
  404c53:	48 8d 3d fa d4 00 00 	lea    rdi,[rip+0xd4fa]        # 412154 <_IO_stdin_used+0x154>
  404c5a:	e8 31 c5 ff ff       	call   401190 <puts@plt>
  404c5f:	48 8d 3d 9e d3 00 00 	lea    rdi,[rip+0xd39e]        # 412004 <_IO_stdin_used+0x4>
  404c66:	31 f6                	xor    esi,esi
  404c68:	31 c0                	xor    eax,eax
  404c6a:	e8 e1 c5 ff ff       	call   401250 <open@plt>
  404c6f:	89 c7                	mov    edi,eax
  404c71:	85 c0                	test   eax,eax
  404c73:	79 34                	jns    404ca9 <win+0x3733>
  404c75:	e8 06 c5 ff ff       	call   401180 <__errno_location@plt>
  404c7a:	8b 38                	mov    edi,DWORD PTR [rax]
  404c7c:	e8 ff c5 ff ff       	call   401280 <strerror@plt>
  404c81:	48 8d 35 82 d3 00 00 	lea    rsi,[rip+0xd382]        # 41200a <_IO_stdin_used+0xa>
  404c88:	bf 01 00 00 00       	mov    edi,0x1
  404c8d:	48 89 c2             	mov    rdx,rax
  404c90:	31 c0                	xor    eax,eax
  404c92:	e8 99 c5 ff ff       	call   401230 <__printf_chk@plt>
  404c97:	e8 44 c5 ff ff       	call   4011e0 <geteuid@plt>
  404c9c:	85 c0                	test   eax,eax
  404c9e:	0f 84 35 c9 ff ff    	je     4015d9 <win+0x63>
  404ca4:	e9 18 c9 ff ff       	jmp    4015c1 <win+0x4b>
  404ca9:	ba 00 01 00 00       	mov    edx,0x100
  404cae:	48 89 ee             	mov    rsi,rbp
  404cb1:	e8 4a c5 ff ff       	call   401200 <read@plt>
  404cb6:	85 c0                	test   eax,eax
  404cb8:	7f 2a                	jg     404ce4 <win+0x376e>
  404cba:	e8 c1 c4 ff ff       	call   401180 <__errno_location@plt>
  404cbf:	8b 38                	mov    edi,DWORD PTR [rax]
  404cc1:	e8 ba c5 ff ff       	call   401280 <strerror@plt>
  404cc6:	bf 01 00 00 00       	mov    edi,0x1
  404ccb:	48 8d 35 d7 d3 00 00 	lea    rsi,[rip+0xd3d7]        # 4120a9 <_IO_stdin_used+0xa9>
  404cd2:	48 89 c2             	mov    rdx,rax
  404cd5:	31 c0                	xor    eax,eax
  404cd7:	e8 54 c5 ff ff       	call   401230 <__printf_chk@plt>
  404cdc:	83 cf ff             	or     edi,0xffffffff
  404cdf:	e8 7c c5 ff ff       	call   401260 <exit@plt>
  404ce4:	48 63 d0             	movsxd rdx,eax
  404ce7:	48 89 ee             	mov    rsi,rbp
  404cea:	bf 01 00 00 00       	mov    edi,0x1
  404cef:	e8 ac c4 ff ff       	call   4011a0 <write@plt>
  404cf4:	48 8d 3d 59 d4 00 00 	lea    rdi,[rip+0xd459]        # 412154 <_IO_stdin_used+0x154>
  404cfb:	e8 90 c4 ff ff       	call   401190 <puts@plt>
  404d00:	48 8d 3d fd d2 00 00 	lea    rdi,[rip+0xd2fd]        # 412004 <_IO_stdin_used+0x4>
  404d07:	31 f6                	xor    esi,esi
  404d09:	31 c0                	xor    eax,eax
  404d0b:	e8 40 c5 ff ff       	call   401250 <open@plt>
  404d10:	89 c7                	mov    edi,eax
  404d12:	85 c0                	test   eax,eax
  404d14:	79 34                	jns    404d4a <win+0x37d4>
  404d16:	e8 65 c4 ff ff       	call   401180 <__errno_location@plt>
  404d1b:	8b 38                	mov    edi,DWORD PTR [rax]
  404d1d:	e8 5e c5 ff ff       	call   401280 <strerror@plt>
  404d22:	48 8d 35 e1 d2 00 00 	lea    rsi,[rip+0xd2e1]        # 41200a <_IO_stdin_used+0xa>
  404d29:	bf 01 00 00 00       	mov    edi,0x1
  404d2e:	48 89 c2             	mov    rdx,rax
  404d31:	31 c0                	xor    eax,eax
  404d33:	e8 f8 c4 ff ff       	call   401230 <__printf_chk@plt>
  404d38:	e8 a3 c4 ff ff       	call   4011e0 <geteuid@plt>
  404d3d:	85 c0                	test   eax,eax
  404d3f:	0f 84 94 c8 ff ff    	je     4015d9 <win+0x63>
  404d45:	e9 77 c8 ff ff       	jmp    4015c1 <win+0x4b>
  404d4a:	ba 00 01 00 00       	mov    edx,0x100
  404d4f:	48 89 ee             	mov    rsi,rbp
  404d52:	e8 a9 c4 ff ff       	call   401200 <read@plt>
  404d57:	85 c0                	test   eax,eax
  404d59:	7f 2a                	jg     404d85 <win+0x380f>
  404d5b:	e8 20 c4 ff ff       	call   401180 <__errno_location@plt>
  404d60:	8b 38                	mov    edi,DWORD PTR [rax]
  404d62:	e8 19 c5 ff ff       	call   401280 <strerror@plt>
  404d67:	bf 01 00 00 00       	mov    edi,0x1
  404d6c:	48 8d 35 36 d3 00 00 	lea    rsi,[rip+0xd336]        # 4120a9 <_IO_stdin_used+0xa9>
  404d73:	48 89 c2             	mov    rdx,rax
  404d76:	31 c0                	xor    eax,eax
  404d78:	e8 b3 c4 ff ff       	call   401230 <__printf_chk@plt>
  404d7d:	83 cf ff             	or     edi,0xffffffff
  404d80:	e8 db c4 ff ff       	call   401260 <exit@plt>
  404d85:	48 63 d0             	movsxd rdx,eax
  404d88:	48 89 ee             	mov    rsi,rbp
  404d8b:	bf 01 00 00 00       	mov    edi,0x1
  404d90:	e8 0b c4 ff ff       	call   4011a0 <write@plt>
  404d95:	48 8d 3d b8 d3 00 00 	lea    rdi,[rip+0xd3b8]        # 412154 <_IO_stdin_used+0x154>
  404d9c:	e8 ef c3 ff ff       	call   401190 <puts@plt>
  404da1:	48 8d 3d 5c d2 00 00 	lea    rdi,[rip+0xd25c]        # 412004 <_IO_stdin_used+0x4>
  404da8:	31 f6                	xor    esi,esi
  404daa:	31 c0                	xor    eax,eax
  404dac:	e8 9f c4 ff ff       	call   401250 <open@plt>
  404db1:	89 c7                	mov    edi,eax
  404db3:	85 c0                	test   eax,eax
  404db5:	79 34                	jns    404deb <win+0x3875>
  404db7:	e8 c4 c3 ff ff       	call   401180 <__errno_location@plt>
  404dbc:	8b 38                	mov    edi,DWORD PTR [rax]
  404dbe:	e8 bd c4 ff ff       	call   401280 <strerror@plt>
  404dc3:	48 8d 35 40 d2 00 00 	lea    rsi,[rip+0xd240]        # 41200a <_IO_stdin_used+0xa>
  404dca:	bf 01 00 00 00       	mov    edi,0x1
  404dcf:	48 89 c2             	mov    rdx,rax
  404dd2:	31 c0                	xor    eax,eax
  404dd4:	e8 57 c4 ff ff       	call   401230 <__printf_chk@plt>
  404dd9:	e8 02 c4 ff ff       	call   4011e0 <geteuid@plt>
  404dde:	85 c0                	test   eax,eax
  404de0:	0f 84 f3 c7 ff ff    	je     4015d9 <win+0x63>
  404de6:	e9 d6 c7 ff ff       	jmp    4015c1 <win+0x4b>
  404deb:	ba 00 01 00 00       	mov    edx,0x100
  404df0:	48 89 ee             	mov    rsi,rbp
  404df3:	e8 08 c4 ff ff       	call   401200 <read@plt>
  404df8:	85 c0                	test   eax,eax
  404dfa:	7f 2a                	jg     404e26 <win+0x38b0>
  404dfc:	e8 7f c3 ff ff       	call   401180 <__errno_location@plt>
  404e01:	8b 38                	mov    edi,DWORD PTR [rax]
  404e03:	e8 78 c4 ff ff       	call   401280 <strerror@plt>
  404e08:	bf 01 00 00 00       	mov    edi,0x1
  404e0d:	48 8d 35 95 d2 00 00 	lea    rsi,[rip+0xd295]        # 4120a9 <_IO_stdin_used+0xa9>
  404e14:	48 89 c2             	mov    rdx,rax
  404e17:	31 c0                	xor    eax,eax
  404e19:	e8 12 c4 ff ff       	call   401230 <__printf_chk@plt>
  404e1e:	83 cf ff             	or     edi,0xffffffff
  404e21:	e8 3a c4 ff ff       	call   401260 <exit@plt>
  404e26:	48 63 d0             	movsxd rdx,eax
  404e29:	48 89 ee             	mov    rsi,rbp
  404e2c:	bf 01 00 00 00       	mov    edi,0x1
  404e31:	e8 6a c3 ff ff       	call   4011a0 <write@plt>
  404e36:	48 8d 3d 17 d3 00 00 	lea    rdi,[rip+0xd317]        # 412154 <_IO_stdin_used+0x154>
  404e3d:	e8 4e c3 ff ff       	call   401190 <puts@plt>
  404e42:	48 8d 3d bb d1 00 00 	lea    rdi,[rip+0xd1bb]        # 412004 <_IO_stdin_used+0x4>
  404e49:	31 f6                	xor    esi,esi
  404e4b:	31 c0                	xor    eax,eax
  404e4d:	e8 fe c3 ff ff       	call   401250 <open@plt>
  404e52:	89 c7                	mov    edi,eax
  404e54:	85 c0                	test   eax,eax
  404e56:	79 34                	jns    404e8c <win+0x3916>
  404e58:	e8 23 c3 ff ff       	call   401180 <__errno_location@plt>
  404e5d:	8b 38                	mov    edi,DWORD PTR [rax]
  404e5f:	e8 1c c4 ff ff       	call   401280 <strerror@plt>
  404e64:	48 8d 35 9f d1 00 00 	lea    rsi,[rip+0xd19f]        # 41200a <_IO_stdin_used+0xa>
  404e6b:	bf 01 00 00 00       	mov    edi,0x1
  404e70:	48 89 c2             	mov    rdx,rax
  404e73:	31 c0                	xor    eax,eax
  404e75:	e8 b6 c3 ff ff       	call   401230 <__printf_chk@plt>
  404e7a:	e8 61 c3 ff ff       	call   4011e0 <geteuid@plt>
  404e7f:	85 c0                	test   eax,eax
  404e81:	0f 84 52 c7 ff ff    	je     4015d9 <win+0x63>
  404e87:	e9 35 c7 ff ff       	jmp    4015c1 <win+0x4b>
  404e8c:	ba 00 01 00 00       	mov    edx,0x100
  404e91:	48 89 ee             	mov    rsi,rbp
  404e94:	e8 67 c3 ff ff       	call   401200 <read@plt>
  404e99:	85 c0                	test   eax,eax
  404e9b:	7f 2a                	jg     404ec7 <win+0x3951>
  404e9d:	e8 de c2 ff ff       	call   401180 <__errno_location@plt>
  404ea2:	8b 38                	mov    edi,DWORD PTR [rax]
  404ea4:	e8 d7 c3 ff ff       	call   401280 <strerror@plt>
  404ea9:	bf 01 00 00 00       	mov    edi,0x1
  404eae:	48 8d 35 f4 d1 00 00 	lea    rsi,[rip+0xd1f4]        # 4120a9 <_IO_stdin_used+0xa9>
  404eb5:	48 89 c2             	mov    rdx,rax
  404eb8:	31 c0                	xor    eax,eax
  404eba:	e8 71 c3 ff ff       	call   401230 <__printf_chk@plt>
  404ebf:	83 cf ff             	or     edi,0xffffffff
  404ec2:	e8 99 c3 ff ff       	call   401260 <exit@plt>
  404ec7:	48 63 d0             	movsxd rdx,eax
  404eca:	48 89 ee             	mov    rsi,rbp
  404ecd:	bf 01 00 00 00       	mov    edi,0x1
  404ed2:	e8 c9 c2 ff ff       	call   4011a0 <write@plt>
  404ed7:	48 8d 3d 76 d2 00 00 	lea    rdi,[rip+0xd276]        # 412154 <_IO_stdin_used+0x154>
  404ede:	e8 ad c2 ff ff       	call   401190 <puts@plt>
  404ee3:	48 8d 3d 1a d1 00 00 	lea    rdi,[rip+0xd11a]        # 412004 <_IO_stdin_used+0x4>
  404eea:	31 f6                	xor    esi,esi
  404eec:	31 c0                	xor    eax,eax
  404eee:	e8 5d c3 ff ff       	call   401250 <open@plt>
  404ef3:	89 c7                	mov    edi,eax
  404ef5:	85 c0                	test   eax,eax
  404ef7:	79 34                	jns    404f2d <win+0x39b7>
  404ef9:	e8 82 c2 ff ff       	call   401180 <__errno_location@plt>
  404efe:	8b 38                	mov    edi,DWORD PTR [rax]
  404f00:	e8 7b c3 ff ff       	call   401280 <strerror@plt>
  404f05:	48 8d 35 fe d0 00 00 	lea    rsi,[rip+0xd0fe]        # 41200a <_IO_stdin_used+0xa>
  404f0c:	bf 01 00 00 00       	mov    edi,0x1
  404f11:	48 89 c2             	mov    rdx,rax
  404f14:	31 c0                	xor    eax,eax
  404f16:	e8 15 c3 ff ff       	call   401230 <__printf_chk@plt>
  404f1b:	e8 c0 c2 ff ff       	call   4011e0 <geteuid@plt>
  404f20:	85 c0                	test   eax,eax
  404f22:	0f 84 b1 c6 ff ff    	je     4015d9 <win+0x63>
  404f28:	e9 94 c6 ff ff       	jmp    4015c1 <win+0x4b>
  404f2d:	ba 00 01 00 00       	mov    edx,0x100
  404f32:	48 89 ee             	mov    rsi,rbp
  404f35:	e8 c6 c2 ff ff       	call   401200 <read@plt>
  404f3a:	85 c0                	test   eax,eax
  404f3c:	7f 2a                	jg     404f68 <win+0x39f2>
  404f3e:	e8 3d c2 ff ff       	call   401180 <__errno_location@plt>
  404f43:	8b 38                	mov    edi,DWORD PTR [rax]
  404f45:	e8 36 c3 ff ff       	call   401280 <strerror@plt>
  404f4a:	bf 01 00 00 00       	mov    edi,0x1
  404f4f:	48 8d 35 53 d1 00 00 	lea    rsi,[rip+0xd153]        # 4120a9 <_IO_stdin_used+0xa9>
  404f56:	48 89 c2             	mov    rdx,rax
  404f59:	31 c0                	xor    eax,eax
  404f5b:	e8 d0 c2 ff ff       	call   401230 <__printf_chk@plt>
  404f60:	83 cf ff             	or     edi,0xffffffff
  404f63:	e8 f8 c2 ff ff       	call   401260 <exit@plt>
  404f68:	48 63 d0             	movsxd rdx,eax
  404f6b:	48 89 ee             	mov    rsi,rbp
  404f6e:	bf 01 00 00 00       	mov    edi,0x1
  404f73:	e8 28 c2 ff ff       	call   4011a0 <write@plt>
  404f78:	48 8d 3d d5 d1 00 00 	lea    rdi,[rip+0xd1d5]        # 412154 <_IO_stdin_used+0x154>
  404f7f:	e8 0c c2 ff ff       	call   401190 <puts@plt>
  404f84:	48 8d 3d 79 d0 00 00 	lea    rdi,[rip+0xd079]        # 412004 <_IO_stdin_used+0x4>
  404f8b:	31 f6                	xor    esi,esi
  404f8d:	31 c0                	xor    eax,eax
  404f8f:	e8 bc c2 ff ff       	call   401250 <open@plt>
  404f94:	89 c7                	mov    edi,eax
  404f96:	85 c0                	test   eax,eax
  404f98:	79 34                	jns    404fce <win+0x3a58>
  404f9a:	e8 e1 c1 ff ff       	call   401180 <__errno_location@plt>
  404f9f:	8b 38                	mov    edi,DWORD PTR [rax]
  404fa1:	e8 da c2 ff ff       	call   401280 <strerror@plt>
  404fa6:	48 8d 35 5d d0 00 00 	lea    rsi,[rip+0xd05d]        # 41200a <_IO_stdin_used+0xa>
  404fad:	bf 01 00 00 00       	mov    edi,0x1
  404fb2:	48 89 c2             	mov    rdx,rax
  404fb5:	31 c0                	xor    eax,eax
  404fb7:	e8 74 c2 ff ff       	call   401230 <__printf_chk@plt>
  404fbc:	e8 1f c2 ff ff       	call   4011e0 <geteuid@plt>
  404fc1:	85 c0                	test   eax,eax
  404fc3:	0f 84 10 c6 ff ff    	je     4015d9 <win+0x63>
  404fc9:	e9 f3 c5 ff ff       	jmp    4015c1 <win+0x4b>
  404fce:	ba 00 01 00 00       	mov    edx,0x100
  404fd3:	48 89 ee             	mov    rsi,rbp
  404fd6:	e8 25 c2 ff ff       	call   401200 <read@plt>
  404fdb:	85 c0                	test   eax,eax
  404fdd:	7f 2a                	jg     405009 <win+0x3a93>
  404fdf:	e8 9c c1 ff ff       	call   401180 <__errno_location@plt>
  404fe4:	8b 38                	mov    edi,DWORD PTR [rax]
  404fe6:	e8 95 c2 ff ff       	call   401280 <strerror@plt>
  404feb:	bf 01 00 00 00       	mov    edi,0x1
  404ff0:	48 8d 35 b2 d0 00 00 	lea    rsi,[rip+0xd0b2]        # 4120a9 <_IO_stdin_used+0xa9>
  404ff7:	48 89 c2             	mov    rdx,rax
  404ffa:	31 c0                	xor    eax,eax
  404ffc:	e8 2f c2 ff ff       	call   401230 <__printf_chk@plt>
  405001:	83 cf ff             	or     edi,0xffffffff
  405004:	e8 57 c2 ff ff       	call   401260 <exit@plt>
  405009:	48 63 d0             	movsxd rdx,eax
  40500c:	48 89 ee             	mov    rsi,rbp
  40500f:	bf 01 00 00 00       	mov    edi,0x1
  405014:	e8 87 c1 ff ff       	call   4011a0 <write@plt>
  405019:	48 8d 3d 34 d1 00 00 	lea    rdi,[rip+0xd134]        # 412154 <_IO_stdin_used+0x154>
  405020:	e8 6b c1 ff ff       	call   401190 <puts@plt>
  405025:	48 8d 3d d8 cf 00 00 	lea    rdi,[rip+0xcfd8]        # 412004 <_IO_stdin_used+0x4>
  40502c:	31 f6                	xor    esi,esi
  40502e:	31 c0                	xor    eax,eax
  405030:	e8 1b c2 ff ff       	call   401250 <open@plt>
  405035:	89 c7                	mov    edi,eax
  405037:	85 c0                	test   eax,eax
  405039:	79 34                	jns    40506f <win+0x3af9>
  40503b:	e8 40 c1 ff ff       	call   401180 <__errno_location@plt>
  405040:	8b 38                	mov    edi,DWORD PTR [rax]
  405042:	e8 39 c2 ff ff       	call   401280 <strerror@plt>
  405047:	48 8d 35 bc cf 00 00 	lea    rsi,[rip+0xcfbc]        # 41200a <_IO_stdin_used+0xa>
  40504e:	bf 01 00 00 00       	mov    edi,0x1
  405053:	48 89 c2             	mov    rdx,rax
  405056:	31 c0                	xor    eax,eax
  405058:	e8 d3 c1 ff ff       	call   401230 <__printf_chk@plt>
  40505d:	e8 7e c1 ff ff       	call   4011e0 <geteuid@plt>
  405062:	85 c0                	test   eax,eax
  405064:	0f 84 6f c5 ff ff    	je     4015d9 <win+0x63>
  40506a:	e9 52 c5 ff ff       	jmp    4015c1 <win+0x4b>
  40506f:	ba 00 01 00 00       	mov    edx,0x100
  405074:	48 89 ee             	mov    rsi,rbp
  405077:	e8 84 c1 ff ff       	call   401200 <read@plt>
  40507c:	85 c0                	test   eax,eax
  40507e:	7f 2a                	jg     4050aa <win+0x3b34>
  405080:	e8 fb c0 ff ff       	call   401180 <__errno_location@plt>
  405085:	8b 38                	mov    edi,DWORD PTR [rax]
  405087:	e8 f4 c1 ff ff       	call   401280 <strerror@plt>
  40508c:	bf 01 00 00 00       	mov    edi,0x1
  405091:	48 8d 35 11 d0 00 00 	lea    rsi,[rip+0xd011]        # 4120a9 <_IO_stdin_used+0xa9>
  405098:	48 89 c2             	mov    rdx,rax
  40509b:	31 c0                	xor    eax,eax
  40509d:	e8 8e c1 ff ff       	call   401230 <__printf_chk@plt>
  4050a2:	83 cf ff             	or     edi,0xffffffff
  4050a5:	e8 b6 c1 ff ff       	call   401260 <exit@plt>
  4050aa:	48 63 d0             	movsxd rdx,eax
  4050ad:	48 89 ee             	mov    rsi,rbp
  4050b0:	bf 01 00 00 00       	mov    edi,0x1
  4050b5:	e8 e6 c0 ff ff       	call   4011a0 <write@plt>
  4050ba:	48 8d 3d 93 d0 00 00 	lea    rdi,[rip+0xd093]        # 412154 <_IO_stdin_used+0x154>
  4050c1:	e8 ca c0 ff ff       	call   401190 <puts@plt>
  4050c6:	48 8d 3d 37 cf 00 00 	lea    rdi,[rip+0xcf37]        # 412004 <_IO_stdin_used+0x4>
  4050cd:	31 f6                	xor    esi,esi
  4050cf:	31 c0                	xor    eax,eax
  4050d1:	e8 7a c1 ff ff       	call   401250 <open@plt>
  4050d6:	89 c7                	mov    edi,eax
  4050d8:	85 c0                	test   eax,eax
  4050da:	79 34                	jns    405110 <win+0x3b9a>
  4050dc:	e8 9f c0 ff ff       	call   401180 <__errno_location@plt>
  4050e1:	8b 38                	mov    edi,DWORD PTR [rax]
  4050e3:	e8 98 c1 ff ff       	call   401280 <strerror@plt>
  4050e8:	48 8d 35 1b cf 00 00 	lea    rsi,[rip+0xcf1b]        # 41200a <_IO_stdin_used+0xa>
  4050ef:	bf 01 00 00 00       	mov    edi,0x1
  4050f4:	48 89 c2             	mov    rdx,rax
  4050f7:	31 c0                	xor    eax,eax
  4050f9:	e8 32 c1 ff ff       	call   401230 <__printf_chk@plt>
  4050fe:	e8 dd c0 ff ff       	call   4011e0 <geteuid@plt>
  405103:	85 c0                	test   eax,eax
  405105:	0f 84 ce c4 ff ff    	je     4015d9 <win+0x63>
  40510b:	e9 b1 c4 ff ff       	jmp    4015c1 <win+0x4b>
  405110:	ba 00 01 00 00       	mov    edx,0x100
  405115:	48 89 ee             	mov    rsi,rbp
  405118:	e8 e3 c0 ff ff       	call   401200 <read@plt>
  40511d:	85 c0                	test   eax,eax
  40511f:	7f 2a                	jg     40514b <win+0x3bd5>
  405121:	e8 5a c0 ff ff       	call   401180 <__errno_location@plt>
  405126:	8b 38                	mov    edi,DWORD PTR [rax]
  405128:	e8 53 c1 ff ff       	call   401280 <strerror@plt>
  40512d:	bf 01 00 00 00       	mov    edi,0x1
  405132:	48 8d 35 70 cf 00 00 	lea    rsi,[rip+0xcf70]        # 4120a9 <_IO_stdin_used+0xa9>
  405139:	48 89 c2             	mov    rdx,rax
  40513c:	31 c0                	xor    eax,eax
  40513e:	e8 ed c0 ff ff       	call   401230 <__printf_chk@plt>
  405143:	83 cf ff             	or     edi,0xffffffff
  405146:	e8 15 c1 ff ff       	call   401260 <exit@plt>
  40514b:	48 63 d0             	movsxd rdx,eax
  40514e:	48 89 ee             	mov    rsi,rbp
  405151:	bf 01 00 00 00       	mov    edi,0x1
  405156:	e8 45 c0 ff ff       	call   4011a0 <write@plt>
  40515b:	48 8d 3d f2 cf 00 00 	lea    rdi,[rip+0xcff2]        # 412154 <_IO_stdin_used+0x154>
  405162:	e8 29 c0 ff ff       	call   401190 <puts@plt>
  405167:	48 8d 3d 96 ce 00 00 	lea    rdi,[rip+0xce96]        # 412004 <_IO_stdin_used+0x4>
  40516e:	31 f6                	xor    esi,esi
  405170:	31 c0                	xor    eax,eax
  405172:	e8 d9 c0 ff ff       	call   401250 <open@plt>
  405177:	89 c7                	mov    edi,eax
  405179:	85 c0                	test   eax,eax
  40517b:	79 34                	jns    4051b1 <win+0x3c3b>
  40517d:	e8 fe bf ff ff       	call   401180 <__errno_location@plt>
  405182:	8b 38                	mov    edi,DWORD PTR [rax]
  405184:	e8 f7 c0 ff ff       	call   401280 <strerror@plt>
  405189:	48 8d 35 7a ce 00 00 	lea    rsi,[rip+0xce7a]        # 41200a <_IO_stdin_used+0xa>
  405190:	bf 01 00 00 00       	mov    edi,0x1
  405195:	48 89 c2             	mov    rdx,rax
  405198:	31 c0                	xor    eax,eax
  40519a:	e8 91 c0 ff ff       	call   401230 <__printf_chk@plt>
  40519f:	e8 3c c0 ff ff       	call   4011e0 <geteuid@plt>
  4051a4:	85 c0                	test   eax,eax
  4051a6:	0f 84 2d c4 ff ff    	je     4015d9 <win+0x63>
  4051ac:	e9 10 c4 ff ff       	jmp    4015c1 <win+0x4b>
  4051b1:	ba 00 01 00 00       	mov    edx,0x100
  4051b6:	48 89 ee             	mov    rsi,rbp
  4051b9:	e8 42 c0 ff ff       	call   401200 <read@plt>
  4051be:	85 c0                	test   eax,eax
  4051c0:	7f 2a                	jg     4051ec <win+0x3c76>
  4051c2:	e8 b9 bf ff ff       	call   401180 <__errno_location@plt>
  4051c7:	8b 38                	mov    edi,DWORD PTR [rax]
  4051c9:	e8 b2 c0 ff ff       	call   401280 <strerror@plt>
  4051ce:	bf 01 00 00 00       	mov    edi,0x1
  4051d3:	48 8d 35 cf ce 00 00 	lea    rsi,[rip+0xcecf]        # 4120a9 <_IO_stdin_used+0xa9>
  4051da:	48 89 c2             	mov    rdx,rax
  4051dd:	31 c0                	xor    eax,eax
  4051df:	e8 4c c0 ff ff       	call   401230 <__printf_chk@plt>
  4051e4:	83 cf ff             	or     edi,0xffffffff
  4051e7:	e8 74 c0 ff ff       	call   401260 <exit@plt>
  4051ec:	48 63 d0             	movsxd rdx,eax
  4051ef:	48 89 ee             	mov    rsi,rbp
  4051f2:	bf 01 00 00 00       	mov    edi,0x1
  4051f7:	e8 a4 bf ff ff       	call   4011a0 <write@plt>
  4051fc:	48 8d 3d 51 cf 00 00 	lea    rdi,[rip+0xcf51]        # 412154 <_IO_stdin_used+0x154>
  405203:	e8 88 bf ff ff       	call   401190 <puts@plt>
  405208:	48 8d 3d f5 cd 00 00 	lea    rdi,[rip+0xcdf5]        # 412004 <_IO_stdin_used+0x4>
  40520f:	31 f6                	xor    esi,esi
  405211:	31 c0                	xor    eax,eax
  405213:	e8 38 c0 ff ff       	call   401250 <open@plt>
  405218:	89 c7                	mov    edi,eax
  40521a:	85 c0                	test   eax,eax
  40521c:	79 34                	jns    405252 <win+0x3cdc>
  40521e:	e8 5d bf ff ff       	call   401180 <__errno_location@plt>
  405223:	8b 38                	mov    edi,DWORD PTR [rax]
  405225:	e8 56 c0 ff ff       	call   401280 <strerror@plt>
  40522a:	48 8d 35 d9 cd 00 00 	lea    rsi,[rip+0xcdd9]        # 41200a <_IO_stdin_used+0xa>
  405231:	bf 01 00 00 00       	mov    edi,0x1
  405236:	48 89 c2             	mov    rdx,rax
  405239:	31 c0                	xor    eax,eax
  40523b:	e8 f0 bf ff ff       	call   401230 <__printf_chk@plt>
  405240:	e8 9b bf ff ff       	call   4011e0 <geteuid@plt>
  405245:	85 c0                	test   eax,eax
  405247:	0f 84 8c c3 ff ff    	je     4015d9 <win+0x63>
  40524d:	e9 6f c3 ff ff       	jmp    4015c1 <win+0x4b>
  405252:	ba 00 01 00 00       	mov    edx,0x100
  405257:	48 89 ee             	mov    rsi,rbp
  40525a:	e8 a1 bf ff ff       	call   401200 <read@plt>
  40525f:	85 c0                	test   eax,eax
  405261:	7f 2a                	jg     40528d <win+0x3d17>
  405263:	e8 18 bf ff ff       	call   401180 <__errno_location@plt>
  405268:	8b 38                	mov    edi,DWORD PTR [rax]
  40526a:	e8 11 c0 ff ff       	call   401280 <strerror@plt>
  40526f:	bf 01 00 00 00       	mov    edi,0x1
  405274:	48 8d 35 2e ce 00 00 	lea    rsi,[rip+0xce2e]        # 4120a9 <_IO_stdin_used+0xa9>
  40527b:	48 89 c2             	mov    rdx,rax
  40527e:	31 c0                	xor    eax,eax
  405280:	e8 ab bf ff ff       	call   401230 <__printf_chk@plt>
  405285:	83 cf ff             	or     edi,0xffffffff
  405288:	e8 d3 bf ff ff       	call   401260 <exit@plt>
  40528d:	48 63 d0             	movsxd rdx,eax
  405290:	48 89 ee             	mov    rsi,rbp
  405293:	bf 01 00 00 00       	mov    edi,0x1
  405298:	e8 03 bf ff ff       	call   4011a0 <write@plt>
  40529d:	48 8d 3d b0 ce 00 00 	lea    rdi,[rip+0xceb0]        # 412154 <_IO_stdin_used+0x154>
  4052a4:	e8 e7 be ff ff       	call   401190 <puts@plt>
  4052a9:	48 8d 3d 54 cd 00 00 	lea    rdi,[rip+0xcd54]        # 412004 <_IO_stdin_used+0x4>
  4052b0:	31 f6                	xor    esi,esi
  4052b2:	31 c0                	xor    eax,eax
  4052b4:	e8 97 bf ff ff       	call   401250 <open@plt>
  4052b9:	89 c7                	mov    edi,eax
  4052bb:	85 c0                	test   eax,eax
  4052bd:	79 34                	jns    4052f3 <win+0x3d7d>
  4052bf:	e8 bc be ff ff       	call   401180 <__errno_location@plt>
  4052c4:	8b 38                	mov    edi,DWORD PTR [rax]
  4052c6:	e8 b5 bf ff ff       	call   401280 <strerror@plt>
  4052cb:	48 8d 35 38 cd 00 00 	lea    rsi,[rip+0xcd38]        # 41200a <_IO_stdin_used+0xa>
  4052d2:	bf 01 00 00 00       	mov    edi,0x1
  4052d7:	48 89 c2             	mov    rdx,rax
  4052da:	31 c0                	xor    eax,eax
  4052dc:	e8 4f bf ff ff       	call   401230 <__printf_chk@plt>
  4052e1:	e8 fa be ff ff       	call   4011e0 <geteuid@plt>
  4052e6:	85 c0                	test   eax,eax
  4052e8:	0f 84 eb c2 ff ff    	je     4015d9 <win+0x63>
  4052ee:	e9 ce c2 ff ff       	jmp    4015c1 <win+0x4b>
  4052f3:	ba 00 01 00 00       	mov    edx,0x100
  4052f8:	48 89 ee             	mov    rsi,rbp
  4052fb:	e8 00 bf ff ff       	call   401200 <read@plt>
  405300:	85 c0                	test   eax,eax
  405302:	7f 2a                	jg     40532e <win+0x3db8>
  405304:	e8 77 be ff ff       	call   401180 <__errno_location@plt>
  405309:	8b 38                	mov    edi,DWORD PTR [rax]
  40530b:	e8 70 bf ff ff       	call   401280 <strerror@plt>
  405310:	bf 01 00 00 00       	mov    edi,0x1
  405315:	48 8d 35 8d cd 00 00 	lea    rsi,[rip+0xcd8d]        # 4120a9 <_IO_stdin_used+0xa9>
  40531c:	48 89 c2             	mov    rdx,rax
  40531f:	31 c0                	xor    eax,eax
  405321:	e8 0a bf ff ff       	call   401230 <__printf_chk@plt>
  405326:	83 cf ff             	or     edi,0xffffffff
  405329:	e8 32 bf ff ff       	call   401260 <exit@plt>
  40532e:	48 63 d0             	movsxd rdx,eax
  405331:	48 89 ee             	mov    rsi,rbp
  405334:	bf 01 00 00 00       	mov    edi,0x1
  405339:	e8 62 be ff ff       	call   4011a0 <write@plt>
  40533e:	48 8d 3d 0f ce 00 00 	lea    rdi,[rip+0xce0f]        # 412154 <_IO_stdin_used+0x154>
  405345:	e8 46 be ff ff       	call   401190 <puts@plt>
  40534a:	48 8d 3d b3 cc 00 00 	lea    rdi,[rip+0xccb3]        # 412004 <_IO_stdin_used+0x4>
  405351:	31 f6                	xor    esi,esi
  405353:	31 c0                	xor    eax,eax
  405355:	e8 f6 be ff ff       	call   401250 <open@plt>
  40535a:	89 c7                	mov    edi,eax
  40535c:	85 c0                	test   eax,eax
  40535e:	79 34                	jns    405394 <win+0x3e1e>
  405360:	e8 1b be ff ff       	call   401180 <__errno_location@plt>
  405365:	8b 38                	mov    edi,DWORD PTR [rax]
  405367:	e8 14 bf ff ff       	call   401280 <strerror@plt>
  40536c:	48 8d 35 97 cc 00 00 	lea    rsi,[rip+0xcc97]        # 41200a <_IO_stdin_used+0xa>
  405373:	bf 01 00 00 00       	mov    edi,0x1
  405378:	48 89 c2             	mov    rdx,rax
  40537b:	31 c0                	xor    eax,eax
  40537d:	e8 ae be ff ff       	call   401230 <__printf_chk@plt>
  405382:	e8 59 be ff ff       	call   4011e0 <geteuid@plt>
  405387:	85 c0                	test   eax,eax
  405389:	0f 84 4a c2 ff ff    	je     4015d9 <win+0x63>
  40538f:	e9 2d c2 ff ff       	jmp    4015c1 <win+0x4b>
  405394:	ba 00 01 00 00       	mov    edx,0x100
  405399:	48 89 ee             	mov    rsi,rbp
  40539c:	e8 5f be ff ff       	call   401200 <read@plt>
  4053a1:	85 c0                	test   eax,eax
  4053a3:	7f 2a                	jg     4053cf <win+0x3e59>
  4053a5:	e8 d6 bd ff ff       	call   401180 <__errno_location@plt>
  4053aa:	8b 38                	mov    edi,DWORD PTR [rax]
  4053ac:	e8 cf be ff ff       	call   401280 <strerror@plt>
  4053b1:	bf 01 00 00 00       	mov    edi,0x1
  4053b6:	48 8d 35 ec cc 00 00 	lea    rsi,[rip+0xccec]        # 4120a9 <_IO_stdin_used+0xa9>
  4053bd:	48 89 c2             	mov    rdx,rax
  4053c0:	31 c0                	xor    eax,eax
  4053c2:	e8 69 be ff ff       	call   401230 <__printf_chk@plt>
  4053c7:	83 cf ff             	or     edi,0xffffffff
  4053ca:	e8 91 be ff ff       	call   401260 <exit@plt>
  4053cf:	48 63 d0             	movsxd rdx,eax
  4053d2:	48 89 ee             	mov    rsi,rbp
  4053d5:	bf 01 00 00 00       	mov    edi,0x1
  4053da:	e8 c1 bd ff ff       	call   4011a0 <write@plt>
  4053df:	48 8d 3d 6e cd 00 00 	lea    rdi,[rip+0xcd6e]        # 412154 <_IO_stdin_used+0x154>
  4053e6:	e8 a5 bd ff ff       	call   401190 <puts@plt>
  4053eb:	48 8d 3d 12 cc 00 00 	lea    rdi,[rip+0xcc12]        # 412004 <_IO_stdin_used+0x4>
  4053f2:	31 f6                	xor    esi,esi
  4053f4:	31 c0                	xor    eax,eax
  4053f6:	e8 55 be ff ff       	call   401250 <open@plt>
  4053fb:	89 c7                	mov    edi,eax
  4053fd:	85 c0                	test   eax,eax
  4053ff:	79 34                	jns    405435 <win+0x3ebf>
  405401:	e8 7a bd ff ff       	call   401180 <__errno_location@plt>
  405406:	8b 38                	mov    edi,DWORD PTR [rax]
  405408:	e8 73 be ff ff       	call   401280 <strerror@plt>
  40540d:	48 8d 35 f6 cb 00 00 	lea    rsi,[rip+0xcbf6]        # 41200a <_IO_stdin_used+0xa>
  405414:	bf 01 00 00 00       	mov    edi,0x1
  405419:	48 89 c2             	mov    rdx,rax
  40541c:	31 c0                	xor    eax,eax
  40541e:	e8 0d be ff ff       	call   401230 <__printf_chk@plt>
  405423:	e8 b8 bd ff ff       	call   4011e0 <geteuid@plt>
  405428:	85 c0                	test   eax,eax
  40542a:	0f 84 a9 c1 ff ff    	je     4015d9 <win+0x63>
  405430:	e9 8c c1 ff ff       	jmp    4015c1 <win+0x4b>
  405435:	ba 00 01 00 00       	mov    edx,0x100
  40543a:	48 89 ee             	mov    rsi,rbp
  40543d:	e8 be bd ff ff       	call   401200 <read@plt>
  405442:	85 c0                	test   eax,eax
  405444:	7f 2a                	jg     405470 <win+0x3efa>
  405446:	e8 35 bd ff ff       	call   401180 <__errno_location@plt>
  40544b:	8b 38                	mov    edi,DWORD PTR [rax]
  40544d:	e8 2e be ff ff       	call   401280 <strerror@plt>
  405452:	bf 01 00 00 00       	mov    edi,0x1
  405457:	48 8d 35 4b cc 00 00 	lea    rsi,[rip+0xcc4b]        # 4120a9 <_IO_stdin_used+0xa9>
  40545e:	48 89 c2             	mov    rdx,rax
  405461:	31 c0                	xor    eax,eax
  405463:	e8 c8 bd ff ff       	call   401230 <__printf_chk@plt>
  405468:	83 cf ff             	or     edi,0xffffffff
  40546b:	e8 f0 bd ff ff       	call   401260 <exit@plt>
  405470:	48 89 e5             	mov    rbp,rsp
  405473:	48 63 d0             	movsxd rdx,eax
  405476:	bf 01 00 00 00       	mov    edi,0x1
  40547b:	48 89 ee             	mov    rsi,rbp
  40547e:	e8 1d bd ff ff       	call   4011a0 <write@plt>
  405483:	48 8d 3d ca cc 00 00 	lea    rdi,[rip+0xccca]        # 412154 <_IO_stdin_used+0x154>
  40548a:	e8 01 bd ff ff       	call   401190 <puts@plt>
  40548f:	48 8d 3d 6e cb 00 00 	lea    rdi,[rip+0xcb6e]        # 412004 <_IO_stdin_used+0x4>
  405496:	31 f6                	xor    esi,esi
  405498:	31 c0                	xor    eax,eax
  40549a:	e8 b1 bd ff ff       	call   401250 <open@plt>
  40549f:	89 c7                	mov    edi,eax
  4054a1:	85 c0                	test   eax,eax
  4054a3:	79 34                	jns    4054d9 <win+0x3f63>
  4054a5:	e8 d6 bc ff ff       	call   401180 <__errno_location@plt>
  4054aa:	8b 38                	mov    edi,DWORD PTR [rax]
  4054ac:	e8 cf bd ff ff       	call   401280 <strerror@plt>
  4054b1:	48 8d 35 52 cb 00 00 	lea    rsi,[rip+0xcb52]        # 41200a <_IO_stdin_used+0xa>
  4054b8:	bf 01 00 00 00       	mov    edi,0x1
  4054bd:	48 89 c2             	mov    rdx,rax
  4054c0:	31 c0                	xor    eax,eax
  4054c2:	e8 69 bd ff ff       	call   401230 <__printf_chk@plt>
  4054c7:	e8 14 bd ff ff       	call   4011e0 <geteuid@plt>
  4054cc:	85 c0                	test   eax,eax
  4054ce:	0f 84 05 c1 ff ff    	je     4015d9 <win+0x63>
  4054d4:	e9 e8 c0 ff ff       	jmp    4015c1 <win+0x4b>
  4054d9:	ba 00 01 00 00       	mov    edx,0x100
  4054de:	48 89 ee             	mov    rsi,rbp
  4054e1:	e8 1a bd ff ff       	call   401200 <read@plt>
  4054e6:	85 c0                	test   eax,eax
  4054e8:	7f 2a                	jg     405514 <win+0x3f9e>
  4054ea:	e8 91 bc ff ff       	call   401180 <__errno_location@plt>
  4054ef:	8b 38                	mov    edi,DWORD PTR [rax]
  4054f1:	e8 8a bd ff ff       	call   401280 <strerror@plt>
  4054f6:	bf 01 00 00 00       	mov    edi,0x1
  4054fb:	48 8d 35 a7 cb 00 00 	lea    rsi,[rip+0xcba7]        # 4120a9 <_IO_stdin_used+0xa9>
  405502:	48 89 c2             	mov    rdx,rax
  405505:	31 c0                	xor    eax,eax
  405507:	e8 24 bd ff ff       	call   401230 <__printf_chk@plt>
  40550c:	83 cf ff             	or     edi,0xffffffff
  40550f:	e8 4c bd ff ff       	call   401260 <exit@plt>
  405514:	48 63 d0             	movsxd rdx,eax
  405517:	48 89 ee             	mov    rsi,rbp
  40551a:	bf 01 00 00 00       	mov    edi,0x1
  40551f:	e8 7c bc ff ff       	call   4011a0 <write@plt>
  405524:	48 8d 3d 29 cc 00 00 	lea    rdi,[rip+0xcc29]        # 412154 <_IO_stdin_used+0x154>
  40552b:	e8 60 bc ff ff       	call   401190 <puts@plt>
  405530:	48 8d 3d cd ca 00 00 	lea    rdi,[rip+0xcacd]        # 412004 <_IO_stdin_used+0x4>
  405537:	31 f6                	xor    esi,esi
  405539:	31 c0                	xor    eax,eax
  40553b:	e8 10 bd ff ff       	call   401250 <open@plt>
  405540:	89 c7                	mov    edi,eax
  405542:	85 c0                	test   eax,eax
  405544:	79 34                	jns    40557a <win+0x4004>
  405546:	e8 35 bc ff ff       	call   401180 <__errno_location@plt>
  40554b:	8b 38                	mov    edi,DWORD PTR [rax]
  40554d:	e8 2e bd ff ff       	call   401280 <strerror@plt>
  405552:	48 8d 35 b1 ca 00 00 	lea    rsi,[rip+0xcab1]        # 41200a <_IO_stdin_used+0xa>
  405559:	bf 01 00 00 00       	mov    edi,0x1
  40555e:	48 89 c2             	mov    rdx,rax
  405561:	31 c0                	xor    eax,eax
  405563:	e8 c8 bc ff ff       	call   401230 <__printf_chk@plt>
  405568:	e8 73 bc ff ff       	call   4011e0 <geteuid@plt>
  40556d:	85 c0                	test   eax,eax
  40556f:	0f 84 64 c0 ff ff    	je     4015d9 <win+0x63>
  405575:	e9 47 c0 ff ff       	jmp    4015c1 <win+0x4b>
  40557a:	ba 00 01 00 00       	mov    edx,0x100
  40557f:	48 89 ee             	mov    rsi,rbp
  405582:	e8 79 bc ff ff       	call   401200 <read@plt>
  405587:	85 c0                	test   eax,eax
  405589:	7f 2a                	jg     4055b5 <win+0x403f>
  40558b:	e8 f0 bb ff ff       	call   401180 <__errno_location@plt>
  405590:	8b 38                	mov    edi,DWORD PTR [rax]
  405592:	e8 e9 bc ff ff       	call   401280 <strerror@plt>
  405597:	bf 01 00 00 00       	mov    edi,0x1
  40559c:	48 8d 35 06 cb 00 00 	lea    rsi,[rip+0xcb06]        # 4120a9 <_IO_stdin_used+0xa9>
  4055a3:	48 89 c2             	mov    rdx,rax
  4055a6:	31 c0                	xor    eax,eax
  4055a8:	e8 83 bc ff ff       	call   401230 <__printf_chk@plt>
  4055ad:	83 cf ff             	or     edi,0xffffffff
  4055b0:	e8 ab bc ff ff       	call   401260 <exit@plt>
  4055b5:	48 63 d0             	movsxd rdx,eax
  4055b8:	48 89 ee             	mov    rsi,rbp
  4055bb:	bf 01 00 00 00       	mov    edi,0x1
  4055c0:	e8 db bb ff ff       	call   4011a0 <write@plt>
  4055c5:	48 8d 3d 88 cb 00 00 	lea    rdi,[rip+0xcb88]        # 412154 <_IO_stdin_used+0x154>
  4055cc:	e8 bf bb ff ff       	call   401190 <puts@plt>
  4055d1:	48 8d 3d 2c ca 00 00 	lea    rdi,[rip+0xca2c]        # 412004 <_IO_stdin_used+0x4>
  4055d8:	31 f6                	xor    esi,esi
  4055da:	31 c0                	xor    eax,eax
  4055dc:	e8 6f bc ff ff       	call   401250 <open@plt>
  4055e1:	89 c7                	mov    edi,eax
  4055e3:	85 c0                	test   eax,eax
  4055e5:	79 34                	jns    40561b <win+0x40a5>
  4055e7:	e8 94 bb ff ff       	call   401180 <__errno_location@plt>
  4055ec:	8b 38                	mov    edi,DWORD PTR [rax]
  4055ee:	e8 8d bc ff ff       	call   401280 <strerror@plt>
  4055f3:	48 8d 35 10 ca 00 00 	lea    rsi,[rip+0xca10]        # 41200a <_IO_stdin_used+0xa>
  4055fa:	bf 01 00 00 00       	mov    edi,0x1
  4055ff:	48 89 c2             	mov    rdx,rax
  405602:	31 c0                	xor    eax,eax
  405604:	e8 27 bc ff ff       	call   401230 <__printf_chk@plt>
  405609:	e8 d2 bb ff ff       	call   4011e0 <geteuid@plt>
  40560e:	85 c0                	test   eax,eax
  405610:	0f 84 c3 bf ff ff    	je     4015d9 <win+0x63>
  405616:	e9 a6 bf ff ff       	jmp    4015c1 <win+0x4b>
  40561b:	ba 00 01 00 00       	mov    edx,0x100
  405620:	48 89 ee             	mov    rsi,rbp
  405623:	e8 d8 bb ff ff       	call   401200 <read@plt>
  405628:	85 c0                	test   eax,eax
  40562a:	7f 2a                	jg     405656 <win+0x40e0>
  40562c:	e8 4f bb ff ff       	call   401180 <__errno_location@plt>
  405631:	8b 38                	mov    edi,DWORD PTR [rax]
  405633:	e8 48 bc ff ff       	call   401280 <strerror@plt>
  405638:	bf 01 00 00 00       	mov    edi,0x1
  40563d:	48 8d 35 65 ca 00 00 	lea    rsi,[rip+0xca65]        # 4120a9 <_IO_stdin_used+0xa9>
  405644:	48 89 c2             	mov    rdx,rax
  405647:	31 c0                	xor    eax,eax
  405649:	e8 e2 bb ff ff       	call   401230 <__printf_chk@plt>
  40564e:	83 cf ff             	or     edi,0xffffffff
  405651:	e8 0a bc ff ff       	call   401260 <exit@plt>
  405656:	48 63 d0             	movsxd rdx,eax
  405659:	48 89 ee             	mov    rsi,rbp
  40565c:	bf 01 00 00 00       	mov    edi,0x1
  405661:	e8 3a bb ff ff       	call   4011a0 <write@plt>
  405666:	48 8d 3d e7 ca 00 00 	lea    rdi,[rip+0xcae7]        # 412154 <_IO_stdin_used+0x154>
  40566d:	e8 1e bb ff ff       	call   401190 <puts@plt>
  405672:	48 8d 3d 8b c9 00 00 	lea    rdi,[rip+0xc98b]        # 412004 <_IO_stdin_used+0x4>
  405679:	31 f6                	xor    esi,esi
  40567b:	31 c0                	xor    eax,eax
  40567d:	e8 ce bb ff ff       	call   401250 <open@plt>
  405682:	89 c7                	mov    edi,eax
  405684:	85 c0                	test   eax,eax
  405686:	79 34                	jns    4056bc <win+0x4146>
  405688:	e8 f3 ba ff ff       	call   401180 <__errno_location@plt>
  40568d:	8b 38                	mov    edi,DWORD PTR [rax]
  40568f:	e8 ec bb ff ff       	call   401280 <strerror@plt>
  405694:	48 8d 35 6f c9 00 00 	lea    rsi,[rip+0xc96f]        # 41200a <_IO_stdin_used+0xa>
  40569b:	bf 01 00 00 00       	mov    edi,0x1
  4056a0:	48 89 c2             	mov    rdx,rax
  4056a3:	31 c0                	xor    eax,eax
  4056a5:	e8 86 bb ff ff       	call   401230 <__printf_chk@plt>
  4056aa:	e8 31 bb ff ff       	call   4011e0 <geteuid@plt>
  4056af:	85 c0                	test   eax,eax
  4056b1:	0f 84 22 bf ff ff    	je     4015d9 <win+0x63>
  4056b7:	e9 05 bf ff ff       	jmp    4015c1 <win+0x4b>
  4056bc:	ba 00 01 00 00       	mov    edx,0x100
  4056c1:	48 89 ee             	mov    rsi,rbp
  4056c4:	e8 37 bb ff ff       	call   401200 <read@plt>
  4056c9:	85 c0                	test   eax,eax
  4056cb:	7f 2a                	jg     4056f7 <win+0x4181>
  4056cd:	e8 ae ba ff ff       	call   401180 <__errno_location@plt>
  4056d2:	8b 38                	mov    edi,DWORD PTR [rax]
  4056d4:	e8 a7 bb ff ff       	call   401280 <strerror@plt>
  4056d9:	bf 01 00 00 00       	mov    edi,0x1
  4056de:	48 8d 35 c4 c9 00 00 	lea    rsi,[rip+0xc9c4]        # 4120a9 <_IO_stdin_used+0xa9>
  4056e5:	48 89 c2             	mov    rdx,rax
  4056e8:	31 c0                	xor    eax,eax
  4056ea:	e8 41 bb ff ff       	call   401230 <__printf_chk@plt>
  4056ef:	83 cf ff             	or     edi,0xffffffff
  4056f2:	e8 69 bb ff ff       	call   401260 <exit@plt>
  4056f7:	48 63 d0             	movsxd rdx,eax
  4056fa:	48 89 ee             	mov    rsi,rbp
  4056fd:	bf 01 00 00 00       	mov    edi,0x1
  405702:	e8 99 ba ff ff       	call   4011a0 <write@plt>
  405707:	48 8d 3d 46 ca 00 00 	lea    rdi,[rip+0xca46]        # 412154 <_IO_stdin_used+0x154>
  40570e:	e8 7d ba ff ff       	call   401190 <puts@plt>
  405713:	48 8d 3d ea c8 00 00 	lea    rdi,[rip+0xc8ea]        # 412004 <_IO_stdin_used+0x4>
  40571a:	31 f6                	xor    esi,esi
  40571c:	31 c0                	xor    eax,eax
  40571e:	e8 2d bb ff ff       	call   401250 <open@plt>
  405723:	89 c7                	mov    edi,eax
  405725:	85 c0                	test   eax,eax
  405727:	79 34                	jns    40575d <win+0x41e7>
  405729:	e8 52 ba ff ff       	call   401180 <__errno_location@plt>
  40572e:	8b 38                	mov    edi,DWORD PTR [rax]
  405730:	e8 4b bb ff ff       	call   401280 <strerror@plt>
  405735:	48 8d 35 ce c8 00 00 	lea    rsi,[rip+0xc8ce]        # 41200a <_IO_stdin_used+0xa>
  40573c:	bf 01 00 00 00       	mov    edi,0x1
  405741:	48 89 c2             	mov    rdx,rax
  405744:	31 c0                	xor    eax,eax
  405746:	e8 e5 ba ff ff       	call   401230 <__printf_chk@plt>
  40574b:	e8 90 ba ff ff       	call   4011e0 <geteuid@plt>
  405750:	85 c0                	test   eax,eax
  405752:	0f 84 81 be ff ff    	je     4015d9 <win+0x63>
  405758:	e9 64 be ff ff       	jmp    4015c1 <win+0x4b>
  40575d:	ba 00 01 00 00       	mov    edx,0x100
  405762:	48 89 ee             	mov    rsi,rbp
  405765:	e8 96 ba ff ff       	call   401200 <read@plt>
  40576a:	85 c0                	test   eax,eax
  40576c:	7f 2a                	jg     405798 <win+0x4222>
  40576e:	e8 0d ba ff ff       	call   401180 <__errno_location@plt>
  405773:	8b 38                	mov    edi,DWORD PTR [rax]
  405775:	e8 06 bb ff ff       	call   401280 <strerror@plt>
  40577a:	bf 01 00 00 00       	mov    edi,0x1
  40577f:	48 8d 35 23 c9 00 00 	lea    rsi,[rip+0xc923]        # 4120a9 <_IO_stdin_used+0xa9>
  405786:	48 89 c2             	mov    rdx,rax
  405789:	31 c0                	xor    eax,eax
  40578b:	e8 a0 ba ff ff       	call   401230 <__printf_chk@plt>
  405790:	83 cf ff             	or     edi,0xffffffff
  405793:	e8 c8 ba ff ff       	call   401260 <exit@plt>
  405798:	48 63 d0             	movsxd rdx,eax
  40579b:	48 89 ee             	mov    rsi,rbp
  40579e:	bf 01 00 00 00       	mov    edi,0x1
  4057a3:	e8 f8 b9 ff ff       	call   4011a0 <write@plt>
  4057a8:	48 8d 3d a5 c9 00 00 	lea    rdi,[rip+0xc9a5]        # 412154 <_IO_stdin_used+0x154>
  4057af:	e8 dc b9 ff ff       	call   401190 <puts@plt>
  4057b4:	48 8d 3d 49 c8 00 00 	lea    rdi,[rip+0xc849]        # 412004 <_IO_stdin_used+0x4>
  4057bb:	31 f6                	xor    esi,esi
  4057bd:	31 c0                	xor    eax,eax
  4057bf:	e8 8c ba ff ff       	call   401250 <open@plt>
  4057c4:	89 c7                	mov    edi,eax
  4057c6:	85 c0                	test   eax,eax
  4057c8:	79 34                	jns    4057fe <win+0x4288>
  4057ca:	e8 b1 b9 ff ff       	call   401180 <__errno_location@plt>
  4057cf:	8b 38                	mov    edi,DWORD PTR [rax]
  4057d1:	e8 aa ba ff ff       	call   401280 <strerror@plt>
  4057d6:	48 8d 35 2d c8 00 00 	lea    rsi,[rip+0xc82d]        # 41200a <_IO_stdin_used+0xa>
  4057dd:	bf 01 00 00 00       	mov    edi,0x1
  4057e2:	48 89 c2             	mov    rdx,rax
  4057e5:	31 c0                	xor    eax,eax
  4057e7:	e8 44 ba ff ff       	call   401230 <__printf_chk@plt>
  4057ec:	e8 ef b9 ff ff       	call   4011e0 <geteuid@plt>
  4057f1:	85 c0                	test   eax,eax
  4057f3:	0f 84 e0 bd ff ff    	je     4015d9 <win+0x63>
  4057f9:	e9 c3 bd ff ff       	jmp    4015c1 <win+0x4b>
  4057fe:	ba 00 01 00 00       	mov    edx,0x100
  405803:	48 89 ee             	mov    rsi,rbp
  405806:	e8 f5 b9 ff ff       	call   401200 <read@plt>
  40580b:	85 c0                	test   eax,eax
  40580d:	7f 2a                	jg     405839 <win+0x42c3>
  40580f:	e8 6c b9 ff ff       	call   401180 <__errno_location@plt>
  405814:	8b 38                	mov    edi,DWORD PTR [rax]
  405816:	e8 65 ba ff ff       	call   401280 <strerror@plt>
  40581b:	bf 01 00 00 00       	mov    edi,0x1
  405820:	48 8d 35 82 c8 00 00 	lea    rsi,[rip+0xc882]        # 4120a9 <_IO_stdin_used+0xa9>
  405827:	48 89 c2             	mov    rdx,rax
  40582a:	31 c0                	xor    eax,eax
  40582c:	e8 ff b9 ff ff       	call   401230 <__printf_chk@plt>
  405831:	83 cf ff             	or     edi,0xffffffff
  405834:	e8 27 ba ff ff       	call   401260 <exit@plt>
  405839:	48 63 d0             	movsxd rdx,eax
  40583c:	48 89 ee             	mov    rsi,rbp
  40583f:	bf 01 00 00 00       	mov    edi,0x1
  405844:	e8 57 b9 ff ff       	call   4011a0 <write@plt>
  405849:	48 8d 3d 04 c9 00 00 	lea    rdi,[rip+0xc904]        # 412154 <_IO_stdin_used+0x154>
  405850:	e8 3b b9 ff ff       	call   401190 <puts@plt>
  405855:	48 8d 3d a8 c7 00 00 	lea    rdi,[rip+0xc7a8]        # 412004 <_IO_stdin_used+0x4>
  40585c:	31 f6                	xor    esi,esi
  40585e:	31 c0                	xor    eax,eax
  405860:	e8 eb b9 ff ff       	call   401250 <open@plt>
  405865:	89 c7                	mov    edi,eax
  405867:	85 c0                	test   eax,eax
  405869:	79 34                	jns    40589f <win+0x4329>
  40586b:	e8 10 b9 ff ff       	call   401180 <__errno_location@plt>
  405870:	8b 38                	mov    edi,DWORD PTR [rax]
  405872:	e8 09 ba ff ff       	call   401280 <strerror@plt>
  405877:	48 8d 35 8c c7 00 00 	lea    rsi,[rip+0xc78c]        # 41200a <_IO_stdin_used+0xa>
  40587e:	bf 01 00 00 00       	mov    edi,0x1
  405883:	48 89 c2             	mov    rdx,rax
  405886:	31 c0                	xor    eax,eax
  405888:	e8 a3 b9 ff ff       	call   401230 <__printf_chk@plt>
  40588d:	e8 4e b9 ff ff       	call   4011e0 <geteuid@plt>
  405892:	85 c0                	test   eax,eax
  405894:	0f 84 3f bd ff ff    	je     4015d9 <win+0x63>
  40589a:	e9 22 bd ff ff       	jmp    4015c1 <win+0x4b>
  40589f:	ba 00 01 00 00       	mov    edx,0x100
  4058a4:	48 89 ee             	mov    rsi,rbp
  4058a7:	e8 54 b9 ff ff       	call   401200 <read@plt>
  4058ac:	85 c0                	test   eax,eax
  4058ae:	7f 2a                	jg     4058da <win+0x4364>
  4058b0:	e8 cb b8 ff ff       	call   401180 <__errno_location@plt>
  4058b5:	8b 38                	mov    edi,DWORD PTR [rax]
  4058b7:	e8 c4 b9 ff ff       	call   401280 <strerror@plt>
  4058bc:	bf 01 00 00 00       	mov    edi,0x1
  4058c1:	48 8d 35 e1 c7 00 00 	lea    rsi,[rip+0xc7e1]        # 4120a9 <_IO_stdin_used+0xa9>
  4058c8:	48 89 c2             	mov    rdx,rax
  4058cb:	31 c0                	xor    eax,eax
  4058cd:	e8 5e b9 ff ff       	call   401230 <__printf_chk@plt>
  4058d2:	83 cf ff             	or     edi,0xffffffff
  4058d5:	e8 86 b9 ff ff       	call   401260 <exit@plt>
  4058da:	48 63 d0             	movsxd rdx,eax
  4058dd:	48 89 ee             	mov    rsi,rbp
  4058e0:	bf 01 00 00 00       	mov    edi,0x1
  4058e5:	e8 b6 b8 ff ff       	call   4011a0 <write@plt>
  4058ea:	48 8d 3d 63 c8 00 00 	lea    rdi,[rip+0xc863]        # 412154 <_IO_stdin_used+0x154>
  4058f1:	e8 9a b8 ff ff       	call   401190 <puts@plt>
  4058f6:	48 8d 3d 07 c7 00 00 	lea    rdi,[rip+0xc707]        # 412004 <_IO_stdin_used+0x4>
  4058fd:	31 f6                	xor    esi,esi
  4058ff:	31 c0                	xor    eax,eax
  405901:	e8 4a b9 ff ff       	call   401250 <open@plt>
  405906:	89 c7                	mov    edi,eax
  405908:	85 c0                	test   eax,eax
  40590a:	79 34                	jns    405940 <win+0x43ca>
  40590c:	e8 6f b8 ff ff       	call   401180 <__errno_location@plt>
  405911:	8b 38                	mov    edi,DWORD PTR [rax]
  405913:	e8 68 b9 ff ff       	call   401280 <strerror@plt>
  405918:	48 8d 35 eb c6 00 00 	lea    rsi,[rip+0xc6eb]        # 41200a <_IO_stdin_used+0xa>
  40591f:	bf 01 00 00 00       	mov    edi,0x1
  405924:	48 89 c2             	mov    rdx,rax
  405927:	31 c0                	xor    eax,eax
  405929:	e8 02 b9 ff ff       	call   401230 <__printf_chk@plt>
  40592e:	e8 ad b8 ff ff       	call   4011e0 <geteuid@plt>
  405933:	85 c0                	test   eax,eax
  405935:	0f 84 9e bc ff ff    	je     4015d9 <win+0x63>
  40593b:	e9 81 bc ff ff       	jmp    4015c1 <win+0x4b>
  405940:	ba 00 01 00 00       	mov    edx,0x100
  405945:	48 89 ee             	mov    rsi,rbp
  405948:	e8 b3 b8 ff ff       	call   401200 <read@plt>
  40594d:	85 c0                	test   eax,eax
  40594f:	7f 2a                	jg     40597b <win+0x4405>
  405951:	e8 2a b8 ff ff       	call   401180 <__errno_location@plt>
  405956:	8b 38                	mov    edi,DWORD PTR [rax]
  405958:	e8 23 b9 ff ff       	call   401280 <strerror@plt>
  40595d:	bf 01 00 00 00       	mov    edi,0x1
  405962:	48 8d 35 40 c7 00 00 	lea    rsi,[rip+0xc740]        # 4120a9 <_IO_stdin_used+0xa9>
  405969:	48 89 c2             	mov    rdx,rax
  40596c:	31 c0                	xor    eax,eax
  40596e:	e8 bd b8 ff ff       	call   401230 <__printf_chk@plt>
  405973:	83 cf ff             	or     edi,0xffffffff
  405976:	e8 e5 b8 ff ff       	call   401260 <exit@plt>
  40597b:	48 63 d0             	movsxd rdx,eax
  40597e:	48 89 ee             	mov    rsi,rbp
  405981:	bf 01 00 00 00       	mov    edi,0x1
  405986:	e8 15 b8 ff ff       	call   4011a0 <write@plt>
  40598b:	48 8d 3d c2 c7 00 00 	lea    rdi,[rip+0xc7c2]        # 412154 <_IO_stdin_used+0x154>
  405992:	e8 f9 b7 ff ff       	call   401190 <puts@plt>
  405997:	48 8d 3d 66 c6 00 00 	lea    rdi,[rip+0xc666]        # 412004 <_IO_stdin_used+0x4>
  40599e:	31 f6                	xor    esi,esi
  4059a0:	31 c0                	xor    eax,eax
  4059a2:	e8 a9 b8 ff ff       	call   401250 <open@plt>
  4059a7:	89 c7                	mov    edi,eax
  4059a9:	85 c0                	test   eax,eax
  4059ab:	79 34                	jns    4059e1 <win+0x446b>
  4059ad:	e8 ce b7 ff ff       	call   401180 <__errno_location@plt>
  4059b2:	8b 38                	mov    edi,DWORD PTR [rax]
  4059b4:	e8 c7 b8 ff ff       	call   401280 <strerror@plt>
  4059b9:	48 8d 35 4a c6 00 00 	lea    rsi,[rip+0xc64a]        # 41200a <_IO_stdin_used+0xa>
  4059c0:	bf 01 00 00 00       	mov    edi,0x1
  4059c5:	48 89 c2             	mov    rdx,rax
  4059c8:	31 c0                	xor    eax,eax
  4059ca:	e8 61 b8 ff ff       	call   401230 <__printf_chk@plt>
  4059cf:	e8 0c b8 ff ff       	call   4011e0 <geteuid@plt>
  4059d4:	85 c0                	test   eax,eax
  4059d6:	0f 84 fd bb ff ff    	je     4015d9 <win+0x63>
  4059dc:	e9 e0 bb ff ff       	jmp    4015c1 <win+0x4b>
  4059e1:	ba 00 01 00 00       	mov    edx,0x100
  4059e6:	48 89 ee             	mov    rsi,rbp
  4059e9:	e8 12 b8 ff ff       	call   401200 <read@plt>
  4059ee:	85 c0                	test   eax,eax
  4059f0:	7f 2a                	jg     405a1c <win+0x44a6>
  4059f2:	e8 89 b7 ff ff       	call   401180 <__errno_location@plt>
  4059f7:	8b 38                	mov    edi,DWORD PTR [rax]
  4059f9:	e8 82 b8 ff ff       	call   401280 <strerror@plt>
  4059fe:	bf 01 00 00 00       	mov    edi,0x1
  405a03:	48 8d 35 9f c6 00 00 	lea    rsi,[rip+0xc69f]        # 4120a9 <_IO_stdin_used+0xa9>
  405a0a:	48 89 c2             	mov    rdx,rax
  405a0d:	31 c0                	xor    eax,eax
  405a0f:	e8 1c b8 ff ff       	call   401230 <__printf_chk@plt>
  405a14:	83 cf ff             	or     edi,0xffffffff
  405a17:	e8 44 b8 ff ff       	call   401260 <exit@plt>
  405a1c:	48 63 d0             	movsxd rdx,eax
  405a1f:	48 89 ee             	mov    rsi,rbp
  405a22:	bf 01 00 00 00       	mov    edi,0x1
  405a27:	e8 74 b7 ff ff       	call   4011a0 <write@plt>
  405a2c:	48 8d 3d 21 c7 00 00 	lea    rdi,[rip+0xc721]        # 412154 <_IO_stdin_used+0x154>
  405a33:	e8 58 b7 ff ff       	call   401190 <puts@plt>
  405a38:	48 8d 3d c5 c5 00 00 	lea    rdi,[rip+0xc5c5]        # 412004 <_IO_stdin_used+0x4>
  405a3f:	31 f6                	xor    esi,esi
  405a41:	31 c0                	xor    eax,eax
  405a43:	e8 08 b8 ff ff       	call   401250 <open@plt>
  405a48:	89 c7                	mov    edi,eax
  405a4a:	85 c0                	test   eax,eax
  405a4c:	79 34                	jns    405a82 <win+0x450c>
  405a4e:	e8 2d b7 ff ff       	call   401180 <__errno_location@plt>
  405a53:	8b 38                	mov    edi,DWORD PTR [rax]
  405a55:	e8 26 b8 ff ff       	call   401280 <strerror@plt>
  405a5a:	48 8d 35 a9 c5 00 00 	lea    rsi,[rip+0xc5a9]        # 41200a <_IO_stdin_used+0xa>
  405a61:	bf 01 00 00 00       	mov    edi,0x1
  405a66:	48 89 c2             	mov    rdx,rax
  405a69:	31 c0                	xor    eax,eax
  405a6b:	e8 c0 b7 ff ff       	call   401230 <__printf_chk@plt>
  405a70:	e8 6b b7 ff ff       	call   4011e0 <geteuid@plt>
  405a75:	85 c0                	test   eax,eax
  405a77:	0f 84 5c bb ff ff    	je     4015d9 <win+0x63>
  405a7d:	e9 3f bb ff ff       	jmp    4015c1 <win+0x4b>
  405a82:	ba 00 01 00 00       	mov    edx,0x100
  405a87:	48 89 ee             	mov    rsi,rbp
  405a8a:	e8 71 b7 ff ff       	call   401200 <read@plt>
  405a8f:	85 c0                	test   eax,eax
  405a91:	7f 2a                	jg     405abd <win+0x4547>
  405a93:	e8 e8 b6 ff ff       	call   401180 <__errno_location@plt>
  405a98:	8b 38                	mov    edi,DWORD PTR [rax]
  405a9a:	e8 e1 b7 ff ff       	call   401280 <strerror@plt>
  405a9f:	bf 01 00 00 00       	mov    edi,0x1
  405aa4:	48 8d 35 fe c5 00 00 	lea    rsi,[rip+0xc5fe]        # 4120a9 <_IO_stdin_used+0xa9>
  405aab:	48 89 c2             	mov    rdx,rax
  405aae:	31 c0                	xor    eax,eax
  405ab0:	e8 7b b7 ff ff       	call   401230 <__printf_chk@plt>
  405ab5:	83 cf ff             	or     edi,0xffffffff
  405ab8:	e8 a3 b7 ff ff       	call   401260 <exit@plt>
  405abd:	48 63 d0             	movsxd rdx,eax
  405ac0:	48 89 ee             	mov    rsi,rbp
  405ac3:	bf 01 00 00 00       	mov    edi,0x1
  405ac8:	e8 d3 b6 ff ff       	call   4011a0 <write@plt>
  405acd:	48 8d 3d 80 c6 00 00 	lea    rdi,[rip+0xc680]        # 412154 <_IO_stdin_used+0x154>
  405ad4:	e8 b7 b6 ff ff       	call   401190 <puts@plt>
  405ad9:	48 8d 3d 24 c5 00 00 	lea    rdi,[rip+0xc524]        # 412004 <_IO_stdin_used+0x4>
  405ae0:	31 f6                	xor    esi,esi
  405ae2:	31 c0                	xor    eax,eax
  405ae4:	e8 67 b7 ff ff       	call   401250 <open@plt>
  405ae9:	89 c7                	mov    edi,eax
  405aeb:	85 c0                	test   eax,eax
  405aed:	79 34                	jns    405b23 <win+0x45ad>
  405aef:	e8 8c b6 ff ff       	call   401180 <__errno_location@plt>
  405af4:	8b 38                	mov    edi,DWORD PTR [rax]
  405af6:	e8 85 b7 ff ff       	call   401280 <strerror@plt>
  405afb:	48 8d 35 08 c5 00 00 	lea    rsi,[rip+0xc508]        # 41200a <_IO_stdin_used+0xa>
  405b02:	bf 01 00 00 00       	mov    edi,0x1
  405b07:	48 89 c2             	mov    rdx,rax
  405b0a:	31 c0                	xor    eax,eax
  405b0c:	e8 1f b7 ff ff       	call   401230 <__printf_chk@plt>
  405b11:	e8 ca b6 ff ff       	call   4011e0 <geteuid@plt>
  405b16:	85 c0                	test   eax,eax
  405b18:	0f 84 bb ba ff ff    	je     4015d9 <win+0x63>
  405b1e:	e9 9e ba ff ff       	jmp    4015c1 <win+0x4b>
  405b23:	ba 00 01 00 00       	mov    edx,0x100
  405b28:	48 89 ee             	mov    rsi,rbp
  405b2b:	e8 d0 b6 ff ff       	call   401200 <read@plt>
  405b30:	85 c0                	test   eax,eax
  405b32:	7f 2a                	jg     405b5e <win+0x45e8>
  405b34:	e8 47 b6 ff ff       	call   401180 <__errno_location@plt>
  405b39:	8b 38                	mov    edi,DWORD PTR [rax]
  405b3b:	e8 40 b7 ff ff       	call   401280 <strerror@plt>
  405b40:	bf 01 00 00 00       	mov    edi,0x1
  405b45:	48 8d 35 5d c5 00 00 	lea    rsi,[rip+0xc55d]        # 4120a9 <_IO_stdin_used+0xa9>
  405b4c:	48 89 c2             	mov    rdx,rax
  405b4f:	31 c0                	xor    eax,eax
  405b51:	e8 da b6 ff ff       	call   401230 <__printf_chk@plt>
  405b56:	83 cf ff             	or     edi,0xffffffff
  405b59:	e8 02 b7 ff ff       	call   401260 <exit@plt>
  405b5e:	48 63 d0             	movsxd rdx,eax
  405b61:	48 89 ee             	mov    rsi,rbp
  405b64:	bf 01 00 00 00       	mov    edi,0x1
  405b69:	e8 32 b6 ff ff       	call   4011a0 <write@plt>
  405b6e:	48 8d 3d df c5 00 00 	lea    rdi,[rip+0xc5df]        # 412154 <_IO_stdin_used+0x154>
  405b75:	e8 16 b6 ff ff       	call   401190 <puts@plt>
  405b7a:	48 8d 3d 83 c4 00 00 	lea    rdi,[rip+0xc483]        # 412004 <_IO_stdin_used+0x4>
  405b81:	31 f6                	xor    esi,esi
  405b83:	31 c0                	xor    eax,eax
  405b85:	e8 c6 b6 ff ff       	call   401250 <open@plt>
  405b8a:	89 c7                	mov    edi,eax
  405b8c:	85 c0                	test   eax,eax
  405b8e:	79 34                	jns    405bc4 <win+0x464e>
  405b90:	e8 eb b5 ff ff       	call   401180 <__errno_location@plt>
  405b95:	8b 38                	mov    edi,DWORD PTR [rax]
  405b97:	e8 e4 b6 ff ff       	call   401280 <strerror@plt>
  405b9c:	48 8d 35 67 c4 00 00 	lea    rsi,[rip+0xc467]        # 41200a <_IO_stdin_used+0xa>
  405ba3:	bf 01 00 00 00       	mov    edi,0x1
  405ba8:	48 89 c2             	mov    rdx,rax
  405bab:	31 c0                	xor    eax,eax
  405bad:	e8 7e b6 ff ff       	call   401230 <__printf_chk@plt>
  405bb2:	e8 29 b6 ff ff       	call   4011e0 <geteuid@plt>
  405bb7:	85 c0                	test   eax,eax
  405bb9:	0f 84 1a ba ff ff    	je     4015d9 <win+0x63>
  405bbf:	e9 fd b9 ff ff       	jmp    4015c1 <win+0x4b>
  405bc4:	ba 00 01 00 00       	mov    edx,0x100
  405bc9:	48 89 ee             	mov    rsi,rbp
  405bcc:	e8 2f b6 ff ff       	call   401200 <read@plt>
  405bd1:	85 c0                	test   eax,eax
  405bd3:	7f 2a                	jg     405bff <win+0x4689>
  405bd5:	e8 a6 b5 ff ff       	call   401180 <__errno_location@plt>
  405bda:	8b 38                	mov    edi,DWORD PTR [rax]
  405bdc:	e8 9f b6 ff ff       	call   401280 <strerror@plt>
  405be1:	bf 01 00 00 00       	mov    edi,0x1
  405be6:	48 8d 35 bc c4 00 00 	lea    rsi,[rip+0xc4bc]        # 4120a9 <_IO_stdin_used+0xa9>
  405bed:	48 89 c2             	mov    rdx,rax
  405bf0:	31 c0                	xor    eax,eax
  405bf2:	e8 39 b6 ff ff       	call   401230 <__printf_chk@plt>
  405bf7:	83 cf ff             	or     edi,0xffffffff
  405bfa:	e8 61 b6 ff ff       	call   401260 <exit@plt>
  405bff:	48 63 d0             	movsxd rdx,eax
  405c02:	48 89 ee             	mov    rsi,rbp
  405c05:	bf 01 00 00 00       	mov    edi,0x1
  405c0a:	e8 91 b5 ff ff       	call   4011a0 <write@plt>
  405c0f:	48 8d 3d 3e c5 00 00 	lea    rdi,[rip+0xc53e]        # 412154 <_IO_stdin_used+0x154>
  405c16:	e8 75 b5 ff ff       	call   401190 <puts@plt>
  405c1b:	48 8d 3d e2 c3 00 00 	lea    rdi,[rip+0xc3e2]        # 412004 <_IO_stdin_used+0x4>
  405c22:	31 f6                	xor    esi,esi
  405c24:	31 c0                	xor    eax,eax
  405c26:	e8 25 b6 ff ff       	call   401250 <open@plt>
  405c2b:	89 c7                	mov    edi,eax
  405c2d:	85 c0                	test   eax,eax
  405c2f:	79 34                	jns    405c65 <win+0x46ef>
  405c31:	e8 4a b5 ff ff       	call   401180 <__errno_location@plt>
  405c36:	8b 38                	mov    edi,DWORD PTR [rax]
  405c38:	e8 43 b6 ff ff       	call   401280 <strerror@plt>
  405c3d:	48 8d 35 c6 c3 00 00 	lea    rsi,[rip+0xc3c6]        # 41200a <_IO_stdin_used+0xa>
  405c44:	bf 01 00 00 00       	mov    edi,0x1
  405c49:	48 89 c2             	mov    rdx,rax
  405c4c:	31 c0                	xor    eax,eax
  405c4e:	e8 dd b5 ff ff       	call   401230 <__printf_chk@plt>
  405c53:	e8 88 b5 ff ff       	call   4011e0 <geteuid@plt>
  405c58:	85 c0                	test   eax,eax
  405c5a:	0f 84 79 b9 ff ff    	je     4015d9 <win+0x63>
  405c60:	e9 5c b9 ff ff       	jmp    4015c1 <win+0x4b>
  405c65:	ba 00 01 00 00       	mov    edx,0x100
  405c6a:	48 89 ee             	mov    rsi,rbp
  405c6d:	e8 8e b5 ff ff       	call   401200 <read@plt>
  405c72:	85 c0                	test   eax,eax
  405c74:	7f 2a                	jg     405ca0 <win+0x472a>
  405c76:	e8 05 b5 ff ff       	call   401180 <__errno_location@plt>
  405c7b:	8b 38                	mov    edi,DWORD PTR [rax]
  405c7d:	e8 fe b5 ff ff       	call   401280 <strerror@plt>
  405c82:	bf 01 00 00 00       	mov    edi,0x1
  405c87:	48 8d 35 1b c4 00 00 	lea    rsi,[rip+0xc41b]        # 4120a9 <_IO_stdin_used+0xa9>
  405c8e:	48 89 c2             	mov    rdx,rax
  405c91:	31 c0                	xor    eax,eax
  405c93:	e8 98 b5 ff ff       	call   401230 <__printf_chk@plt>
  405c98:	83 cf ff             	or     edi,0xffffffff
  405c9b:	e8 c0 b5 ff ff       	call   401260 <exit@plt>
  405ca0:	48 63 d0             	movsxd rdx,eax
  405ca3:	48 89 ee             	mov    rsi,rbp
  405ca6:	bf 01 00 00 00       	mov    edi,0x1
  405cab:	e8 f0 b4 ff ff       	call   4011a0 <write@plt>
  405cb0:	48 8d 3d 9d c4 00 00 	lea    rdi,[rip+0xc49d]        # 412154 <_IO_stdin_used+0x154>
  405cb7:	e8 d4 b4 ff ff       	call   401190 <puts@plt>
  405cbc:	48 8d 3d 41 c3 00 00 	lea    rdi,[rip+0xc341]        # 412004 <_IO_stdin_used+0x4>
  405cc3:	31 f6                	xor    esi,esi
  405cc5:	31 c0                	xor    eax,eax
  405cc7:	e8 84 b5 ff ff       	call   401250 <open@plt>
  405ccc:	89 c7                	mov    edi,eax
  405cce:	85 c0                	test   eax,eax
  405cd0:	79 34                	jns    405d06 <win+0x4790>
  405cd2:	e8 a9 b4 ff ff       	call   401180 <__errno_location@plt>
  405cd7:	8b 38                	mov    edi,DWORD PTR [rax]
  405cd9:	e8 a2 b5 ff ff       	call   401280 <strerror@plt>
  405cde:	48 8d 35 25 c3 00 00 	lea    rsi,[rip+0xc325]        # 41200a <_IO_stdin_used+0xa>
  405ce5:	bf 01 00 00 00       	mov    edi,0x1
  405cea:	48 89 c2             	mov    rdx,rax
  405ced:	31 c0                	xor    eax,eax
  405cef:	e8 3c b5 ff ff       	call   401230 <__printf_chk@plt>
  405cf4:	e8 e7 b4 ff ff       	call   4011e0 <geteuid@plt>
  405cf9:	85 c0                	test   eax,eax
  405cfb:	0f 84 d8 b8 ff ff    	je     4015d9 <win+0x63>
  405d01:	e9 bb b8 ff ff       	jmp    4015c1 <win+0x4b>
  405d06:	ba 00 01 00 00       	mov    edx,0x100
  405d0b:	48 89 ee             	mov    rsi,rbp
  405d0e:	e8 ed b4 ff ff       	call   401200 <read@plt>
  405d13:	85 c0                	test   eax,eax
  405d15:	7f 2a                	jg     405d41 <win+0x47cb>
  405d17:	e8 64 b4 ff ff       	call   401180 <__errno_location@plt>
  405d1c:	8b 38                	mov    edi,DWORD PTR [rax]
  405d1e:	e8 5d b5 ff ff       	call   401280 <strerror@plt>
  405d23:	bf 01 00 00 00       	mov    edi,0x1
  405d28:	48 8d 35 7a c3 00 00 	lea    rsi,[rip+0xc37a]        # 4120a9 <_IO_stdin_used+0xa9>
  405d2f:	48 89 c2             	mov    rdx,rax
  405d32:	31 c0                	xor    eax,eax
  405d34:	e8 f7 b4 ff ff       	call   401230 <__printf_chk@plt>
  405d39:	83 cf ff             	or     edi,0xffffffff
  405d3c:	e8 1f b5 ff ff       	call   401260 <exit@plt>
  405d41:	48 63 d0             	movsxd rdx,eax
  405d44:	48 89 ee             	mov    rsi,rbp
  405d47:	bf 01 00 00 00       	mov    edi,0x1
  405d4c:	e8 4f b4 ff ff       	call   4011a0 <write@plt>
  405d51:	48 8d 3d fc c3 00 00 	lea    rdi,[rip+0xc3fc]        # 412154 <_IO_stdin_used+0x154>
  405d58:	e8 33 b4 ff ff       	call   401190 <puts@plt>
  405d5d:	48 8d 3d a0 c2 00 00 	lea    rdi,[rip+0xc2a0]        # 412004 <_IO_stdin_used+0x4>
  405d64:	31 f6                	xor    esi,esi
  405d66:	31 c0                	xor    eax,eax
  405d68:	e8 e3 b4 ff ff       	call   401250 <open@plt>
  405d6d:	89 c7                	mov    edi,eax
  405d6f:	85 c0                	test   eax,eax
  405d71:	79 34                	jns    405da7 <win+0x4831>
  405d73:	e8 08 b4 ff ff       	call   401180 <__errno_location@plt>
  405d78:	8b 38                	mov    edi,DWORD PTR [rax]
  405d7a:	e8 01 b5 ff ff       	call   401280 <strerror@plt>
  405d7f:	48 8d 35 84 c2 00 00 	lea    rsi,[rip+0xc284]        # 41200a <_IO_stdin_used+0xa>
  405d86:	bf 01 00 00 00       	mov    edi,0x1
  405d8b:	48 89 c2             	mov    rdx,rax
  405d8e:	31 c0                	xor    eax,eax
  405d90:	e8 9b b4 ff ff       	call   401230 <__printf_chk@plt>
  405d95:	e8 46 b4 ff ff       	call   4011e0 <geteuid@plt>
  405d9a:	85 c0                	test   eax,eax
  405d9c:	0f 84 37 b8 ff ff    	je     4015d9 <win+0x63>
  405da2:	e9 1a b8 ff ff       	jmp    4015c1 <win+0x4b>
  405da7:	ba 00 01 00 00       	mov    edx,0x100
  405dac:	48 89 ee             	mov    rsi,rbp
  405daf:	e8 4c b4 ff ff       	call   401200 <read@plt>
  405db4:	85 c0                	test   eax,eax
  405db6:	7f 2a                	jg     405de2 <win+0x486c>
  405db8:	e8 c3 b3 ff ff       	call   401180 <__errno_location@plt>
  405dbd:	8b 38                	mov    edi,DWORD PTR [rax]
  405dbf:	e8 bc b4 ff ff       	call   401280 <strerror@plt>
  405dc4:	bf 01 00 00 00       	mov    edi,0x1
  405dc9:	48 8d 35 d9 c2 00 00 	lea    rsi,[rip+0xc2d9]        # 4120a9 <_IO_stdin_used+0xa9>
  405dd0:	48 89 c2             	mov    rdx,rax
  405dd3:	31 c0                	xor    eax,eax
  405dd5:	e8 56 b4 ff ff       	call   401230 <__printf_chk@plt>
  405dda:	83 cf ff             	or     edi,0xffffffff
  405ddd:	e8 7e b4 ff ff       	call   401260 <exit@plt>
  405de2:	48 63 d0             	movsxd rdx,eax
  405de5:	48 89 ee             	mov    rsi,rbp
  405de8:	bf 01 00 00 00       	mov    edi,0x1
  405ded:	e8 ae b3 ff ff       	call   4011a0 <write@plt>
  405df2:	48 8d 3d 5b c3 00 00 	lea    rdi,[rip+0xc35b]        # 412154 <_IO_stdin_used+0x154>
  405df9:	e8 92 b3 ff ff       	call   401190 <puts@plt>
  405dfe:	48 8d 3d ff c1 00 00 	lea    rdi,[rip+0xc1ff]        # 412004 <_IO_stdin_used+0x4>
  405e05:	31 f6                	xor    esi,esi
  405e07:	31 c0                	xor    eax,eax
  405e09:	e8 42 b4 ff ff       	call   401250 <open@plt>
  405e0e:	89 c7                	mov    edi,eax
  405e10:	85 c0                	test   eax,eax
  405e12:	79 34                	jns    405e48 <win+0x48d2>
  405e14:	e8 67 b3 ff ff       	call   401180 <__errno_location@plt>
  405e19:	8b 38                	mov    edi,DWORD PTR [rax]
  405e1b:	e8 60 b4 ff ff       	call   401280 <strerror@plt>
  405e20:	48 8d 35 e3 c1 00 00 	lea    rsi,[rip+0xc1e3]        # 41200a <_IO_stdin_used+0xa>
  405e27:	bf 01 00 00 00       	mov    edi,0x1
  405e2c:	48 89 c2             	mov    rdx,rax
  405e2f:	31 c0                	xor    eax,eax
  405e31:	e8 fa b3 ff ff       	call   401230 <__printf_chk@plt>
  405e36:	e8 a5 b3 ff ff       	call   4011e0 <geteuid@plt>
  405e3b:	85 c0                	test   eax,eax
  405e3d:	0f 84 96 b7 ff ff    	je     4015d9 <win+0x63>
  405e43:	e9 79 b7 ff ff       	jmp    4015c1 <win+0x4b>
  405e48:	ba 00 01 00 00       	mov    edx,0x100
  405e4d:	48 89 ee             	mov    rsi,rbp
  405e50:	e8 ab b3 ff ff       	call   401200 <read@plt>
  405e55:	85 c0                	test   eax,eax
  405e57:	7f 2a                	jg     405e83 <win+0x490d>
  405e59:	e8 22 b3 ff ff       	call   401180 <__errno_location@plt>
  405e5e:	8b 38                	mov    edi,DWORD PTR [rax]
  405e60:	e8 1b b4 ff ff       	call   401280 <strerror@plt>
  405e65:	bf 01 00 00 00       	mov    edi,0x1
  405e6a:	48 8d 35 38 c2 00 00 	lea    rsi,[rip+0xc238]        # 4120a9 <_IO_stdin_used+0xa9>
  405e71:	48 89 c2             	mov    rdx,rax
  405e74:	31 c0                	xor    eax,eax
  405e76:	e8 b5 b3 ff ff       	call   401230 <__printf_chk@plt>
  405e7b:	83 cf ff             	or     edi,0xffffffff
  405e7e:	e8 dd b3 ff ff       	call   401260 <exit@plt>
  405e83:	48 63 d0             	movsxd rdx,eax
  405e86:	48 89 ee             	mov    rsi,rbp
  405e89:	bf 01 00 00 00       	mov    edi,0x1
  405e8e:	e8 0d b3 ff ff       	call   4011a0 <write@plt>
  405e93:	48 8d 3d ba c2 00 00 	lea    rdi,[rip+0xc2ba]        # 412154 <_IO_stdin_used+0x154>
  405e9a:	e8 f1 b2 ff ff       	call   401190 <puts@plt>
  405e9f:	48 8d 3d 5e c1 00 00 	lea    rdi,[rip+0xc15e]        # 412004 <_IO_stdin_used+0x4>
  405ea6:	31 f6                	xor    esi,esi
  405ea8:	31 c0                	xor    eax,eax
  405eaa:	e8 a1 b3 ff ff       	call   401250 <open@plt>
  405eaf:	89 c7                	mov    edi,eax
  405eb1:	85 c0                	test   eax,eax
  405eb3:	79 34                	jns    405ee9 <win+0x4973>
  405eb5:	e8 c6 b2 ff ff       	call   401180 <__errno_location@plt>
  405eba:	8b 38                	mov    edi,DWORD PTR [rax]
  405ebc:	e8 bf b3 ff ff       	call   401280 <strerror@plt>
  405ec1:	48 8d 35 42 c1 00 00 	lea    rsi,[rip+0xc142]        # 41200a <_IO_stdin_used+0xa>
  405ec8:	bf 01 00 00 00       	mov    edi,0x1
  405ecd:	48 89 c2             	mov    rdx,rax
  405ed0:	31 c0                	xor    eax,eax
  405ed2:	e8 59 b3 ff ff       	call   401230 <__printf_chk@plt>
  405ed7:	e8 04 b3 ff ff       	call   4011e0 <geteuid@plt>
  405edc:	85 c0                	test   eax,eax
  405ede:	0f 84 f5 b6 ff ff    	je     4015d9 <win+0x63>
  405ee4:	e9 d8 b6 ff ff       	jmp    4015c1 <win+0x4b>
  405ee9:	ba 00 01 00 00       	mov    edx,0x100
  405eee:	48 89 ee             	mov    rsi,rbp
  405ef1:	e8 0a b3 ff ff       	call   401200 <read@plt>
  405ef6:	85 c0                	test   eax,eax
  405ef8:	7f 2a                	jg     405f24 <win+0x49ae>
  405efa:	e8 81 b2 ff ff       	call   401180 <__errno_location@plt>
  405eff:	8b 38                	mov    edi,DWORD PTR [rax]
  405f01:	e8 7a b3 ff ff       	call   401280 <strerror@plt>
  405f06:	bf 01 00 00 00       	mov    edi,0x1
  405f0b:	48 8d 35 97 c1 00 00 	lea    rsi,[rip+0xc197]        # 4120a9 <_IO_stdin_used+0xa9>
  405f12:	48 89 c2             	mov    rdx,rax
  405f15:	31 c0                	xor    eax,eax
  405f17:	e8 14 b3 ff ff       	call   401230 <__printf_chk@plt>
  405f1c:	83 cf ff             	or     edi,0xffffffff
  405f1f:	e8 3c b3 ff ff       	call   401260 <exit@plt>
  405f24:	48 63 d0             	movsxd rdx,eax
  405f27:	48 89 ee             	mov    rsi,rbp
  405f2a:	bf 01 00 00 00       	mov    edi,0x1
  405f2f:	e8 6c b2 ff ff       	call   4011a0 <write@plt>
  405f34:	48 8d 3d 19 c2 00 00 	lea    rdi,[rip+0xc219]        # 412154 <_IO_stdin_used+0x154>
  405f3b:	e8 50 b2 ff ff       	call   401190 <puts@plt>
  405f40:	48 8d 3d bd c0 00 00 	lea    rdi,[rip+0xc0bd]        # 412004 <_IO_stdin_used+0x4>
  405f47:	31 f6                	xor    esi,esi
  405f49:	31 c0                	xor    eax,eax
  405f4b:	e8 00 b3 ff ff       	call   401250 <open@plt>
  405f50:	89 c7                	mov    edi,eax
  405f52:	85 c0                	test   eax,eax
  405f54:	79 34                	jns    405f8a <win+0x4a14>
  405f56:	e8 25 b2 ff ff       	call   401180 <__errno_location@plt>
  405f5b:	8b 38                	mov    edi,DWORD PTR [rax]
  405f5d:	e8 1e b3 ff ff       	call   401280 <strerror@plt>
  405f62:	48 8d 35 a1 c0 00 00 	lea    rsi,[rip+0xc0a1]        # 41200a <_IO_stdin_used+0xa>
  405f69:	bf 01 00 00 00       	mov    edi,0x1
  405f6e:	48 89 c2             	mov    rdx,rax
  405f71:	31 c0                	xor    eax,eax
  405f73:	e8 b8 b2 ff ff       	call   401230 <__printf_chk@plt>
  405f78:	e8 63 b2 ff ff       	call   4011e0 <geteuid@plt>
  405f7d:	85 c0                	test   eax,eax
  405f7f:	0f 84 54 b6 ff ff    	je     4015d9 <win+0x63>
  405f85:	e9 37 b6 ff ff       	jmp    4015c1 <win+0x4b>
  405f8a:	ba 00 01 00 00       	mov    edx,0x100
  405f8f:	48 89 ee             	mov    rsi,rbp
  405f92:	e8 69 b2 ff ff       	call   401200 <read@plt>
  405f97:	85 c0                	test   eax,eax
  405f99:	7f 2a                	jg     405fc5 <win+0x4a4f>
  405f9b:	e8 e0 b1 ff ff       	call   401180 <__errno_location@plt>
  405fa0:	8b 38                	mov    edi,DWORD PTR [rax]
  405fa2:	e8 d9 b2 ff ff       	call   401280 <strerror@plt>
  405fa7:	bf 01 00 00 00       	mov    edi,0x1
  405fac:	48 8d 35 f6 c0 00 00 	lea    rsi,[rip+0xc0f6]        # 4120a9 <_IO_stdin_used+0xa9>
  405fb3:	48 89 c2             	mov    rdx,rax
  405fb6:	31 c0                	xor    eax,eax
  405fb8:	e8 73 b2 ff ff       	call   401230 <__printf_chk@plt>
  405fbd:	83 cf ff             	or     edi,0xffffffff
  405fc0:	e8 9b b2 ff ff       	call   401260 <exit@plt>
  405fc5:	48 63 d0             	movsxd rdx,eax
  405fc8:	48 89 ee             	mov    rsi,rbp
  405fcb:	bf 01 00 00 00       	mov    edi,0x1
  405fd0:	e8 cb b1 ff ff       	call   4011a0 <write@plt>
  405fd5:	48 8d 3d 78 c1 00 00 	lea    rdi,[rip+0xc178]        # 412154 <_IO_stdin_used+0x154>
  405fdc:	e8 af b1 ff ff       	call   401190 <puts@plt>
  405fe1:	48 8d 3d 1c c0 00 00 	lea    rdi,[rip+0xc01c]        # 412004 <_IO_stdin_used+0x4>
  405fe8:	31 f6                	xor    esi,esi
  405fea:	31 c0                	xor    eax,eax
  405fec:	e8 5f b2 ff ff       	call   401250 <open@plt>
  405ff1:	89 c7                	mov    edi,eax
  405ff3:	85 c0                	test   eax,eax
  405ff5:	79 34                	jns    40602b <win+0x4ab5>
  405ff7:	e8 84 b1 ff ff       	call   401180 <__errno_location@plt>
  405ffc:	8b 38                	mov    edi,DWORD PTR [rax]
  405ffe:	e8 7d b2 ff ff       	call   401280 <strerror@plt>
  406003:	48 8d 35 00 c0 00 00 	lea    rsi,[rip+0xc000]        # 41200a <_IO_stdin_used+0xa>
  40600a:	bf 01 00 00 00       	mov    edi,0x1
  40600f:	48 89 c2             	mov    rdx,rax
  406012:	31 c0                	xor    eax,eax
  406014:	e8 17 b2 ff ff       	call   401230 <__printf_chk@plt>
  406019:	e8 c2 b1 ff ff       	call   4011e0 <geteuid@plt>
  40601e:	85 c0                	test   eax,eax
  406020:	0f 84 b3 b5 ff ff    	je     4015d9 <win+0x63>
  406026:	e9 96 b5 ff ff       	jmp    4015c1 <win+0x4b>
  40602b:	ba 00 01 00 00       	mov    edx,0x100
  406030:	48 89 ee             	mov    rsi,rbp
  406033:	e8 c8 b1 ff ff       	call   401200 <read@plt>
  406038:	85 c0                	test   eax,eax
  40603a:	7f 2a                	jg     406066 <win+0x4af0>
  40603c:	e8 3f b1 ff ff       	call   401180 <__errno_location@plt>
  406041:	8b 38                	mov    edi,DWORD PTR [rax]
  406043:	e8 38 b2 ff ff       	call   401280 <strerror@plt>
  406048:	bf 01 00 00 00       	mov    edi,0x1
  40604d:	48 8d 35 55 c0 00 00 	lea    rsi,[rip+0xc055]        # 4120a9 <_IO_stdin_used+0xa9>
  406054:	48 89 c2             	mov    rdx,rax
  406057:	31 c0                	xor    eax,eax
  406059:	e8 d2 b1 ff ff       	call   401230 <__printf_chk@plt>
  40605e:	83 cf ff             	or     edi,0xffffffff
  406061:	e8 fa b1 ff ff       	call   401260 <exit@plt>
  406066:	48 63 d0             	movsxd rdx,eax
  406069:	48 89 ee             	mov    rsi,rbp
  40606c:	bf 01 00 00 00       	mov    edi,0x1
  406071:	e8 2a b1 ff ff       	call   4011a0 <write@plt>
  406076:	48 8d 3d d7 c0 00 00 	lea    rdi,[rip+0xc0d7]        # 412154 <_IO_stdin_used+0x154>
  40607d:	e8 0e b1 ff ff       	call   401190 <puts@plt>
  406082:	48 8d 3d 7b bf 00 00 	lea    rdi,[rip+0xbf7b]        # 412004 <_IO_stdin_used+0x4>
  406089:	31 f6                	xor    esi,esi
  40608b:	31 c0                	xor    eax,eax
  40608d:	e8 be b1 ff ff       	call   401250 <open@plt>
  406092:	89 c7                	mov    edi,eax
  406094:	85 c0                	test   eax,eax
  406096:	79 34                	jns    4060cc <win+0x4b56>
  406098:	e8 e3 b0 ff ff       	call   401180 <__errno_location@plt>
  40609d:	8b 38                	mov    edi,DWORD PTR [rax]
  40609f:	e8 dc b1 ff ff       	call   401280 <strerror@plt>
  4060a4:	48 8d 35 5f bf 00 00 	lea    rsi,[rip+0xbf5f]        # 41200a <_IO_stdin_used+0xa>
  4060ab:	bf 01 00 00 00       	mov    edi,0x1
  4060b0:	48 89 c2             	mov    rdx,rax
  4060b3:	31 c0                	xor    eax,eax
  4060b5:	e8 76 b1 ff ff       	call   401230 <__printf_chk@plt>
  4060ba:	e8 21 b1 ff ff       	call   4011e0 <geteuid@plt>
  4060bf:	85 c0                	test   eax,eax
  4060c1:	0f 84 12 b5 ff ff    	je     4015d9 <win+0x63>
  4060c7:	e9 f5 b4 ff ff       	jmp    4015c1 <win+0x4b>
  4060cc:	ba 00 01 00 00       	mov    edx,0x100
  4060d1:	48 89 ee             	mov    rsi,rbp
  4060d4:	e8 27 b1 ff ff       	call   401200 <read@plt>
  4060d9:	85 c0                	test   eax,eax
  4060db:	7f 2a                	jg     406107 <win+0x4b91>
  4060dd:	e8 9e b0 ff ff       	call   401180 <__errno_location@plt>
  4060e2:	8b 38                	mov    edi,DWORD PTR [rax]
  4060e4:	e8 97 b1 ff ff       	call   401280 <strerror@plt>
  4060e9:	bf 01 00 00 00       	mov    edi,0x1
  4060ee:	48 8d 35 b4 bf 00 00 	lea    rsi,[rip+0xbfb4]        # 4120a9 <_IO_stdin_used+0xa9>
  4060f5:	48 89 c2             	mov    rdx,rax
  4060f8:	31 c0                	xor    eax,eax
  4060fa:	e8 31 b1 ff ff       	call   401230 <__printf_chk@plt>
  4060ff:	83 cf ff             	or     edi,0xffffffff
  406102:	e8 59 b1 ff ff       	call   401260 <exit@plt>
  406107:	48 89 e5             	mov    rbp,rsp
  40610a:	48 63 d0             	movsxd rdx,eax
  40610d:	bf 01 00 00 00       	mov    edi,0x1
  406112:	48 89 ee             	mov    rsi,rbp
  406115:	e8 86 b0 ff ff       	call   4011a0 <write@plt>
  40611a:	48 8d 3d 33 c0 00 00 	lea    rdi,[rip+0xc033]        # 412154 <_IO_stdin_used+0x154>
  406121:	e8 6a b0 ff ff       	call   401190 <puts@plt>
  406126:	48 8d 3d d7 be 00 00 	lea    rdi,[rip+0xbed7]        # 412004 <_IO_stdin_used+0x4>
  40612d:	31 f6                	xor    esi,esi
  40612f:	31 c0                	xor    eax,eax
  406131:	e8 1a b1 ff ff       	call   401250 <open@plt>
  406136:	89 c7                	mov    edi,eax
  406138:	85 c0                	test   eax,eax
  40613a:	79 34                	jns    406170 <win+0x4bfa>
  40613c:	e8 3f b0 ff ff       	call   401180 <__errno_location@plt>
  406141:	8b 38                	mov    edi,DWORD PTR [rax]
  406143:	e8 38 b1 ff ff       	call   401280 <strerror@plt>
  406148:	48 8d 35 bb be 00 00 	lea    rsi,[rip+0xbebb]        # 41200a <_IO_stdin_used+0xa>
  40614f:	bf 01 00 00 00       	mov    edi,0x1
  406154:	48 89 c2             	mov    rdx,rax
  406157:	31 c0                	xor    eax,eax
  406159:	e8 d2 b0 ff ff       	call   401230 <__printf_chk@plt>
  40615e:	e8 7d b0 ff ff       	call   4011e0 <geteuid@plt>
  406163:	85 c0                	test   eax,eax
  406165:	0f 84 6e b4 ff ff    	je     4015d9 <win+0x63>
  40616b:	e9 51 b4 ff ff       	jmp    4015c1 <win+0x4b>
  406170:	ba 00 01 00 00       	mov    edx,0x100
  406175:	48 89 ee             	mov    rsi,rbp
  406178:	e8 83 b0 ff ff       	call   401200 <read@plt>
  40617d:	85 c0                	test   eax,eax
  40617f:	7f 2a                	jg     4061ab <win+0x4c35>
  406181:	e8 fa af ff ff       	call   401180 <__errno_location@plt>
  406186:	8b 38                	mov    edi,DWORD PTR [rax]
  406188:	e8 f3 b0 ff ff       	call   401280 <strerror@plt>
  40618d:	bf 01 00 00 00       	mov    edi,0x1
  406192:	48 8d 35 10 bf 00 00 	lea    rsi,[rip+0xbf10]        # 4120a9 <_IO_stdin_used+0xa9>
  406199:	48 89 c2             	mov    rdx,rax
  40619c:	31 c0                	xor    eax,eax
  40619e:	e8 8d b0 ff ff       	call   401230 <__printf_chk@plt>
  4061a3:	83 cf ff             	or     edi,0xffffffff
  4061a6:	e8 b5 b0 ff ff       	call   401260 <exit@plt>
  4061ab:	48 63 d0             	movsxd rdx,eax
  4061ae:	48 89 ee             	mov    rsi,rbp
  4061b1:	bf 01 00 00 00       	mov    edi,0x1
  4061b6:	e8 e5 af ff ff       	call   4011a0 <write@plt>
  4061bb:	48 8d 3d 92 bf 00 00 	lea    rdi,[rip+0xbf92]        # 412154 <_IO_stdin_used+0x154>
  4061c2:	e8 c9 af ff ff       	call   401190 <puts@plt>
  4061c7:	48 8d 3d 36 be 00 00 	lea    rdi,[rip+0xbe36]        # 412004 <_IO_stdin_used+0x4>
  4061ce:	31 f6                	xor    esi,esi
  4061d0:	31 c0                	xor    eax,eax
  4061d2:	e8 79 b0 ff ff       	call   401250 <open@plt>
  4061d7:	89 c7                	mov    edi,eax
  4061d9:	85 c0                	test   eax,eax
  4061db:	79 34                	jns    406211 <win+0x4c9b>
  4061dd:	e8 9e af ff ff       	call   401180 <__errno_location@plt>
  4061e2:	8b 38                	mov    edi,DWORD PTR [rax]
  4061e4:	e8 97 b0 ff ff       	call   401280 <strerror@plt>
  4061e9:	48 8d 35 1a be 00 00 	lea    rsi,[rip+0xbe1a]        # 41200a <_IO_stdin_used+0xa>
  4061f0:	bf 01 00 00 00       	mov    edi,0x1
  4061f5:	48 89 c2             	mov    rdx,rax
  4061f8:	31 c0                	xor    eax,eax
  4061fa:	e8 31 b0 ff ff       	call   401230 <__printf_chk@plt>
  4061ff:	e8 dc af ff ff       	call   4011e0 <geteuid@plt>
  406204:	85 c0                	test   eax,eax
  406206:	0f 84 cd b3 ff ff    	je     4015d9 <win+0x63>
  40620c:	e9 b0 b3 ff ff       	jmp    4015c1 <win+0x4b>
  406211:	ba 00 01 00 00       	mov    edx,0x100
  406216:	48 89 ee             	mov    rsi,rbp
  406219:	e8 e2 af ff ff       	call   401200 <read@plt>
  40621e:	85 c0                	test   eax,eax
  406220:	7f 2a                	jg     40624c <win+0x4cd6>
  406222:	e8 59 af ff ff       	call   401180 <__errno_location@plt>
  406227:	8b 38                	mov    edi,DWORD PTR [rax]
  406229:	e8 52 b0 ff ff       	call   401280 <strerror@plt>
  40622e:	bf 01 00 00 00       	mov    edi,0x1
  406233:	48 8d 35 6f be 00 00 	lea    rsi,[rip+0xbe6f]        # 4120a9 <_IO_stdin_used+0xa9>
  40623a:	48 89 c2             	mov    rdx,rax
  40623d:	31 c0                	xor    eax,eax
  40623f:	e8 ec af ff ff       	call   401230 <__printf_chk@plt>
  406244:	83 cf ff             	or     edi,0xffffffff
  406247:	e8 14 b0 ff ff       	call   401260 <exit@plt>
  40624c:	48 63 d0             	movsxd rdx,eax
  40624f:	48 89 ee             	mov    rsi,rbp
  406252:	bf 01 00 00 00       	mov    edi,0x1
  406257:	e8 44 af ff ff       	call   4011a0 <write@plt>
  40625c:	48 8d 3d f1 be 00 00 	lea    rdi,[rip+0xbef1]        # 412154 <_IO_stdin_used+0x154>
  406263:	e8 28 af ff ff       	call   401190 <puts@plt>
  406268:	48 8d 3d 95 bd 00 00 	lea    rdi,[rip+0xbd95]        # 412004 <_IO_stdin_used+0x4>
  40626f:	31 f6                	xor    esi,esi
  406271:	31 c0                	xor    eax,eax
  406273:	e8 d8 af ff ff       	call   401250 <open@plt>
  406278:	89 c7                	mov    edi,eax
  40627a:	85 c0                	test   eax,eax
  40627c:	79 34                	jns    4062b2 <win+0x4d3c>
  40627e:	e8 fd ae ff ff       	call   401180 <__errno_location@plt>
  406283:	8b 38                	mov    edi,DWORD PTR [rax]
  406285:	e8 f6 af ff ff       	call   401280 <strerror@plt>
  40628a:	48 8d 35 79 bd 00 00 	lea    rsi,[rip+0xbd79]        # 41200a <_IO_stdin_used+0xa>
  406291:	bf 01 00 00 00       	mov    edi,0x1
  406296:	48 89 c2             	mov    rdx,rax
  406299:	31 c0                	xor    eax,eax
  40629b:	e8 90 af ff ff       	call   401230 <__printf_chk@plt>
  4062a0:	e8 3b af ff ff       	call   4011e0 <geteuid@plt>
  4062a5:	85 c0                	test   eax,eax
  4062a7:	0f 84 2c b3 ff ff    	je     4015d9 <win+0x63>
  4062ad:	e9 0f b3 ff ff       	jmp    4015c1 <win+0x4b>
  4062b2:	ba 00 01 00 00       	mov    edx,0x100
  4062b7:	48 89 ee             	mov    rsi,rbp
  4062ba:	e8 41 af ff ff       	call   401200 <read@plt>
  4062bf:	85 c0                	test   eax,eax
  4062c1:	7f 2a                	jg     4062ed <win+0x4d77>
  4062c3:	e8 b8 ae ff ff       	call   401180 <__errno_location@plt>
  4062c8:	8b 38                	mov    edi,DWORD PTR [rax]
  4062ca:	e8 b1 af ff ff       	call   401280 <strerror@plt>
  4062cf:	bf 01 00 00 00       	mov    edi,0x1
  4062d4:	48 8d 35 ce bd 00 00 	lea    rsi,[rip+0xbdce]        # 4120a9 <_IO_stdin_used+0xa9>
  4062db:	48 89 c2             	mov    rdx,rax
  4062de:	31 c0                	xor    eax,eax
  4062e0:	e8 4b af ff ff       	call   401230 <__printf_chk@plt>
  4062e5:	83 cf ff             	or     edi,0xffffffff
  4062e8:	e8 73 af ff ff       	call   401260 <exit@plt>
  4062ed:	48 63 d0             	movsxd rdx,eax
  4062f0:	48 89 ee             	mov    rsi,rbp
  4062f3:	bf 01 00 00 00       	mov    edi,0x1
  4062f8:	e8 a3 ae ff ff       	call   4011a0 <write@plt>
  4062fd:	48 8d 3d 50 be 00 00 	lea    rdi,[rip+0xbe50]        # 412154 <_IO_stdin_used+0x154>
  406304:	e8 87 ae ff ff       	call   401190 <puts@plt>
  406309:	48 8d 3d f4 bc 00 00 	lea    rdi,[rip+0xbcf4]        # 412004 <_IO_stdin_used+0x4>
  406310:	31 f6                	xor    esi,esi
  406312:	31 c0                	xor    eax,eax
  406314:	e8 37 af ff ff       	call   401250 <open@plt>
  406319:	89 c7                	mov    edi,eax
  40631b:	85 c0                	test   eax,eax
  40631d:	79 34                	jns    406353 <win+0x4ddd>
  40631f:	e8 5c ae ff ff       	call   401180 <__errno_location@plt>
  406324:	8b 38                	mov    edi,DWORD PTR [rax]
  406326:	e8 55 af ff ff       	call   401280 <strerror@plt>
  40632b:	48 8d 35 d8 bc 00 00 	lea    rsi,[rip+0xbcd8]        # 41200a <_IO_stdin_used+0xa>
  406332:	bf 01 00 00 00       	mov    edi,0x1
  406337:	48 89 c2             	mov    rdx,rax
  40633a:	31 c0                	xor    eax,eax
  40633c:	e8 ef ae ff ff       	call   401230 <__printf_chk@plt>
  406341:	e8 9a ae ff ff       	call   4011e0 <geteuid@plt>
  406346:	85 c0                	test   eax,eax
  406348:	0f 84 8b b2 ff ff    	je     4015d9 <win+0x63>
  40634e:	e9 6e b2 ff ff       	jmp    4015c1 <win+0x4b>
  406353:	ba 00 01 00 00       	mov    edx,0x100
  406358:	48 89 ee             	mov    rsi,rbp
  40635b:	e8 a0 ae ff ff       	call   401200 <read@plt>
  406360:	85 c0                	test   eax,eax
  406362:	7f 2a                	jg     40638e <win+0x4e18>
  406364:	e8 17 ae ff ff       	call   401180 <__errno_location@plt>
  406369:	8b 38                	mov    edi,DWORD PTR [rax]
  40636b:	e8 10 af ff ff       	call   401280 <strerror@plt>
  406370:	bf 01 00 00 00       	mov    edi,0x1
  406375:	48 8d 35 2d bd 00 00 	lea    rsi,[rip+0xbd2d]        # 4120a9 <_IO_stdin_used+0xa9>
  40637c:	48 89 c2             	mov    rdx,rax
  40637f:	31 c0                	xor    eax,eax
  406381:	e8 aa ae ff ff       	call   401230 <__printf_chk@plt>
  406386:	83 cf ff             	or     edi,0xffffffff
  406389:	e8 d2 ae ff ff       	call   401260 <exit@plt>
  40638e:	48 63 d0             	movsxd rdx,eax
  406391:	48 89 ee             	mov    rsi,rbp
  406394:	bf 01 00 00 00       	mov    edi,0x1
  406399:	e8 02 ae ff ff       	call   4011a0 <write@plt>
  40639e:	48 8d 3d af bd 00 00 	lea    rdi,[rip+0xbdaf]        # 412154 <_IO_stdin_used+0x154>
  4063a5:	e8 e6 ad ff ff       	call   401190 <puts@plt>
  4063aa:	48 8d 3d 53 bc 00 00 	lea    rdi,[rip+0xbc53]        # 412004 <_IO_stdin_used+0x4>
  4063b1:	31 f6                	xor    esi,esi
  4063b3:	31 c0                	xor    eax,eax
  4063b5:	e8 96 ae ff ff       	call   401250 <open@plt>
  4063ba:	89 c7                	mov    edi,eax
  4063bc:	85 c0                	test   eax,eax
  4063be:	79 34                	jns    4063f4 <win+0x4e7e>
  4063c0:	e8 bb ad ff ff       	call   401180 <__errno_location@plt>
  4063c5:	8b 38                	mov    edi,DWORD PTR [rax]
  4063c7:	e8 b4 ae ff ff       	call   401280 <strerror@plt>
  4063cc:	48 8d 35 37 bc 00 00 	lea    rsi,[rip+0xbc37]        # 41200a <_IO_stdin_used+0xa>
  4063d3:	bf 01 00 00 00       	mov    edi,0x1
  4063d8:	48 89 c2             	mov    rdx,rax
  4063db:	31 c0                	xor    eax,eax
  4063dd:	e8 4e ae ff ff       	call   401230 <__printf_chk@plt>
  4063e2:	e8 f9 ad ff ff       	call   4011e0 <geteuid@plt>
  4063e7:	85 c0                	test   eax,eax
  4063e9:	0f 84 ea b1 ff ff    	je     4015d9 <win+0x63>
  4063ef:	e9 cd b1 ff ff       	jmp    4015c1 <win+0x4b>
  4063f4:	ba 00 01 00 00       	mov    edx,0x100
  4063f9:	48 89 ee             	mov    rsi,rbp
  4063fc:	e8 ff ad ff ff       	call   401200 <read@plt>
  406401:	85 c0                	test   eax,eax
  406403:	7f 2a                	jg     40642f <win+0x4eb9>
  406405:	e8 76 ad ff ff       	call   401180 <__errno_location@plt>
  40640a:	8b 38                	mov    edi,DWORD PTR [rax]
  40640c:	e8 6f ae ff ff       	call   401280 <strerror@plt>
  406411:	bf 01 00 00 00       	mov    edi,0x1
  406416:	48 8d 35 8c bc 00 00 	lea    rsi,[rip+0xbc8c]        # 4120a9 <_IO_stdin_used+0xa9>
  40641d:	48 89 c2             	mov    rdx,rax
  406420:	31 c0                	xor    eax,eax
  406422:	e8 09 ae ff ff       	call   401230 <__printf_chk@plt>
  406427:	83 cf ff             	or     edi,0xffffffff
  40642a:	e8 31 ae ff ff       	call   401260 <exit@plt>
  40642f:	48 63 d0             	movsxd rdx,eax
  406432:	48 89 ee             	mov    rsi,rbp
  406435:	bf 01 00 00 00       	mov    edi,0x1
  40643a:	e8 61 ad ff ff       	call   4011a0 <write@plt>
  40643f:	48 8d 3d 0e bd 00 00 	lea    rdi,[rip+0xbd0e]        # 412154 <_IO_stdin_used+0x154>
  406446:	e8 45 ad ff ff       	call   401190 <puts@plt>
  40644b:	48 8d 3d b2 bb 00 00 	lea    rdi,[rip+0xbbb2]        # 412004 <_IO_stdin_used+0x4>
  406452:	31 f6                	xor    esi,esi
  406454:	31 c0                	xor    eax,eax
  406456:	e8 f5 ad ff ff       	call   401250 <open@plt>
  40645b:	89 c7                	mov    edi,eax
  40645d:	85 c0                	test   eax,eax
  40645f:	79 34                	jns    406495 <win+0x4f1f>
  406461:	e8 1a ad ff ff       	call   401180 <__errno_location@plt>
  406466:	8b 38                	mov    edi,DWORD PTR [rax]
  406468:	e8 13 ae ff ff       	call   401280 <strerror@plt>
  40646d:	48 8d 35 96 bb 00 00 	lea    rsi,[rip+0xbb96]        # 41200a <_IO_stdin_used+0xa>
  406474:	bf 01 00 00 00       	mov    edi,0x1
  406479:	48 89 c2             	mov    rdx,rax
  40647c:	31 c0                	xor    eax,eax
  40647e:	e8 ad ad ff ff       	call   401230 <__printf_chk@plt>
  406483:	e8 58 ad ff ff       	call   4011e0 <geteuid@plt>
  406488:	85 c0                	test   eax,eax
  40648a:	0f 84 49 b1 ff ff    	je     4015d9 <win+0x63>
  406490:	e9 2c b1 ff ff       	jmp    4015c1 <win+0x4b>
  406495:	ba 00 01 00 00       	mov    edx,0x100
  40649a:	48 89 ee             	mov    rsi,rbp
  40649d:	e8 5e ad ff ff       	call   401200 <read@plt>
  4064a2:	85 c0                	test   eax,eax
  4064a4:	7f 2a                	jg     4064d0 <win+0x4f5a>
  4064a6:	e8 d5 ac ff ff       	call   401180 <__errno_location@plt>
  4064ab:	8b 38                	mov    edi,DWORD PTR [rax]
  4064ad:	e8 ce ad ff ff       	call   401280 <strerror@plt>
  4064b2:	bf 01 00 00 00       	mov    edi,0x1
  4064b7:	48 8d 35 eb bb 00 00 	lea    rsi,[rip+0xbbeb]        # 4120a9 <_IO_stdin_used+0xa9>
  4064be:	48 89 c2             	mov    rdx,rax
  4064c1:	31 c0                	xor    eax,eax
  4064c3:	e8 68 ad ff ff       	call   401230 <__printf_chk@plt>
  4064c8:	83 cf ff             	or     edi,0xffffffff
  4064cb:	e8 90 ad ff ff       	call   401260 <exit@plt>
  4064d0:	48 63 d0             	movsxd rdx,eax
  4064d3:	48 89 ee             	mov    rsi,rbp
  4064d6:	bf 01 00 00 00       	mov    edi,0x1
  4064db:	e8 c0 ac ff ff       	call   4011a0 <write@plt>
  4064e0:	48 8d 3d 6d bc 00 00 	lea    rdi,[rip+0xbc6d]        # 412154 <_IO_stdin_used+0x154>
  4064e7:	e8 a4 ac ff ff       	call   401190 <puts@plt>
  4064ec:	48 8d 3d 11 bb 00 00 	lea    rdi,[rip+0xbb11]        # 412004 <_IO_stdin_used+0x4>
  4064f3:	31 f6                	xor    esi,esi
  4064f5:	31 c0                	xor    eax,eax
  4064f7:	e8 54 ad ff ff       	call   401250 <open@plt>
  4064fc:	89 c7                	mov    edi,eax
  4064fe:	85 c0                	test   eax,eax
  406500:	79 34                	jns    406536 <win+0x4fc0>
  406502:	e8 79 ac ff ff       	call   401180 <__errno_location@plt>
  406507:	8b 38                	mov    edi,DWORD PTR [rax]
  406509:	e8 72 ad ff ff       	call   401280 <strerror@plt>
  40650e:	48 8d 35 f5 ba 00 00 	lea    rsi,[rip+0xbaf5]        # 41200a <_IO_stdin_used+0xa>
  406515:	bf 01 00 00 00       	mov    edi,0x1
  40651a:	48 89 c2             	mov    rdx,rax
  40651d:	31 c0                	xor    eax,eax
  40651f:	e8 0c ad ff ff       	call   401230 <__printf_chk@plt>
  406524:	e8 b7 ac ff ff       	call   4011e0 <geteuid@plt>
  406529:	85 c0                	test   eax,eax
  40652b:	0f 84 a8 b0 ff ff    	je     4015d9 <win+0x63>
  406531:	e9 8b b0 ff ff       	jmp    4015c1 <win+0x4b>
  406536:	ba 00 01 00 00       	mov    edx,0x100
  40653b:	48 89 ee             	mov    rsi,rbp
  40653e:	e8 bd ac ff ff       	call   401200 <read@plt>
  406543:	85 c0                	test   eax,eax
  406545:	7f 2a                	jg     406571 <win+0x4ffb>
  406547:	e8 34 ac ff ff       	call   401180 <__errno_location@plt>
  40654c:	8b 38                	mov    edi,DWORD PTR [rax]
  40654e:	e8 2d ad ff ff       	call   401280 <strerror@plt>
  406553:	bf 01 00 00 00       	mov    edi,0x1
  406558:	48 8d 35 4a bb 00 00 	lea    rsi,[rip+0xbb4a]        # 4120a9 <_IO_stdin_used+0xa9>
  40655f:	48 89 c2             	mov    rdx,rax
  406562:	31 c0                	xor    eax,eax
  406564:	e8 c7 ac ff ff       	call   401230 <__printf_chk@plt>
  406569:	83 cf ff             	or     edi,0xffffffff
  40656c:	e8 ef ac ff ff       	call   401260 <exit@plt>
  406571:	48 63 d0             	movsxd rdx,eax
  406574:	48 89 ee             	mov    rsi,rbp
  406577:	bf 01 00 00 00       	mov    edi,0x1
  40657c:	e8 1f ac ff ff       	call   4011a0 <write@plt>
  406581:	48 8d 3d cc bb 00 00 	lea    rdi,[rip+0xbbcc]        # 412154 <_IO_stdin_used+0x154>
  406588:	e8 03 ac ff ff       	call   401190 <puts@plt>
  40658d:	48 8d 3d 70 ba 00 00 	lea    rdi,[rip+0xba70]        # 412004 <_IO_stdin_used+0x4>
  406594:	31 f6                	xor    esi,esi
  406596:	31 c0                	xor    eax,eax
  406598:	e8 b3 ac ff ff       	call   401250 <open@plt>
  40659d:	89 c7                	mov    edi,eax
  40659f:	85 c0                	test   eax,eax
  4065a1:	79 34                	jns    4065d7 <win+0x5061>
  4065a3:	e8 d8 ab ff ff       	call   401180 <__errno_location@plt>
  4065a8:	8b 38                	mov    edi,DWORD PTR [rax]
  4065aa:	e8 d1 ac ff ff       	call   401280 <strerror@plt>
  4065af:	48 8d 35 54 ba 00 00 	lea    rsi,[rip+0xba54]        # 41200a <_IO_stdin_used+0xa>
  4065b6:	bf 01 00 00 00       	mov    edi,0x1
  4065bb:	48 89 c2             	mov    rdx,rax
  4065be:	31 c0                	xor    eax,eax
  4065c0:	e8 6b ac ff ff       	call   401230 <__printf_chk@plt>
  4065c5:	e8 16 ac ff ff       	call   4011e0 <geteuid@plt>
  4065ca:	85 c0                	test   eax,eax
  4065cc:	0f 84 07 b0 ff ff    	je     4015d9 <win+0x63>
  4065d2:	e9 ea af ff ff       	jmp    4015c1 <win+0x4b>
  4065d7:	ba 00 01 00 00       	mov    edx,0x100
  4065dc:	48 89 ee             	mov    rsi,rbp
  4065df:	e8 1c ac ff ff       	call   401200 <read@plt>
  4065e4:	85 c0                	test   eax,eax
  4065e6:	7f 2a                	jg     406612 <win+0x509c>
  4065e8:	e8 93 ab ff ff       	call   401180 <__errno_location@plt>
  4065ed:	8b 38                	mov    edi,DWORD PTR [rax]
  4065ef:	e8 8c ac ff ff       	call   401280 <strerror@plt>
  4065f4:	bf 01 00 00 00       	mov    edi,0x1
  4065f9:	48 8d 35 a9 ba 00 00 	lea    rsi,[rip+0xbaa9]        # 4120a9 <_IO_stdin_used+0xa9>
  406600:	48 89 c2             	mov    rdx,rax
  406603:	31 c0                	xor    eax,eax
  406605:	e8 26 ac ff ff       	call   401230 <__printf_chk@plt>
  40660a:	83 cf ff             	or     edi,0xffffffff
  40660d:	e8 4e ac ff ff       	call   401260 <exit@plt>
  406612:	48 63 d0             	movsxd rdx,eax
  406615:	48 89 ee             	mov    rsi,rbp
  406618:	bf 01 00 00 00       	mov    edi,0x1
  40661d:	e8 7e ab ff ff       	call   4011a0 <write@plt>
  406622:	48 8d 3d 2b bb 00 00 	lea    rdi,[rip+0xbb2b]        # 412154 <_IO_stdin_used+0x154>
  406629:	e8 62 ab ff ff       	call   401190 <puts@plt>
  40662e:	48 8d 3d cf b9 00 00 	lea    rdi,[rip+0xb9cf]        # 412004 <_IO_stdin_used+0x4>
  406635:	31 f6                	xor    esi,esi
  406637:	31 c0                	xor    eax,eax
  406639:	e8 12 ac ff ff       	call   401250 <open@plt>
  40663e:	89 c7                	mov    edi,eax
  406640:	85 c0                	test   eax,eax
  406642:	79 34                	jns    406678 <win+0x5102>
  406644:	e8 37 ab ff ff       	call   401180 <__errno_location@plt>
  406649:	8b 38                	mov    edi,DWORD PTR [rax]
  40664b:	e8 30 ac ff ff       	call   401280 <strerror@plt>
  406650:	48 8d 35 b3 b9 00 00 	lea    rsi,[rip+0xb9b3]        # 41200a <_IO_stdin_used+0xa>
  406657:	bf 01 00 00 00       	mov    edi,0x1
  40665c:	48 89 c2             	mov    rdx,rax
  40665f:	31 c0                	xor    eax,eax
  406661:	e8 ca ab ff ff       	call   401230 <__printf_chk@plt>
  406666:	e8 75 ab ff ff       	call   4011e0 <geteuid@plt>
  40666b:	85 c0                	test   eax,eax
  40666d:	0f 84 66 af ff ff    	je     4015d9 <win+0x63>
  406673:	e9 49 af ff ff       	jmp    4015c1 <win+0x4b>
  406678:	ba 00 01 00 00       	mov    edx,0x100
  40667d:	48 89 ee             	mov    rsi,rbp
  406680:	e8 7b ab ff ff       	call   401200 <read@plt>
  406685:	85 c0                	test   eax,eax
  406687:	7f 2a                	jg     4066b3 <win+0x513d>
  406689:	e8 f2 aa ff ff       	call   401180 <__errno_location@plt>
  40668e:	8b 38                	mov    edi,DWORD PTR [rax]
  406690:	e8 eb ab ff ff       	call   401280 <strerror@plt>
  406695:	bf 01 00 00 00       	mov    edi,0x1
  40669a:	48 8d 35 08 ba 00 00 	lea    rsi,[rip+0xba08]        # 4120a9 <_IO_stdin_used+0xa9>
  4066a1:	48 89 c2             	mov    rdx,rax
  4066a4:	31 c0                	xor    eax,eax
  4066a6:	e8 85 ab ff ff       	call   401230 <__printf_chk@plt>
  4066ab:	83 cf ff             	or     edi,0xffffffff
  4066ae:	e8 ad ab ff ff       	call   401260 <exit@plt>
  4066b3:	48 63 d0             	movsxd rdx,eax
  4066b6:	48 89 ee             	mov    rsi,rbp
  4066b9:	bf 01 00 00 00       	mov    edi,0x1
  4066be:	e8 dd aa ff ff       	call   4011a0 <write@plt>
  4066c3:	48 8d 3d 8a ba 00 00 	lea    rdi,[rip+0xba8a]        # 412154 <_IO_stdin_used+0x154>
  4066ca:	e8 c1 aa ff ff       	call   401190 <puts@plt>
  4066cf:	48 8d 3d 2e b9 00 00 	lea    rdi,[rip+0xb92e]        # 412004 <_IO_stdin_used+0x4>
  4066d6:	31 f6                	xor    esi,esi
  4066d8:	31 c0                	xor    eax,eax
  4066da:	e8 71 ab ff ff       	call   401250 <open@plt>
  4066df:	89 c7                	mov    edi,eax
  4066e1:	85 c0                	test   eax,eax
  4066e3:	79 34                	jns    406719 <win+0x51a3>
  4066e5:	e8 96 aa ff ff       	call   401180 <__errno_location@plt>
  4066ea:	8b 38                	mov    edi,DWORD PTR [rax]
  4066ec:	e8 8f ab ff ff       	call   401280 <strerror@plt>
  4066f1:	48 8d 35 12 b9 00 00 	lea    rsi,[rip+0xb912]        # 41200a <_IO_stdin_used+0xa>
  4066f8:	bf 01 00 00 00       	mov    edi,0x1
  4066fd:	48 89 c2             	mov    rdx,rax
  406700:	31 c0                	xor    eax,eax
  406702:	e8 29 ab ff ff       	call   401230 <__printf_chk@plt>
  406707:	e8 d4 aa ff ff       	call   4011e0 <geteuid@plt>
  40670c:	85 c0                	test   eax,eax
  40670e:	0f 84 c5 ae ff ff    	je     4015d9 <win+0x63>
  406714:	e9 a8 ae ff ff       	jmp    4015c1 <win+0x4b>
  406719:	ba 00 01 00 00       	mov    edx,0x100
  40671e:	48 89 ee             	mov    rsi,rbp
  406721:	e8 da aa ff ff       	call   401200 <read@plt>
  406726:	85 c0                	test   eax,eax
  406728:	7f 2a                	jg     406754 <win+0x51de>
  40672a:	e8 51 aa ff ff       	call   401180 <__errno_location@plt>
  40672f:	8b 38                	mov    edi,DWORD PTR [rax]
  406731:	e8 4a ab ff ff       	call   401280 <strerror@plt>
  406736:	bf 01 00 00 00       	mov    edi,0x1
  40673b:	48 8d 35 67 b9 00 00 	lea    rsi,[rip+0xb967]        # 4120a9 <_IO_stdin_used+0xa9>
  406742:	48 89 c2             	mov    rdx,rax
  406745:	31 c0                	xor    eax,eax
  406747:	e8 e4 aa ff ff       	call   401230 <__printf_chk@plt>
  40674c:	83 cf ff             	or     edi,0xffffffff
  40674f:	e8 0c ab ff ff       	call   401260 <exit@plt>
  406754:	48 63 d0             	movsxd rdx,eax
  406757:	48 89 ee             	mov    rsi,rbp
  40675a:	bf 01 00 00 00       	mov    edi,0x1
  40675f:	e8 3c aa ff ff       	call   4011a0 <write@plt>
  406764:	48 8d 3d e9 b9 00 00 	lea    rdi,[rip+0xb9e9]        # 412154 <_IO_stdin_used+0x154>
  40676b:	e8 20 aa ff ff       	call   401190 <puts@plt>
  406770:	48 8d 3d 8d b8 00 00 	lea    rdi,[rip+0xb88d]        # 412004 <_IO_stdin_used+0x4>
  406777:	31 f6                	xor    esi,esi
  406779:	31 c0                	xor    eax,eax
  40677b:	e8 d0 aa ff ff       	call   401250 <open@plt>
  406780:	89 c7                	mov    edi,eax
  406782:	85 c0                	test   eax,eax
  406784:	79 34                	jns    4067ba <win+0x5244>
  406786:	e8 f5 a9 ff ff       	call   401180 <__errno_location@plt>
  40678b:	8b 38                	mov    edi,DWORD PTR [rax]
  40678d:	e8 ee aa ff ff       	call   401280 <strerror@plt>
  406792:	48 8d 35 71 b8 00 00 	lea    rsi,[rip+0xb871]        # 41200a <_IO_stdin_used+0xa>
  406799:	bf 01 00 00 00       	mov    edi,0x1
  40679e:	48 89 c2             	mov    rdx,rax
  4067a1:	31 c0                	xor    eax,eax
  4067a3:	e8 88 aa ff ff       	call   401230 <__printf_chk@plt>
  4067a8:	e8 33 aa ff ff       	call   4011e0 <geteuid@plt>
  4067ad:	85 c0                	test   eax,eax
  4067af:	0f 84 24 ae ff ff    	je     4015d9 <win+0x63>
  4067b5:	e9 07 ae ff ff       	jmp    4015c1 <win+0x4b>
  4067ba:	ba 00 01 00 00       	mov    edx,0x100
  4067bf:	48 89 ee             	mov    rsi,rbp
  4067c2:	e8 39 aa ff ff       	call   401200 <read@plt>
  4067c7:	85 c0                	test   eax,eax
  4067c9:	7f 2a                	jg     4067f5 <win+0x527f>
  4067cb:	e8 b0 a9 ff ff       	call   401180 <__errno_location@plt>
  4067d0:	8b 38                	mov    edi,DWORD PTR [rax]
  4067d2:	e8 a9 aa ff ff       	call   401280 <strerror@plt>
  4067d7:	bf 01 00 00 00       	mov    edi,0x1
  4067dc:	48 8d 35 c6 b8 00 00 	lea    rsi,[rip+0xb8c6]        # 4120a9 <_IO_stdin_used+0xa9>
  4067e3:	48 89 c2             	mov    rdx,rax
  4067e6:	31 c0                	xor    eax,eax
  4067e8:	e8 43 aa ff ff       	call   401230 <__printf_chk@plt>
  4067ed:	83 cf ff             	or     edi,0xffffffff
  4067f0:	e8 6b aa ff ff       	call   401260 <exit@plt>
  4067f5:	48 63 d0             	movsxd rdx,eax
  4067f8:	48 89 ee             	mov    rsi,rbp
  4067fb:	bf 01 00 00 00       	mov    edi,0x1
  406800:	e8 9b a9 ff ff       	call   4011a0 <write@plt>
  406805:	48 8d 3d 48 b9 00 00 	lea    rdi,[rip+0xb948]        # 412154 <_IO_stdin_used+0x154>
  40680c:	e8 7f a9 ff ff       	call   401190 <puts@plt>
  406811:	48 8d 3d ec b7 00 00 	lea    rdi,[rip+0xb7ec]        # 412004 <_IO_stdin_used+0x4>
  406818:	31 f6                	xor    esi,esi
  40681a:	31 c0                	xor    eax,eax
  40681c:	e8 2f aa ff ff       	call   401250 <open@plt>
  406821:	89 c7                	mov    edi,eax
  406823:	85 c0                	test   eax,eax
  406825:	79 34                	jns    40685b <win+0x52e5>
  406827:	e8 54 a9 ff ff       	call   401180 <__errno_location@plt>
  40682c:	8b 38                	mov    edi,DWORD PTR [rax]
  40682e:	e8 4d aa ff ff       	call   401280 <strerror@plt>
  406833:	48 8d 35 d0 b7 00 00 	lea    rsi,[rip+0xb7d0]        # 41200a <_IO_stdin_used+0xa>
  40683a:	bf 01 00 00 00       	mov    edi,0x1
  40683f:	48 89 c2             	mov    rdx,rax
  406842:	31 c0                	xor    eax,eax
  406844:	e8 e7 a9 ff ff       	call   401230 <__printf_chk@plt>
  406849:	e8 92 a9 ff ff       	call   4011e0 <geteuid@plt>
  40684e:	85 c0                	test   eax,eax
  406850:	0f 84 83 ad ff ff    	je     4015d9 <win+0x63>
  406856:	e9 66 ad ff ff       	jmp    4015c1 <win+0x4b>
  40685b:	ba 00 01 00 00       	mov    edx,0x100
  406860:	48 89 ee             	mov    rsi,rbp
  406863:	e8 98 a9 ff ff       	call   401200 <read@plt>
  406868:	85 c0                	test   eax,eax
  40686a:	7f 2a                	jg     406896 <win+0x5320>
  40686c:	e8 0f a9 ff ff       	call   401180 <__errno_location@plt>
  406871:	8b 38                	mov    edi,DWORD PTR [rax]
  406873:	e8 08 aa ff ff       	call   401280 <strerror@plt>
  406878:	bf 01 00 00 00       	mov    edi,0x1
  40687d:	48 8d 35 25 b8 00 00 	lea    rsi,[rip+0xb825]        # 4120a9 <_IO_stdin_used+0xa9>
  406884:	48 89 c2             	mov    rdx,rax
  406887:	31 c0                	xor    eax,eax
  406889:	e8 a2 a9 ff ff       	call   401230 <__printf_chk@plt>
  40688e:	83 cf ff             	or     edi,0xffffffff
  406891:	e8 ca a9 ff ff       	call   401260 <exit@plt>
  406896:	48 63 d0             	movsxd rdx,eax
  406899:	48 89 ee             	mov    rsi,rbp
  40689c:	bf 01 00 00 00       	mov    edi,0x1
  4068a1:	e8 fa a8 ff ff       	call   4011a0 <write@plt>
  4068a6:	48 8d 3d a7 b8 00 00 	lea    rdi,[rip+0xb8a7]        # 412154 <_IO_stdin_used+0x154>
  4068ad:	e8 de a8 ff ff       	call   401190 <puts@plt>
  4068b2:	48 8d 3d 4b b7 00 00 	lea    rdi,[rip+0xb74b]        # 412004 <_IO_stdin_used+0x4>
  4068b9:	31 f6                	xor    esi,esi
  4068bb:	31 c0                	xor    eax,eax
  4068bd:	e8 8e a9 ff ff       	call   401250 <open@plt>
  4068c2:	89 c7                	mov    edi,eax
  4068c4:	85 c0                	test   eax,eax
  4068c6:	79 34                	jns    4068fc <win+0x5386>
  4068c8:	e8 b3 a8 ff ff       	call   401180 <__errno_location@plt>
  4068cd:	8b 38                	mov    edi,DWORD PTR [rax]
  4068cf:	e8 ac a9 ff ff       	call   401280 <strerror@plt>
  4068d4:	48 8d 35 2f b7 00 00 	lea    rsi,[rip+0xb72f]        # 41200a <_IO_stdin_used+0xa>
  4068db:	bf 01 00 00 00       	mov    edi,0x1
  4068e0:	48 89 c2             	mov    rdx,rax
  4068e3:	31 c0                	xor    eax,eax
  4068e5:	e8 46 a9 ff ff       	call   401230 <__printf_chk@plt>
  4068ea:	e8 f1 a8 ff ff       	call   4011e0 <geteuid@plt>
  4068ef:	85 c0                	test   eax,eax
  4068f1:	0f 84 e2 ac ff ff    	je     4015d9 <win+0x63>
  4068f7:	e9 c5 ac ff ff       	jmp    4015c1 <win+0x4b>
  4068fc:	ba 00 01 00 00       	mov    edx,0x100
  406901:	48 89 ee             	mov    rsi,rbp
  406904:	e8 f7 a8 ff ff       	call   401200 <read@plt>
  406909:	85 c0                	test   eax,eax
  40690b:	7f 2a                	jg     406937 <win+0x53c1>
  40690d:	e8 6e a8 ff ff       	call   401180 <__errno_location@plt>
  406912:	8b 38                	mov    edi,DWORD PTR [rax]
  406914:	e8 67 a9 ff ff       	call   401280 <strerror@plt>
  406919:	bf 01 00 00 00       	mov    edi,0x1
  40691e:	48 8d 35 84 b7 00 00 	lea    rsi,[rip+0xb784]        # 4120a9 <_IO_stdin_used+0xa9>
  406925:	48 89 c2             	mov    rdx,rax
  406928:	31 c0                	xor    eax,eax
  40692a:	e8 01 a9 ff ff       	call   401230 <__printf_chk@plt>
  40692f:	83 cf ff             	or     edi,0xffffffff
  406932:	e8 29 a9 ff ff       	call   401260 <exit@plt>
  406937:	48 63 d0             	movsxd rdx,eax
  40693a:	48 89 ee             	mov    rsi,rbp
  40693d:	bf 01 00 00 00       	mov    edi,0x1
  406942:	e8 59 a8 ff ff       	call   4011a0 <write@plt>
  406947:	48 8d 3d 06 b8 00 00 	lea    rdi,[rip+0xb806]        # 412154 <_IO_stdin_used+0x154>
  40694e:	e8 3d a8 ff ff       	call   401190 <puts@plt>
  406953:	48 8d 3d aa b6 00 00 	lea    rdi,[rip+0xb6aa]        # 412004 <_IO_stdin_used+0x4>
  40695a:	31 f6                	xor    esi,esi
  40695c:	31 c0                	xor    eax,eax
  40695e:	e8 ed a8 ff ff       	call   401250 <open@plt>
  406963:	89 c7                	mov    edi,eax
  406965:	85 c0                	test   eax,eax
  406967:	79 34                	jns    40699d <win+0x5427>
  406969:	e8 12 a8 ff ff       	call   401180 <__errno_location@plt>
  40696e:	8b 38                	mov    edi,DWORD PTR [rax]
  406970:	e8 0b a9 ff ff       	call   401280 <strerror@plt>
  406975:	48 8d 35 8e b6 00 00 	lea    rsi,[rip+0xb68e]        # 41200a <_IO_stdin_used+0xa>
  40697c:	bf 01 00 00 00       	mov    edi,0x1
  406981:	48 89 c2             	mov    rdx,rax
  406984:	31 c0                	xor    eax,eax
  406986:	e8 a5 a8 ff ff       	call   401230 <__printf_chk@plt>
  40698b:	e8 50 a8 ff ff       	call   4011e0 <geteuid@plt>
  406990:	85 c0                	test   eax,eax
  406992:	0f 84 41 ac ff ff    	je     4015d9 <win+0x63>
  406998:	e9 24 ac ff ff       	jmp    4015c1 <win+0x4b>
  40699d:	ba 00 01 00 00       	mov    edx,0x100
  4069a2:	48 89 ee             	mov    rsi,rbp
  4069a5:	e8 56 a8 ff ff       	call   401200 <read@plt>
  4069aa:	85 c0                	test   eax,eax
  4069ac:	7f 2a                	jg     4069d8 <win+0x5462>
  4069ae:	e8 cd a7 ff ff       	call   401180 <__errno_location@plt>
  4069b3:	8b 38                	mov    edi,DWORD PTR [rax]
  4069b5:	e8 c6 a8 ff ff       	call   401280 <strerror@plt>
  4069ba:	bf 01 00 00 00       	mov    edi,0x1
  4069bf:	48 8d 35 e3 b6 00 00 	lea    rsi,[rip+0xb6e3]        # 4120a9 <_IO_stdin_used+0xa9>
  4069c6:	48 89 c2             	mov    rdx,rax
  4069c9:	31 c0                	xor    eax,eax
  4069cb:	e8 60 a8 ff ff       	call   401230 <__printf_chk@plt>
  4069d0:	83 cf ff             	or     edi,0xffffffff
  4069d3:	e8 88 a8 ff ff       	call   401260 <exit@plt>
  4069d8:	48 63 d0             	movsxd rdx,eax
  4069db:	48 89 ee             	mov    rsi,rbp
  4069de:	bf 01 00 00 00       	mov    edi,0x1
  4069e3:	e8 b8 a7 ff ff       	call   4011a0 <write@plt>
  4069e8:	48 8d 3d 65 b7 00 00 	lea    rdi,[rip+0xb765]        # 412154 <_IO_stdin_used+0x154>
  4069ef:	e8 9c a7 ff ff       	call   401190 <puts@plt>
  4069f4:	48 8d 3d 09 b6 00 00 	lea    rdi,[rip+0xb609]        # 412004 <_IO_stdin_used+0x4>
  4069fb:	31 f6                	xor    esi,esi
  4069fd:	31 c0                	xor    eax,eax
  4069ff:	e8 4c a8 ff ff       	call   401250 <open@plt>
  406a04:	89 c7                	mov    edi,eax
  406a06:	85 c0                	test   eax,eax
  406a08:	79 34                	jns    406a3e <win+0x54c8>
  406a0a:	e8 71 a7 ff ff       	call   401180 <__errno_location@plt>
  406a0f:	8b 38                	mov    edi,DWORD PTR [rax]
  406a11:	e8 6a a8 ff ff       	call   401280 <strerror@plt>
  406a16:	48 8d 35 ed b5 00 00 	lea    rsi,[rip+0xb5ed]        # 41200a <_IO_stdin_used+0xa>
  406a1d:	bf 01 00 00 00       	mov    edi,0x1
  406a22:	48 89 c2             	mov    rdx,rax
  406a25:	31 c0                	xor    eax,eax
  406a27:	e8 04 a8 ff ff       	call   401230 <__printf_chk@plt>
  406a2c:	e8 af a7 ff ff       	call   4011e0 <geteuid@plt>
  406a31:	85 c0                	test   eax,eax
  406a33:	0f 84 a0 ab ff ff    	je     4015d9 <win+0x63>
  406a39:	e9 83 ab ff ff       	jmp    4015c1 <win+0x4b>
  406a3e:	ba 00 01 00 00       	mov    edx,0x100
  406a43:	48 89 ee             	mov    rsi,rbp
  406a46:	e8 b5 a7 ff ff       	call   401200 <read@plt>
  406a4b:	85 c0                	test   eax,eax
  406a4d:	7f 2a                	jg     406a79 <win+0x5503>
  406a4f:	e8 2c a7 ff ff       	call   401180 <__errno_location@plt>
  406a54:	8b 38                	mov    edi,DWORD PTR [rax]
  406a56:	e8 25 a8 ff ff       	call   401280 <strerror@plt>
  406a5b:	bf 01 00 00 00       	mov    edi,0x1
  406a60:	48 8d 35 42 b6 00 00 	lea    rsi,[rip+0xb642]        # 4120a9 <_IO_stdin_used+0xa9>
  406a67:	48 89 c2             	mov    rdx,rax
  406a6a:	31 c0                	xor    eax,eax
  406a6c:	e8 bf a7 ff ff       	call   401230 <__printf_chk@plt>
  406a71:	83 cf ff             	or     edi,0xffffffff
  406a74:	e8 e7 a7 ff ff       	call   401260 <exit@plt>
  406a79:	48 63 d0             	movsxd rdx,eax
  406a7c:	48 89 ee             	mov    rsi,rbp
  406a7f:	bf 01 00 00 00       	mov    edi,0x1
  406a84:	e8 17 a7 ff ff       	call   4011a0 <write@plt>
  406a89:	48 8d 3d c4 b6 00 00 	lea    rdi,[rip+0xb6c4]        # 412154 <_IO_stdin_used+0x154>
  406a90:	e8 fb a6 ff ff       	call   401190 <puts@plt>
  406a95:	48 8d 3d 68 b5 00 00 	lea    rdi,[rip+0xb568]        # 412004 <_IO_stdin_used+0x4>
  406a9c:	31 f6                	xor    esi,esi
  406a9e:	31 c0                	xor    eax,eax
  406aa0:	e8 ab a7 ff ff       	call   401250 <open@plt>
  406aa5:	89 c7                	mov    edi,eax
  406aa7:	85 c0                	test   eax,eax
  406aa9:	79 34                	jns    406adf <win+0x5569>
  406aab:	e8 d0 a6 ff ff       	call   401180 <__errno_location@plt>
  406ab0:	8b 38                	mov    edi,DWORD PTR [rax]
  406ab2:	e8 c9 a7 ff ff       	call   401280 <strerror@plt>
  406ab7:	48 8d 35 4c b5 00 00 	lea    rsi,[rip+0xb54c]        # 41200a <_IO_stdin_used+0xa>
  406abe:	bf 01 00 00 00       	mov    edi,0x1
  406ac3:	48 89 c2             	mov    rdx,rax
  406ac6:	31 c0                	xor    eax,eax
  406ac8:	e8 63 a7 ff ff       	call   401230 <__printf_chk@plt>
  406acd:	e8 0e a7 ff ff       	call   4011e0 <geteuid@plt>
  406ad2:	85 c0                	test   eax,eax
  406ad4:	0f 84 ff aa ff ff    	je     4015d9 <win+0x63>
  406ada:	e9 e2 aa ff ff       	jmp    4015c1 <win+0x4b>
  406adf:	ba 00 01 00 00       	mov    edx,0x100
  406ae4:	48 89 ee             	mov    rsi,rbp
  406ae7:	e8 14 a7 ff ff       	call   401200 <read@plt>
  406aec:	85 c0                	test   eax,eax
  406aee:	7f 2a                	jg     406b1a <win+0x55a4>
  406af0:	e8 8b a6 ff ff       	call   401180 <__errno_location@plt>
  406af5:	8b 38                	mov    edi,DWORD PTR [rax]
  406af7:	e8 84 a7 ff ff       	call   401280 <strerror@plt>
  406afc:	bf 01 00 00 00       	mov    edi,0x1
  406b01:	48 8d 35 a1 b5 00 00 	lea    rsi,[rip+0xb5a1]        # 4120a9 <_IO_stdin_used+0xa9>
  406b08:	48 89 c2             	mov    rdx,rax
  406b0b:	31 c0                	xor    eax,eax
  406b0d:	e8 1e a7 ff ff       	call   401230 <__printf_chk@plt>
  406b12:	83 cf ff             	or     edi,0xffffffff
  406b15:	e8 46 a7 ff ff       	call   401260 <exit@plt>
  406b1a:	48 63 d0             	movsxd rdx,eax
  406b1d:	48 89 ee             	mov    rsi,rbp
  406b20:	bf 01 00 00 00       	mov    edi,0x1
  406b25:	e8 76 a6 ff ff       	call   4011a0 <write@plt>
  406b2a:	48 8d 3d 23 b6 00 00 	lea    rdi,[rip+0xb623]        # 412154 <_IO_stdin_used+0x154>
  406b31:	e8 5a a6 ff ff       	call   401190 <puts@plt>
  406b36:	48 8d 3d c7 b4 00 00 	lea    rdi,[rip+0xb4c7]        # 412004 <_IO_stdin_used+0x4>
  406b3d:	31 f6                	xor    esi,esi
  406b3f:	31 c0                	xor    eax,eax
  406b41:	e8 0a a7 ff ff       	call   401250 <open@plt>
  406b46:	89 c7                	mov    edi,eax
  406b48:	85 c0                	test   eax,eax
  406b4a:	79 34                	jns    406b80 <win+0x560a>
  406b4c:	e8 2f a6 ff ff       	call   401180 <__errno_location@plt>
  406b51:	8b 38                	mov    edi,DWORD PTR [rax]
  406b53:	e8 28 a7 ff ff       	call   401280 <strerror@plt>
  406b58:	48 8d 35 ab b4 00 00 	lea    rsi,[rip+0xb4ab]        # 41200a <_IO_stdin_used+0xa>
  406b5f:	bf 01 00 00 00       	mov    edi,0x1
  406b64:	48 89 c2             	mov    rdx,rax
  406b67:	31 c0                	xor    eax,eax
  406b69:	e8 c2 a6 ff ff       	call   401230 <__printf_chk@plt>
  406b6e:	e8 6d a6 ff ff       	call   4011e0 <geteuid@plt>
  406b73:	85 c0                	test   eax,eax
  406b75:	0f 84 5e aa ff ff    	je     4015d9 <win+0x63>
  406b7b:	e9 41 aa ff ff       	jmp    4015c1 <win+0x4b>
  406b80:	ba 00 01 00 00       	mov    edx,0x100
  406b85:	48 89 ee             	mov    rsi,rbp
  406b88:	e8 73 a6 ff ff       	call   401200 <read@plt>
  406b8d:	85 c0                	test   eax,eax
  406b8f:	7f 2a                	jg     406bbb <win+0x5645>
  406b91:	e8 ea a5 ff ff       	call   401180 <__errno_location@plt>
  406b96:	8b 38                	mov    edi,DWORD PTR [rax]
  406b98:	e8 e3 a6 ff ff       	call   401280 <strerror@plt>
  406b9d:	bf 01 00 00 00       	mov    edi,0x1
  406ba2:	48 8d 35 00 b5 00 00 	lea    rsi,[rip+0xb500]        # 4120a9 <_IO_stdin_used+0xa9>
  406ba9:	48 89 c2             	mov    rdx,rax
  406bac:	31 c0                	xor    eax,eax
  406bae:	e8 7d a6 ff ff       	call   401230 <__printf_chk@plt>
  406bb3:	83 cf ff             	or     edi,0xffffffff
  406bb6:	e8 a5 a6 ff ff       	call   401260 <exit@plt>
  406bbb:	48 63 d0             	movsxd rdx,eax
  406bbe:	48 89 ee             	mov    rsi,rbp
  406bc1:	bf 01 00 00 00       	mov    edi,0x1
  406bc6:	e8 d5 a5 ff ff       	call   4011a0 <write@plt>
  406bcb:	48 8d 3d 82 b5 00 00 	lea    rdi,[rip+0xb582]        # 412154 <_IO_stdin_used+0x154>
  406bd2:	e8 b9 a5 ff ff       	call   401190 <puts@plt>
  406bd7:	48 8d 3d 26 b4 00 00 	lea    rdi,[rip+0xb426]        # 412004 <_IO_stdin_used+0x4>
  406bde:	31 f6                	xor    esi,esi
  406be0:	31 c0                	xor    eax,eax
  406be2:	e8 69 a6 ff ff       	call   401250 <open@plt>
  406be7:	89 c7                	mov    edi,eax
  406be9:	85 c0                	test   eax,eax
  406beb:	79 34                	jns    406c21 <win+0x56ab>
  406bed:	e8 8e a5 ff ff       	call   401180 <__errno_location@plt>
  406bf2:	8b 38                	mov    edi,DWORD PTR [rax]
  406bf4:	e8 87 a6 ff ff       	call   401280 <strerror@plt>
  406bf9:	48 8d 35 0a b4 00 00 	lea    rsi,[rip+0xb40a]        # 41200a <_IO_stdin_used+0xa>
  406c00:	bf 01 00 00 00       	mov    edi,0x1
  406c05:	48 89 c2             	mov    rdx,rax
  406c08:	31 c0                	xor    eax,eax
  406c0a:	e8 21 a6 ff ff       	call   401230 <__printf_chk@plt>
  406c0f:	e8 cc a5 ff ff       	call   4011e0 <geteuid@plt>
  406c14:	85 c0                	test   eax,eax
  406c16:	0f 84 bd a9 ff ff    	je     4015d9 <win+0x63>
  406c1c:	e9 a0 a9 ff ff       	jmp    4015c1 <win+0x4b>
  406c21:	ba 00 01 00 00       	mov    edx,0x100
  406c26:	48 89 ee             	mov    rsi,rbp
  406c29:	e8 d2 a5 ff ff       	call   401200 <read@plt>
  406c2e:	85 c0                	test   eax,eax
  406c30:	7f 2a                	jg     406c5c <win+0x56e6>
  406c32:	e8 49 a5 ff ff       	call   401180 <__errno_location@plt>
  406c37:	8b 38                	mov    edi,DWORD PTR [rax]
  406c39:	e8 42 a6 ff ff       	call   401280 <strerror@plt>
  406c3e:	bf 01 00 00 00       	mov    edi,0x1
  406c43:	48 8d 35 5f b4 00 00 	lea    rsi,[rip+0xb45f]        # 4120a9 <_IO_stdin_used+0xa9>
  406c4a:	48 89 c2             	mov    rdx,rax
  406c4d:	31 c0                	xor    eax,eax
  406c4f:	e8 dc a5 ff ff       	call   401230 <__printf_chk@plt>
  406c54:	83 cf ff             	or     edi,0xffffffff
  406c57:	e8 04 a6 ff ff       	call   401260 <exit@plt>
  406c5c:	48 63 d0             	movsxd rdx,eax
  406c5f:	48 89 ee             	mov    rsi,rbp
  406c62:	bf 01 00 00 00       	mov    edi,0x1
  406c67:	e8 34 a5 ff ff       	call   4011a0 <write@plt>
  406c6c:	48 8d 3d e1 b4 00 00 	lea    rdi,[rip+0xb4e1]        # 412154 <_IO_stdin_used+0x154>
  406c73:	e8 18 a5 ff ff       	call   401190 <puts@plt>
  406c78:	48 8d 3d 85 b3 00 00 	lea    rdi,[rip+0xb385]        # 412004 <_IO_stdin_used+0x4>
  406c7f:	31 f6                	xor    esi,esi
  406c81:	31 c0                	xor    eax,eax
  406c83:	e8 c8 a5 ff ff       	call   401250 <open@plt>
  406c88:	89 c7                	mov    edi,eax
  406c8a:	85 c0                	test   eax,eax
  406c8c:	79 34                	jns    406cc2 <win+0x574c>
  406c8e:	e8 ed a4 ff ff       	call   401180 <__errno_location@plt>
  406c93:	8b 38                	mov    edi,DWORD PTR [rax]
  406c95:	e8 e6 a5 ff ff       	call   401280 <strerror@plt>
  406c9a:	48 8d 35 69 b3 00 00 	lea    rsi,[rip+0xb369]        # 41200a <_IO_stdin_used+0xa>
  406ca1:	bf 01 00 00 00       	mov    edi,0x1
  406ca6:	48 89 c2             	mov    rdx,rax
  406ca9:	31 c0                	xor    eax,eax
  406cab:	e8 80 a5 ff ff       	call   401230 <__printf_chk@plt>
  406cb0:	e8 2b a5 ff ff       	call   4011e0 <geteuid@plt>
  406cb5:	85 c0                	test   eax,eax
  406cb7:	0f 84 1c a9 ff ff    	je     4015d9 <win+0x63>
  406cbd:	e9 ff a8 ff ff       	jmp    4015c1 <win+0x4b>
  406cc2:	ba 00 01 00 00       	mov    edx,0x100
  406cc7:	48 89 ee             	mov    rsi,rbp
  406cca:	e8 31 a5 ff ff       	call   401200 <read@plt>
  406ccf:	85 c0                	test   eax,eax
  406cd1:	7f 2a                	jg     406cfd <win+0x5787>
  406cd3:	e8 a8 a4 ff ff       	call   401180 <__errno_location@plt>
  406cd8:	8b 38                	mov    edi,DWORD PTR [rax]
  406cda:	e8 a1 a5 ff ff       	call   401280 <strerror@plt>
  406cdf:	bf 01 00 00 00       	mov    edi,0x1
  406ce4:	48 8d 35 be b3 00 00 	lea    rsi,[rip+0xb3be]        # 4120a9 <_IO_stdin_used+0xa9>
  406ceb:	48 89 c2             	mov    rdx,rax
  406cee:	31 c0                	xor    eax,eax
  406cf0:	e8 3b a5 ff ff       	call   401230 <__printf_chk@plt>
  406cf5:	83 cf ff             	or     edi,0xffffffff
  406cf8:	e8 63 a5 ff ff       	call   401260 <exit@plt>
  406cfd:	48 63 d0             	movsxd rdx,eax
  406d00:	48 89 ee             	mov    rsi,rbp
  406d03:	bf 01 00 00 00       	mov    edi,0x1
  406d08:	e8 93 a4 ff ff       	call   4011a0 <write@plt>
  406d0d:	48 8d 3d 40 b4 00 00 	lea    rdi,[rip+0xb440]        # 412154 <_IO_stdin_used+0x154>
  406d14:	e8 77 a4 ff ff       	call   401190 <puts@plt>
  406d19:	48 8d 3d e4 b2 00 00 	lea    rdi,[rip+0xb2e4]        # 412004 <_IO_stdin_used+0x4>
  406d20:	31 f6                	xor    esi,esi
  406d22:	31 c0                	xor    eax,eax
  406d24:	e8 27 a5 ff ff       	call   401250 <open@plt>
  406d29:	89 c7                	mov    edi,eax
  406d2b:	85 c0                	test   eax,eax
  406d2d:	79 34                	jns    406d63 <win+0x57ed>
  406d2f:	e8 4c a4 ff ff       	call   401180 <__errno_location@plt>
  406d34:	8b 38                	mov    edi,DWORD PTR [rax]
  406d36:	e8 45 a5 ff ff       	call   401280 <strerror@plt>
  406d3b:	48 8d 35 c8 b2 00 00 	lea    rsi,[rip+0xb2c8]        # 41200a <_IO_stdin_used+0xa>
  406d42:	bf 01 00 00 00       	mov    edi,0x1
  406d47:	48 89 c2             	mov    rdx,rax
  406d4a:	31 c0                	xor    eax,eax
  406d4c:	e8 df a4 ff ff       	call   401230 <__printf_chk@plt>
  406d51:	e8 8a a4 ff ff       	call   4011e0 <geteuid@plt>
  406d56:	85 c0                	test   eax,eax
  406d58:	0f 84 7b a8 ff ff    	je     4015d9 <win+0x63>
  406d5e:	e9 5e a8 ff ff       	jmp    4015c1 <win+0x4b>
  406d63:	ba 00 01 00 00       	mov    edx,0x100
  406d68:	48 89 ee             	mov    rsi,rbp
  406d6b:	e8 90 a4 ff ff       	call   401200 <read@plt>
  406d70:	85 c0                	test   eax,eax
  406d72:	7f 2a                	jg     406d9e <win+0x5828>
  406d74:	e8 07 a4 ff ff       	call   401180 <__errno_location@plt>
  406d79:	8b 38                	mov    edi,DWORD PTR [rax]
  406d7b:	e8 00 a5 ff ff       	call   401280 <strerror@plt>
  406d80:	bf 01 00 00 00       	mov    edi,0x1
  406d85:	48 8d 35 1d b3 00 00 	lea    rsi,[rip+0xb31d]        # 4120a9 <_IO_stdin_used+0xa9>
  406d8c:	48 89 c2             	mov    rdx,rax
  406d8f:	31 c0                	xor    eax,eax
  406d91:	e8 9a a4 ff ff       	call   401230 <__printf_chk@plt>
  406d96:	83 cf ff             	or     edi,0xffffffff
  406d99:	e8 c2 a4 ff ff       	call   401260 <exit@plt>
  406d9e:	48 89 e5             	mov    rbp,rsp
  406da1:	48 63 d0             	movsxd rdx,eax
  406da4:	bf 01 00 00 00       	mov    edi,0x1
  406da9:	48 89 ee             	mov    rsi,rbp
  406dac:	e8 ef a3 ff ff       	call   4011a0 <write@plt>
  406db1:	48 8d 3d 9c b3 00 00 	lea    rdi,[rip+0xb39c]        # 412154 <_IO_stdin_used+0x154>
  406db8:	e8 d3 a3 ff ff       	call   401190 <puts@plt>
  406dbd:	48 8d 3d 40 b2 00 00 	lea    rdi,[rip+0xb240]        # 412004 <_IO_stdin_used+0x4>
  406dc4:	31 f6                	xor    esi,esi
  406dc6:	31 c0                	xor    eax,eax
  406dc8:	e8 83 a4 ff ff       	call   401250 <open@plt>
  406dcd:	89 c7                	mov    edi,eax
  406dcf:	85 c0                	test   eax,eax
  406dd1:	79 34                	jns    406e07 <win+0x5891>
  406dd3:	e8 a8 a3 ff ff       	call   401180 <__errno_location@plt>
  406dd8:	8b 38                	mov    edi,DWORD PTR [rax]
  406dda:	e8 a1 a4 ff ff       	call   401280 <strerror@plt>
  406ddf:	48 8d 35 24 b2 00 00 	lea    rsi,[rip+0xb224]        # 41200a <_IO_stdin_used+0xa>
  406de6:	bf 01 00 00 00       	mov    edi,0x1
  406deb:	48 89 c2             	mov    rdx,rax
  406dee:	31 c0                	xor    eax,eax
  406df0:	e8 3b a4 ff ff       	call   401230 <__printf_chk@plt>
  406df5:	e8 e6 a3 ff ff       	call   4011e0 <geteuid@plt>
  406dfa:	85 c0                	test   eax,eax
  406dfc:	0f 84 d7 a7 ff ff    	je     4015d9 <win+0x63>
  406e02:	e9 ba a7 ff ff       	jmp    4015c1 <win+0x4b>
  406e07:	ba 00 01 00 00       	mov    edx,0x100
  406e0c:	48 89 ee             	mov    rsi,rbp
  406e0f:	e8 ec a3 ff ff       	call   401200 <read@plt>
  406e14:	85 c0                	test   eax,eax
  406e16:	7f 2a                	jg     406e42 <win+0x58cc>
  406e18:	e8 63 a3 ff ff       	call   401180 <__errno_location@plt>
  406e1d:	8b 38                	mov    edi,DWORD PTR [rax]
  406e1f:	e8 5c a4 ff ff       	call   401280 <strerror@plt>
  406e24:	bf 01 00 00 00       	mov    edi,0x1
  406e29:	48 8d 35 79 b2 00 00 	lea    rsi,[rip+0xb279]        # 4120a9 <_IO_stdin_used+0xa9>
  406e30:	48 89 c2             	mov    rdx,rax
  406e33:	31 c0                	xor    eax,eax
  406e35:	e8 f6 a3 ff ff       	call   401230 <__printf_chk@plt>
  406e3a:	83 cf ff             	or     edi,0xffffffff
  406e3d:	e8 1e a4 ff ff       	call   401260 <exit@plt>
  406e42:	48 63 d0             	movsxd rdx,eax
  406e45:	48 89 ee             	mov    rsi,rbp
  406e48:	bf 01 00 00 00       	mov    edi,0x1
  406e4d:	e8 4e a3 ff ff       	call   4011a0 <write@plt>
  406e52:	48 8d 3d fb b2 00 00 	lea    rdi,[rip+0xb2fb]        # 412154 <_IO_stdin_used+0x154>
  406e59:	e8 32 a3 ff ff       	call   401190 <puts@plt>
  406e5e:	48 8d 3d 9f b1 00 00 	lea    rdi,[rip+0xb19f]        # 412004 <_IO_stdin_used+0x4>
  406e65:	31 f6                	xor    esi,esi
  406e67:	31 c0                	xor    eax,eax
  406e69:	e8 e2 a3 ff ff       	call   401250 <open@plt>
  406e6e:	89 c7                	mov    edi,eax
  406e70:	85 c0                	test   eax,eax
  406e72:	79 34                	jns    406ea8 <win+0x5932>
  406e74:	e8 07 a3 ff ff       	call   401180 <__errno_location@plt>
  406e79:	8b 38                	mov    edi,DWORD PTR [rax]
  406e7b:	e8 00 a4 ff ff       	call   401280 <strerror@plt>
  406e80:	48 8d 35 83 b1 00 00 	lea    rsi,[rip+0xb183]        # 41200a <_IO_stdin_used+0xa>
  406e87:	bf 01 00 00 00       	mov    edi,0x1
  406e8c:	48 89 c2             	mov    rdx,rax
  406e8f:	31 c0                	xor    eax,eax
  406e91:	e8 9a a3 ff ff       	call   401230 <__printf_chk@plt>
  406e96:	e8 45 a3 ff ff       	call   4011e0 <geteuid@plt>
  406e9b:	85 c0                	test   eax,eax
  406e9d:	0f 84 36 a7 ff ff    	je     4015d9 <win+0x63>
  406ea3:	e9 19 a7 ff ff       	jmp    4015c1 <win+0x4b>
  406ea8:	ba 00 01 00 00       	mov    edx,0x100
  406ead:	48 89 ee             	mov    rsi,rbp
  406eb0:	e8 4b a3 ff ff       	call   401200 <read@plt>
  406eb5:	85 c0                	test   eax,eax
  406eb7:	7f 2a                	jg     406ee3 <win+0x596d>
  406eb9:	e8 c2 a2 ff ff       	call   401180 <__errno_location@plt>
  406ebe:	8b 38                	mov    edi,DWORD PTR [rax]
  406ec0:	e8 bb a3 ff ff       	call   401280 <strerror@plt>
  406ec5:	bf 01 00 00 00       	mov    edi,0x1
  406eca:	48 8d 35 d8 b1 00 00 	lea    rsi,[rip+0xb1d8]        # 4120a9 <_IO_stdin_used+0xa9>
  406ed1:	48 89 c2             	mov    rdx,rax
  406ed4:	31 c0                	xor    eax,eax
  406ed6:	e8 55 a3 ff ff       	call   401230 <__printf_chk@plt>
  406edb:	83 cf ff             	or     edi,0xffffffff
  406ede:	e8 7d a3 ff ff       	call   401260 <exit@plt>
  406ee3:	48 63 d0             	movsxd rdx,eax
  406ee6:	48 89 ee             	mov    rsi,rbp
  406ee9:	bf 01 00 00 00       	mov    edi,0x1
  406eee:	e8 ad a2 ff ff       	call   4011a0 <write@plt>
  406ef3:	48 8d 3d 5a b2 00 00 	lea    rdi,[rip+0xb25a]        # 412154 <_IO_stdin_used+0x154>
  406efa:	e8 91 a2 ff ff       	call   401190 <puts@plt>
  406eff:	48 8d 3d fe b0 00 00 	lea    rdi,[rip+0xb0fe]        # 412004 <_IO_stdin_used+0x4>
  406f06:	31 f6                	xor    esi,esi
  406f08:	31 c0                	xor    eax,eax
  406f0a:	e8 41 a3 ff ff       	call   401250 <open@plt>
  406f0f:	89 c7                	mov    edi,eax
  406f11:	85 c0                	test   eax,eax
  406f13:	79 34                	jns    406f49 <win+0x59d3>
  406f15:	e8 66 a2 ff ff       	call   401180 <__errno_location@plt>
  406f1a:	8b 38                	mov    edi,DWORD PTR [rax]
  406f1c:	e8 5f a3 ff ff       	call   401280 <strerror@plt>
  406f21:	48 8d 35 e2 b0 00 00 	lea    rsi,[rip+0xb0e2]        # 41200a <_IO_stdin_used+0xa>
  406f28:	bf 01 00 00 00       	mov    edi,0x1
  406f2d:	48 89 c2             	mov    rdx,rax
  406f30:	31 c0                	xor    eax,eax
  406f32:	e8 f9 a2 ff ff       	call   401230 <__printf_chk@plt>
  406f37:	e8 a4 a2 ff ff       	call   4011e0 <geteuid@plt>
  406f3c:	85 c0                	test   eax,eax
  406f3e:	0f 84 95 a6 ff ff    	je     4015d9 <win+0x63>
  406f44:	e9 78 a6 ff ff       	jmp    4015c1 <win+0x4b>
  406f49:	ba 00 01 00 00       	mov    edx,0x100
  406f4e:	48 89 ee             	mov    rsi,rbp
  406f51:	e8 aa a2 ff ff       	call   401200 <read@plt>
  406f56:	85 c0                	test   eax,eax
  406f58:	7f 2a                	jg     406f84 <win+0x5a0e>
  406f5a:	e8 21 a2 ff ff       	call   401180 <__errno_location@plt>
  406f5f:	8b 38                	mov    edi,DWORD PTR [rax]
  406f61:	e8 1a a3 ff ff       	call   401280 <strerror@plt>
  406f66:	bf 01 00 00 00       	mov    edi,0x1
  406f6b:	48 8d 35 37 b1 00 00 	lea    rsi,[rip+0xb137]        # 4120a9 <_IO_stdin_used+0xa9>
  406f72:	48 89 c2             	mov    rdx,rax
  406f75:	31 c0                	xor    eax,eax
  406f77:	e8 b4 a2 ff ff       	call   401230 <__printf_chk@plt>
  406f7c:	83 cf ff             	or     edi,0xffffffff
  406f7f:	e8 dc a2 ff ff       	call   401260 <exit@plt>
  406f84:	48 63 d0             	movsxd rdx,eax
  406f87:	48 89 ee             	mov    rsi,rbp
  406f8a:	bf 01 00 00 00       	mov    edi,0x1
  406f8f:	e8 0c a2 ff ff       	call   4011a0 <write@plt>
  406f94:	48 8d 3d b9 b1 00 00 	lea    rdi,[rip+0xb1b9]        # 412154 <_IO_stdin_used+0x154>
  406f9b:	e8 f0 a1 ff ff       	call   401190 <puts@plt>
  406fa0:	48 8d 3d 5d b0 00 00 	lea    rdi,[rip+0xb05d]        # 412004 <_IO_stdin_used+0x4>
  406fa7:	31 f6                	xor    esi,esi
  406fa9:	31 c0                	xor    eax,eax
  406fab:	e8 a0 a2 ff ff       	call   401250 <open@plt>
  406fb0:	89 c7                	mov    edi,eax
  406fb2:	85 c0                	test   eax,eax
  406fb4:	79 34                	jns    406fea <win+0x5a74>
  406fb6:	e8 c5 a1 ff ff       	call   401180 <__errno_location@plt>
  406fbb:	8b 38                	mov    edi,DWORD PTR [rax]
  406fbd:	e8 be a2 ff ff       	call   401280 <strerror@plt>
  406fc2:	48 8d 35 41 b0 00 00 	lea    rsi,[rip+0xb041]        # 41200a <_IO_stdin_used+0xa>
  406fc9:	bf 01 00 00 00       	mov    edi,0x1
  406fce:	48 89 c2             	mov    rdx,rax
  406fd1:	31 c0                	xor    eax,eax
  406fd3:	e8 58 a2 ff ff       	call   401230 <__printf_chk@plt>
  406fd8:	e8 03 a2 ff ff       	call   4011e0 <geteuid@plt>
  406fdd:	85 c0                	test   eax,eax
  406fdf:	0f 84 f4 a5 ff ff    	je     4015d9 <win+0x63>
  406fe5:	e9 d7 a5 ff ff       	jmp    4015c1 <win+0x4b>
  406fea:	ba 00 01 00 00       	mov    edx,0x100
  406fef:	48 89 ee             	mov    rsi,rbp
  406ff2:	e8 09 a2 ff ff       	call   401200 <read@plt>
  406ff7:	85 c0                	test   eax,eax
  406ff9:	7f 2a                	jg     407025 <win+0x5aaf>
  406ffb:	e8 80 a1 ff ff       	call   401180 <__errno_location@plt>
  407000:	8b 38                	mov    edi,DWORD PTR [rax]
  407002:	e8 79 a2 ff ff       	call   401280 <strerror@plt>
  407007:	bf 01 00 00 00       	mov    edi,0x1
  40700c:	48 8d 35 96 b0 00 00 	lea    rsi,[rip+0xb096]        # 4120a9 <_IO_stdin_used+0xa9>
  407013:	48 89 c2             	mov    rdx,rax
  407016:	31 c0                	xor    eax,eax
  407018:	e8 13 a2 ff ff       	call   401230 <__printf_chk@plt>
  40701d:	83 cf ff             	or     edi,0xffffffff
  407020:	e8 3b a2 ff ff       	call   401260 <exit@plt>
  407025:	48 63 d0             	movsxd rdx,eax
  407028:	48 89 ee             	mov    rsi,rbp
  40702b:	bf 01 00 00 00       	mov    edi,0x1
  407030:	e8 6b a1 ff ff       	call   4011a0 <write@plt>
  407035:	48 8d 3d 18 b1 00 00 	lea    rdi,[rip+0xb118]        # 412154 <_IO_stdin_used+0x154>
  40703c:	e8 4f a1 ff ff       	call   401190 <puts@plt>
  407041:	48 8d 3d bc af 00 00 	lea    rdi,[rip+0xafbc]        # 412004 <_IO_stdin_used+0x4>
  407048:	31 f6                	xor    esi,esi
  40704a:	31 c0                	xor    eax,eax
  40704c:	e8 ff a1 ff ff       	call   401250 <open@plt>
  407051:	89 c7                	mov    edi,eax
  407053:	85 c0                	test   eax,eax
  407055:	79 34                	jns    40708b <win+0x5b15>
  407057:	e8 24 a1 ff ff       	call   401180 <__errno_location@plt>
  40705c:	8b 38                	mov    edi,DWORD PTR [rax]
  40705e:	e8 1d a2 ff ff       	call   401280 <strerror@plt>
  407063:	48 8d 35 a0 af 00 00 	lea    rsi,[rip+0xafa0]        # 41200a <_IO_stdin_used+0xa>
  40706a:	bf 01 00 00 00       	mov    edi,0x1
  40706f:	48 89 c2             	mov    rdx,rax
  407072:	31 c0                	xor    eax,eax
  407074:	e8 b7 a1 ff ff       	call   401230 <__printf_chk@plt>
  407079:	e8 62 a1 ff ff       	call   4011e0 <geteuid@plt>
  40707e:	85 c0                	test   eax,eax
  407080:	0f 84 53 a5 ff ff    	je     4015d9 <win+0x63>
  407086:	e9 36 a5 ff ff       	jmp    4015c1 <win+0x4b>
  40708b:	ba 00 01 00 00       	mov    edx,0x100
  407090:	48 89 ee             	mov    rsi,rbp
  407093:	e8 68 a1 ff ff       	call   401200 <read@plt>
  407098:	85 c0                	test   eax,eax
  40709a:	7f 2a                	jg     4070c6 <win+0x5b50>
  40709c:	e8 df a0 ff ff       	call   401180 <__errno_location@plt>
  4070a1:	8b 38                	mov    edi,DWORD PTR [rax]
  4070a3:	e8 d8 a1 ff ff       	call   401280 <strerror@plt>
  4070a8:	bf 01 00 00 00       	mov    edi,0x1
  4070ad:	48 8d 35 f5 af 00 00 	lea    rsi,[rip+0xaff5]        # 4120a9 <_IO_stdin_used+0xa9>
  4070b4:	48 89 c2             	mov    rdx,rax
  4070b7:	31 c0                	xor    eax,eax
  4070b9:	e8 72 a1 ff ff       	call   401230 <__printf_chk@plt>
  4070be:	83 cf ff             	or     edi,0xffffffff
  4070c1:	e8 9a a1 ff ff       	call   401260 <exit@plt>
  4070c6:	48 63 d0             	movsxd rdx,eax
  4070c9:	48 89 ee             	mov    rsi,rbp
  4070cc:	bf 01 00 00 00       	mov    edi,0x1
  4070d1:	e8 ca a0 ff ff       	call   4011a0 <write@plt>
  4070d6:	48 8d 3d 77 b0 00 00 	lea    rdi,[rip+0xb077]        # 412154 <_IO_stdin_used+0x154>
  4070dd:	e8 ae a0 ff ff       	call   401190 <puts@plt>
  4070e2:	48 8d 3d 1b af 00 00 	lea    rdi,[rip+0xaf1b]        # 412004 <_IO_stdin_used+0x4>
  4070e9:	31 f6                	xor    esi,esi
  4070eb:	31 c0                	xor    eax,eax
  4070ed:	e8 5e a1 ff ff       	call   401250 <open@plt>
  4070f2:	89 c7                	mov    edi,eax
  4070f4:	85 c0                	test   eax,eax
  4070f6:	79 34                	jns    40712c <win+0x5bb6>
  4070f8:	e8 83 a0 ff ff       	call   401180 <__errno_location@plt>
  4070fd:	8b 38                	mov    edi,DWORD PTR [rax]
  4070ff:	e8 7c a1 ff ff       	call   401280 <strerror@plt>
  407104:	48 8d 35 ff ae 00 00 	lea    rsi,[rip+0xaeff]        # 41200a <_IO_stdin_used+0xa>
  40710b:	bf 01 00 00 00       	mov    edi,0x1
  407110:	48 89 c2             	mov    rdx,rax
  407113:	31 c0                	xor    eax,eax
  407115:	e8 16 a1 ff ff       	call   401230 <__printf_chk@plt>
  40711a:	e8 c1 a0 ff ff       	call   4011e0 <geteuid@plt>
  40711f:	85 c0                	test   eax,eax
  407121:	0f 84 b2 a4 ff ff    	je     4015d9 <win+0x63>
  407127:	e9 95 a4 ff ff       	jmp    4015c1 <win+0x4b>
  40712c:	ba 00 01 00 00       	mov    edx,0x100
  407131:	48 89 ee             	mov    rsi,rbp
  407134:	e8 c7 a0 ff ff       	call   401200 <read@plt>
  407139:	85 c0                	test   eax,eax
  40713b:	7f 2a                	jg     407167 <win+0x5bf1>
  40713d:	e8 3e a0 ff ff       	call   401180 <__errno_location@plt>
  407142:	8b 38                	mov    edi,DWORD PTR [rax]
  407144:	e8 37 a1 ff ff       	call   401280 <strerror@plt>
  407149:	bf 01 00 00 00       	mov    edi,0x1
  40714e:	48 8d 35 54 af 00 00 	lea    rsi,[rip+0xaf54]        # 4120a9 <_IO_stdin_used+0xa9>
  407155:	48 89 c2             	mov    rdx,rax
  407158:	31 c0                	xor    eax,eax
  40715a:	e8 d1 a0 ff ff       	call   401230 <__printf_chk@plt>
  40715f:	83 cf ff             	or     edi,0xffffffff
  407162:	e8 f9 a0 ff ff       	call   401260 <exit@plt>
  407167:	48 63 d0             	movsxd rdx,eax
  40716a:	48 89 ee             	mov    rsi,rbp
  40716d:	bf 01 00 00 00       	mov    edi,0x1
  407172:	e8 29 a0 ff ff       	call   4011a0 <write@plt>
  407177:	48 8d 3d d6 af 00 00 	lea    rdi,[rip+0xafd6]        # 412154 <_IO_stdin_used+0x154>
  40717e:	e8 0d a0 ff ff       	call   401190 <puts@plt>
  407183:	48 8d 3d 7a ae 00 00 	lea    rdi,[rip+0xae7a]        # 412004 <_IO_stdin_used+0x4>
  40718a:	31 f6                	xor    esi,esi
  40718c:	31 c0                	xor    eax,eax
  40718e:	e8 bd a0 ff ff       	call   401250 <open@plt>
  407193:	89 c7                	mov    edi,eax
  407195:	85 c0                	test   eax,eax
  407197:	79 34                	jns    4071cd <win+0x5c57>
  407199:	e8 e2 9f ff ff       	call   401180 <__errno_location@plt>
  40719e:	8b 38                	mov    edi,DWORD PTR [rax]
  4071a0:	e8 db a0 ff ff       	call   401280 <strerror@plt>
  4071a5:	48 8d 35 5e ae 00 00 	lea    rsi,[rip+0xae5e]        # 41200a <_IO_stdin_used+0xa>
  4071ac:	bf 01 00 00 00       	mov    edi,0x1
  4071b1:	48 89 c2             	mov    rdx,rax
  4071b4:	31 c0                	xor    eax,eax
  4071b6:	e8 75 a0 ff ff       	call   401230 <__printf_chk@plt>
  4071bb:	e8 20 a0 ff ff       	call   4011e0 <geteuid@plt>
  4071c0:	85 c0                	test   eax,eax
  4071c2:	0f 84 11 a4 ff ff    	je     4015d9 <win+0x63>
  4071c8:	e9 f4 a3 ff ff       	jmp    4015c1 <win+0x4b>
  4071cd:	ba 00 01 00 00       	mov    edx,0x100
  4071d2:	48 89 ee             	mov    rsi,rbp
  4071d5:	e8 26 a0 ff ff       	call   401200 <read@plt>
  4071da:	85 c0                	test   eax,eax
  4071dc:	7f 2a                	jg     407208 <win+0x5c92>
  4071de:	e8 9d 9f ff ff       	call   401180 <__errno_location@plt>
  4071e3:	8b 38                	mov    edi,DWORD PTR [rax]
  4071e5:	e8 96 a0 ff ff       	call   401280 <strerror@plt>
  4071ea:	bf 01 00 00 00       	mov    edi,0x1
  4071ef:	48 8d 35 b3 ae 00 00 	lea    rsi,[rip+0xaeb3]        # 4120a9 <_IO_stdin_used+0xa9>
  4071f6:	48 89 c2             	mov    rdx,rax
  4071f9:	31 c0                	xor    eax,eax
  4071fb:	e8 30 a0 ff ff       	call   401230 <__printf_chk@plt>
  407200:	83 cf ff             	or     edi,0xffffffff
  407203:	e8 58 a0 ff ff       	call   401260 <exit@plt>
  407208:	48 63 d0             	movsxd rdx,eax
  40720b:	48 89 ee             	mov    rsi,rbp
  40720e:	bf 01 00 00 00       	mov    edi,0x1
  407213:	e8 88 9f ff ff       	call   4011a0 <write@plt>
  407218:	48 8d 3d 35 af 00 00 	lea    rdi,[rip+0xaf35]        # 412154 <_IO_stdin_used+0x154>
  40721f:	e8 6c 9f ff ff       	call   401190 <puts@plt>
  407224:	48 8d 3d d9 ad 00 00 	lea    rdi,[rip+0xadd9]        # 412004 <_IO_stdin_used+0x4>
  40722b:	31 f6                	xor    esi,esi
  40722d:	31 c0                	xor    eax,eax
  40722f:	e8 1c a0 ff ff       	call   401250 <open@plt>
  407234:	89 c7                	mov    edi,eax
  407236:	85 c0                	test   eax,eax
  407238:	79 34                	jns    40726e <win+0x5cf8>
  40723a:	e8 41 9f ff ff       	call   401180 <__errno_location@plt>
  40723f:	8b 38                	mov    edi,DWORD PTR [rax]
  407241:	e8 3a a0 ff ff       	call   401280 <strerror@plt>
  407246:	48 8d 35 bd ad 00 00 	lea    rsi,[rip+0xadbd]        # 41200a <_IO_stdin_used+0xa>
  40724d:	bf 01 00 00 00       	mov    edi,0x1
  407252:	48 89 c2             	mov    rdx,rax
  407255:	31 c0                	xor    eax,eax
  407257:	e8 d4 9f ff ff       	call   401230 <__printf_chk@plt>
  40725c:	e8 7f 9f ff ff       	call   4011e0 <geteuid@plt>
  407261:	85 c0                	test   eax,eax
  407263:	0f 84 70 a3 ff ff    	je     4015d9 <win+0x63>
  407269:	e9 53 a3 ff ff       	jmp    4015c1 <win+0x4b>
  40726e:	ba 00 01 00 00       	mov    edx,0x100
  407273:	48 89 ee             	mov    rsi,rbp
  407276:	e8 85 9f ff ff       	call   401200 <read@plt>
  40727b:	85 c0                	test   eax,eax
  40727d:	7f 2a                	jg     4072a9 <win+0x5d33>
  40727f:	e8 fc 9e ff ff       	call   401180 <__errno_location@plt>
  407284:	8b 38                	mov    edi,DWORD PTR [rax]
  407286:	e8 f5 9f ff ff       	call   401280 <strerror@plt>
  40728b:	bf 01 00 00 00       	mov    edi,0x1
  407290:	48 8d 35 12 ae 00 00 	lea    rsi,[rip+0xae12]        # 4120a9 <_IO_stdin_used+0xa9>
  407297:	48 89 c2             	mov    rdx,rax
  40729a:	31 c0                	xor    eax,eax
  40729c:	e8 8f 9f ff ff       	call   401230 <__printf_chk@plt>
  4072a1:	83 cf ff             	or     edi,0xffffffff
  4072a4:	e8 b7 9f ff ff       	call   401260 <exit@plt>
  4072a9:	48 63 d0             	movsxd rdx,eax
  4072ac:	48 89 ee             	mov    rsi,rbp
  4072af:	bf 01 00 00 00       	mov    edi,0x1
  4072b4:	e8 e7 9e ff ff       	call   4011a0 <write@plt>
  4072b9:	48 8d 3d 94 ae 00 00 	lea    rdi,[rip+0xae94]        # 412154 <_IO_stdin_used+0x154>
  4072c0:	e8 cb 9e ff ff       	call   401190 <puts@plt>
  4072c5:	48 8d 3d 38 ad 00 00 	lea    rdi,[rip+0xad38]        # 412004 <_IO_stdin_used+0x4>
  4072cc:	31 f6                	xor    esi,esi
  4072ce:	31 c0                	xor    eax,eax
  4072d0:	e8 7b 9f ff ff       	call   401250 <open@plt>
  4072d5:	89 c7                	mov    edi,eax
  4072d7:	85 c0                	test   eax,eax
  4072d9:	79 34                	jns    40730f <win+0x5d99>
  4072db:	e8 a0 9e ff ff       	call   401180 <__errno_location@plt>
  4072e0:	8b 38                	mov    edi,DWORD PTR [rax]
  4072e2:	e8 99 9f ff ff       	call   401280 <strerror@plt>
  4072e7:	48 8d 35 1c ad 00 00 	lea    rsi,[rip+0xad1c]        # 41200a <_IO_stdin_used+0xa>
  4072ee:	bf 01 00 00 00       	mov    edi,0x1
  4072f3:	48 89 c2             	mov    rdx,rax
  4072f6:	31 c0                	xor    eax,eax
  4072f8:	e8 33 9f ff ff       	call   401230 <__printf_chk@plt>
  4072fd:	e8 de 9e ff ff       	call   4011e0 <geteuid@plt>
  407302:	85 c0                	test   eax,eax
  407304:	0f 84 cf a2 ff ff    	je     4015d9 <win+0x63>
  40730a:	e9 b2 a2 ff ff       	jmp    4015c1 <win+0x4b>
  40730f:	ba 00 01 00 00       	mov    edx,0x100
  407314:	48 89 ee             	mov    rsi,rbp
  407317:	e8 e4 9e ff ff       	call   401200 <read@plt>
  40731c:	85 c0                	test   eax,eax
  40731e:	7f 2a                	jg     40734a <win+0x5dd4>
  407320:	e8 5b 9e ff ff       	call   401180 <__errno_location@plt>
  407325:	8b 38                	mov    edi,DWORD PTR [rax]
  407327:	e8 54 9f ff ff       	call   401280 <strerror@plt>
  40732c:	bf 01 00 00 00       	mov    edi,0x1
  407331:	48 8d 35 71 ad 00 00 	lea    rsi,[rip+0xad71]        # 4120a9 <_IO_stdin_used+0xa9>
  407338:	48 89 c2             	mov    rdx,rax
  40733b:	31 c0                	xor    eax,eax
  40733d:	e8 ee 9e ff ff       	call   401230 <__printf_chk@plt>
  407342:	83 cf ff             	or     edi,0xffffffff
  407345:	e8 16 9f ff ff       	call   401260 <exit@plt>
  40734a:	48 63 d0             	movsxd rdx,eax
  40734d:	48 89 ee             	mov    rsi,rbp
  407350:	bf 01 00 00 00       	mov    edi,0x1
  407355:	e8 46 9e ff ff       	call   4011a0 <write@plt>
  40735a:	48 8d 3d f3 ad 00 00 	lea    rdi,[rip+0xadf3]        # 412154 <_IO_stdin_used+0x154>
  407361:	e8 2a 9e ff ff       	call   401190 <puts@plt>
  407366:	48 8d 3d 97 ac 00 00 	lea    rdi,[rip+0xac97]        # 412004 <_IO_stdin_used+0x4>
  40736d:	31 f6                	xor    esi,esi
  40736f:	31 c0                	xor    eax,eax
  407371:	e8 da 9e ff ff       	call   401250 <open@plt>
  407376:	89 c7                	mov    edi,eax
  407378:	85 c0                	test   eax,eax
  40737a:	79 34                	jns    4073b0 <win+0x5e3a>
  40737c:	e8 ff 9d ff ff       	call   401180 <__errno_location@plt>
  407381:	8b 38                	mov    edi,DWORD PTR [rax]
  407383:	e8 f8 9e ff ff       	call   401280 <strerror@plt>
  407388:	48 8d 35 7b ac 00 00 	lea    rsi,[rip+0xac7b]        # 41200a <_IO_stdin_used+0xa>
  40738f:	bf 01 00 00 00       	mov    edi,0x1
  407394:	48 89 c2             	mov    rdx,rax
  407397:	31 c0                	xor    eax,eax
  407399:	e8 92 9e ff ff       	call   401230 <__printf_chk@plt>
  40739e:	e8 3d 9e ff ff       	call   4011e0 <geteuid@plt>
  4073a3:	85 c0                	test   eax,eax
  4073a5:	0f 84 2e a2 ff ff    	je     4015d9 <win+0x63>
  4073ab:	e9 11 a2 ff ff       	jmp    4015c1 <win+0x4b>
  4073b0:	ba 00 01 00 00       	mov    edx,0x100
  4073b5:	48 89 ee             	mov    rsi,rbp
  4073b8:	e8 43 9e ff ff       	call   401200 <read@plt>
  4073bd:	85 c0                	test   eax,eax
  4073bf:	7f 2a                	jg     4073eb <win+0x5e75>
  4073c1:	e8 ba 9d ff ff       	call   401180 <__errno_location@plt>
  4073c6:	8b 38                	mov    edi,DWORD PTR [rax]
  4073c8:	e8 b3 9e ff ff       	call   401280 <strerror@plt>
  4073cd:	bf 01 00 00 00       	mov    edi,0x1
  4073d2:	48 8d 35 d0 ac 00 00 	lea    rsi,[rip+0xacd0]        # 4120a9 <_IO_stdin_used+0xa9>
  4073d9:	48 89 c2             	mov    rdx,rax
  4073dc:	31 c0                	xor    eax,eax
  4073de:	e8 4d 9e ff ff       	call   401230 <__printf_chk@plt>
  4073e3:	83 cf ff             	or     edi,0xffffffff
  4073e6:	e8 75 9e ff ff       	call   401260 <exit@plt>
  4073eb:	48 63 d0             	movsxd rdx,eax
  4073ee:	48 89 ee             	mov    rsi,rbp
  4073f1:	bf 01 00 00 00       	mov    edi,0x1
  4073f6:	e8 a5 9d ff ff       	call   4011a0 <write@plt>
  4073fb:	48 8d 3d 52 ad 00 00 	lea    rdi,[rip+0xad52]        # 412154 <_IO_stdin_used+0x154>
  407402:	e8 89 9d ff ff       	call   401190 <puts@plt>
  407407:	48 8d 3d f6 ab 00 00 	lea    rdi,[rip+0xabf6]        # 412004 <_IO_stdin_used+0x4>
  40740e:	31 f6                	xor    esi,esi
  407410:	31 c0                	xor    eax,eax
  407412:	e8 39 9e ff ff       	call   401250 <open@plt>
  407417:	89 c7                	mov    edi,eax
  407419:	85 c0                	test   eax,eax
  40741b:	79 34                	jns    407451 <win+0x5edb>
  40741d:	e8 5e 9d ff ff       	call   401180 <__errno_location@plt>
  407422:	8b 38                	mov    edi,DWORD PTR [rax]
  407424:	e8 57 9e ff ff       	call   401280 <strerror@plt>
  407429:	48 8d 35 da ab 00 00 	lea    rsi,[rip+0xabda]        # 41200a <_IO_stdin_used+0xa>
  407430:	bf 01 00 00 00       	mov    edi,0x1
  407435:	48 89 c2             	mov    rdx,rax
  407438:	31 c0                	xor    eax,eax
  40743a:	e8 f1 9d ff ff       	call   401230 <__printf_chk@plt>
  40743f:	e8 9c 9d ff ff       	call   4011e0 <geteuid@plt>
  407444:	85 c0                	test   eax,eax
  407446:	0f 84 8d a1 ff ff    	je     4015d9 <win+0x63>
  40744c:	e9 70 a1 ff ff       	jmp    4015c1 <win+0x4b>
  407451:	ba 00 01 00 00       	mov    edx,0x100
  407456:	48 89 ee             	mov    rsi,rbp
  407459:	e8 a2 9d ff ff       	call   401200 <read@plt>
  40745e:	85 c0                	test   eax,eax
  407460:	7f 2a                	jg     40748c <win+0x5f16>
  407462:	e8 19 9d ff ff       	call   401180 <__errno_location@plt>
  407467:	8b 38                	mov    edi,DWORD PTR [rax]
  407469:	e8 12 9e ff ff       	call   401280 <strerror@plt>
  40746e:	bf 01 00 00 00       	mov    edi,0x1
  407473:	48 8d 35 2f ac 00 00 	lea    rsi,[rip+0xac2f]        # 4120a9 <_IO_stdin_used+0xa9>
  40747a:	48 89 c2             	mov    rdx,rax
  40747d:	31 c0                	xor    eax,eax
  40747f:	e8 ac 9d ff ff       	call   401230 <__printf_chk@plt>
  407484:	83 cf ff             	or     edi,0xffffffff
  407487:	e8 d4 9d ff ff       	call   401260 <exit@plt>
  40748c:	48 63 d0             	movsxd rdx,eax
  40748f:	48 89 ee             	mov    rsi,rbp
  407492:	bf 01 00 00 00       	mov    edi,0x1
  407497:	e8 04 9d ff ff       	call   4011a0 <write@plt>
  40749c:	48 8d 3d b1 ac 00 00 	lea    rdi,[rip+0xacb1]        # 412154 <_IO_stdin_used+0x154>
  4074a3:	e8 e8 9c ff ff       	call   401190 <puts@plt>
  4074a8:	48 8d 3d 55 ab 00 00 	lea    rdi,[rip+0xab55]        # 412004 <_IO_stdin_used+0x4>
  4074af:	31 f6                	xor    esi,esi
  4074b1:	31 c0                	xor    eax,eax
  4074b3:	e8 98 9d ff ff       	call   401250 <open@plt>
  4074b8:	89 c7                	mov    edi,eax
  4074ba:	85 c0                	test   eax,eax
  4074bc:	79 34                	jns    4074f2 <win+0x5f7c>
  4074be:	e8 bd 9c ff ff       	call   401180 <__errno_location@plt>
  4074c3:	8b 38                	mov    edi,DWORD PTR [rax]
  4074c5:	e8 b6 9d ff ff       	call   401280 <strerror@plt>
  4074ca:	48 8d 35 39 ab 00 00 	lea    rsi,[rip+0xab39]        # 41200a <_IO_stdin_used+0xa>
  4074d1:	bf 01 00 00 00       	mov    edi,0x1
  4074d6:	48 89 c2             	mov    rdx,rax
  4074d9:	31 c0                	xor    eax,eax
  4074db:	e8 50 9d ff ff       	call   401230 <__printf_chk@plt>
  4074e0:	e8 fb 9c ff ff       	call   4011e0 <geteuid@plt>
  4074e5:	85 c0                	test   eax,eax
  4074e7:	0f 84 ec a0 ff ff    	je     4015d9 <win+0x63>
  4074ed:	e9 cf a0 ff ff       	jmp    4015c1 <win+0x4b>
  4074f2:	ba 00 01 00 00       	mov    edx,0x100
  4074f7:	48 89 ee             	mov    rsi,rbp
  4074fa:	e8 01 9d ff ff       	call   401200 <read@plt>
  4074ff:	85 c0                	test   eax,eax
  407501:	7f 2a                	jg     40752d <win+0x5fb7>
  407503:	e8 78 9c ff ff       	call   401180 <__errno_location@plt>
  407508:	8b 38                	mov    edi,DWORD PTR [rax]
  40750a:	e8 71 9d ff ff       	call   401280 <strerror@plt>
  40750f:	bf 01 00 00 00       	mov    edi,0x1
  407514:	48 8d 35 8e ab 00 00 	lea    rsi,[rip+0xab8e]        # 4120a9 <_IO_stdin_used+0xa9>
  40751b:	48 89 c2             	mov    rdx,rax
  40751e:	31 c0                	xor    eax,eax
  407520:	e8 0b 9d ff ff       	call   401230 <__printf_chk@plt>
  407525:	83 cf ff             	or     edi,0xffffffff
  407528:	e8 33 9d ff ff       	call   401260 <exit@plt>
  40752d:	48 63 d0             	movsxd rdx,eax
  407530:	48 89 ee             	mov    rsi,rbp
  407533:	bf 01 00 00 00       	mov    edi,0x1
  407538:	e8 63 9c ff ff       	call   4011a0 <write@plt>
  40753d:	48 8d 3d 10 ac 00 00 	lea    rdi,[rip+0xac10]        # 412154 <_IO_stdin_used+0x154>
  407544:	e8 47 9c ff ff       	call   401190 <puts@plt>
  407549:	48 8d 3d b4 aa 00 00 	lea    rdi,[rip+0xaab4]        # 412004 <_IO_stdin_used+0x4>
  407550:	31 f6                	xor    esi,esi
  407552:	31 c0                	xor    eax,eax
  407554:	e8 f7 9c ff ff       	call   401250 <open@plt>
  407559:	89 c7                	mov    edi,eax
  40755b:	85 c0                	test   eax,eax
  40755d:	79 34                	jns    407593 <win+0x601d>
  40755f:	e8 1c 9c ff ff       	call   401180 <__errno_location@plt>
  407564:	8b 38                	mov    edi,DWORD PTR [rax]
  407566:	e8 15 9d ff ff       	call   401280 <strerror@plt>
  40756b:	48 8d 35 98 aa 00 00 	lea    rsi,[rip+0xaa98]        # 41200a <_IO_stdin_used+0xa>
  407572:	bf 01 00 00 00       	mov    edi,0x1
  407577:	48 89 c2             	mov    rdx,rax
  40757a:	31 c0                	xor    eax,eax
  40757c:	e8 af 9c ff ff       	call   401230 <__printf_chk@plt>
  407581:	e8 5a 9c ff ff       	call   4011e0 <geteuid@plt>
  407586:	85 c0                	test   eax,eax
  407588:	0f 84 4b a0 ff ff    	je     4015d9 <win+0x63>
  40758e:	e9 2e a0 ff ff       	jmp    4015c1 <win+0x4b>
  407593:	ba 00 01 00 00       	mov    edx,0x100
  407598:	48 89 ee             	mov    rsi,rbp
  40759b:	e8 60 9c ff ff       	call   401200 <read@plt>
  4075a0:	85 c0                	test   eax,eax
  4075a2:	7f 2a                	jg     4075ce <win+0x6058>
  4075a4:	e8 d7 9b ff ff       	call   401180 <__errno_location@plt>
  4075a9:	8b 38                	mov    edi,DWORD PTR [rax]
  4075ab:	e8 d0 9c ff ff       	call   401280 <strerror@plt>
  4075b0:	bf 01 00 00 00       	mov    edi,0x1
  4075b5:	48 8d 35 ed aa 00 00 	lea    rsi,[rip+0xaaed]        # 4120a9 <_IO_stdin_used+0xa9>
  4075bc:	48 89 c2             	mov    rdx,rax
  4075bf:	31 c0                	xor    eax,eax
  4075c1:	e8 6a 9c ff ff       	call   401230 <__printf_chk@plt>
  4075c6:	83 cf ff             	or     edi,0xffffffff
  4075c9:	e8 92 9c ff ff       	call   401260 <exit@plt>
  4075ce:	48 63 d0             	movsxd rdx,eax
  4075d1:	48 89 ee             	mov    rsi,rbp
  4075d4:	bf 01 00 00 00       	mov    edi,0x1
  4075d9:	e8 c2 9b ff ff       	call   4011a0 <write@plt>
  4075de:	48 8d 3d 6f ab 00 00 	lea    rdi,[rip+0xab6f]        # 412154 <_IO_stdin_used+0x154>
  4075e5:	e8 a6 9b ff ff       	call   401190 <puts@plt>
  4075ea:	48 8d 3d 13 aa 00 00 	lea    rdi,[rip+0xaa13]        # 412004 <_IO_stdin_used+0x4>
  4075f1:	31 f6                	xor    esi,esi
  4075f3:	31 c0                	xor    eax,eax
  4075f5:	e8 56 9c ff ff       	call   401250 <open@plt>
  4075fa:	89 c7                	mov    edi,eax
  4075fc:	85 c0                	test   eax,eax
  4075fe:	79 34                	jns    407634 <win+0x60be>
  407600:	e8 7b 9b ff ff       	call   401180 <__errno_location@plt>
  407605:	8b 38                	mov    edi,DWORD PTR [rax]
  407607:	e8 74 9c ff ff       	call   401280 <strerror@plt>
  40760c:	48 8d 35 f7 a9 00 00 	lea    rsi,[rip+0xa9f7]        # 41200a <_IO_stdin_used+0xa>
  407613:	bf 01 00 00 00       	mov    edi,0x1
  407618:	48 89 c2             	mov    rdx,rax
  40761b:	31 c0                	xor    eax,eax
  40761d:	e8 0e 9c ff ff       	call   401230 <__printf_chk@plt>
  407622:	e8 b9 9b ff ff       	call   4011e0 <geteuid@plt>
  407627:	85 c0                	test   eax,eax
  407629:	0f 84 aa 9f ff ff    	je     4015d9 <win+0x63>
  40762f:	e9 8d 9f ff ff       	jmp    4015c1 <win+0x4b>
  407634:	ba 00 01 00 00       	mov    edx,0x100
  407639:	48 89 ee             	mov    rsi,rbp
  40763c:	e8 bf 9b ff ff       	call   401200 <read@plt>
  407641:	85 c0                	test   eax,eax
  407643:	7f 2a                	jg     40766f <win+0x60f9>
  407645:	e8 36 9b ff ff       	call   401180 <__errno_location@plt>
  40764a:	8b 38                	mov    edi,DWORD PTR [rax]
  40764c:	e8 2f 9c ff ff       	call   401280 <strerror@plt>
  407651:	bf 01 00 00 00       	mov    edi,0x1
  407656:	48 8d 35 4c aa 00 00 	lea    rsi,[rip+0xaa4c]        # 4120a9 <_IO_stdin_used+0xa9>
  40765d:	48 89 c2             	mov    rdx,rax
  407660:	31 c0                	xor    eax,eax
  407662:	e8 c9 9b ff ff       	call   401230 <__printf_chk@plt>
  407667:	83 cf ff             	or     edi,0xffffffff
  40766a:	e8 f1 9b ff ff       	call   401260 <exit@plt>
  40766f:	48 63 d0             	movsxd rdx,eax
  407672:	48 89 ee             	mov    rsi,rbp
  407675:	bf 01 00 00 00       	mov    edi,0x1
  40767a:	e8 21 9b ff ff       	call   4011a0 <write@plt>
  40767f:	48 8d 3d ce aa 00 00 	lea    rdi,[rip+0xaace]        # 412154 <_IO_stdin_used+0x154>
  407686:	e8 05 9b ff ff       	call   401190 <puts@plt>
  40768b:	48 8d 3d 72 a9 00 00 	lea    rdi,[rip+0xa972]        # 412004 <_IO_stdin_used+0x4>
  407692:	31 f6                	xor    esi,esi
  407694:	31 c0                	xor    eax,eax
  407696:	e8 b5 9b ff ff       	call   401250 <open@plt>
  40769b:	89 c7                	mov    edi,eax
  40769d:	85 c0                	test   eax,eax
  40769f:	79 34                	jns    4076d5 <win+0x615f>
  4076a1:	e8 da 9a ff ff       	call   401180 <__errno_location@plt>
  4076a6:	8b 38                	mov    edi,DWORD PTR [rax]
  4076a8:	e8 d3 9b ff ff       	call   401280 <strerror@plt>
  4076ad:	48 8d 35 56 a9 00 00 	lea    rsi,[rip+0xa956]        # 41200a <_IO_stdin_used+0xa>
  4076b4:	bf 01 00 00 00       	mov    edi,0x1
  4076b9:	48 89 c2             	mov    rdx,rax
  4076bc:	31 c0                	xor    eax,eax
  4076be:	e8 6d 9b ff ff       	call   401230 <__printf_chk@plt>
  4076c3:	e8 18 9b ff ff       	call   4011e0 <geteuid@plt>
  4076c8:	85 c0                	test   eax,eax
  4076ca:	0f 84 09 9f ff ff    	je     4015d9 <win+0x63>
  4076d0:	e9 ec 9e ff ff       	jmp    4015c1 <win+0x4b>
  4076d5:	ba 00 01 00 00       	mov    edx,0x100
  4076da:	48 89 ee             	mov    rsi,rbp
  4076dd:	e8 1e 9b ff ff       	call   401200 <read@plt>
  4076e2:	85 c0                	test   eax,eax
  4076e4:	7f 2a                	jg     407710 <win+0x619a>
  4076e6:	e8 95 9a ff ff       	call   401180 <__errno_location@plt>
  4076eb:	8b 38                	mov    edi,DWORD PTR [rax]
  4076ed:	e8 8e 9b ff ff       	call   401280 <strerror@plt>
  4076f2:	bf 01 00 00 00       	mov    edi,0x1
  4076f7:	48 8d 35 ab a9 00 00 	lea    rsi,[rip+0xa9ab]        # 4120a9 <_IO_stdin_used+0xa9>
  4076fe:	48 89 c2             	mov    rdx,rax
  407701:	31 c0                	xor    eax,eax
  407703:	e8 28 9b ff ff       	call   401230 <__printf_chk@plt>
  407708:	83 cf ff             	or     edi,0xffffffff
  40770b:	e8 50 9b ff ff       	call   401260 <exit@plt>
  407710:	48 63 d0             	movsxd rdx,eax
  407713:	48 89 ee             	mov    rsi,rbp
  407716:	bf 01 00 00 00       	mov    edi,0x1
  40771b:	e8 80 9a ff ff       	call   4011a0 <write@plt>
  407720:	48 8d 3d 2d aa 00 00 	lea    rdi,[rip+0xaa2d]        # 412154 <_IO_stdin_used+0x154>
  407727:	e8 64 9a ff ff       	call   401190 <puts@plt>
  40772c:	48 8d 3d d1 a8 00 00 	lea    rdi,[rip+0xa8d1]        # 412004 <_IO_stdin_used+0x4>
  407733:	31 f6                	xor    esi,esi
  407735:	31 c0                	xor    eax,eax
  407737:	e8 14 9b ff ff       	call   401250 <open@plt>
  40773c:	89 c7                	mov    edi,eax
  40773e:	85 c0                	test   eax,eax
  407740:	79 34                	jns    407776 <win+0x6200>
  407742:	e8 39 9a ff ff       	call   401180 <__errno_location@plt>
  407747:	8b 38                	mov    edi,DWORD PTR [rax]
  407749:	e8 32 9b ff ff       	call   401280 <strerror@plt>
  40774e:	48 8d 35 b5 a8 00 00 	lea    rsi,[rip+0xa8b5]        # 41200a <_IO_stdin_used+0xa>
  407755:	bf 01 00 00 00       	mov    edi,0x1
  40775a:	48 89 c2             	mov    rdx,rax
  40775d:	31 c0                	xor    eax,eax
  40775f:	e8 cc 9a ff ff       	call   401230 <__printf_chk@plt>
  407764:	e8 77 9a ff ff       	call   4011e0 <geteuid@plt>
  407769:	85 c0                	test   eax,eax
  40776b:	0f 84 68 9e ff ff    	je     4015d9 <win+0x63>
  407771:	e9 4b 9e ff ff       	jmp    4015c1 <win+0x4b>
  407776:	ba 00 01 00 00       	mov    edx,0x100
  40777b:	48 89 ee             	mov    rsi,rbp
  40777e:	e8 7d 9a ff ff       	call   401200 <read@plt>
  407783:	85 c0                	test   eax,eax
  407785:	7f 2a                	jg     4077b1 <win+0x623b>
  407787:	e8 f4 99 ff ff       	call   401180 <__errno_location@plt>
  40778c:	8b 38                	mov    edi,DWORD PTR [rax]
  40778e:	e8 ed 9a ff ff       	call   401280 <strerror@plt>
  407793:	bf 01 00 00 00       	mov    edi,0x1
  407798:	48 8d 35 0a a9 00 00 	lea    rsi,[rip+0xa90a]        # 4120a9 <_IO_stdin_used+0xa9>
  40779f:	48 89 c2             	mov    rdx,rax
  4077a2:	31 c0                	xor    eax,eax
  4077a4:	e8 87 9a ff ff       	call   401230 <__printf_chk@plt>
  4077a9:	83 cf ff             	or     edi,0xffffffff
  4077ac:	e8 af 9a ff ff       	call   401260 <exit@plt>
  4077b1:	48 63 d0             	movsxd rdx,eax
  4077b4:	48 89 ee             	mov    rsi,rbp
  4077b7:	bf 01 00 00 00       	mov    edi,0x1
  4077bc:	e8 df 99 ff ff       	call   4011a0 <write@plt>
  4077c1:	48 8d 3d 8c a9 00 00 	lea    rdi,[rip+0xa98c]        # 412154 <_IO_stdin_used+0x154>
  4077c8:	e8 c3 99 ff ff       	call   401190 <puts@plt>
  4077cd:	48 8d 3d 30 a8 00 00 	lea    rdi,[rip+0xa830]        # 412004 <_IO_stdin_used+0x4>
  4077d4:	31 f6                	xor    esi,esi
  4077d6:	31 c0                	xor    eax,eax
  4077d8:	e8 73 9a ff ff       	call   401250 <open@plt>
  4077dd:	89 c7                	mov    edi,eax
  4077df:	85 c0                	test   eax,eax
  4077e1:	79 34                	jns    407817 <win+0x62a1>
  4077e3:	e8 98 99 ff ff       	call   401180 <__errno_location@plt>
  4077e8:	8b 38                	mov    edi,DWORD PTR [rax]
  4077ea:	e8 91 9a ff ff       	call   401280 <strerror@plt>
  4077ef:	48 8d 35 14 a8 00 00 	lea    rsi,[rip+0xa814]        # 41200a <_IO_stdin_used+0xa>
  4077f6:	bf 01 00 00 00       	mov    edi,0x1
  4077fb:	48 89 c2             	mov    rdx,rax
  4077fe:	31 c0                	xor    eax,eax
  407800:	e8 2b 9a ff ff       	call   401230 <__printf_chk@plt>
  407805:	e8 d6 99 ff ff       	call   4011e0 <geteuid@plt>
  40780a:	85 c0                	test   eax,eax
  40780c:	0f 84 c7 9d ff ff    	je     4015d9 <win+0x63>
  407812:	e9 aa 9d ff ff       	jmp    4015c1 <win+0x4b>
  407817:	ba 00 01 00 00       	mov    edx,0x100
  40781c:	48 89 ee             	mov    rsi,rbp
  40781f:	e8 dc 99 ff ff       	call   401200 <read@plt>
  407824:	85 c0                	test   eax,eax
  407826:	7f 2a                	jg     407852 <win+0x62dc>
  407828:	e8 53 99 ff ff       	call   401180 <__errno_location@plt>
  40782d:	8b 38                	mov    edi,DWORD PTR [rax]
  40782f:	e8 4c 9a ff ff       	call   401280 <strerror@plt>
  407834:	bf 01 00 00 00       	mov    edi,0x1
  407839:	48 8d 35 69 a8 00 00 	lea    rsi,[rip+0xa869]        # 4120a9 <_IO_stdin_used+0xa9>
  407840:	48 89 c2             	mov    rdx,rax
  407843:	31 c0                	xor    eax,eax
  407845:	e8 e6 99 ff ff       	call   401230 <__printf_chk@plt>
  40784a:	83 cf ff             	or     edi,0xffffffff
  40784d:	e8 0e 9a ff ff       	call   401260 <exit@plt>
  407852:	48 63 d0             	movsxd rdx,eax
  407855:	48 89 ee             	mov    rsi,rbp
  407858:	bf 01 00 00 00       	mov    edi,0x1
  40785d:	e8 3e 99 ff ff       	call   4011a0 <write@plt>
  407862:	48 8d 3d eb a8 00 00 	lea    rdi,[rip+0xa8eb]        # 412154 <_IO_stdin_used+0x154>
  407869:	e8 22 99 ff ff       	call   401190 <puts@plt>
  40786e:	48 8d 3d 8f a7 00 00 	lea    rdi,[rip+0xa78f]        # 412004 <_IO_stdin_used+0x4>
  407875:	31 f6                	xor    esi,esi
  407877:	31 c0                	xor    eax,eax
  407879:	e8 d2 99 ff ff       	call   401250 <open@plt>
  40787e:	89 c7                	mov    edi,eax
  407880:	85 c0                	test   eax,eax
  407882:	79 34                	jns    4078b8 <win+0x6342>
  407884:	e8 f7 98 ff ff       	call   401180 <__errno_location@plt>
  407889:	8b 38                	mov    edi,DWORD PTR [rax]
  40788b:	e8 f0 99 ff ff       	call   401280 <strerror@plt>
  407890:	48 8d 35 73 a7 00 00 	lea    rsi,[rip+0xa773]        # 41200a <_IO_stdin_used+0xa>
  407897:	bf 01 00 00 00       	mov    edi,0x1
  40789c:	48 89 c2             	mov    rdx,rax
  40789f:	31 c0                	xor    eax,eax
  4078a1:	e8 8a 99 ff ff       	call   401230 <__printf_chk@plt>
  4078a6:	e8 35 99 ff ff       	call   4011e0 <geteuid@plt>
  4078ab:	85 c0                	test   eax,eax
  4078ad:	0f 84 26 9d ff ff    	je     4015d9 <win+0x63>
  4078b3:	e9 09 9d ff ff       	jmp    4015c1 <win+0x4b>
  4078b8:	ba 00 01 00 00       	mov    edx,0x100
  4078bd:	48 89 ee             	mov    rsi,rbp
  4078c0:	e8 3b 99 ff ff       	call   401200 <read@plt>
  4078c5:	85 c0                	test   eax,eax
  4078c7:	7f 2a                	jg     4078f3 <win+0x637d>
  4078c9:	e8 b2 98 ff ff       	call   401180 <__errno_location@plt>
  4078ce:	8b 38                	mov    edi,DWORD PTR [rax]
  4078d0:	e8 ab 99 ff ff       	call   401280 <strerror@plt>
  4078d5:	bf 01 00 00 00       	mov    edi,0x1
  4078da:	48 8d 35 c8 a7 00 00 	lea    rsi,[rip+0xa7c8]        # 4120a9 <_IO_stdin_used+0xa9>
  4078e1:	48 89 c2             	mov    rdx,rax
  4078e4:	31 c0                	xor    eax,eax
  4078e6:	e8 45 99 ff ff       	call   401230 <__printf_chk@plt>
  4078eb:	83 cf ff             	or     edi,0xffffffff
  4078ee:	e8 6d 99 ff ff       	call   401260 <exit@plt>
  4078f3:	48 63 d0             	movsxd rdx,eax
  4078f6:	48 89 ee             	mov    rsi,rbp
  4078f9:	bf 01 00 00 00       	mov    edi,0x1
  4078fe:	e8 9d 98 ff ff       	call   4011a0 <write@plt>
  407903:	48 8d 3d 4a a8 00 00 	lea    rdi,[rip+0xa84a]        # 412154 <_IO_stdin_used+0x154>
  40790a:	e8 81 98 ff ff       	call   401190 <puts@plt>
  40790f:	48 8d 3d ee a6 00 00 	lea    rdi,[rip+0xa6ee]        # 412004 <_IO_stdin_used+0x4>
  407916:	31 f6                	xor    esi,esi
  407918:	31 c0                	xor    eax,eax
  40791a:	e8 31 99 ff ff       	call   401250 <open@plt>
  40791f:	89 c7                	mov    edi,eax
  407921:	85 c0                	test   eax,eax
  407923:	79 34                	jns    407959 <win+0x63e3>
  407925:	e8 56 98 ff ff       	call   401180 <__errno_location@plt>
  40792a:	8b 38                	mov    edi,DWORD PTR [rax]
  40792c:	e8 4f 99 ff ff       	call   401280 <strerror@plt>
  407931:	48 8d 35 d2 a6 00 00 	lea    rsi,[rip+0xa6d2]        # 41200a <_IO_stdin_used+0xa>
  407938:	bf 01 00 00 00       	mov    edi,0x1
  40793d:	48 89 c2             	mov    rdx,rax
  407940:	31 c0                	xor    eax,eax
  407942:	e8 e9 98 ff ff       	call   401230 <__printf_chk@plt>
  407947:	e8 94 98 ff ff       	call   4011e0 <geteuid@plt>
  40794c:	85 c0                	test   eax,eax
  40794e:	0f 84 85 9c ff ff    	je     4015d9 <win+0x63>
  407954:	e9 68 9c ff ff       	jmp    4015c1 <win+0x4b>
  407959:	ba 00 01 00 00       	mov    edx,0x100
  40795e:	48 89 ee             	mov    rsi,rbp
  407961:	e8 9a 98 ff ff       	call   401200 <read@plt>
  407966:	85 c0                	test   eax,eax
  407968:	7f 2a                	jg     407994 <win+0x641e>
  40796a:	e8 11 98 ff ff       	call   401180 <__errno_location@plt>
  40796f:	8b 38                	mov    edi,DWORD PTR [rax]
  407971:	e8 0a 99 ff ff       	call   401280 <strerror@plt>
  407976:	bf 01 00 00 00       	mov    edi,0x1
  40797b:	48 8d 35 27 a7 00 00 	lea    rsi,[rip+0xa727]        # 4120a9 <_IO_stdin_used+0xa9>
  407982:	48 89 c2             	mov    rdx,rax
  407985:	31 c0                	xor    eax,eax
  407987:	e8 a4 98 ff ff       	call   401230 <__printf_chk@plt>
  40798c:	83 cf ff             	or     edi,0xffffffff
  40798f:	e8 cc 98 ff ff       	call   401260 <exit@plt>
  407994:	48 63 d0             	movsxd rdx,eax
  407997:	48 89 ee             	mov    rsi,rbp
  40799a:	bf 01 00 00 00       	mov    edi,0x1
  40799f:	e8 fc 97 ff ff       	call   4011a0 <write@plt>
  4079a4:	48 8d 3d a9 a7 00 00 	lea    rdi,[rip+0xa7a9]        # 412154 <_IO_stdin_used+0x154>
  4079ab:	e8 e0 97 ff ff       	call   401190 <puts@plt>
  4079b0:	48 8d 3d 4d a6 00 00 	lea    rdi,[rip+0xa64d]        # 412004 <_IO_stdin_used+0x4>
  4079b7:	31 f6                	xor    esi,esi
  4079b9:	31 c0                	xor    eax,eax
  4079bb:	e8 90 98 ff ff       	call   401250 <open@plt>
  4079c0:	89 c7                	mov    edi,eax
  4079c2:	85 c0                	test   eax,eax
  4079c4:	79 34                	jns    4079fa <win+0x6484>
  4079c6:	e8 b5 97 ff ff       	call   401180 <__errno_location@plt>
  4079cb:	8b 38                	mov    edi,DWORD PTR [rax]
  4079cd:	e8 ae 98 ff ff       	call   401280 <strerror@plt>
  4079d2:	48 8d 35 31 a6 00 00 	lea    rsi,[rip+0xa631]        # 41200a <_IO_stdin_used+0xa>
  4079d9:	bf 01 00 00 00       	mov    edi,0x1
  4079de:	48 89 c2             	mov    rdx,rax
  4079e1:	31 c0                	xor    eax,eax
  4079e3:	e8 48 98 ff ff       	call   401230 <__printf_chk@plt>
  4079e8:	e8 f3 97 ff ff       	call   4011e0 <geteuid@plt>
  4079ed:	85 c0                	test   eax,eax
  4079ef:	0f 84 e4 9b ff ff    	je     4015d9 <win+0x63>
  4079f5:	e9 c7 9b ff ff       	jmp    4015c1 <win+0x4b>
  4079fa:	ba 00 01 00 00       	mov    edx,0x100
  4079ff:	48 89 ee             	mov    rsi,rbp
  407a02:	e8 f9 97 ff ff       	call   401200 <read@plt>
  407a07:	85 c0                	test   eax,eax
  407a09:	7f 2a                	jg     407a35 <win+0x64bf>
  407a0b:	e8 70 97 ff ff       	call   401180 <__errno_location@plt>
  407a10:	8b 38                	mov    edi,DWORD PTR [rax]
  407a12:	e8 69 98 ff ff       	call   401280 <strerror@plt>
  407a17:	bf 01 00 00 00       	mov    edi,0x1
  407a1c:	48 8d 35 86 a6 00 00 	lea    rsi,[rip+0xa686]        # 4120a9 <_IO_stdin_used+0xa9>
  407a23:	48 89 c2             	mov    rdx,rax
  407a26:	31 c0                	xor    eax,eax
  407a28:	e8 03 98 ff ff       	call   401230 <__printf_chk@plt>
  407a2d:	83 cf ff             	or     edi,0xffffffff
  407a30:	e8 2b 98 ff ff       	call   401260 <exit@plt>
  407a35:	48 89 e5             	mov    rbp,rsp
  407a38:	48 63 d0             	movsxd rdx,eax
  407a3b:	bf 01 00 00 00       	mov    edi,0x1
  407a40:	48 89 ee             	mov    rsi,rbp
  407a43:	e8 58 97 ff ff       	call   4011a0 <write@plt>
  407a48:	48 8d 3d 05 a7 00 00 	lea    rdi,[rip+0xa705]        # 412154 <_IO_stdin_used+0x154>
  407a4f:	e8 3c 97 ff ff       	call   401190 <puts@plt>
  407a54:	48 8d 3d a9 a5 00 00 	lea    rdi,[rip+0xa5a9]        # 412004 <_IO_stdin_used+0x4>
  407a5b:	31 f6                	xor    esi,esi
  407a5d:	31 c0                	xor    eax,eax
  407a5f:	e8 ec 97 ff ff       	call   401250 <open@plt>
  407a64:	89 c7                	mov    edi,eax
  407a66:	85 c0                	test   eax,eax
  407a68:	79 34                	jns    407a9e <win+0x6528>
  407a6a:	e8 11 97 ff ff       	call   401180 <__errno_location@plt>
  407a6f:	8b 38                	mov    edi,DWORD PTR [rax]
  407a71:	e8 0a 98 ff ff       	call   401280 <strerror@plt>
  407a76:	48 8d 35 8d a5 00 00 	lea    rsi,[rip+0xa58d]        # 41200a <_IO_stdin_used+0xa>
  407a7d:	bf 01 00 00 00       	mov    edi,0x1
  407a82:	48 89 c2             	mov    rdx,rax
  407a85:	31 c0                	xor    eax,eax
  407a87:	e8 a4 97 ff ff       	call   401230 <__printf_chk@plt>
  407a8c:	e8 4f 97 ff ff       	call   4011e0 <geteuid@plt>
  407a91:	85 c0                	test   eax,eax
  407a93:	0f 84 40 9b ff ff    	je     4015d9 <win+0x63>
  407a99:	e9 23 9b ff ff       	jmp    4015c1 <win+0x4b>
  407a9e:	ba 00 01 00 00       	mov    edx,0x100
  407aa3:	48 89 ee             	mov    rsi,rbp
  407aa6:	e8 55 97 ff ff       	call   401200 <read@plt>
  407aab:	85 c0                	test   eax,eax
  407aad:	7f 2a                	jg     407ad9 <win+0x6563>
  407aaf:	e8 cc 96 ff ff       	call   401180 <__errno_location@plt>
  407ab4:	8b 38                	mov    edi,DWORD PTR [rax]
  407ab6:	e8 c5 97 ff ff       	call   401280 <strerror@plt>
  407abb:	bf 01 00 00 00       	mov    edi,0x1
  407ac0:	48 8d 35 e2 a5 00 00 	lea    rsi,[rip+0xa5e2]        # 4120a9 <_IO_stdin_used+0xa9>
  407ac7:	48 89 c2             	mov    rdx,rax
  407aca:	31 c0                	xor    eax,eax
  407acc:	e8 5f 97 ff ff       	call   401230 <__printf_chk@plt>
  407ad1:	83 cf ff             	or     edi,0xffffffff
  407ad4:	e8 87 97 ff ff       	call   401260 <exit@plt>
  407ad9:	48 63 d0             	movsxd rdx,eax
  407adc:	48 89 ee             	mov    rsi,rbp
  407adf:	bf 01 00 00 00       	mov    edi,0x1
  407ae4:	e8 b7 96 ff ff       	call   4011a0 <write@plt>
  407ae9:	48 8d 3d 64 a6 00 00 	lea    rdi,[rip+0xa664]        # 412154 <_IO_stdin_used+0x154>
  407af0:	e8 9b 96 ff ff       	call   401190 <puts@plt>
  407af5:	48 8d 3d 08 a5 00 00 	lea    rdi,[rip+0xa508]        # 412004 <_IO_stdin_used+0x4>
  407afc:	31 f6                	xor    esi,esi
  407afe:	31 c0                	xor    eax,eax
  407b00:	e8 4b 97 ff ff       	call   401250 <open@plt>
  407b05:	89 c7                	mov    edi,eax
  407b07:	85 c0                	test   eax,eax
  407b09:	79 34                	jns    407b3f <win+0x65c9>
  407b0b:	e8 70 96 ff ff       	call   401180 <__errno_location@plt>
  407b10:	8b 38                	mov    edi,DWORD PTR [rax]
  407b12:	e8 69 97 ff ff       	call   401280 <strerror@plt>
  407b17:	48 8d 35 ec a4 00 00 	lea    rsi,[rip+0xa4ec]        # 41200a <_IO_stdin_used+0xa>
  407b1e:	bf 01 00 00 00       	mov    edi,0x1
  407b23:	48 89 c2             	mov    rdx,rax
  407b26:	31 c0                	xor    eax,eax
  407b28:	e8 03 97 ff ff       	call   401230 <__printf_chk@plt>
  407b2d:	e8 ae 96 ff ff       	call   4011e0 <geteuid@plt>
  407b32:	85 c0                	test   eax,eax
  407b34:	0f 84 9f 9a ff ff    	je     4015d9 <win+0x63>
  407b3a:	e9 82 9a ff ff       	jmp    4015c1 <win+0x4b>
  407b3f:	ba 00 01 00 00       	mov    edx,0x100
  407b44:	48 89 ee             	mov    rsi,rbp
  407b47:	e8 b4 96 ff ff       	call   401200 <read@plt>
  407b4c:	85 c0                	test   eax,eax
  407b4e:	7f 2a                	jg     407b7a <win+0x6604>
  407b50:	e8 2b 96 ff ff       	call   401180 <__errno_location@plt>
  407b55:	8b 38                	mov    edi,DWORD PTR [rax]
  407b57:	e8 24 97 ff ff       	call   401280 <strerror@plt>
  407b5c:	bf 01 00 00 00       	mov    edi,0x1
  407b61:	48 8d 35 41 a5 00 00 	lea    rsi,[rip+0xa541]        # 4120a9 <_IO_stdin_used+0xa9>
  407b68:	48 89 c2             	mov    rdx,rax
  407b6b:	31 c0                	xor    eax,eax
  407b6d:	e8 be 96 ff ff       	call   401230 <__printf_chk@plt>
  407b72:	83 cf ff             	or     edi,0xffffffff
  407b75:	e8 e6 96 ff ff       	call   401260 <exit@plt>
  407b7a:	48 63 d0             	movsxd rdx,eax
  407b7d:	48 89 ee             	mov    rsi,rbp
  407b80:	bf 01 00 00 00       	mov    edi,0x1
  407b85:	e8 16 96 ff ff       	call   4011a0 <write@plt>
  407b8a:	48 8d 3d c3 a5 00 00 	lea    rdi,[rip+0xa5c3]        # 412154 <_IO_stdin_used+0x154>
  407b91:	e8 fa 95 ff ff       	call   401190 <puts@plt>
  407b96:	48 8d 3d 67 a4 00 00 	lea    rdi,[rip+0xa467]        # 412004 <_IO_stdin_used+0x4>
  407b9d:	31 f6                	xor    esi,esi
  407b9f:	31 c0                	xor    eax,eax
  407ba1:	e8 aa 96 ff ff       	call   401250 <open@plt>
  407ba6:	89 c7                	mov    edi,eax
  407ba8:	85 c0                	test   eax,eax
  407baa:	79 34                	jns    407be0 <win+0x666a>
  407bac:	e8 cf 95 ff ff       	call   401180 <__errno_location@plt>
  407bb1:	8b 38                	mov    edi,DWORD PTR [rax]
  407bb3:	e8 c8 96 ff ff       	call   401280 <strerror@plt>
  407bb8:	48 8d 35 4b a4 00 00 	lea    rsi,[rip+0xa44b]        # 41200a <_IO_stdin_used+0xa>
  407bbf:	bf 01 00 00 00       	mov    edi,0x1
  407bc4:	48 89 c2             	mov    rdx,rax
  407bc7:	31 c0                	xor    eax,eax
  407bc9:	e8 62 96 ff ff       	call   401230 <__printf_chk@plt>
  407bce:	e8 0d 96 ff ff       	call   4011e0 <geteuid@plt>
  407bd3:	85 c0                	test   eax,eax
  407bd5:	0f 84 fe 99 ff ff    	je     4015d9 <win+0x63>
  407bdb:	e9 e1 99 ff ff       	jmp    4015c1 <win+0x4b>
  407be0:	ba 00 01 00 00       	mov    edx,0x100
  407be5:	48 89 ee             	mov    rsi,rbp
  407be8:	e8 13 96 ff ff       	call   401200 <read@plt>
  407bed:	85 c0                	test   eax,eax
  407bef:	7f 2a                	jg     407c1b <win+0x66a5>
  407bf1:	e8 8a 95 ff ff       	call   401180 <__errno_location@plt>
  407bf6:	8b 38                	mov    edi,DWORD PTR [rax]
  407bf8:	e8 83 96 ff ff       	call   401280 <strerror@plt>
  407bfd:	bf 01 00 00 00       	mov    edi,0x1
  407c02:	48 8d 35 a0 a4 00 00 	lea    rsi,[rip+0xa4a0]        # 4120a9 <_IO_stdin_used+0xa9>
  407c09:	48 89 c2             	mov    rdx,rax
  407c0c:	31 c0                	xor    eax,eax
  407c0e:	e8 1d 96 ff ff       	call   401230 <__printf_chk@plt>
  407c13:	83 cf ff             	or     edi,0xffffffff
  407c16:	e8 45 96 ff ff       	call   401260 <exit@plt>
  407c1b:	48 63 d0             	movsxd rdx,eax
  407c1e:	48 89 ee             	mov    rsi,rbp
  407c21:	bf 01 00 00 00       	mov    edi,0x1
  407c26:	e8 75 95 ff ff       	call   4011a0 <write@plt>
  407c2b:	48 8d 3d 22 a5 00 00 	lea    rdi,[rip+0xa522]        # 412154 <_IO_stdin_used+0x154>
  407c32:	e8 59 95 ff ff       	call   401190 <puts@plt>
  407c37:	48 8d 3d c6 a3 00 00 	lea    rdi,[rip+0xa3c6]        # 412004 <_IO_stdin_used+0x4>
  407c3e:	31 f6                	xor    esi,esi
  407c40:	31 c0                	xor    eax,eax
  407c42:	e8 09 96 ff ff       	call   401250 <open@plt>
  407c47:	89 c7                	mov    edi,eax
  407c49:	85 c0                	test   eax,eax
  407c4b:	79 34                	jns    407c81 <win+0x670b>
  407c4d:	e8 2e 95 ff ff       	call   401180 <__errno_location@plt>
  407c52:	8b 38                	mov    edi,DWORD PTR [rax]
  407c54:	e8 27 96 ff ff       	call   401280 <strerror@plt>
  407c59:	48 8d 35 aa a3 00 00 	lea    rsi,[rip+0xa3aa]        # 41200a <_IO_stdin_used+0xa>
  407c60:	bf 01 00 00 00       	mov    edi,0x1
  407c65:	48 89 c2             	mov    rdx,rax
  407c68:	31 c0                	xor    eax,eax
  407c6a:	e8 c1 95 ff ff       	call   401230 <__printf_chk@plt>
  407c6f:	e8 6c 95 ff ff       	call   4011e0 <geteuid@plt>
  407c74:	85 c0                	test   eax,eax
  407c76:	0f 84 5d 99 ff ff    	je     4015d9 <win+0x63>
  407c7c:	e9 40 99 ff ff       	jmp    4015c1 <win+0x4b>
  407c81:	ba 00 01 00 00       	mov    edx,0x100
  407c86:	48 89 ee             	mov    rsi,rbp
  407c89:	e8 72 95 ff ff       	call   401200 <read@plt>
  407c8e:	85 c0                	test   eax,eax
  407c90:	7f 2a                	jg     407cbc <win+0x6746>
  407c92:	e8 e9 94 ff ff       	call   401180 <__errno_location@plt>
  407c97:	8b 38                	mov    edi,DWORD PTR [rax]
  407c99:	e8 e2 95 ff ff       	call   401280 <strerror@plt>
  407c9e:	bf 01 00 00 00       	mov    edi,0x1
  407ca3:	48 8d 35 ff a3 00 00 	lea    rsi,[rip+0xa3ff]        # 4120a9 <_IO_stdin_used+0xa9>
  407caa:	48 89 c2             	mov    rdx,rax
  407cad:	31 c0                	xor    eax,eax
  407caf:	e8 7c 95 ff ff       	call   401230 <__printf_chk@plt>
  407cb4:	83 cf ff             	or     edi,0xffffffff
  407cb7:	e8 a4 95 ff ff       	call   401260 <exit@plt>
  407cbc:	48 63 d0             	movsxd rdx,eax
  407cbf:	48 89 ee             	mov    rsi,rbp
  407cc2:	bf 01 00 00 00       	mov    edi,0x1
  407cc7:	e8 d4 94 ff ff       	call   4011a0 <write@plt>
  407ccc:	48 8d 3d 81 a4 00 00 	lea    rdi,[rip+0xa481]        # 412154 <_IO_stdin_used+0x154>
  407cd3:	e8 b8 94 ff ff       	call   401190 <puts@plt>
  407cd8:	48 8d 3d 25 a3 00 00 	lea    rdi,[rip+0xa325]        # 412004 <_IO_stdin_used+0x4>
  407cdf:	31 f6                	xor    esi,esi
  407ce1:	31 c0                	xor    eax,eax
  407ce3:	e8 68 95 ff ff       	call   401250 <open@plt>
  407ce8:	89 c7                	mov    edi,eax
  407cea:	85 c0                	test   eax,eax
  407cec:	79 34                	jns    407d22 <win+0x67ac>
  407cee:	e8 8d 94 ff ff       	call   401180 <__errno_location@plt>
  407cf3:	8b 38                	mov    edi,DWORD PTR [rax]
  407cf5:	e8 86 95 ff ff       	call   401280 <strerror@plt>
  407cfa:	48 8d 35 09 a3 00 00 	lea    rsi,[rip+0xa309]        # 41200a <_IO_stdin_used+0xa>
  407d01:	bf 01 00 00 00       	mov    edi,0x1
  407d06:	48 89 c2             	mov    rdx,rax
  407d09:	31 c0                	xor    eax,eax
  407d0b:	e8 20 95 ff ff       	call   401230 <__printf_chk@plt>
  407d10:	e8 cb 94 ff ff       	call   4011e0 <geteuid@plt>
  407d15:	85 c0                	test   eax,eax
  407d17:	0f 84 bc 98 ff ff    	je     4015d9 <win+0x63>
  407d1d:	e9 9f 98 ff ff       	jmp    4015c1 <win+0x4b>
  407d22:	ba 00 01 00 00       	mov    edx,0x100
  407d27:	48 89 ee             	mov    rsi,rbp
  407d2a:	e8 d1 94 ff ff       	call   401200 <read@plt>
  407d2f:	85 c0                	test   eax,eax
  407d31:	7f 2a                	jg     407d5d <win+0x67e7>
  407d33:	e8 48 94 ff ff       	call   401180 <__errno_location@plt>
  407d38:	8b 38                	mov    edi,DWORD PTR [rax]
  407d3a:	e8 41 95 ff ff       	call   401280 <strerror@plt>
  407d3f:	bf 01 00 00 00       	mov    edi,0x1
  407d44:	48 8d 35 5e a3 00 00 	lea    rsi,[rip+0xa35e]        # 4120a9 <_IO_stdin_used+0xa9>
  407d4b:	48 89 c2             	mov    rdx,rax
  407d4e:	31 c0                	xor    eax,eax
  407d50:	e8 db 94 ff ff       	call   401230 <__printf_chk@plt>
  407d55:	83 cf ff             	or     edi,0xffffffff
  407d58:	e8 03 95 ff ff       	call   401260 <exit@plt>
  407d5d:	48 63 d0             	movsxd rdx,eax
  407d60:	48 89 ee             	mov    rsi,rbp
  407d63:	bf 01 00 00 00       	mov    edi,0x1
  407d68:	e8 33 94 ff ff       	call   4011a0 <write@plt>
  407d6d:	48 8d 3d e0 a3 00 00 	lea    rdi,[rip+0xa3e0]        # 412154 <_IO_stdin_used+0x154>
  407d74:	e8 17 94 ff ff       	call   401190 <puts@plt>
  407d79:	48 8d 3d 84 a2 00 00 	lea    rdi,[rip+0xa284]        # 412004 <_IO_stdin_used+0x4>
  407d80:	31 f6                	xor    esi,esi
  407d82:	31 c0                	xor    eax,eax
  407d84:	e8 c7 94 ff ff       	call   401250 <open@plt>
  407d89:	89 c7                	mov    edi,eax
  407d8b:	85 c0                	test   eax,eax
  407d8d:	79 34                	jns    407dc3 <win+0x684d>
  407d8f:	e8 ec 93 ff ff       	call   401180 <__errno_location@plt>
  407d94:	8b 38                	mov    edi,DWORD PTR [rax]
  407d96:	e8 e5 94 ff ff       	call   401280 <strerror@plt>
  407d9b:	48 8d 35 68 a2 00 00 	lea    rsi,[rip+0xa268]        # 41200a <_IO_stdin_used+0xa>
  407da2:	bf 01 00 00 00       	mov    edi,0x1
  407da7:	48 89 c2             	mov    rdx,rax
  407daa:	31 c0                	xor    eax,eax
  407dac:	e8 7f 94 ff ff       	call   401230 <__printf_chk@plt>
  407db1:	e8 2a 94 ff ff       	call   4011e0 <geteuid@plt>
  407db6:	85 c0                	test   eax,eax
  407db8:	0f 84 1b 98 ff ff    	je     4015d9 <win+0x63>
  407dbe:	e9 fe 97 ff ff       	jmp    4015c1 <win+0x4b>
  407dc3:	ba 00 01 00 00       	mov    edx,0x100
  407dc8:	48 89 ee             	mov    rsi,rbp
  407dcb:	e8 30 94 ff ff       	call   401200 <read@plt>
  407dd0:	85 c0                	test   eax,eax
  407dd2:	7f 2a                	jg     407dfe <win+0x6888>
  407dd4:	e8 a7 93 ff ff       	call   401180 <__errno_location@plt>
  407dd9:	8b 38                	mov    edi,DWORD PTR [rax]
  407ddb:	e8 a0 94 ff ff       	call   401280 <strerror@plt>
  407de0:	bf 01 00 00 00       	mov    edi,0x1
  407de5:	48 8d 35 bd a2 00 00 	lea    rsi,[rip+0xa2bd]        # 4120a9 <_IO_stdin_used+0xa9>
  407dec:	48 89 c2             	mov    rdx,rax
  407def:	31 c0                	xor    eax,eax
  407df1:	e8 3a 94 ff ff       	call   401230 <__printf_chk@plt>
  407df6:	83 cf ff             	or     edi,0xffffffff
  407df9:	e8 62 94 ff ff       	call   401260 <exit@plt>
  407dfe:	48 63 d0             	movsxd rdx,eax
  407e01:	48 89 ee             	mov    rsi,rbp
  407e04:	bf 01 00 00 00       	mov    edi,0x1
  407e09:	e8 92 93 ff ff       	call   4011a0 <write@plt>
  407e0e:	48 8d 3d 3f a3 00 00 	lea    rdi,[rip+0xa33f]        # 412154 <_IO_stdin_used+0x154>
  407e15:	e8 76 93 ff ff       	call   401190 <puts@plt>
  407e1a:	48 8d 3d e3 a1 00 00 	lea    rdi,[rip+0xa1e3]        # 412004 <_IO_stdin_used+0x4>
  407e21:	31 f6                	xor    esi,esi
  407e23:	31 c0                	xor    eax,eax
  407e25:	e8 26 94 ff ff       	call   401250 <open@plt>
  407e2a:	89 c7                	mov    edi,eax
  407e2c:	85 c0                	test   eax,eax
  407e2e:	79 34                	jns    407e64 <win+0x68ee>
  407e30:	e8 4b 93 ff ff       	call   401180 <__errno_location@plt>
  407e35:	8b 38                	mov    edi,DWORD PTR [rax]
  407e37:	e8 44 94 ff ff       	call   401280 <strerror@plt>
  407e3c:	48 8d 35 c7 a1 00 00 	lea    rsi,[rip+0xa1c7]        # 41200a <_IO_stdin_used+0xa>
  407e43:	bf 01 00 00 00       	mov    edi,0x1
  407e48:	48 89 c2             	mov    rdx,rax
  407e4b:	31 c0                	xor    eax,eax
  407e4d:	e8 de 93 ff ff       	call   401230 <__printf_chk@plt>
  407e52:	e8 89 93 ff ff       	call   4011e0 <geteuid@plt>
  407e57:	85 c0                	test   eax,eax
  407e59:	0f 84 7a 97 ff ff    	je     4015d9 <win+0x63>
  407e5f:	e9 5d 97 ff ff       	jmp    4015c1 <win+0x4b>
  407e64:	ba 00 01 00 00       	mov    edx,0x100
  407e69:	48 89 ee             	mov    rsi,rbp
  407e6c:	e8 8f 93 ff ff       	call   401200 <read@plt>
  407e71:	85 c0                	test   eax,eax
  407e73:	7f 2a                	jg     407e9f <win+0x6929>
  407e75:	e8 06 93 ff ff       	call   401180 <__errno_location@plt>
  407e7a:	8b 38                	mov    edi,DWORD PTR [rax]
  407e7c:	e8 ff 93 ff ff       	call   401280 <strerror@plt>
  407e81:	bf 01 00 00 00       	mov    edi,0x1
  407e86:	48 8d 35 1c a2 00 00 	lea    rsi,[rip+0xa21c]        # 4120a9 <_IO_stdin_used+0xa9>
  407e8d:	48 89 c2             	mov    rdx,rax
  407e90:	31 c0                	xor    eax,eax
  407e92:	e8 99 93 ff ff       	call   401230 <__printf_chk@plt>
  407e97:	83 cf ff             	or     edi,0xffffffff
  407e9a:	e8 c1 93 ff ff       	call   401260 <exit@plt>
  407e9f:	48 63 d0             	movsxd rdx,eax
  407ea2:	48 89 ee             	mov    rsi,rbp
  407ea5:	bf 01 00 00 00       	mov    edi,0x1
  407eaa:	e8 f1 92 ff ff       	call   4011a0 <write@plt>
  407eaf:	48 8d 3d 9e a2 00 00 	lea    rdi,[rip+0xa29e]        # 412154 <_IO_stdin_used+0x154>
  407eb6:	e8 d5 92 ff ff       	call   401190 <puts@plt>
  407ebb:	48 8d 3d 42 a1 00 00 	lea    rdi,[rip+0xa142]        # 412004 <_IO_stdin_used+0x4>
  407ec2:	31 f6                	xor    esi,esi
  407ec4:	31 c0                	xor    eax,eax
  407ec6:	e8 85 93 ff ff       	call   401250 <open@plt>
  407ecb:	89 c7                	mov    edi,eax
  407ecd:	85 c0                	test   eax,eax
  407ecf:	79 34                	jns    407f05 <win+0x698f>
  407ed1:	e8 aa 92 ff ff       	call   401180 <__errno_location@plt>
  407ed6:	8b 38                	mov    edi,DWORD PTR [rax]
  407ed8:	e8 a3 93 ff ff       	call   401280 <strerror@plt>
  407edd:	48 8d 35 26 a1 00 00 	lea    rsi,[rip+0xa126]        # 41200a <_IO_stdin_used+0xa>
  407ee4:	bf 01 00 00 00       	mov    edi,0x1
  407ee9:	48 89 c2             	mov    rdx,rax
  407eec:	31 c0                	xor    eax,eax
  407eee:	e8 3d 93 ff ff       	call   401230 <__printf_chk@plt>
  407ef3:	e8 e8 92 ff ff       	call   4011e0 <geteuid@plt>
  407ef8:	85 c0                	test   eax,eax
  407efa:	0f 84 d9 96 ff ff    	je     4015d9 <win+0x63>
  407f00:	e9 bc 96 ff ff       	jmp    4015c1 <win+0x4b>
  407f05:	ba 00 01 00 00       	mov    edx,0x100
  407f0a:	48 89 ee             	mov    rsi,rbp
  407f0d:	e8 ee 92 ff ff       	call   401200 <read@plt>
  407f12:	85 c0                	test   eax,eax
  407f14:	7f 2a                	jg     407f40 <win+0x69ca>
  407f16:	e8 65 92 ff ff       	call   401180 <__errno_location@plt>
  407f1b:	8b 38                	mov    edi,DWORD PTR [rax]
  407f1d:	e8 5e 93 ff ff       	call   401280 <strerror@plt>
  407f22:	bf 01 00 00 00       	mov    edi,0x1
  407f27:	48 8d 35 7b a1 00 00 	lea    rsi,[rip+0xa17b]        # 4120a9 <_IO_stdin_used+0xa9>
  407f2e:	48 89 c2             	mov    rdx,rax
  407f31:	31 c0                	xor    eax,eax
  407f33:	e8 f8 92 ff ff       	call   401230 <__printf_chk@plt>
  407f38:	83 cf ff             	or     edi,0xffffffff
  407f3b:	e8 20 93 ff ff       	call   401260 <exit@plt>
  407f40:	48 63 d0             	movsxd rdx,eax
  407f43:	48 89 ee             	mov    rsi,rbp
  407f46:	bf 01 00 00 00       	mov    edi,0x1
  407f4b:	e8 50 92 ff ff       	call   4011a0 <write@plt>
  407f50:	48 8d 3d fd a1 00 00 	lea    rdi,[rip+0xa1fd]        # 412154 <_IO_stdin_used+0x154>
  407f57:	e8 34 92 ff ff       	call   401190 <puts@plt>
  407f5c:	48 8d 3d a1 a0 00 00 	lea    rdi,[rip+0xa0a1]        # 412004 <_IO_stdin_used+0x4>
  407f63:	31 f6                	xor    esi,esi
  407f65:	31 c0                	xor    eax,eax
  407f67:	e8 e4 92 ff ff       	call   401250 <open@plt>
  407f6c:	89 c7                	mov    edi,eax
  407f6e:	85 c0                	test   eax,eax
  407f70:	79 34                	jns    407fa6 <win+0x6a30>
  407f72:	e8 09 92 ff ff       	call   401180 <__errno_location@plt>
  407f77:	8b 38                	mov    edi,DWORD PTR [rax]
  407f79:	e8 02 93 ff ff       	call   401280 <strerror@plt>
  407f7e:	48 8d 35 85 a0 00 00 	lea    rsi,[rip+0xa085]        # 41200a <_IO_stdin_used+0xa>
  407f85:	bf 01 00 00 00       	mov    edi,0x1
  407f8a:	48 89 c2             	mov    rdx,rax
  407f8d:	31 c0                	xor    eax,eax
  407f8f:	e8 9c 92 ff ff       	call   401230 <__printf_chk@plt>
  407f94:	e8 47 92 ff ff       	call   4011e0 <geteuid@plt>
  407f99:	85 c0                	test   eax,eax
  407f9b:	0f 84 38 96 ff ff    	je     4015d9 <win+0x63>
  407fa1:	e9 1b 96 ff ff       	jmp    4015c1 <win+0x4b>
  407fa6:	ba 00 01 00 00       	mov    edx,0x100
  407fab:	48 89 ee             	mov    rsi,rbp
  407fae:	e8 4d 92 ff ff       	call   401200 <read@plt>
  407fb3:	85 c0                	test   eax,eax
  407fb5:	7f 2a                	jg     407fe1 <win+0x6a6b>
  407fb7:	e8 c4 91 ff ff       	call   401180 <__errno_location@plt>
  407fbc:	8b 38                	mov    edi,DWORD PTR [rax]
  407fbe:	e8 bd 92 ff ff       	call   401280 <strerror@plt>
  407fc3:	bf 01 00 00 00       	mov    edi,0x1
  407fc8:	48 8d 35 da a0 00 00 	lea    rsi,[rip+0xa0da]        # 4120a9 <_IO_stdin_used+0xa9>
  407fcf:	48 89 c2             	mov    rdx,rax
  407fd2:	31 c0                	xor    eax,eax
  407fd4:	e8 57 92 ff ff       	call   401230 <__printf_chk@plt>
  407fd9:	83 cf ff             	or     edi,0xffffffff
  407fdc:	e8 7f 92 ff ff       	call   401260 <exit@plt>
  407fe1:	48 63 d0             	movsxd rdx,eax
  407fe4:	48 89 ee             	mov    rsi,rbp
  407fe7:	bf 01 00 00 00       	mov    edi,0x1
  407fec:	e8 af 91 ff ff       	call   4011a0 <write@plt>
  407ff1:	48 8d 3d 5c a1 00 00 	lea    rdi,[rip+0xa15c]        # 412154 <_IO_stdin_used+0x154>
  407ff8:	e8 93 91 ff ff       	call   401190 <puts@plt>
  407ffd:	48 8d 3d 00 a0 00 00 	lea    rdi,[rip+0xa000]        # 412004 <_IO_stdin_used+0x4>
  408004:	31 f6                	xor    esi,esi
  408006:	31 c0                	xor    eax,eax
  408008:	e8 43 92 ff ff       	call   401250 <open@plt>
  40800d:	89 c7                	mov    edi,eax
  40800f:	85 c0                	test   eax,eax
  408011:	79 34                	jns    408047 <win+0x6ad1>
  408013:	e8 68 91 ff ff       	call   401180 <__errno_location@plt>
  408018:	8b 38                	mov    edi,DWORD PTR [rax]
  40801a:	e8 61 92 ff ff       	call   401280 <strerror@plt>
  40801f:	48 8d 35 e4 9f 00 00 	lea    rsi,[rip+0x9fe4]        # 41200a <_IO_stdin_used+0xa>
  408026:	bf 01 00 00 00       	mov    edi,0x1
  40802b:	48 89 c2             	mov    rdx,rax
  40802e:	31 c0                	xor    eax,eax
  408030:	e8 fb 91 ff ff       	call   401230 <__printf_chk@plt>
  408035:	e8 a6 91 ff ff       	call   4011e0 <geteuid@plt>
  40803a:	85 c0                	test   eax,eax
  40803c:	0f 84 97 95 ff ff    	je     4015d9 <win+0x63>
  408042:	e9 7a 95 ff ff       	jmp    4015c1 <win+0x4b>
  408047:	ba 00 01 00 00       	mov    edx,0x100
  40804c:	48 89 ee             	mov    rsi,rbp
  40804f:	e8 ac 91 ff ff       	call   401200 <read@plt>
  408054:	85 c0                	test   eax,eax
  408056:	7f 2a                	jg     408082 <win+0x6b0c>
  408058:	e8 23 91 ff ff       	call   401180 <__errno_location@plt>
  40805d:	8b 38                	mov    edi,DWORD PTR [rax]
  40805f:	e8 1c 92 ff ff       	call   401280 <strerror@plt>
  408064:	bf 01 00 00 00       	mov    edi,0x1
  408069:	48 8d 35 39 a0 00 00 	lea    rsi,[rip+0xa039]        # 4120a9 <_IO_stdin_used+0xa9>
  408070:	48 89 c2             	mov    rdx,rax
  408073:	31 c0                	xor    eax,eax
  408075:	e8 b6 91 ff ff       	call   401230 <__printf_chk@plt>
  40807a:	83 cf ff             	or     edi,0xffffffff
  40807d:	e8 de 91 ff ff       	call   401260 <exit@plt>
  408082:	48 63 d0             	movsxd rdx,eax
  408085:	48 89 ee             	mov    rsi,rbp
  408088:	bf 01 00 00 00       	mov    edi,0x1
  40808d:	e8 0e 91 ff ff       	call   4011a0 <write@plt>
  408092:	48 8d 3d bb a0 00 00 	lea    rdi,[rip+0xa0bb]        # 412154 <_IO_stdin_used+0x154>
  408099:	e8 f2 90 ff ff       	call   401190 <puts@plt>
  40809e:	48 8d 3d 5f 9f 00 00 	lea    rdi,[rip+0x9f5f]        # 412004 <_IO_stdin_used+0x4>
  4080a5:	31 f6                	xor    esi,esi
  4080a7:	31 c0                	xor    eax,eax
  4080a9:	e8 a2 91 ff ff       	call   401250 <open@plt>
  4080ae:	89 c7                	mov    edi,eax
  4080b0:	85 c0                	test   eax,eax
  4080b2:	79 34                	jns    4080e8 <win+0x6b72>
  4080b4:	e8 c7 90 ff ff       	call   401180 <__errno_location@plt>
  4080b9:	8b 38                	mov    edi,DWORD PTR [rax]
  4080bb:	e8 c0 91 ff ff       	call   401280 <strerror@plt>
  4080c0:	48 8d 35 43 9f 00 00 	lea    rsi,[rip+0x9f43]        # 41200a <_IO_stdin_used+0xa>
  4080c7:	bf 01 00 00 00       	mov    edi,0x1
  4080cc:	48 89 c2             	mov    rdx,rax
  4080cf:	31 c0                	xor    eax,eax
  4080d1:	e8 5a 91 ff ff       	call   401230 <__printf_chk@plt>
  4080d6:	e8 05 91 ff ff       	call   4011e0 <geteuid@plt>
  4080db:	85 c0                	test   eax,eax
  4080dd:	0f 84 f6 94 ff ff    	je     4015d9 <win+0x63>
  4080e3:	e9 d9 94 ff ff       	jmp    4015c1 <win+0x4b>
  4080e8:	ba 00 01 00 00       	mov    edx,0x100
  4080ed:	48 89 ee             	mov    rsi,rbp
  4080f0:	e8 0b 91 ff ff       	call   401200 <read@plt>
  4080f5:	85 c0                	test   eax,eax
  4080f7:	7f 2a                	jg     408123 <win+0x6bad>
  4080f9:	e8 82 90 ff ff       	call   401180 <__errno_location@plt>
  4080fe:	8b 38                	mov    edi,DWORD PTR [rax]
  408100:	e8 7b 91 ff ff       	call   401280 <strerror@plt>
  408105:	bf 01 00 00 00       	mov    edi,0x1
  40810a:	48 8d 35 98 9f 00 00 	lea    rsi,[rip+0x9f98]        # 4120a9 <_IO_stdin_used+0xa9>
  408111:	48 89 c2             	mov    rdx,rax
  408114:	31 c0                	xor    eax,eax
  408116:	e8 15 91 ff ff       	call   401230 <__printf_chk@plt>
  40811b:	83 cf ff             	or     edi,0xffffffff
  40811e:	e8 3d 91 ff ff       	call   401260 <exit@plt>
  408123:	48 63 d0             	movsxd rdx,eax
  408126:	48 89 ee             	mov    rsi,rbp
  408129:	bf 01 00 00 00       	mov    edi,0x1
  40812e:	e8 6d 90 ff ff       	call   4011a0 <write@plt>
  408133:	48 8d 3d 1a a0 00 00 	lea    rdi,[rip+0xa01a]        # 412154 <_IO_stdin_used+0x154>
  40813a:	e8 51 90 ff ff       	call   401190 <puts@plt>
  40813f:	48 8d 3d be 9e 00 00 	lea    rdi,[rip+0x9ebe]        # 412004 <_IO_stdin_used+0x4>
  408146:	31 f6                	xor    esi,esi
  408148:	31 c0                	xor    eax,eax
  40814a:	e8 01 91 ff ff       	call   401250 <open@plt>
  40814f:	89 c7                	mov    edi,eax
  408151:	85 c0                	test   eax,eax
  408153:	79 34                	jns    408189 <win+0x6c13>
  408155:	e8 26 90 ff ff       	call   401180 <__errno_location@plt>
  40815a:	8b 38                	mov    edi,DWORD PTR [rax]
  40815c:	e8 1f 91 ff ff       	call   401280 <strerror@plt>
  408161:	48 8d 35 a2 9e 00 00 	lea    rsi,[rip+0x9ea2]        # 41200a <_IO_stdin_used+0xa>
  408168:	bf 01 00 00 00       	mov    edi,0x1
  40816d:	48 89 c2             	mov    rdx,rax
  408170:	31 c0                	xor    eax,eax
  408172:	e8 b9 90 ff ff       	call   401230 <__printf_chk@plt>
  408177:	e8 64 90 ff ff       	call   4011e0 <geteuid@plt>
  40817c:	85 c0                	test   eax,eax
  40817e:	0f 84 55 94 ff ff    	je     4015d9 <win+0x63>
  408184:	e9 38 94 ff ff       	jmp    4015c1 <win+0x4b>
  408189:	ba 00 01 00 00       	mov    edx,0x100
  40818e:	48 89 ee             	mov    rsi,rbp
  408191:	e8 6a 90 ff ff       	call   401200 <read@plt>
  408196:	85 c0                	test   eax,eax
  408198:	7f 2a                	jg     4081c4 <win+0x6c4e>
  40819a:	e8 e1 8f ff ff       	call   401180 <__errno_location@plt>
  40819f:	8b 38                	mov    edi,DWORD PTR [rax]
  4081a1:	e8 da 90 ff ff       	call   401280 <strerror@plt>
  4081a6:	bf 01 00 00 00       	mov    edi,0x1
  4081ab:	48 8d 35 f7 9e 00 00 	lea    rsi,[rip+0x9ef7]        # 4120a9 <_IO_stdin_used+0xa9>
  4081b2:	48 89 c2             	mov    rdx,rax
  4081b5:	31 c0                	xor    eax,eax
  4081b7:	e8 74 90 ff ff       	call   401230 <__printf_chk@plt>
  4081bc:	83 cf ff             	or     edi,0xffffffff
  4081bf:	e8 9c 90 ff ff       	call   401260 <exit@plt>
  4081c4:	48 63 d0             	movsxd rdx,eax
  4081c7:	48 89 ee             	mov    rsi,rbp
  4081ca:	bf 01 00 00 00       	mov    edi,0x1
  4081cf:	e8 cc 8f ff ff       	call   4011a0 <write@plt>
  4081d4:	48 8d 3d 79 9f 00 00 	lea    rdi,[rip+0x9f79]        # 412154 <_IO_stdin_used+0x154>
  4081db:	e8 b0 8f ff ff       	call   401190 <puts@plt>
  4081e0:	48 8d 3d 1d 9e 00 00 	lea    rdi,[rip+0x9e1d]        # 412004 <_IO_stdin_used+0x4>
  4081e7:	31 f6                	xor    esi,esi
  4081e9:	31 c0                	xor    eax,eax
  4081eb:	e8 60 90 ff ff       	call   401250 <open@plt>
  4081f0:	89 c7                	mov    edi,eax
  4081f2:	85 c0                	test   eax,eax
  4081f4:	79 34                	jns    40822a <win+0x6cb4>
  4081f6:	e8 85 8f ff ff       	call   401180 <__errno_location@plt>
  4081fb:	8b 38                	mov    edi,DWORD PTR [rax]
  4081fd:	e8 7e 90 ff ff       	call   401280 <strerror@plt>
  408202:	48 8d 35 01 9e 00 00 	lea    rsi,[rip+0x9e01]        # 41200a <_IO_stdin_used+0xa>
  408209:	bf 01 00 00 00       	mov    edi,0x1
  40820e:	48 89 c2             	mov    rdx,rax
  408211:	31 c0                	xor    eax,eax
  408213:	e8 18 90 ff ff       	call   401230 <__printf_chk@plt>
  408218:	e8 c3 8f ff ff       	call   4011e0 <geteuid@plt>
  40821d:	85 c0                	test   eax,eax
  40821f:	0f 84 b4 93 ff ff    	je     4015d9 <win+0x63>
  408225:	e9 97 93 ff ff       	jmp    4015c1 <win+0x4b>
  40822a:	ba 00 01 00 00       	mov    edx,0x100
  40822f:	48 89 ee             	mov    rsi,rbp
  408232:	e8 c9 8f ff ff       	call   401200 <read@plt>
  408237:	85 c0                	test   eax,eax
  408239:	7f 2a                	jg     408265 <win+0x6cef>
  40823b:	e8 40 8f ff ff       	call   401180 <__errno_location@plt>
  408240:	8b 38                	mov    edi,DWORD PTR [rax]
  408242:	e8 39 90 ff ff       	call   401280 <strerror@plt>
  408247:	bf 01 00 00 00       	mov    edi,0x1
  40824c:	48 8d 35 56 9e 00 00 	lea    rsi,[rip+0x9e56]        # 4120a9 <_IO_stdin_used+0xa9>
  408253:	48 89 c2             	mov    rdx,rax
  408256:	31 c0                	xor    eax,eax
  408258:	e8 d3 8f ff ff       	call   401230 <__printf_chk@plt>
  40825d:	83 cf ff             	or     edi,0xffffffff
  408260:	e8 fb 8f ff ff       	call   401260 <exit@plt>
  408265:	48 63 d0             	movsxd rdx,eax
  408268:	48 89 ee             	mov    rsi,rbp
  40826b:	bf 01 00 00 00       	mov    edi,0x1
  408270:	e8 2b 8f ff ff       	call   4011a0 <write@plt>
  408275:	48 8d 3d d8 9e 00 00 	lea    rdi,[rip+0x9ed8]        # 412154 <_IO_stdin_used+0x154>
  40827c:	e8 0f 8f ff ff       	call   401190 <puts@plt>
  408281:	48 8d 3d 7c 9d 00 00 	lea    rdi,[rip+0x9d7c]        # 412004 <_IO_stdin_used+0x4>
  408288:	31 f6                	xor    esi,esi
  40828a:	31 c0                	xor    eax,eax
  40828c:	e8 bf 8f ff ff       	call   401250 <open@plt>
  408291:	89 c7                	mov    edi,eax
  408293:	85 c0                	test   eax,eax
  408295:	79 34                	jns    4082cb <win+0x6d55>
  408297:	e8 e4 8e ff ff       	call   401180 <__errno_location@plt>
  40829c:	8b 38                	mov    edi,DWORD PTR [rax]
  40829e:	e8 dd 8f ff ff       	call   401280 <strerror@plt>
  4082a3:	48 8d 35 60 9d 00 00 	lea    rsi,[rip+0x9d60]        # 41200a <_IO_stdin_used+0xa>
  4082aa:	bf 01 00 00 00       	mov    edi,0x1
  4082af:	48 89 c2             	mov    rdx,rax
  4082b2:	31 c0                	xor    eax,eax
  4082b4:	e8 77 8f ff ff       	call   401230 <__printf_chk@plt>
  4082b9:	e8 22 8f ff ff       	call   4011e0 <geteuid@plt>
  4082be:	85 c0                	test   eax,eax
  4082c0:	0f 84 13 93 ff ff    	je     4015d9 <win+0x63>
  4082c6:	e9 f6 92 ff ff       	jmp    4015c1 <win+0x4b>
  4082cb:	ba 00 01 00 00       	mov    edx,0x100
  4082d0:	48 89 ee             	mov    rsi,rbp
  4082d3:	e8 28 8f ff ff       	call   401200 <read@plt>
  4082d8:	85 c0                	test   eax,eax
  4082da:	7f 2a                	jg     408306 <win+0x6d90>
  4082dc:	e8 9f 8e ff ff       	call   401180 <__errno_location@plt>
  4082e1:	8b 38                	mov    edi,DWORD PTR [rax]
  4082e3:	e8 98 8f ff ff       	call   401280 <strerror@plt>
  4082e8:	bf 01 00 00 00       	mov    edi,0x1
  4082ed:	48 8d 35 b5 9d 00 00 	lea    rsi,[rip+0x9db5]        # 4120a9 <_IO_stdin_used+0xa9>
  4082f4:	48 89 c2             	mov    rdx,rax
  4082f7:	31 c0                	xor    eax,eax
  4082f9:	e8 32 8f ff ff       	call   401230 <__printf_chk@plt>
  4082fe:	83 cf ff             	or     edi,0xffffffff
  408301:	e8 5a 8f ff ff       	call   401260 <exit@plt>
  408306:	48 63 d0             	movsxd rdx,eax
  408309:	48 89 ee             	mov    rsi,rbp
  40830c:	bf 01 00 00 00       	mov    edi,0x1
  408311:	e8 8a 8e ff ff       	call   4011a0 <write@plt>
  408316:	48 8d 3d 37 9e 00 00 	lea    rdi,[rip+0x9e37]        # 412154 <_IO_stdin_used+0x154>
  40831d:	e8 6e 8e ff ff       	call   401190 <puts@plt>
  408322:	48 8d 3d db 9c 00 00 	lea    rdi,[rip+0x9cdb]        # 412004 <_IO_stdin_used+0x4>
  408329:	31 f6                	xor    esi,esi
  40832b:	31 c0                	xor    eax,eax
  40832d:	e8 1e 8f ff ff       	call   401250 <open@plt>
  408332:	89 c7                	mov    edi,eax
  408334:	85 c0                	test   eax,eax
  408336:	79 34                	jns    40836c <win+0x6df6>
  408338:	e8 43 8e ff ff       	call   401180 <__errno_location@plt>
  40833d:	8b 38                	mov    edi,DWORD PTR [rax]
  40833f:	e8 3c 8f ff ff       	call   401280 <strerror@plt>
  408344:	48 8d 35 bf 9c 00 00 	lea    rsi,[rip+0x9cbf]        # 41200a <_IO_stdin_used+0xa>
  40834b:	bf 01 00 00 00       	mov    edi,0x1
  408350:	48 89 c2             	mov    rdx,rax
  408353:	31 c0                	xor    eax,eax
  408355:	e8 d6 8e ff ff       	call   401230 <__printf_chk@plt>
  40835a:	e8 81 8e ff ff       	call   4011e0 <geteuid@plt>
  40835f:	85 c0                	test   eax,eax
  408361:	0f 84 72 92 ff ff    	je     4015d9 <win+0x63>
  408367:	e9 55 92 ff ff       	jmp    4015c1 <win+0x4b>
  40836c:	ba 00 01 00 00       	mov    edx,0x100
  408371:	48 89 ee             	mov    rsi,rbp
  408374:	e8 87 8e ff ff       	call   401200 <read@plt>
  408379:	85 c0                	test   eax,eax
  40837b:	7f 2a                	jg     4083a7 <win+0x6e31>
  40837d:	e8 fe 8d ff ff       	call   401180 <__errno_location@plt>
  408382:	8b 38                	mov    edi,DWORD PTR [rax]
  408384:	e8 f7 8e ff ff       	call   401280 <strerror@plt>
  408389:	bf 01 00 00 00       	mov    edi,0x1
  40838e:	48 8d 35 14 9d 00 00 	lea    rsi,[rip+0x9d14]        # 4120a9 <_IO_stdin_used+0xa9>
  408395:	48 89 c2             	mov    rdx,rax
  408398:	31 c0                	xor    eax,eax
  40839a:	e8 91 8e ff ff       	call   401230 <__printf_chk@plt>
  40839f:	83 cf ff             	or     edi,0xffffffff
  4083a2:	e8 b9 8e ff ff       	call   401260 <exit@plt>
  4083a7:	48 63 d0             	movsxd rdx,eax
  4083aa:	48 89 ee             	mov    rsi,rbp
  4083ad:	bf 01 00 00 00       	mov    edi,0x1
  4083b2:	e8 e9 8d ff ff       	call   4011a0 <write@plt>
  4083b7:	48 8d 3d 96 9d 00 00 	lea    rdi,[rip+0x9d96]        # 412154 <_IO_stdin_used+0x154>
  4083be:	e8 cd 8d ff ff       	call   401190 <puts@plt>
  4083c3:	48 8d 3d 3a 9c 00 00 	lea    rdi,[rip+0x9c3a]        # 412004 <_IO_stdin_used+0x4>
  4083ca:	31 f6                	xor    esi,esi
  4083cc:	31 c0                	xor    eax,eax
  4083ce:	e8 7d 8e ff ff       	call   401250 <open@plt>
  4083d3:	89 c7                	mov    edi,eax
  4083d5:	85 c0                	test   eax,eax
  4083d7:	79 34                	jns    40840d <win+0x6e97>
  4083d9:	e8 a2 8d ff ff       	call   401180 <__errno_location@plt>
  4083de:	8b 38                	mov    edi,DWORD PTR [rax]
  4083e0:	e8 9b 8e ff ff       	call   401280 <strerror@plt>
  4083e5:	48 8d 35 1e 9c 00 00 	lea    rsi,[rip+0x9c1e]        # 41200a <_IO_stdin_used+0xa>
  4083ec:	bf 01 00 00 00       	mov    edi,0x1
  4083f1:	48 89 c2             	mov    rdx,rax
  4083f4:	31 c0                	xor    eax,eax
  4083f6:	e8 35 8e ff ff       	call   401230 <__printf_chk@plt>
  4083fb:	e8 e0 8d ff ff       	call   4011e0 <geteuid@plt>
  408400:	85 c0                	test   eax,eax
  408402:	0f 84 d1 91 ff ff    	je     4015d9 <win+0x63>
  408408:	e9 b4 91 ff ff       	jmp    4015c1 <win+0x4b>
  40840d:	ba 00 01 00 00       	mov    edx,0x100
  408412:	48 89 ee             	mov    rsi,rbp
  408415:	e8 e6 8d ff ff       	call   401200 <read@plt>
  40841a:	85 c0                	test   eax,eax
  40841c:	7f 2a                	jg     408448 <win+0x6ed2>
  40841e:	e8 5d 8d ff ff       	call   401180 <__errno_location@plt>
  408423:	8b 38                	mov    edi,DWORD PTR [rax]
  408425:	e8 56 8e ff ff       	call   401280 <strerror@plt>
  40842a:	bf 01 00 00 00       	mov    edi,0x1
  40842f:	48 8d 35 73 9c 00 00 	lea    rsi,[rip+0x9c73]        # 4120a9 <_IO_stdin_used+0xa9>
  408436:	48 89 c2             	mov    rdx,rax
  408439:	31 c0                	xor    eax,eax
  40843b:	e8 f0 8d ff ff       	call   401230 <__printf_chk@plt>
  408440:	83 cf ff             	or     edi,0xffffffff
  408443:	e8 18 8e ff ff       	call   401260 <exit@plt>
  408448:	48 63 d0             	movsxd rdx,eax
  40844b:	48 89 ee             	mov    rsi,rbp
  40844e:	bf 01 00 00 00       	mov    edi,0x1
  408453:	e8 48 8d ff ff       	call   4011a0 <write@plt>
  408458:	48 8d 3d f5 9c 00 00 	lea    rdi,[rip+0x9cf5]        # 412154 <_IO_stdin_used+0x154>
  40845f:	e8 2c 8d ff ff       	call   401190 <puts@plt>
  408464:	48 8d 3d 99 9b 00 00 	lea    rdi,[rip+0x9b99]        # 412004 <_IO_stdin_used+0x4>
  40846b:	31 f6                	xor    esi,esi
  40846d:	31 c0                	xor    eax,eax
  40846f:	e8 dc 8d ff ff       	call   401250 <open@plt>
  408474:	89 c7                	mov    edi,eax
  408476:	85 c0                	test   eax,eax
  408478:	79 34                	jns    4084ae <win+0x6f38>
  40847a:	e8 01 8d ff ff       	call   401180 <__errno_location@plt>
  40847f:	8b 38                	mov    edi,DWORD PTR [rax]
  408481:	e8 fa 8d ff ff       	call   401280 <strerror@plt>
  408486:	48 8d 35 7d 9b 00 00 	lea    rsi,[rip+0x9b7d]        # 41200a <_IO_stdin_used+0xa>
  40848d:	bf 01 00 00 00       	mov    edi,0x1
  408492:	48 89 c2             	mov    rdx,rax
  408495:	31 c0                	xor    eax,eax
  408497:	e8 94 8d ff ff       	call   401230 <__printf_chk@plt>
  40849c:	e8 3f 8d ff ff       	call   4011e0 <geteuid@plt>
  4084a1:	85 c0                	test   eax,eax
  4084a3:	0f 84 30 91 ff ff    	je     4015d9 <win+0x63>
  4084a9:	e9 13 91 ff ff       	jmp    4015c1 <win+0x4b>
  4084ae:	ba 00 01 00 00       	mov    edx,0x100
  4084b3:	48 89 ee             	mov    rsi,rbp
  4084b6:	e8 45 8d ff ff       	call   401200 <read@plt>
  4084bb:	85 c0                	test   eax,eax
  4084bd:	7f 2a                	jg     4084e9 <win+0x6f73>
  4084bf:	e8 bc 8c ff ff       	call   401180 <__errno_location@plt>
  4084c4:	8b 38                	mov    edi,DWORD PTR [rax]
  4084c6:	e8 b5 8d ff ff       	call   401280 <strerror@plt>
  4084cb:	bf 01 00 00 00       	mov    edi,0x1
  4084d0:	48 8d 35 d2 9b 00 00 	lea    rsi,[rip+0x9bd2]        # 4120a9 <_IO_stdin_used+0xa9>
  4084d7:	48 89 c2             	mov    rdx,rax
  4084da:	31 c0                	xor    eax,eax
  4084dc:	e8 4f 8d ff ff       	call   401230 <__printf_chk@plt>
  4084e1:	83 cf ff             	or     edi,0xffffffff
  4084e4:	e8 77 8d ff ff       	call   401260 <exit@plt>
  4084e9:	48 63 d0             	movsxd rdx,eax
  4084ec:	48 89 ee             	mov    rsi,rbp
  4084ef:	bf 01 00 00 00       	mov    edi,0x1
  4084f4:	e8 a7 8c ff ff       	call   4011a0 <write@plt>
  4084f9:	48 8d 3d 54 9c 00 00 	lea    rdi,[rip+0x9c54]        # 412154 <_IO_stdin_used+0x154>
  408500:	e8 8b 8c ff ff       	call   401190 <puts@plt>
  408505:	48 8d 3d f8 9a 00 00 	lea    rdi,[rip+0x9af8]        # 412004 <_IO_stdin_used+0x4>
  40850c:	31 f6                	xor    esi,esi
  40850e:	31 c0                	xor    eax,eax
  408510:	e8 3b 8d ff ff       	call   401250 <open@plt>
  408515:	89 c7                	mov    edi,eax
  408517:	85 c0                	test   eax,eax
  408519:	79 34                	jns    40854f <win+0x6fd9>
  40851b:	e8 60 8c ff ff       	call   401180 <__errno_location@plt>
  408520:	8b 38                	mov    edi,DWORD PTR [rax]
  408522:	e8 59 8d ff ff       	call   401280 <strerror@plt>
  408527:	48 8d 35 dc 9a 00 00 	lea    rsi,[rip+0x9adc]        # 41200a <_IO_stdin_used+0xa>
  40852e:	bf 01 00 00 00       	mov    edi,0x1
  408533:	48 89 c2             	mov    rdx,rax
  408536:	31 c0                	xor    eax,eax
  408538:	e8 f3 8c ff ff       	call   401230 <__printf_chk@plt>
  40853d:	e8 9e 8c ff ff       	call   4011e0 <geteuid@plt>
  408542:	85 c0                	test   eax,eax
  408544:	0f 84 8f 90 ff ff    	je     4015d9 <win+0x63>
  40854a:	e9 72 90 ff ff       	jmp    4015c1 <win+0x4b>
  40854f:	ba 00 01 00 00       	mov    edx,0x100
  408554:	48 89 ee             	mov    rsi,rbp
  408557:	e8 a4 8c ff ff       	call   401200 <read@plt>
  40855c:	85 c0                	test   eax,eax
  40855e:	7f 2a                	jg     40858a <win+0x7014>
  408560:	e8 1b 8c ff ff       	call   401180 <__errno_location@plt>
  408565:	8b 38                	mov    edi,DWORD PTR [rax]
  408567:	e8 14 8d ff ff       	call   401280 <strerror@plt>
  40856c:	bf 01 00 00 00       	mov    edi,0x1
  408571:	48 8d 35 31 9b 00 00 	lea    rsi,[rip+0x9b31]        # 4120a9 <_IO_stdin_used+0xa9>
  408578:	48 89 c2             	mov    rdx,rax
  40857b:	31 c0                	xor    eax,eax
  40857d:	e8 ae 8c ff ff       	call   401230 <__printf_chk@plt>
  408582:	83 cf ff             	or     edi,0xffffffff
  408585:	e8 d6 8c ff ff       	call   401260 <exit@plt>
  40858a:	48 63 d0             	movsxd rdx,eax
  40858d:	48 89 ee             	mov    rsi,rbp
  408590:	bf 01 00 00 00       	mov    edi,0x1
  408595:	e8 06 8c ff ff       	call   4011a0 <write@plt>
  40859a:	48 8d 3d b3 9b 00 00 	lea    rdi,[rip+0x9bb3]        # 412154 <_IO_stdin_used+0x154>
  4085a1:	e8 ea 8b ff ff       	call   401190 <puts@plt>
  4085a6:	48 8d 3d 57 9a 00 00 	lea    rdi,[rip+0x9a57]        # 412004 <_IO_stdin_used+0x4>
  4085ad:	31 f6                	xor    esi,esi
  4085af:	31 c0                	xor    eax,eax
  4085b1:	e8 9a 8c ff ff       	call   401250 <open@plt>
  4085b6:	89 c7                	mov    edi,eax
  4085b8:	85 c0                	test   eax,eax
  4085ba:	79 34                	jns    4085f0 <win+0x707a>
  4085bc:	e8 bf 8b ff ff       	call   401180 <__errno_location@plt>
  4085c1:	8b 38                	mov    edi,DWORD PTR [rax]
  4085c3:	e8 b8 8c ff ff       	call   401280 <strerror@plt>
  4085c8:	48 8d 35 3b 9a 00 00 	lea    rsi,[rip+0x9a3b]        # 41200a <_IO_stdin_used+0xa>
  4085cf:	bf 01 00 00 00       	mov    edi,0x1
  4085d4:	48 89 c2             	mov    rdx,rax
  4085d7:	31 c0                	xor    eax,eax
  4085d9:	e8 52 8c ff ff       	call   401230 <__printf_chk@plt>
  4085de:	e8 fd 8b ff ff       	call   4011e0 <geteuid@plt>
  4085e3:	85 c0                	test   eax,eax
  4085e5:	0f 84 ee 8f ff ff    	je     4015d9 <win+0x63>
  4085eb:	e9 d1 8f ff ff       	jmp    4015c1 <win+0x4b>
  4085f0:	ba 00 01 00 00       	mov    edx,0x100
  4085f5:	48 89 ee             	mov    rsi,rbp
  4085f8:	e8 03 8c ff ff       	call   401200 <read@plt>
  4085fd:	85 c0                	test   eax,eax
  4085ff:	7f 2a                	jg     40862b <win+0x70b5>
  408601:	e8 7a 8b ff ff       	call   401180 <__errno_location@plt>
  408606:	8b 38                	mov    edi,DWORD PTR [rax]
  408608:	e8 73 8c ff ff       	call   401280 <strerror@plt>
  40860d:	bf 01 00 00 00       	mov    edi,0x1
  408612:	48 8d 35 90 9a 00 00 	lea    rsi,[rip+0x9a90]        # 4120a9 <_IO_stdin_used+0xa9>
  408619:	48 89 c2             	mov    rdx,rax
  40861c:	31 c0                	xor    eax,eax
  40861e:	e8 0d 8c ff ff       	call   401230 <__printf_chk@plt>
  408623:	83 cf ff             	or     edi,0xffffffff
  408626:	e8 35 8c ff ff       	call   401260 <exit@plt>
  40862b:	48 63 d0             	movsxd rdx,eax
  40862e:	48 89 ee             	mov    rsi,rbp
  408631:	bf 01 00 00 00       	mov    edi,0x1
  408636:	e8 65 8b ff ff       	call   4011a0 <write@plt>
  40863b:	48 8d 3d 12 9b 00 00 	lea    rdi,[rip+0x9b12]        # 412154 <_IO_stdin_used+0x154>
  408642:	e8 49 8b ff ff       	call   401190 <puts@plt>
  408647:	48 8d 3d b6 99 00 00 	lea    rdi,[rip+0x99b6]        # 412004 <_IO_stdin_used+0x4>
  40864e:	31 f6                	xor    esi,esi
  408650:	31 c0                	xor    eax,eax
  408652:	e8 f9 8b ff ff       	call   401250 <open@plt>
  408657:	89 c7                	mov    edi,eax
  408659:	85 c0                	test   eax,eax
  40865b:	79 34                	jns    408691 <win+0x711b>
  40865d:	e8 1e 8b ff ff       	call   401180 <__errno_location@plt>
  408662:	8b 38                	mov    edi,DWORD PTR [rax]
  408664:	e8 17 8c ff ff       	call   401280 <strerror@plt>
  408669:	48 8d 35 9a 99 00 00 	lea    rsi,[rip+0x999a]        # 41200a <_IO_stdin_used+0xa>
  408670:	bf 01 00 00 00       	mov    edi,0x1
  408675:	48 89 c2             	mov    rdx,rax
  408678:	31 c0                	xor    eax,eax
  40867a:	e8 b1 8b ff ff       	call   401230 <__printf_chk@plt>
  40867f:	e8 5c 8b ff ff       	call   4011e0 <geteuid@plt>
  408684:	85 c0                	test   eax,eax
  408686:	0f 84 4d 8f ff ff    	je     4015d9 <win+0x63>
  40868c:	e9 30 8f ff ff       	jmp    4015c1 <win+0x4b>
  408691:	ba 00 01 00 00       	mov    edx,0x100
  408696:	48 89 ee             	mov    rsi,rbp
  408699:	e8 62 8b ff ff       	call   401200 <read@plt>
  40869e:	85 c0                	test   eax,eax
  4086a0:	7f 2a                	jg     4086cc <win+0x7156>
  4086a2:	e8 d9 8a ff ff       	call   401180 <__errno_location@plt>
  4086a7:	8b 38                	mov    edi,DWORD PTR [rax]
  4086a9:	e8 d2 8b ff ff       	call   401280 <strerror@plt>
  4086ae:	bf 01 00 00 00       	mov    edi,0x1
  4086b3:	48 8d 35 ef 99 00 00 	lea    rsi,[rip+0x99ef]        # 4120a9 <_IO_stdin_used+0xa9>
  4086ba:	48 89 c2             	mov    rdx,rax
  4086bd:	31 c0                	xor    eax,eax
  4086bf:	e8 6c 8b ff ff       	call   401230 <__printf_chk@plt>
  4086c4:	83 cf ff             	or     edi,0xffffffff
  4086c7:	e8 94 8b ff ff       	call   401260 <exit@plt>
  4086cc:	48 89 e5             	mov    rbp,rsp
  4086cf:	48 63 d0             	movsxd rdx,eax
  4086d2:	bf 01 00 00 00       	mov    edi,0x1
  4086d7:	48 89 ee             	mov    rsi,rbp
  4086da:	e8 c1 8a ff ff       	call   4011a0 <write@plt>
  4086df:	48 8d 3d 6e 9a 00 00 	lea    rdi,[rip+0x9a6e]        # 412154 <_IO_stdin_used+0x154>
  4086e6:	e8 a5 8a ff ff       	call   401190 <puts@plt>
  4086eb:	48 8d 3d 12 99 00 00 	lea    rdi,[rip+0x9912]        # 412004 <_IO_stdin_used+0x4>
  4086f2:	31 f6                	xor    esi,esi
  4086f4:	31 c0                	xor    eax,eax
  4086f6:	e8 55 8b ff ff       	call   401250 <open@plt>
  4086fb:	89 c7                	mov    edi,eax
  4086fd:	85 c0                	test   eax,eax
  4086ff:	79 34                	jns    408735 <win+0x71bf>
  408701:	e8 7a 8a ff ff       	call   401180 <__errno_location@plt>
  408706:	8b 38                	mov    edi,DWORD PTR [rax]
  408708:	e8 73 8b ff ff       	call   401280 <strerror@plt>
  40870d:	48 8d 35 f6 98 00 00 	lea    rsi,[rip+0x98f6]        # 41200a <_IO_stdin_used+0xa>
  408714:	bf 01 00 00 00       	mov    edi,0x1
  408719:	48 89 c2             	mov    rdx,rax
  40871c:	31 c0                	xor    eax,eax
  40871e:	e8 0d 8b ff ff       	call   401230 <__printf_chk@plt>
  408723:	e8 b8 8a ff ff       	call   4011e0 <geteuid@plt>
  408728:	85 c0                	test   eax,eax
  40872a:	0f 84 a9 8e ff ff    	je     4015d9 <win+0x63>
  408730:	e9 8c 8e ff ff       	jmp    4015c1 <win+0x4b>
  408735:	ba 00 01 00 00       	mov    edx,0x100
  40873a:	48 89 ee             	mov    rsi,rbp
  40873d:	e8 be 8a ff ff       	call   401200 <read@plt>
  408742:	85 c0                	test   eax,eax
  408744:	7f 2a                	jg     408770 <win+0x71fa>
  408746:	e8 35 8a ff ff       	call   401180 <__errno_location@plt>
  40874b:	8b 38                	mov    edi,DWORD PTR [rax]
  40874d:	e8 2e 8b ff ff       	call   401280 <strerror@plt>
  408752:	bf 01 00 00 00       	mov    edi,0x1
  408757:	48 8d 35 4b 99 00 00 	lea    rsi,[rip+0x994b]        # 4120a9 <_IO_stdin_used+0xa9>
  40875e:	48 89 c2             	mov    rdx,rax
  408761:	31 c0                	xor    eax,eax
  408763:	e8 c8 8a ff ff       	call   401230 <__printf_chk@plt>
  408768:	83 cf ff             	or     edi,0xffffffff
  40876b:	e8 f0 8a ff ff       	call   401260 <exit@plt>
  408770:	48 63 d0             	movsxd rdx,eax
  408773:	48 89 ee             	mov    rsi,rbp
  408776:	bf 01 00 00 00       	mov    edi,0x1
  40877b:	e8 20 8a ff ff       	call   4011a0 <write@plt>
  408780:	48 8d 3d cd 99 00 00 	lea    rdi,[rip+0x99cd]        # 412154 <_IO_stdin_used+0x154>
  408787:	e8 04 8a ff ff       	call   401190 <puts@plt>
  40878c:	48 8d 3d 71 98 00 00 	lea    rdi,[rip+0x9871]        # 412004 <_IO_stdin_used+0x4>
  408793:	31 f6                	xor    esi,esi
  408795:	31 c0                	xor    eax,eax
  408797:	e8 b4 8a ff ff       	call   401250 <open@plt>
  40879c:	89 c7                	mov    edi,eax
  40879e:	85 c0                	test   eax,eax
  4087a0:	79 34                	jns    4087d6 <win+0x7260>
  4087a2:	e8 d9 89 ff ff       	call   401180 <__errno_location@plt>
  4087a7:	8b 38                	mov    edi,DWORD PTR [rax]
  4087a9:	e8 d2 8a ff ff       	call   401280 <strerror@plt>
  4087ae:	48 8d 35 55 98 00 00 	lea    rsi,[rip+0x9855]        # 41200a <_IO_stdin_used+0xa>
  4087b5:	bf 01 00 00 00       	mov    edi,0x1
  4087ba:	48 89 c2             	mov    rdx,rax
  4087bd:	31 c0                	xor    eax,eax
  4087bf:	e8 6c 8a ff ff       	call   401230 <__printf_chk@plt>
  4087c4:	e8 17 8a ff ff       	call   4011e0 <geteuid@plt>
  4087c9:	85 c0                	test   eax,eax
  4087cb:	0f 84 08 8e ff ff    	je     4015d9 <win+0x63>
  4087d1:	e9 eb 8d ff ff       	jmp    4015c1 <win+0x4b>
  4087d6:	ba 00 01 00 00       	mov    edx,0x100
  4087db:	48 89 ee             	mov    rsi,rbp
  4087de:	e8 1d 8a ff ff       	call   401200 <read@plt>
  4087e3:	85 c0                	test   eax,eax
  4087e5:	7f 2a                	jg     408811 <win+0x729b>
  4087e7:	e8 94 89 ff ff       	call   401180 <__errno_location@plt>
  4087ec:	8b 38                	mov    edi,DWORD PTR [rax]
  4087ee:	e8 8d 8a ff ff       	call   401280 <strerror@plt>
  4087f3:	bf 01 00 00 00       	mov    edi,0x1
  4087f8:	48 8d 35 aa 98 00 00 	lea    rsi,[rip+0x98aa]        # 4120a9 <_IO_stdin_used+0xa9>
  4087ff:	48 89 c2             	mov    rdx,rax
  408802:	31 c0                	xor    eax,eax
  408804:	e8 27 8a ff ff       	call   401230 <__printf_chk@plt>
  408809:	83 cf ff             	or     edi,0xffffffff
  40880c:	e8 4f 8a ff ff       	call   401260 <exit@plt>
  408811:	48 63 d0             	movsxd rdx,eax
  408814:	48 89 ee             	mov    rsi,rbp
  408817:	bf 01 00 00 00       	mov    edi,0x1
  40881c:	e8 7f 89 ff ff       	call   4011a0 <write@plt>
  408821:	48 8d 3d 2c 99 00 00 	lea    rdi,[rip+0x992c]        # 412154 <_IO_stdin_used+0x154>
  408828:	e8 63 89 ff ff       	call   401190 <puts@plt>
  40882d:	48 8d 3d d0 97 00 00 	lea    rdi,[rip+0x97d0]        # 412004 <_IO_stdin_used+0x4>
  408834:	31 f6                	xor    esi,esi
  408836:	31 c0                	xor    eax,eax
  408838:	e8 13 8a ff ff       	call   401250 <open@plt>
  40883d:	89 c7                	mov    edi,eax
  40883f:	85 c0                	test   eax,eax
  408841:	79 34                	jns    408877 <win+0x7301>
  408843:	e8 38 89 ff ff       	call   401180 <__errno_location@plt>
  408848:	8b 38                	mov    edi,DWORD PTR [rax]
  40884a:	e8 31 8a ff ff       	call   401280 <strerror@plt>
  40884f:	48 8d 35 b4 97 00 00 	lea    rsi,[rip+0x97b4]        # 41200a <_IO_stdin_used+0xa>
  408856:	bf 01 00 00 00       	mov    edi,0x1
  40885b:	48 89 c2             	mov    rdx,rax
  40885e:	31 c0                	xor    eax,eax
  408860:	e8 cb 89 ff ff       	call   401230 <__printf_chk@plt>
  408865:	e8 76 89 ff ff       	call   4011e0 <geteuid@plt>
  40886a:	85 c0                	test   eax,eax
  40886c:	0f 84 67 8d ff ff    	je     4015d9 <win+0x63>
  408872:	e9 4a 8d ff ff       	jmp    4015c1 <win+0x4b>
  408877:	ba 00 01 00 00       	mov    edx,0x100
  40887c:	48 89 ee             	mov    rsi,rbp
  40887f:	e8 7c 89 ff ff       	call   401200 <read@plt>
  408884:	85 c0                	test   eax,eax
  408886:	7f 2a                	jg     4088b2 <win+0x733c>
  408888:	e8 f3 88 ff ff       	call   401180 <__errno_location@plt>
  40888d:	8b 38                	mov    edi,DWORD PTR [rax]
  40888f:	e8 ec 89 ff ff       	call   401280 <strerror@plt>
  408894:	bf 01 00 00 00       	mov    edi,0x1
  408899:	48 8d 35 09 98 00 00 	lea    rsi,[rip+0x9809]        # 4120a9 <_IO_stdin_used+0xa9>
  4088a0:	48 89 c2             	mov    rdx,rax
  4088a3:	31 c0                	xor    eax,eax
  4088a5:	e8 86 89 ff ff       	call   401230 <__printf_chk@plt>
  4088aa:	83 cf ff             	or     edi,0xffffffff
  4088ad:	e8 ae 89 ff ff       	call   401260 <exit@plt>
  4088b2:	48 63 d0             	movsxd rdx,eax
  4088b5:	48 89 ee             	mov    rsi,rbp
  4088b8:	bf 01 00 00 00       	mov    edi,0x1
  4088bd:	e8 de 88 ff ff       	call   4011a0 <write@plt>
  4088c2:	48 8d 3d 8b 98 00 00 	lea    rdi,[rip+0x988b]        # 412154 <_IO_stdin_used+0x154>
  4088c9:	e8 c2 88 ff ff       	call   401190 <puts@plt>
  4088ce:	48 8d 3d 2f 97 00 00 	lea    rdi,[rip+0x972f]        # 412004 <_IO_stdin_used+0x4>
  4088d5:	31 f6                	xor    esi,esi
  4088d7:	31 c0                	xor    eax,eax
  4088d9:	e8 72 89 ff ff       	call   401250 <open@plt>
  4088de:	89 c7                	mov    edi,eax
  4088e0:	85 c0                	test   eax,eax
  4088e2:	79 34                	jns    408918 <win+0x73a2>
  4088e4:	e8 97 88 ff ff       	call   401180 <__errno_location@plt>
  4088e9:	8b 38                	mov    edi,DWORD PTR [rax]
  4088eb:	e8 90 89 ff ff       	call   401280 <strerror@plt>
  4088f0:	48 8d 35 13 97 00 00 	lea    rsi,[rip+0x9713]        # 41200a <_IO_stdin_used+0xa>
  4088f7:	bf 01 00 00 00       	mov    edi,0x1
  4088fc:	48 89 c2             	mov    rdx,rax
  4088ff:	31 c0                	xor    eax,eax
  408901:	e8 2a 89 ff ff       	call   401230 <__printf_chk@plt>
  408906:	e8 d5 88 ff ff       	call   4011e0 <geteuid@plt>
  40890b:	85 c0                	test   eax,eax
  40890d:	0f 84 c6 8c ff ff    	je     4015d9 <win+0x63>
  408913:	e9 a9 8c ff ff       	jmp    4015c1 <win+0x4b>
  408918:	ba 00 01 00 00       	mov    edx,0x100
  40891d:	48 89 ee             	mov    rsi,rbp
  408920:	e8 db 88 ff ff       	call   401200 <read@plt>
  408925:	85 c0                	test   eax,eax
  408927:	7f 2a                	jg     408953 <win+0x73dd>
  408929:	e8 52 88 ff ff       	call   401180 <__errno_location@plt>
  40892e:	8b 38                	mov    edi,DWORD PTR [rax]
  408930:	e8 4b 89 ff ff       	call   401280 <strerror@plt>
  408935:	bf 01 00 00 00       	mov    edi,0x1
  40893a:	48 8d 35 68 97 00 00 	lea    rsi,[rip+0x9768]        # 4120a9 <_IO_stdin_used+0xa9>
  408941:	48 89 c2             	mov    rdx,rax
  408944:	31 c0                	xor    eax,eax
  408946:	e8 e5 88 ff ff       	call   401230 <__printf_chk@plt>
  40894b:	83 cf ff             	or     edi,0xffffffff
  40894e:	e8 0d 89 ff ff       	call   401260 <exit@plt>
  408953:	48 63 d0             	movsxd rdx,eax
  408956:	48 89 ee             	mov    rsi,rbp
  408959:	bf 01 00 00 00       	mov    edi,0x1
  40895e:	e8 3d 88 ff ff       	call   4011a0 <write@plt>
  408963:	48 8d 3d ea 97 00 00 	lea    rdi,[rip+0x97ea]        # 412154 <_IO_stdin_used+0x154>
  40896a:	e8 21 88 ff ff       	call   401190 <puts@plt>
  40896f:	48 8d 3d 8e 96 00 00 	lea    rdi,[rip+0x968e]        # 412004 <_IO_stdin_used+0x4>
  408976:	31 f6                	xor    esi,esi
  408978:	31 c0                	xor    eax,eax
  40897a:	e8 d1 88 ff ff       	call   401250 <open@plt>
  40897f:	89 c7                	mov    edi,eax
  408981:	85 c0                	test   eax,eax
  408983:	79 34                	jns    4089b9 <win+0x7443>
  408985:	e8 f6 87 ff ff       	call   401180 <__errno_location@plt>
  40898a:	8b 38                	mov    edi,DWORD PTR [rax]
  40898c:	e8 ef 88 ff ff       	call   401280 <strerror@plt>
  408991:	48 8d 35 72 96 00 00 	lea    rsi,[rip+0x9672]        # 41200a <_IO_stdin_used+0xa>
  408998:	bf 01 00 00 00       	mov    edi,0x1
  40899d:	48 89 c2             	mov    rdx,rax
  4089a0:	31 c0                	xor    eax,eax
  4089a2:	e8 89 88 ff ff       	call   401230 <__printf_chk@plt>
  4089a7:	e8 34 88 ff ff       	call   4011e0 <geteuid@plt>
  4089ac:	85 c0                	test   eax,eax
  4089ae:	0f 84 25 8c ff ff    	je     4015d9 <win+0x63>
  4089b4:	e9 08 8c ff ff       	jmp    4015c1 <win+0x4b>
  4089b9:	ba 00 01 00 00       	mov    edx,0x100
  4089be:	48 89 ee             	mov    rsi,rbp
  4089c1:	e8 3a 88 ff ff       	call   401200 <read@plt>
  4089c6:	85 c0                	test   eax,eax
  4089c8:	7f 2a                	jg     4089f4 <win+0x747e>
  4089ca:	e8 b1 87 ff ff       	call   401180 <__errno_location@plt>
  4089cf:	8b 38                	mov    edi,DWORD PTR [rax]
  4089d1:	e8 aa 88 ff ff       	call   401280 <strerror@plt>
  4089d6:	bf 01 00 00 00       	mov    edi,0x1
  4089db:	48 8d 35 c7 96 00 00 	lea    rsi,[rip+0x96c7]        # 4120a9 <_IO_stdin_used+0xa9>
  4089e2:	48 89 c2             	mov    rdx,rax
  4089e5:	31 c0                	xor    eax,eax
  4089e7:	e8 44 88 ff ff       	call   401230 <__printf_chk@plt>
  4089ec:	83 cf ff             	or     edi,0xffffffff
  4089ef:	e8 6c 88 ff ff       	call   401260 <exit@plt>
  4089f4:	48 63 d0             	movsxd rdx,eax
  4089f7:	48 89 ee             	mov    rsi,rbp
  4089fa:	bf 01 00 00 00       	mov    edi,0x1
  4089ff:	e8 9c 87 ff ff       	call   4011a0 <write@plt>
  408a04:	48 8d 3d 49 97 00 00 	lea    rdi,[rip+0x9749]        # 412154 <_IO_stdin_used+0x154>
  408a0b:	e8 80 87 ff ff       	call   401190 <puts@plt>
  408a10:	48 8d 3d ed 95 00 00 	lea    rdi,[rip+0x95ed]        # 412004 <_IO_stdin_used+0x4>
  408a17:	31 f6                	xor    esi,esi
  408a19:	31 c0                	xor    eax,eax
  408a1b:	e8 30 88 ff ff       	call   401250 <open@plt>
  408a20:	89 c7                	mov    edi,eax
  408a22:	85 c0                	test   eax,eax
  408a24:	79 34                	jns    408a5a <win+0x74e4>
  408a26:	e8 55 87 ff ff       	call   401180 <__errno_location@plt>
  408a2b:	8b 38                	mov    edi,DWORD PTR [rax]
  408a2d:	e8 4e 88 ff ff       	call   401280 <strerror@plt>
  408a32:	48 8d 35 d1 95 00 00 	lea    rsi,[rip+0x95d1]        # 41200a <_IO_stdin_used+0xa>
  408a39:	bf 01 00 00 00       	mov    edi,0x1
  408a3e:	48 89 c2             	mov    rdx,rax
  408a41:	31 c0                	xor    eax,eax
  408a43:	e8 e8 87 ff ff       	call   401230 <__printf_chk@plt>
  408a48:	e8 93 87 ff ff       	call   4011e0 <geteuid@plt>
  408a4d:	85 c0                	test   eax,eax
  408a4f:	0f 84 84 8b ff ff    	je     4015d9 <win+0x63>
  408a55:	e9 67 8b ff ff       	jmp    4015c1 <win+0x4b>
  408a5a:	ba 00 01 00 00       	mov    edx,0x100
  408a5f:	48 89 ee             	mov    rsi,rbp
  408a62:	e8 99 87 ff ff       	call   401200 <read@plt>
  408a67:	85 c0                	test   eax,eax
  408a69:	7f 2a                	jg     408a95 <win+0x751f>
  408a6b:	e8 10 87 ff ff       	call   401180 <__errno_location@plt>
  408a70:	8b 38                	mov    edi,DWORD PTR [rax]
  408a72:	e8 09 88 ff ff       	call   401280 <strerror@plt>
  408a77:	bf 01 00 00 00       	mov    edi,0x1
  408a7c:	48 8d 35 26 96 00 00 	lea    rsi,[rip+0x9626]        # 4120a9 <_IO_stdin_used+0xa9>
  408a83:	48 89 c2             	mov    rdx,rax
  408a86:	31 c0                	xor    eax,eax
  408a88:	e8 a3 87 ff ff       	call   401230 <__printf_chk@plt>
  408a8d:	83 cf ff             	or     edi,0xffffffff
  408a90:	e8 cb 87 ff ff       	call   401260 <exit@plt>
  408a95:	48 63 d0             	movsxd rdx,eax
  408a98:	48 89 ee             	mov    rsi,rbp
  408a9b:	bf 01 00 00 00       	mov    edi,0x1
  408aa0:	e8 fb 86 ff ff       	call   4011a0 <write@plt>
  408aa5:	48 8d 3d a8 96 00 00 	lea    rdi,[rip+0x96a8]        # 412154 <_IO_stdin_used+0x154>
  408aac:	e8 df 86 ff ff       	call   401190 <puts@plt>
  408ab1:	48 8d 3d 4c 95 00 00 	lea    rdi,[rip+0x954c]        # 412004 <_IO_stdin_used+0x4>
  408ab8:	31 f6                	xor    esi,esi
  408aba:	31 c0                	xor    eax,eax
  408abc:	e8 8f 87 ff ff       	call   401250 <open@plt>
  408ac1:	89 c7                	mov    edi,eax
  408ac3:	85 c0                	test   eax,eax
  408ac5:	79 34                	jns    408afb <win+0x7585>
  408ac7:	e8 b4 86 ff ff       	call   401180 <__errno_location@plt>
  408acc:	8b 38                	mov    edi,DWORD PTR [rax]
  408ace:	e8 ad 87 ff ff       	call   401280 <strerror@plt>
  408ad3:	48 8d 35 30 95 00 00 	lea    rsi,[rip+0x9530]        # 41200a <_IO_stdin_used+0xa>
  408ada:	bf 01 00 00 00       	mov    edi,0x1
  408adf:	48 89 c2             	mov    rdx,rax
  408ae2:	31 c0                	xor    eax,eax
  408ae4:	e8 47 87 ff ff       	call   401230 <__printf_chk@plt>
  408ae9:	e8 f2 86 ff ff       	call   4011e0 <geteuid@plt>
  408aee:	85 c0                	test   eax,eax
  408af0:	0f 84 e3 8a ff ff    	je     4015d9 <win+0x63>
  408af6:	e9 c6 8a ff ff       	jmp    4015c1 <win+0x4b>
  408afb:	ba 00 01 00 00       	mov    edx,0x100
  408b00:	48 89 ee             	mov    rsi,rbp
  408b03:	e8 f8 86 ff ff       	call   401200 <read@plt>
  408b08:	85 c0                	test   eax,eax
  408b0a:	7f 2a                	jg     408b36 <win+0x75c0>
  408b0c:	e8 6f 86 ff ff       	call   401180 <__errno_location@plt>
  408b11:	8b 38                	mov    edi,DWORD PTR [rax]
  408b13:	e8 68 87 ff ff       	call   401280 <strerror@plt>
  408b18:	bf 01 00 00 00       	mov    edi,0x1
  408b1d:	48 8d 35 85 95 00 00 	lea    rsi,[rip+0x9585]        # 4120a9 <_IO_stdin_used+0xa9>
  408b24:	48 89 c2             	mov    rdx,rax
  408b27:	31 c0                	xor    eax,eax
  408b29:	e8 02 87 ff ff       	call   401230 <__printf_chk@plt>
  408b2e:	83 cf ff             	or     edi,0xffffffff
  408b31:	e8 2a 87 ff ff       	call   401260 <exit@plt>
  408b36:	48 63 d0             	movsxd rdx,eax
  408b39:	48 89 ee             	mov    rsi,rbp
  408b3c:	bf 01 00 00 00       	mov    edi,0x1
  408b41:	e8 5a 86 ff ff       	call   4011a0 <write@plt>
  408b46:	48 8d 3d 07 96 00 00 	lea    rdi,[rip+0x9607]        # 412154 <_IO_stdin_used+0x154>
  408b4d:	e8 3e 86 ff ff       	call   401190 <puts@plt>
  408b52:	48 8d 3d ab 94 00 00 	lea    rdi,[rip+0x94ab]        # 412004 <_IO_stdin_used+0x4>
  408b59:	31 f6                	xor    esi,esi
  408b5b:	31 c0                	xor    eax,eax
  408b5d:	e8 ee 86 ff ff       	call   401250 <open@plt>
  408b62:	89 c7                	mov    edi,eax
  408b64:	85 c0                	test   eax,eax
  408b66:	79 34                	jns    408b9c <win+0x7626>
  408b68:	e8 13 86 ff ff       	call   401180 <__errno_location@plt>
  408b6d:	8b 38                	mov    edi,DWORD PTR [rax]
  408b6f:	e8 0c 87 ff ff       	call   401280 <strerror@plt>
  408b74:	48 8d 35 8f 94 00 00 	lea    rsi,[rip+0x948f]        # 41200a <_IO_stdin_used+0xa>
  408b7b:	bf 01 00 00 00       	mov    edi,0x1
  408b80:	48 89 c2             	mov    rdx,rax
  408b83:	31 c0                	xor    eax,eax
  408b85:	e8 a6 86 ff ff       	call   401230 <__printf_chk@plt>
  408b8a:	e8 51 86 ff ff       	call   4011e0 <geteuid@plt>
  408b8f:	85 c0                	test   eax,eax
  408b91:	0f 84 42 8a ff ff    	je     4015d9 <win+0x63>
  408b97:	e9 25 8a ff ff       	jmp    4015c1 <win+0x4b>
  408b9c:	ba 00 01 00 00       	mov    edx,0x100
  408ba1:	48 89 ee             	mov    rsi,rbp
  408ba4:	e8 57 86 ff ff       	call   401200 <read@plt>
  408ba9:	85 c0                	test   eax,eax
  408bab:	7f 2a                	jg     408bd7 <win+0x7661>
  408bad:	e8 ce 85 ff ff       	call   401180 <__errno_location@plt>
  408bb2:	8b 38                	mov    edi,DWORD PTR [rax]
  408bb4:	e8 c7 86 ff ff       	call   401280 <strerror@plt>
  408bb9:	bf 01 00 00 00       	mov    edi,0x1
  408bbe:	48 8d 35 e4 94 00 00 	lea    rsi,[rip+0x94e4]        # 4120a9 <_IO_stdin_used+0xa9>
  408bc5:	48 89 c2             	mov    rdx,rax
  408bc8:	31 c0                	xor    eax,eax
  408bca:	e8 61 86 ff ff       	call   401230 <__printf_chk@plt>
  408bcf:	83 cf ff             	or     edi,0xffffffff
  408bd2:	e8 89 86 ff ff       	call   401260 <exit@plt>
  408bd7:	48 63 d0             	movsxd rdx,eax
  408bda:	48 89 ee             	mov    rsi,rbp
  408bdd:	bf 01 00 00 00       	mov    edi,0x1
  408be2:	e8 b9 85 ff ff       	call   4011a0 <write@plt>
  408be7:	48 8d 3d 66 95 00 00 	lea    rdi,[rip+0x9566]        # 412154 <_IO_stdin_used+0x154>
  408bee:	e8 9d 85 ff ff       	call   401190 <puts@plt>
  408bf3:	48 8d 3d 0a 94 00 00 	lea    rdi,[rip+0x940a]        # 412004 <_IO_stdin_used+0x4>
  408bfa:	31 f6                	xor    esi,esi
  408bfc:	31 c0                	xor    eax,eax
  408bfe:	e8 4d 86 ff ff       	call   401250 <open@plt>
  408c03:	89 c7                	mov    edi,eax
  408c05:	85 c0                	test   eax,eax
  408c07:	79 34                	jns    408c3d <win+0x76c7>
  408c09:	e8 72 85 ff ff       	call   401180 <__errno_location@plt>
  408c0e:	8b 38                	mov    edi,DWORD PTR [rax]
  408c10:	e8 6b 86 ff ff       	call   401280 <strerror@plt>
  408c15:	48 8d 35 ee 93 00 00 	lea    rsi,[rip+0x93ee]        # 41200a <_IO_stdin_used+0xa>
  408c1c:	bf 01 00 00 00       	mov    edi,0x1
  408c21:	48 89 c2             	mov    rdx,rax
  408c24:	31 c0                	xor    eax,eax
  408c26:	e8 05 86 ff ff       	call   401230 <__printf_chk@plt>
  408c2b:	e8 b0 85 ff ff       	call   4011e0 <geteuid@plt>
  408c30:	85 c0                	test   eax,eax
  408c32:	0f 84 a1 89 ff ff    	je     4015d9 <win+0x63>
  408c38:	e9 84 89 ff ff       	jmp    4015c1 <win+0x4b>
  408c3d:	ba 00 01 00 00       	mov    edx,0x100
  408c42:	48 89 ee             	mov    rsi,rbp
  408c45:	e8 b6 85 ff ff       	call   401200 <read@plt>
  408c4a:	85 c0                	test   eax,eax
  408c4c:	7f 2a                	jg     408c78 <win+0x7702>
  408c4e:	e8 2d 85 ff ff       	call   401180 <__errno_location@plt>
  408c53:	8b 38                	mov    edi,DWORD PTR [rax]
  408c55:	e8 26 86 ff ff       	call   401280 <strerror@plt>
  408c5a:	bf 01 00 00 00       	mov    edi,0x1
  408c5f:	48 8d 35 43 94 00 00 	lea    rsi,[rip+0x9443]        # 4120a9 <_IO_stdin_used+0xa9>
  408c66:	48 89 c2             	mov    rdx,rax
  408c69:	31 c0                	xor    eax,eax
  408c6b:	e8 c0 85 ff ff       	call   401230 <__printf_chk@plt>
  408c70:	83 cf ff             	or     edi,0xffffffff
  408c73:	e8 e8 85 ff ff       	call   401260 <exit@plt>
  408c78:	48 63 d0             	movsxd rdx,eax
  408c7b:	48 89 ee             	mov    rsi,rbp
  408c7e:	bf 01 00 00 00       	mov    edi,0x1
  408c83:	e8 18 85 ff ff       	call   4011a0 <write@plt>
  408c88:	48 8d 3d c5 94 00 00 	lea    rdi,[rip+0x94c5]        # 412154 <_IO_stdin_used+0x154>
  408c8f:	e8 fc 84 ff ff       	call   401190 <puts@plt>
  408c94:	48 8d 3d 69 93 00 00 	lea    rdi,[rip+0x9369]        # 412004 <_IO_stdin_used+0x4>
  408c9b:	31 f6                	xor    esi,esi
  408c9d:	31 c0                	xor    eax,eax
  408c9f:	e8 ac 85 ff ff       	call   401250 <open@plt>
  408ca4:	89 c7                	mov    edi,eax
  408ca6:	85 c0                	test   eax,eax
  408ca8:	79 34                	jns    408cde <win+0x7768>
  408caa:	e8 d1 84 ff ff       	call   401180 <__errno_location@plt>
  408caf:	8b 38                	mov    edi,DWORD PTR [rax]
  408cb1:	e8 ca 85 ff ff       	call   401280 <strerror@plt>
  408cb6:	48 8d 35 4d 93 00 00 	lea    rsi,[rip+0x934d]        # 41200a <_IO_stdin_used+0xa>
  408cbd:	bf 01 00 00 00       	mov    edi,0x1
  408cc2:	48 89 c2             	mov    rdx,rax
  408cc5:	31 c0                	xor    eax,eax
  408cc7:	e8 64 85 ff ff       	call   401230 <__printf_chk@plt>
  408ccc:	e8 0f 85 ff ff       	call   4011e0 <geteuid@plt>
  408cd1:	85 c0                	test   eax,eax
  408cd3:	0f 84 00 89 ff ff    	je     4015d9 <win+0x63>
  408cd9:	e9 e3 88 ff ff       	jmp    4015c1 <win+0x4b>
  408cde:	ba 00 01 00 00       	mov    edx,0x100
  408ce3:	48 89 ee             	mov    rsi,rbp
  408ce6:	e8 15 85 ff ff       	call   401200 <read@plt>
  408ceb:	85 c0                	test   eax,eax
  408ced:	7f 2a                	jg     408d19 <win+0x77a3>
  408cef:	e8 8c 84 ff ff       	call   401180 <__errno_location@plt>
  408cf4:	8b 38                	mov    edi,DWORD PTR [rax]
  408cf6:	e8 85 85 ff ff       	call   401280 <strerror@plt>
  408cfb:	bf 01 00 00 00       	mov    edi,0x1
  408d00:	48 8d 35 a2 93 00 00 	lea    rsi,[rip+0x93a2]        # 4120a9 <_IO_stdin_used+0xa9>
  408d07:	48 89 c2             	mov    rdx,rax
  408d0a:	31 c0                	xor    eax,eax
  408d0c:	e8 1f 85 ff ff       	call   401230 <__printf_chk@plt>
  408d11:	83 cf ff             	or     edi,0xffffffff
  408d14:	e8 47 85 ff ff       	call   401260 <exit@plt>
  408d19:	48 63 d0             	movsxd rdx,eax
  408d1c:	48 89 ee             	mov    rsi,rbp
  408d1f:	bf 01 00 00 00       	mov    edi,0x1
  408d24:	e8 77 84 ff ff       	call   4011a0 <write@plt>
  408d29:	48 8d 3d 24 94 00 00 	lea    rdi,[rip+0x9424]        # 412154 <_IO_stdin_used+0x154>
  408d30:	e8 5b 84 ff ff       	call   401190 <puts@plt>
  408d35:	48 8d 3d c8 92 00 00 	lea    rdi,[rip+0x92c8]        # 412004 <_IO_stdin_used+0x4>
  408d3c:	31 f6                	xor    esi,esi
  408d3e:	31 c0                	xor    eax,eax
  408d40:	e8 0b 85 ff ff       	call   401250 <open@plt>
  408d45:	89 c7                	mov    edi,eax
  408d47:	85 c0                	test   eax,eax
  408d49:	79 34                	jns    408d7f <win+0x7809>
  408d4b:	e8 30 84 ff ff       	call   401180 <__errno_location@plt>
  408d50:	8b 38                	mov    edi,DWORD PTR [rax]
  408d52:	e8 29 85 ff ff       	call   401280 <strerror@plt>
  408d57:	48 8d 35 ac 92 00 00 	lea    rsi,[rip+0x92ac]        # 41200a <_IO_stdin_used+0xa>
  408d5e:	bf 01 00 00 00       	mov    edi,0x1
  408d63:	48 89 c2             	mov    rdx,rax
  408d66:	31 c0                	xor    eax,eax
  408d68:	e8 c3 84 ff ff       	call   401230 <__printf_chk@plt>
  408d6d:	e8 6e 84 ff ff       	call   4011e0 <geteuid@plt>
  408d72:	85 c0                	test   eax,eax
  408d74:	0f 84 5f 88 ff ff    	je     4015d9 <win+0x63>
  408d7a:	e9 42 88 ff ff       	jmp    4015c1 <win+0x4b>
  408d7f:	ba 00 01 00 00       	mov    edx,0x100
  408d84:	48 89 ee             	mov    rsi,rbp
  408d87:	e8 74 84 ff ff       	call   401200 <read@plt>
  408d8c:	85 c0                	test   eax,eax
  408d8e:	7f 2a                	jg     408dba <win+0x7844>
  408d90:	e8 eb 83 ff ff       	call   401180 <__errno_location@plt>
  408d95:	8b 38                	mov    edi,DWORD PTR [rax]
  408d97:	e8 e4 84 ff ff       	call   401280 <strerror@plt>
  408d9c:	bf 01 00 00 00       	mov    edi,0x1
  408da1:	48 8d 35 01 93 00 00 	lea    rsi,[rip+0x9301]        # 4120a9 <_IO_stdin_used+0xa9>
  408da8:	48 89 c2             	mov    rdx,rax
  408dab:	31 c0                	xor    eax,eax
  408dad:	e8 7e 84 ff ff       	call   401230 <__printf_chk@plt>
  408db2:	83 cf ff             	or     edi,0xffffffff
  408db5:	e8 a6 84 ff ff       	call   401260 <exit@plt>
  408dba:	48 63 d0             	movsxd rdx,eax
  408dbd:	48 89 ee             	mov    rsi,rbp
  408dc0:	bf 01 00 00 00       	mov    edi,0x1
  408dc5:	e8 d6 83 ff ff       	call   4011a0 <write@plt>
  408dca:	48 8d 3d 83 93 00 00 	lea    rdi,[rip+0x9383]        # 412154 <_IO_stdin_used+0x154>
  408dd1:	e8 ba 83 ff ff       	call   401190 <puts@plt>
  408dd6:	48 8d 3d 27 92 00 00 	lea    rdi,[rip+0x9227]        # 412004 <_IO_stdin_used+0x4>
  408ddd:	31 f6                	xor    esi,esi
  408ddf:	31 c0                	xor    eax,eax
  408de1:	e8 6a 84 ff ff       	call   401250 <open@plt>
  408de6:	89 c7                	mov    edi,eax
  408de8:	85 c0                	test   eax,eax
  408dea:	79 34                	jns    408e20 <win+0x78aa>
  408dec:	e8 8f 83 ff ff       	call   401180 <__errno_location@plt>
  408df1:	8b 38                	mov    edi,DWORD PTR [rax]
  408df3:	e8 88 84 ff ff       	call   401280 <strerror@plt>
  408df8:	48 8d 35 0b 92 00 00 	lea    rsi,[rip+0x920b]        # 41200a <_IO_stdin_used+0xa>
  408dff:	bf 01 00 00 00       	mov    edi,0x1
  408e04:	48 89 c2             	mov    rdx,rax
  408e07:	31 c0                	xor    eax,eax
  408e09:	e8 22 84 ff ff       	call   401230 <__printf_chk@plt>
  408e0e:	e8 cd 83 ff ff       	call   4011e0 <geteuid@plt>
  408e13:	85 c0                	test   eax,eax
  408e15:	0f 84 be 87 ff ff    	je     4015d9 <win+0x63>
  408e1b:	e9 a1 87 ff ff       	jmp    4015c1 <win+0x4b>
  408e20:	ba 00 01 00 00       	mov    edx,0x100
  408e25:	48 89 ee             	mov    rsi,rbp
  408e28:	e8 d3 83 ff ff       	call   401200 <read@plt>
  408e2d:	85 c0                	test   eax,eax
  408e2f:	7f 2a                	jg     408e5b <win+0x78e5>
  408e31:	e8 4a 83 ff ff       	call   401180 <__errno_location@plt>
  408e36:	8b 38                	mov    edi,DWORD PTR [rax]
  408e38:	e8 43 84 ff ff       	call   401280 <strerror@plt>
  408e3d:	bf 01 00 00 00       	mov    edi,0x1
  408e42:	48 8d 35 60 92 00 00 	lea    rsi,[rip+0x9260]        # 4120a9 <_IO_stdin_used+0xa9>
  408e49:	48 89 c2             	mov    rdx,rax
  408e4c:	31 c0                	xor    eax,eax
  408e4e:	e8 dd 83 ff ff       	call   401230 <__printf_chk@plt>
  408e53:	83 cf ff             	or     edi,0xffffffff
  408e56:	e8 05 84 ff ff       	call   401260 <exit@plt>
  408e5b:	48 63 d0             	movsxd rdx,eax
  408e5e:	48 89 ee             	mov    rsi,rbp
  408e61:	bf 01 00 00 00       	mov    edi,0x1
  408e66:	e8 35 83 ff ff       	call   4011a0 <write@plt>
  408e6b:	48 8d 3d e2 92 00 00 	lea    rdi,[rip+0x92e2]        # 412154 <_IO_stdin_used+0x154>
  408e72:	e8 19 83 ff ff       	call   401190 <puts@plt>
  408e77:	48 8d 3d 86 91 00 00 	lea    rdi,[rip+0x9186]        # 412004 <_IO_stdin_used+0x4>
  408e7e:	31 f6                	xor    esi,esi
  408e80:	31 c0                	xor    eax,eax
  408e82:	e8 c9 83 ff ff       	call   401250 <open@plt>
  408e87:	89 c7                	mov    edi,eax
  408e89:	85 c0                	test   eax,eax
  408e8b:	79 34                	jns    408ec1 <win+0x794b>
  408e8d:	e8 ee 82 ff ff       	call   401180 <__errno_location@plt>
  408e92:	8b 38                	mov    edi,DWORD PTR [rax]
  408e94:	e8 e7 83 ff ff       	call   401280 <strerror@plt>
  408e99:	48 8d 35 6a 91 00 00 	lea    rsi,[rip+0x916a]        # 41200a <_IO_stdin_used+0xa>
  408ea0:	bf 01 00 00 00       	mov    edi,0x1
  408ea5:	48 89 c2             	mov    rdx,rax
  408ea8:	31 c0                	xor    eax,eax
  408eaa:	e8 81 83 ff ff       	call   401230 <__printf_chk@plt>
  408eaf:	e8 2c 83 ff ff       	call   4011e0 <geteuid@plt>
  408eb4:	85 c0                	test   eax,eax
  408eb6:	0f 84 1d 87 ff ff    	je     4015d9 <win+0x63>
  408ebc:	e9 00 87 ff ff       	jmp    4015c1 <win+0x4b>
  408ec1:	ba 00 01 00 00       	mov    edx,0x100
  408ec6:	48 89 ee             	mov    rsi,rbp
  408ec9:	e8 32 83 ff ff       	call   401200 <read@plt>
  408ece:	85 c0                	test   eax,eax
  408ed0:	7f 2a                	jg     408efc <win+0x7986>
  408ed2:	e8 a9 82 ff ff       	call   401180 <__errno_location@plt>
  408ed7:	8b 38                	mov    edi,DWORD PTR [rax]
  408ed9:	e8 a2 83 ff ff       	call   401280 <strerror@plt>
  408ede:	bf 01 00 00 00       	mov    edi,0x1
  408ee3:	48 8d 35 bf 91 00 00 	lea    rsi,[rip+0x91bf]        # 4120a9 <_IO_stdin_used+0xa9>
  408eea:	48 89 c2             	mov    rdx,rax
  408eed:	31 c0                	xor    eax,eax
  408eef:	e8 3c 83 ff ff       	call   401230 <__printf_chk@plt>
  408ef4:	83 cf ff             	or     edi,0xffffffff
  408ef7:	e8 64 83 ff ff       	call   401260 <exit@plt>
  408efc:	48 63 d0             	movsxd rdx,eax
  408eff:	48 89 ee             	mov    rsi,rbp
  408f02:	bf 01 00 00 00       	mov    edi,0x1
  408f07:	e8 94 82 ff ff       	call   4011a0 <write@plt>
  408f0c:	48 8d 3d 41 92 00 00 	lea    rdi,[rip+0x9241]        # 412154 <_IO_stdin_used+0x154>
  408f13:	e8 78 82 ff ff       	call   401190 <puts@plt>
  408f18:	48 8d 3d e5 90 00 00 	lea    rdi,[rip+0x90e5]        # 412004 <_IO_stdin_used+0x4>
  408f1f:	31 f6                	xor    esi,esi
  408f21:	31 c0                	xor    eax,eax
  408f23:	e8 28 83 ff ff       	call   401250 <open@plt>
  408f28:	89 c7                	mov    edi,eax
  408f2a:	85 c0                	test   eax,eax
  408f2c:	79 34                	jns    408f62 <win+0x79ec>
  408f2e:	e8 4d 82 ff ff       	call   401180 <__errno_location@plt>
  408f33:	8b 38                	mov    edi,DWORD PTR [rax]
  408f35:	e8 46 83 ff ff       	call   401280 <strerror@plt>
  408f3a:	48 8d 35 c9 90 00 00 	lea    rsi,[rip+0x90c9]        # 41200a <_IO_stdin_used+0xa>
  408f41:	bf 01 00 00 00       	mov    edi,0x1
  408f46:	48 89 c2             	mov    rdx,rax
  408f49:	31 c0                	xor    eax,eax
  408f4b:	e8 e0 82 ff ff       	call   401230 <__printf_chk@plt>
  408f50:	e8 8b 82 ff ff       	call   4011e0 <geteuid@plt>
  408f55:	85 c0                	test   eax,eax
  408f57:	0f 84 7c 86 ff ff    	je     4015d9 <win+0x63>
  408f5d:	e9 5f 86 ff ff       	jmp    4015c1 <win+0x4b>
  408f62:	ba 00 01 00 00       	mov    edx,0x100
  408f67:	48 89 ee             	mov    rsi,rbp
  408f6a:	e8 91 82 ff ff       	call   401200 <read@plt>
  408f6f:	85 c0                	test   eax,eax
  408f71:	7f 2a                	jg     408f9d <win+0x7a27>
  408f73:	e8 08 82 ff ff       	call   401180 <__errno_location@plt>
  408f78:	8b 38                	mov    edi,DWORD PTR [rax]
  408f7a:	e8 01 83 ff ff       	call   401280 <strerror@plt>
  408f7f:	bf 01 00 00 00       	mov    edi,0x1
  408f84:	48 8d 35 1e 91 00 00 	lea    rsi,[rip+0x911e]        # 4120a9 <_IO_stdin_used+0xa9>
  408f8b:	48 89 c2             	mov    rdx,rax
  408f8e:	31 c0                	xor    eax,eax
  408f90:	e8 9b 82 ff ff       	call   401230 <__printf_chk@plt>
  408f95:	83 cf ff             	or     edi,0xffffffff
  408f98:	e8 c3 82 ff ff       	call   401260 <exit@plt>
  408f9d:	48 63 d0             	movsxd rdx,eax
  408fa0:	48 89 ee             	mov    rsi,rbp
  408fa3:	bf 01 00 00 00       	mov    edi,0x1
  408fa8:	e8 f3 81 ff ff       	call   4011a0 <write@plt>
  408fad:	48 8d 3d a0 91 00 00 	lea    rdi,[rip+0x91a0]        # 412154 <_IO_stdin_used+0x154>
  408fb4:	e8 d7 81 ff ff       	call   401190 <puts@plt>
  408fb9:	48 8d 3d 44 90 00 00 	lea    rdi,[rip+0x9044]        # 412004 <_IO_stdin_used+0x4>
  408fc0:	31 f6                	xor    esi,esi
  408fc2:	31 c0                	xor    eax,eax
  408fc4:	e8 87 82 ff ff       	call   401250 <open@plt>
  408fc9:	89 c7                	mov    edi,eax
  408fcb:	85 c0                	test   eax,eax
  408fcd:	79 34                	jns    409003 <win+0x7a8d>
  408fcf:	e8 ac 81 ff ff       	call   401180 <__errno_location@plt>
  408fd4:	8b 38                	mov    edi,DWORD PTR [rax]
  408fd6:	e8 a5 82 ff ff       	call   401280 <strerror@plt>
  408fdb:	48 8d 35 28 90 00 00 	lea    rsi,[rip+0x9028]        # 41200a <_IO_stdin_used+0xa>
  408fe2:	bf 01 00 00 00       	mov    edi,0x1
  408fe7:	48 89 c2             	mov    rdx,rax
  408fea:	31 c0                	xor    eax,eax
  408fec:	e8 3f 82 ff ff       	call   401230 <__printf_chk@plt>
  408ff1:	e8 ea 81 ff ff       	call   4011e0 <geteuid@plt>
  408ff6:	85 c0                	test   eax,eax
  408ff8:	0f 84 db 85 ff ff    	je     4015d9 <win+0x63>
  408ffe:	e9 be 85 ff ff       	jmp    4015c1 <win+0x4b>
  409003:	ba 00 01 00 00       	mov    edx,0x100
  409008:	48 89 ee             	mov    rsi,rbp
  40900b:	e8 f0 81 ff ff       	call   401200 <read@plt>
  409010:	85 c0                	test   eax,eax
  409012:	7f 2a                	jg     40903e <win+0x7ac8>
  409014:	e8 67 81 ff ff       	call   401180 <__errno_location@plt>
  409019:	8b 38                	mov    edi,DWORD PTR [rax]
  40901b:	e8 60 82 ff ff       	call   401280 <strerror@plt>
  409020:	bf 01 00 00 00       	mov    edi,0x1
  409025:	48 8d 35 7d 90 00 00 	lea    rsi,[rip+0x907d]        # 4120a9 <_IO_stdin_used+0xa9>
  40902c:	48 89 c2             	mov    rdx,rax
  40902f:	31 c0                	xor    eax,eax
  409031:	e8 fa 81 ff ff       	call   401230 <__printf_chk@plt>
  409036:	83 cf ff             	or     edi,0xffffffff
  409039:	e8 22 82 ff ff       	call   401260 <exit@plt>
  40903e:	48 63 d0             	movsxd rdx,eax
  409041:	48 89 ee             	mov    rsi,rbp
  409044:	bf 01 00 00 00       	mov    edi,0x1
  409049:	e8 52 81 ff ff       	call   4011a0 <write@plt>
  40904e:	48 8d 3d ff 90 00 00 	lea    rdi,[rip+0x90ff]        # 412154 <_IO_stdin_used+0x154>
  409055:	e8 36 81 ff ff       	call   401190 <puts@plt>
  40905a:	48 8d 3d a3 8f 00 00 	lea    rdi,[rip+0x8fa3]        # 412004 <_IO_stdin_used+0x4>
  409061:	31 f6                	xor    esi,esi
  409063:	31 c0                	xor    eax,eax
  409065:	e8 e6 81 ff ff       	call   401250 <open@plt>
  40906a:	89 c7                	mov    edi,eax
  40906c:	85 c0                	test   eax,eax
  40906e:	79 34                	jns    4090a4 <win+0x7b2e>
  409070:	e8 0b 81 ff ff       	call   401180 <__errno_location@plt>
  409075:	8b 38                	mov    edi,DWORD PTR [rax]
  409077:	e8 04 82 ff ff       	call   401280 <strerror@plt>
  40907c:	48 8d 35 87 8f 00 00 	lea    rsi,[rip+0x8f87]        # 41200a <_IO_stdin_used+0xa>
  409083:	bf 01 00 00 00       	mov    edi,0x1
  409088:	48 89 c2             	mov    rdx,rax
  40908b:	31 c0                	xor    eax,eax
  40908d:	e8 9e 81 ff ff       	call   401230 <__printf_chk@plt>
  409092:	e8 49 81 ff ff       	call   4011e0 <geteuid@plt>
  409097:	85 c0                	test   eax,eax
  409099:	0f 84 3a 85 ff ff    	je     4015d9 <win+0x63>
  40909f:	e9 1d 85 ff ff       	jmp    4015c1 <win+0x4b>
  4090a4:	ba 00 01 00 00       	mov    edx,0x100
  4090a9:	48 89 ee             	mov    rsi,rbp
  4090ac:	e8 4f 81 ff ff       	call   401200 <read@plt>
  4090b1:	85 c0                	test   eax,eax
  4090b3:	7f 2a                	jg     4090df <win+0x7b69>
  4090b5:	e8 c6 80 ff ff       	call   401180 <__errno_location@plt>
  4090ba:	8b 38                	mov    edi,DWORD PTR [rax]
  4090bc:	e8 bf 81 ff ff       	call   401280 <strerror@plt>
  4090c1:	bf 01 00 00 00       	mov    edi,0x1
  4090c6:	48 8d 35 dc 8f 00 00 	lea    rsi,[rip+0x8fdc]        # 4120a9 <_IO_stdin_used+0xa9>
  4090cd:	48 89 c2             	mov    rdx,rax
  4090d0:	31 c0                	xor    eax,eax
  4090d2:	e8 59 81 ff ff       	call   401230 <__printf_chk@plt>
  4090d7:	83 cf ff             	or     edi,0xffffffff
  4090da:	e8 81 81 ff ff       	call   401260 <exit@plt>
  4090df:	48 63 d0             	movsxd rdx,eax
  4090e2:	48 89 ee             	mov    rsi,rbp
  4090e5:	bf 01 00 00 00       	mov    edi,0x1
  4090ea:	e8 b1 80 ff ff       	call   4011a0 <write@plt>
  4090ef:	48 8d 3d 5e 90 00 00 	lea    rdi,[rip+0x905e]        # 412154 <_IO_stdin_used+0x154>
  4090f6:	e8 95 80 ff ff       	call   401190 <puts@plt>
  4090fb:	48 8d 3d 02 8f 00 00 	lea    rdi,[rip+0x8f02]        # 412004 <_IO_stdin_used+0x4>
  409102:	31 f6                	xor    esi,esi
  409104:	31 c0                	xor    eax,eax
  409106:	e8 45 81 ff ff       	call   401250 <open@plt>
  40910b:	89 c7                	mov    edi,eax
  40910d:	85 c0                	test   eax,eax
  40910f:	79 34                	jns    409145 <win+0x7bcf>
  409111:	e8 6a 80 ff ff       	call   401180 <__errno_location@plt>
  409116:	8b 38                	mov    edi,DWORD PTR [rax]
  409118:	e8 63 81 ff ff       	call   401280 <strerror@plt>
  40911d:	48 8d 35 e6 8e 00 00 	lea    rsi,[rip+0x8ee6]        # 41200a <_IO_stdin_used+0xa>
  409124:	bf 01 00 00 00       	mov    edi,0x1
  409129:	48 89 c2             	mov    rdx,rax
  40912c:	31 c0                	xor    eax,eax
  40912e:	e8 fd 80 ff ff       	call   401230 <__printf_chk@plt>
  409133:	e8 a8 80 ff ff       	call   4011e0 <geteuid@plt>
  409138:	85 c0                	test   eax,eax
  40913a:	0f 84 99 84 ff ff    	je     4015d9 <win+0x63>
  409140:	e9 7c 84 ff ff       	jmp    4015c1 <win+0x4b>
  409145:	ba 00 01 00 00       	mov    edx,0x100
  40914a:	48 89 ee             	mov    rsi,rbp
  40914d:	e8 ae 80 ff ff       	call   401200 <read@plt>
  409152:	85 c0                	test   eax,eax
  409154:	7f 2a                	jg     409180 <win+0x7c0a>
  409156:	e8 25 80 ff ff       	call   401180 <__errno_location@plt>
  40915b:	8b 38                	mov    edi,DWORD PTR [rax]
  40915d:	e8 1e 81 ff ff       	call   401280 <strerror@plt>
  409162:	bf 01 00 00 00       	mov    edi,0x1
  409167:	48 8d 35 3b 8f 00 00 	lea    rsi,[rip+0x8f3b]        # 4120a9 <_IO_stdin_used+0xa9>
  40916e:	48 89 c2             	mov    rdx,rax
  409171:	31 c0                	xor    eax,eax
  409173:	e8 b8 80 ff ff       	call   401230 <__printf_chk@plt>
  409178:	83 cf ff             	or     edi,0xffffffff
  40917b:	e8 e0 80 ff ff       	call   401260 <exit@plt>
  409180:	48 63 d0             	movsxd rdx,eax
  409183:	48 89 ee             	mov    rsi,rbp
  409186:	bf 01 00 00 00       	mov    edi,0x1
  40918b:	e8 10 80 ff ff       	call   4011a0 <write@plt>
  409190:	48 8d 3d bd 8f 00 00 	lea    rdi,[rip+0x8fbd]        # 412154 <_IO_stdin_used+0x154>
  409197:	e8 f4 7f ff ff       	call   401190 <puts@plt>
  40919c:	48 8d 3d 61 8e 00 00 	lea    rdi,[rip+0x8e61]        # 412004 <_IO_stdin_used+0x4>
  4091a3:	31 f6                	xor    esi,esi
  4091a5:	31 c0                	xor    eax,eax
  4091a7:	e8 a4 80 ff ff       	call   401250 <open@plt>
  4091ac:	89 c7                	mov    edi,eax
  4091ae:	85 c0                	test   eax,eax
  4091b0:	79 34                	jns    4091e6 <win+0x7c70>
  4091b2:	e8 c9 7f ff ff       	call   401180 <__errno_location@plt>
  4091b7:	8b 38                	mov    edi,DWORD PTR [rax]
  4091b9:	e8 c2 80 ff ff       	call   401280 <strerror@plt>
  4091be:	48 8d 35 45 8e 00 00 	lea    rsi,[rip+0x8e45]        # 41200a <_IO_stdin_used+0xa>
  4091c5:	bf 01 00 00 00       	mov    edi,0x1
  4091ca:	48 89 c2             	mov    rdx,rax
  4091cd:	31 c0                	xor    eax,eax
  4091cf:	e8 5c 80 ff ff       	call   401230 <__printf_chk@plt>
  4091d4:	e8 07 80 ff ff       	call   4011e0 <geteuid@plt>
  4091d9:	85 c0                	test   eax,eax
  4091db:	0f 84 f8 83 ff ff    	je     4015d9 <win+0x63>
  4091e1:	e9 db 83 ff ff       	jmp    4015c1 <win+0x4b>
  4091e6:	ba 00 01 00 00       	mov    edx,0x100
  4091eb:	48 89 ee             	mov    rsi,rbp
  4091ee:	e8 0d 80 ff ff       	call   401200 <read@plt>
  4091f3:	85 c0                	test   eax,eax
  4091f5:	7f 2a                	jg     409221 <win+0x7cab>
  4091f7:	e8 84 7f ff ff       	call   401180 <__errno_location@plt>
  4091fc:	8b 38                	mov    edi,DWORD PTR [rax]
  4091fe:	e8 7d 80 ff ff       	call   401280 <strerror@plt>
  409203:	bf 01 00 00 00       	mov    edi,0x1
  409208:	48 8d 35 9a 8e 00 00 	lea    rsi,[rip+0x8e9a]        # 4120a9 <_IO_stdin_used+0xa9>
  40920f:	48 89 c2             	mov    rdx,rax
  409212:	31 c0                	xor    eax,eax
  409214:	e8 17 80 ff ff       	call   401230 <__printf_chk@plt>
  409219:	83 cf ff             	or     edi,0xffffffff
  40921c:	e8 3f 80 ff ff       	call   401260 <exit@plt>
  409221:	48 63 d0             	movsxd rdx,eax
  409224:	48 89 ee             	mov    rsi,rbp
  409227:	bf 01 00 00 00       	mov    edi,0x1
  40922c:	e8 6f 7f ff ff       	call   4011a0 <write@plt>
  409231:	48 8d 3d 1c 8f 00 00 	lea    rdi,[rip+0x8f1c]        # 412154 <_IO_stdin_used+0x154>
  409238:	e8 53 7f ff ff       	call   401190 <puts@plt>
  40923d:	48 8d 3d c0 8d 00 00 	lea    rdi,[rip+0x8dc0]        # 412004 <_IO_stdin_used+0x4>
  409244:	31 f6                	xor    esi,esi
  409246:	31 c0                	xor    eax,eax
  409248:	e8 03 80 ff ff       	call   401250 <open@plt>
  40924d:	89 c7                	mov    edi,eax
  40924f:	85 c0                	test   eax,eax
  409251:	79 34                	jns    409287 <win+0x7d11>
  409253:	e8 28 7f ff ff       	call   401180 <__errno_location@plt>
  409258:	8b 38                	mov    edi,DWORD PTR [rax]
  40925a:	e8 21 80 ff ff       	call   401280 <strerror@plt>
  40925f:	48 8d 35 a4 8d 00 00 	lea    rsi,[rip+0x8da4]        # 41200a <_IO_stdin_used+0xa>
  409266:	bf 01 00 00 00       	mov    edi,0x1
  40926b:	48 89 c2             	mov    rdx,rax
  40926e:	31 c0                	xor    eax,eax
  409270:	e8 bb 7f ff ff       	call   401230 <__printf_chk@plt>
  409275:	e8 66 7f ff ff       	call   4011e0 <geteuid@plt>
  40927a:	85 c0                	test   eax,eax
  40927c:	0f 84 57 83 ff ff    	je     4015d9 <win+0x63>
  409282:	e9 3a 83 ff ff       	jmp    4015c1 <win+0x4b>
  409287:	ba 00 01 00 00       	mov    edx,0x100
  40928c:	48 89 ee             	mov    rsi,rbp
  40928f:	e8 6c 7f ff ff       	call   401200 <read@plt>
  409294:	85 c0                	test   eax,eax
  409296:	7f 2a                	jg     4092c2 <win+0x7d4c>
  409298:	e8 e3 7e ff ff       	call   401180 <__errno_location@plt>
  40929d:	8b 38                	mov    edi,DWORD PTR [rax]
  40929f:	e8 dc 7f ff ff       	call   401280 <strerror@plt>
  4092a4:	bf 01 00 00 00       	mov    edi,0x1
  4092a9:	48 8d 35 f9 8d 00 00 	lea    rsi,[rip+0x8df9]        # 4120a9 <_IO_stdin_used+0xa9>
  4092b0:	48 89 c2             	mov    rdx,rax
  4092b3:	31 c0                	xor    eax,eax
  4092b5:	e8 76 7f ff ff       	call   401230 <__printf_chk@plt>
  4092ba:	83 cf ff             	or     edi,0xffffffff
  4092bd:	e8 9e 7f ff ff       	call   401260 <exit@plt>
  4092c2:	48 63 d0             	movsxd rdx,eax
  4092c5:	48 89 ee             	mov    rsi,rbp
  4092c8:	bf 01 00 00 00       	mov    edi,0x1
  4092cd:	e8 ce 7e ff ff       	call   4011a0 <write@plt>
  4092d2:	48 8d 3d 7b 8e 00 00 	lea    rdi,[rip+0x8e7b]        # 412154 <_IO_stdin_used+0x154>
  4092d9:	e8 b2 7e ff ff       	call   401190 <puts@plt>
  4092de:	48 8d 3d 1f 8d 00 00 	lea    rdi,[rip+0x8d1f]        # 412004 <_IO_stdin_used+0x4>
  4092e5:	31 f6                	xor    esi,esi
  4092e7:	31 c0                	xor    eax,eax
  4092e9:	e8 62 7f ff ff       	call   401250 <open@plt>
  4092ee:	89 c7                	mov    edi,eax
  4092f0:	85 c0                	test   eax,eax
  4092f2:	79 34                	jns    409328 <win+0x7db2>
  4092f4:	e8 87 7e ff ff       	call   401180 <__errno_location@plt>
  4092f9:	8b 38                	mov    edi,DWORD PTR [rax]
  4092fb:	e8 80 7f ff ff       	call   401280 <strerror@plt>
  409300:	48 8d 35 03 8d 00 00 	lea    rsi,[rip+0x8d03]        # 41200a <_IO_stdin_used+0xa>
  409307:	bf 01 00 00 00       	mov    edi,0x1
  40930c:	48 89 c2             	mov    rdx,rax
  40930f:	31 c0                	xor    eax,eax
  409311:	e8 1a 7f ff ff       	call   401230 <__printf_chk@plt>
  409316:	e8 c5 7e ff ff       	call   4011e0 <geteuid@plt>
  40931b:	85 c0                	test   eax,eax
  40931d:	0f 84 b6 82 ff ff    	je     4015d9 <win+0x63>
  409323:	e9 99 82 ff ff       	jmp    4015c1 <win+0x4b>
  409328:	ba 00 01 00 00       	mov    edx,0x100
  40932d:	48 89 ee             	mov    rsi,rbp
  409330:	e8 cb 7e ff ff       	call   401200 <read@plt>
  409335:	85 c0                	test   eax,eax
  409337:	7f 2a                	jg     409363 <win+0x7ded>
  409339:	e8 42 7e ff ff       	call   401180 <__errno_location@plt>
  40933e:	8b 38                	mov    edi,DWORD PTR [rax]
  409340:	e8 3b 7f ff ff       	call   401280 <strerror@plt>
  409345:	bf 01 00 00 00       	mov    edi,0x1
  40934a:	48 8d 35 58 8d 00 00 	lea    rsi,[rip+0x8d58]        # 4120a9 <_IO_stdin_used+0xa9>
  409351:	48 89 c2             	mov    rdx,rax
  409354:	31 c0                	xor    eax,eax
  409356:	e8 d5 7e ff ff       	call   401230 <__printf_chk@plt>
  40935b:	83 cf ff             	or     edi,0xffffffff
  40935e:	e8 fd 7e ff ff       	call   401260 <exit@plt>
  409363:	48 89 e5             	mov    rbp,rsp
  409366:	48 63 d0             	movsxd rdx,eax
  409369:	bf 01 00 00 00       	mov    edi,0x1
  40936e:	48 89 ee             	mov    rsi,rbp
  409371:	e8 2a 7e ff ff       	call   4011a0 <write@plt>
  409376:	48 8d 3d d7 8d 00 00 	lea    rdi,[rip+0x8dd7]        # 412154 <_IO_stdin_used+0x154>
  40937d:	e8 0e 7e ff ff       	call   401190 <puts@plt>
  409382:	48 8d 3d 7b 8c 00 00 	lea    rdi,[rip+0x8c7b]        # 412004 <_IO_stdin_used+0x4>
  409389:	31 f6                	xor    esi,esi
  40938b:	31 c0                	xor    eax,eax
  40938d:	e8 be 7e ff ff       	call   401250 <open@plt>
  409392:	89 c7                	mov    edi,eax
  409394:	85 c0                	test   eax,eax
  409396:	79 34                	jns    4093cc <win+0x7e56>
  409398:	e8 e3 7d ff ff       	call   401180 <__errno_location@plt>
  40939d:	8b 38                	mov    edi,DWORD PTR [rax]
  40939f:	e8 dc 7e ff ff       	call   401280 <strerror@plt>
  4093a4:	48 8d 35 5f 8c 00 00 	lea    rsi,[rip+0x8c5f]        # 41200a <_IO_stdin_used+0xa>
  4093ab:	bf 01 00 00 00       	mov    edi,0x1
  4093b0:	48 89 c2             	mov    rdx,rax
  4093b3:	31 c0                	xor    eax,eax
  4093b5:	e8 76 7e ff ff       	call   401230 <__printf_chk@plt>
  4093ba:	e8 21 7e ff ff       	call   4011e0 <geteuid@plt>
  4093bf:	85 c0                	test   eax,eax
  4093c1:	0f 84 12 82 ff ff    	je     4015d9 <win+0x63>
  4093c7:	e9 f5 81 ff ff       	jmp    4015c1 <win+0x4b>
  4093cc:	ba 00 01 00 00       	mov    edx,0x100
  4093d1:	48 89 ee             	mov    rsi,rbp
  4093d4:	e8 27 7e ff ff       	call   401200 <read@plt>
  4093d9:	85 c0                	test   eax,eax
  4093db:	7f 2a                	jg     409407 <win+0x7e91>
  4093dd:	e8 9e 7d ff ff       	call   401180 <__errno_location@plt>
  4093e2:	8b 38                	mov    edi,DWORD PTR [rax]
  4093e4:	e8 97 7e ff ff       	call   401280 <strerror@plt>
  4093e9:	bf 01 00 00 00       	mov    edi,0x1
  4093ee:	48 8d 35 b4 8c 00 00 	lea    rsi,[rip+0x8cb4]        # 4120a9 <_IO_stdin_used+0xa9>
  4093f5:	48 89 c2             	mov    rdx,rax
  4093f8:	31 c0                	xor    eax,eax
  4093fa:	e8 31 7e ff ff       	call   401230 <__printf_chk@plt>
  4093ff:	83 cf ff             	or     edi,0xffffffff
  409402:	e8 59 7e ff ff       	call   401260 <exit@plt>
  409407:	48 63 d0             	movsxd rdx,eax
  40940a:	48 89 ee             	mov    rsi,rbp
  40940d:	bf 01 00 00 00       	mov    edi,0x1
  409412:	e8 89 7d ff ff       	call   4011a0 <write@plt>
  409417:	48 8d 3d 36 8d 00 00 	lea    rdi,[rip+0x8d36]        # 412154 <_IO_stdin_used+0x154>
  40941e:	e8 6d 7d ff ff       	call   401190 <puts@plt>
  409423:	48 8d 3d da 8b 00 00 	lea    rdi,[rip+0x8bda]        # 412004 <_IO_stdin_used+0x4>
  40942a:	31 f6                	xor    esi,esi
  40942c:	31 c0                	xor    eax,eax
  40942e:	e8 1d 7e ff ff       	call   401250 <open@plt>
  409433:	89 c7                	mov    edi,eax
  409435:	85 c0                	test   eax,eax
  409437:	79 34                	jns    40946d <win+0x7ef7>
  409439:	e8 42 7d ff ff       	call   401180 <__errno_location@plt>
  40943e:	8b 38                	mov    edi,DWORD PTR [rax]
  409440:	e8 3b 7e ff ff       	call   401280 <strerror@plt>
  409445:	48 8d 35 be 8b 00 00 	lea    rsi,[rip+0x8bbe]        # 41200a <_IO_stdin_used+0xa>
  40944c:	bf 01 00 00 00       	mov    edi,0x1
  409451:	48 89 c2             	mov    rdx,rax
  409454:	31 c0                	xor    eax,eax
  409456:	e8 d5 7d ff ff       	call   401230 <__printf_chk@plt>
  40945b:	e8 80 7d ff ff       	call   4011e0 <geteuid@plt>
  409460:	85 c0                	test   eax,eax
  409462:	0f 84 71 81 ff ff    	je     4015d9 <win+0x63>
  409468:	e9 54 81 ff ff       	jmp    4015c1 <win+0x4b>
  40946d:	ba 00 01 00 00       	mov    edx,0x100
  409472:	48 89 ee             	mov    rsi,rbp
  409475:	e8 86 7d ff ff       	call   401200 <read@plt>
  40947a:	85 c0                	test   eax,eax
  40947c:	7f 2a                	jg     4094a8 <win+0x7f32>
  40947e:	e8 fd 7c ff ff       	call   401180 <__errno_location@plt>
  409483:	8b 38                	mov    edi,DWORD PTR [rax]
  409485:	e8 f6 7d ff ff       	call   401280 <strerror@plt>
  40948a:	bf 01 00 00 00       	mov    edi,0x1
  40948f:	48 8d 35 13 8c 00 00 	lea    rsi,[rip+0x8c13]        # 4120a9 <_IO_stdin_used+0xa9>
  409496:	48 89 c2             	mov    rdx,rax
  409499:	31 c0                	xor    eax,eax
  40949b:	e8 90 7d ff ff       	call   401230 <__printf_chk@plt>
  4094a0:	83 cf ff             	or     edi,0xffffffff
  4094a3:	e8 b8 7d ff ff       	call   401260 <exit@plt>
  4094a8:	48 63 d0             	movsxd rdx,eax
  4094ab:	48 89 ee             	mov    rsi,rbp
  4094ae:	bf 01 00 00 00       	mov    edi,0x1
  4094b3:	e8 e8 7c ff ff       	call   4011a0 <write@plt>
  4094b8:	48 8d 3d 95 8c 00 00 	lea    rdi,[rip+0x8c95]        # 412154 <_IO_stdin_used+0x154>
  4094bf:	e8 cc 7c ff ff       	call   401190 <puts@plt>
  4094c4:	48 8d 3d 39 8b 00 00 	lea    rdi,[rip+0x8b39]        # 412004 <_IO_stdin_used+0x4>
  4094cb:	31 f6                	xor    esi,esi
  4094cd:	31 c0                	xor    eax,eax
  4094cf:	e8 7c 7d ff ff       	call   401250 <open@plt>
  4094d4:	89 c7                	mov    edi,eax
  4094d6:	85 c0                	test   eax,eax
  4094d8:	79 34                	jns    40950e <win+0x7f98>
  4094da:	e8 a1 7c ff ff       	call   401180 <__errno_location@plt>
  4094df:	8b 38                	mov    edi,DWORD PTR [rax]
  4094e1:	e8 9a 7d ff ff       	call   401280 <strerror@plt>
  4094e6:	48 8d 35 1d 8b 00 00 	lea    rsi,[rip+0x8b1d]        # 41200a <_IO_stdin_used+0xa>
  4094ed:	bf 01 00 00 00       	mov    edi,0x1
  4094f2:	48 89 c2             	mov    rdx,rax
  4094f5:	31 c0                	xor    eax,eax
  4094f7:	e8 34 7d ff ff       	call   401230 <__printf_chk@plt>
  4094fc:	e8 df 7c ff ff       	call   4011e0 <geteuid@plt>
  409501:	85 c0                	test   eax,eax
  409503:	0f 84 d0 80 ff ff    	je     4015d9 <win+0x63>
  409509:	e9 b3 80 ff ff       	jmp    4015c1 <win+0x4b>
  40950e:	ba 00 01 00 00       	mov    edx,0x100
  409513:	48 89 ee             	mov    rsi,rbp
  409516:	e8 e5 7c ff ff       	call   401200 <read@plt>
  40951b:	85 c0                	test   eax,eax
  40951d:	7f 2a                	jg     409549 <win+0x7fd3>
  40951f:	e8 5c 7c ff ff       	call   401180 <__errno_location@plt>
  409524:	8b 38                	mov    edi,DWORD PTR [rax]
  409526:	e8 55 7d ff ff       	call   401280 <strerror@plt>
  40952b:	bf 01 00 00 00       	mov    edi,0x1
  409530:	48 8d 35 72 8b 00 00 	lea    rsi,[rip+0x8b72]        # 4120a9 <_IO_stdin_used+0xa9>
  409537:	48 89 c2             	mov    rdx,rax
  40953a:	31 c0                	xor    eax,eax
  40953c:	e8 ef 7c ff ff       	call   401230 <__printf_chk@plt>
  409541:	83 cf ff             	or     edi,0xffffffff
  409544:	e8 17 7d ff ff       	call   401260 <exit@plt>
  409549:	48 63 d0             	movsxd rdx,eax
  40954c:	48 89 ee             	mov    rsi,rbp
  40954f:	bf 01 00 00 00       	mov    edi,0x1
  409554:	e8 47 7c ff ff       	call   4011a0 <write@plt>
  409559:	48 8d 3d f4 8b 00 00 	lea    rdi,[rip+0x8bf4]        # 412154 <_IO_stdin_used+0x154>
  409560:	e8 2b 7c ff ff       	call   401190 <puts@plt>
  409565:	48 8d 3d 98 8a 00 00 	lea    rdi,[rip+0x8a98]        # 412004 <_IO_stdin_used+0x4>
  40956c:	31 f6                	xor    esi,esi
  40956e:	31 c0                	xor    eax,eax
  409570:	e8 db 7c ff ff       	call   401250 <open@plt>
  409575:	89 c7                	mov    edi,eax
  409577:	85 c0                	test   eax,eax
  409579:	79 34                	jns    4095af <win+0x8039>
  40957b:	e8 00 7c ff ff       	call   401180 <__errno_location@plt>
  409580:	8b 38                	mov    edi,DWORD PTR [rax]
  409582:	e8 f9 7c ff ff       	call   401280 <strerror@plt>
  409587:	48 8d 35 7c 8a 00 00 	lea    rsi,[rip+0x8a7c]        # 41200a <_IO_stdin_used+0xa>
  40958e:	bf 01 00 00 00       	mov    edi,0x1
  409593:	48 89 c2             	mov    rdx,rax
  409596:	31 c0                	xor    eax,eax
  409598:	e8 93 7c ff ff       	call   401230 <__printf_chk@plt>
  40959d:	e8 3e 7c ff ff       	call   4011e0 <geteuid@plt>
  4095a2:	85 c0                	test   eax,eax
  4095a4:	0f 84 2f 80 ff ff    	je     4015d9 <win+0x63>
  4095aa:	e9 12 80 ff ff       	jmp    4015c1 <win+0x4b>
  4095af:	ba 00 01 00 00       	mov    edx,0x100
  4095b4:	48 89 ee             	mov    rsi,rbp
  4095b7:	e8 44 7c ff ff       	call   401200 <read@plt>
  4095bc:	85 c0                	test   eax,eax
  4095be:	7f 2a                	jg     4095ea <win+0x8074>
  4095c0:	e8 bb 7b ff ff       	call   401180 <__errno_location@plt>
  4095c5:	8b 38                	mov    edi,DWORD PTR [rax]
  4095c7:	e8 b4 7c ff ff       	call   401280 <strerror@plt>
  4095cc:	bf 01 00 00 00       	mov    edi,0x1
  4095d1:	48 8d 35 d1 8a 00 00 	lea    rsi,[rip+0x8ad1]        # 4120a9 <_IO_stdin_used+0xa9>
  4095d8:	48 89 c2             	mov    rdx,rax
  4095db:	31 c0                	xor    eax,eax
  4095dd:	e8 4e 7c ff ff       	call   401230 <__printf_chk@plt>
  4095e2:	83 cf ff             	or     edi,0xffffffff
  4095e5:	e8 76 7c ff ff       	call   401260 <exit@plt>
  4095ea:	48 63 d0             	movsxd rdx,eax
  4095ed:	48 89 ee             	mov    rsi,rbp
  4095f0:	bf 01 00 00 00       	mov    edi,0x1
  4095f5:	e8 a6 7b ff ff       	call   4011a0 <write@plt>
  4095fa:	48 8d 3d 53 8b 00 00 	lea    rdi,[rip+0x8b53]        # 412154 <_IO_stdin_used+0x154>
  409601:	e8 8a 7b ff ff       	call   401190 <puts@plt>
  409606:	48 8d 3d f7 89 00 00 	lea    rdi,[rip+0x89f7]        # 412004 <_IO_stdin_used+0x4>
  40960d:	31 f6                	xor    esi,esi
  40960f:	31 c0                	xor    eax,eax
  409611:	e8 3a 7c ff ff       	call   401250 <open@plt>
  409616:	89 c7                	mov    edi,eax
  409618:	85 c0                	test   eax,eax
  40961a:	79 34                	jns    409650 <win+0x80da>
  40961c:	e8 5f 7b ff ff       	call   401180 <__errno_location@plt>
  409621:	8b 38                	mov    edi,DWORD PTR [rax]
  409623:	e8 58 7c ff ff       	call   401280 <strerror@plt>
  409628:	48 8d 35 db 89 00 00 	lea    rsi,[rip+0x89db]        # 41200a <_IO_stdin_used+0xa>
  40962f:	bf 01 00 00 00       	mov    edi,0x1
  409634:	48 89 c2             	mov    rdx,rax
  409637:	31 c0                	xor    eax,eax
  409639:	e8 f2 7b ff ff       	call   401230 <__printf_chk@plt>
  40963e:	e8 9d 7b ff ff       	call   4011e0 <geteuid@plt>
  409643:	85 c0                	test   eax,eax
  409645:	0f 84 8e 7f ff ff    	je     4015d9 <win+0x63>
  40964b:	e9 71 7f ff ff       	jmp    4015c1 <win+0x4b>
  409650:	ba 00 01 00 00       	mov    edx,0x100
  409655:	48 89 ee             	mov    rsi,rbp
  409658:	e8 a3 7b ff ff       	call   401200 <read@plt>
  40965d:	85 c0                	test   eax,eax
  40965f:	7f 2a                	jg     40968b <win+0x8115>
  409661:	e8 1a 7b ff ff       	call   401180 <__errno_location@plt>
  409666:	8b 38                	mov    edi,DWORD PTR [rax]
  409668:	e8 13 7c ff ff       	call   401280 <strerror@plt>
  40966d:	bf 01 00 00 00       	mov    edi,0x1
  409672:	48 8d 35 30 8a 00 00 	lea    rsi,[rip+0x8a30]        # 4120a9 <_IO_stdin_used+0xa9>
  409679:	48 89 c2             	mov    rdx,rax
  40967c:	31 c0                	xor    eax,eax
  40967e:	e8 ad 7b ff ff       	call   401230 <__printf_chk@plt>
  409683:	83 cf ff             	or     edi,0xffffffff
  409686:	e8 d5 7b ff ff       	call   401260 <exit@plt>
  40968b:	48 63 d0             	movsxd rdx,eax
  40968e:	48 89 ee             	mov    rsi,rbp
  409691:	bf 01 00 00 00       	mov    edi,0x1
  409696:	e8 05 7b ff ff       	call   4011a0 <write@plt>
  40969b:	48 8d 3d b2 8a 00 00 	lea    rdi,[rip+0x8ab2]        # 412154 <_IO_stdin_used+0x154>
  4096a2:	e8 e9 7a ff ff       	call   401190 <puts@plt>
  4096a7:	48 8d 3d 56 89 00 00 	lea    rdi,[rip+0x8956]        # 412004 <_IO_stdin_used+0x4>
  4096ae:	31 f6                	xor    esi,esi
  4096b0:	31 c0                	xor    eax,eax
  4096b2:	e8 99 7b ff ff       	call   401250 <open@plt>
  4096b7:	89 c7                	mov    edi,eax
  4096b9:	85 c0                	test   eax,eax
  4096bb:	79 34                	jns    4096f1 <win+0x817b>
  4096bd:	e8 be 7a ff ff       	call   401180 <__errno_location@plt>
  4096c2:	8b 38                	mov    edi,DWORD PTR [rax]
  4096c4:	e8 b7 7b ff ff       	call   401280 <strerror@plt>
  4096c9:	48 8d 35 3a 89 00 00 	lea    rsi,[rip+0x893a]        # 41200a <_IO_stdin_used+0xa>
  4096d0:	bf 01 00 00 00       	mov    edi,0x1
  4096d5:	48 89 c2             	mov    rdx,rax
  4096d8:	31 c0                	xor    eax,eax
  4096da:	e8 51 7b ff ff       	call   401230 <__printf_chk@plt>
  4096df:	e8 fc 7a ff ff       	call   4011e0 <geteuid@plt>
  4096e4:	85 c0                	test   eax,eax
  4096e6:	0f 84 ed 7e ff ff    	je     4015d9 <win+0x63>
  4096ec:	e9 d0 7e ff ff       	jmp    4015c1 <win+0x4b>
  4096f1:	ba 00 01 00 00       	mov    edx,0x100
  4096f6:	48 89 ee             	mov    rsi,rbp
  4096f9:	e8 02 7b ff ff       	call   401200 <read@plt>
  4096fe:	85 c0                	test   eax,eax
  409700:	7f 2a                	jg     40972c <win+0x81b6>
  409702:	e8 79 7a ff ff       	call   401180 <__errno_location@plt>
  409707:	8b 38                	mov    edi,DWORD PTR [rax]
  409709:	e8 72 7b ff ff       	call   401280 <strerror@plt>
  40970e:	bf 01 00 00 00       	mov    edi,0x1
  409713:	48 8d 35 8f 89 00 00 	lea    rsi,[rip+0x898f]        # 4120a9 <_IO_stdin_used+0xa9>
  40971a:	48 89 c2             	mov    rdx,rax
  40971d:	31 c0                	xor    eax,eax
  40971f:	e8 0c 7b ff ff       	call   401230 <__printf_chk@plt>
  409724:	83 cf ff             	or     edi,0xffffffff
  409727:	e8 34 7b ff ff       	call   401260 <exit@plt>
  40972c:	48 63 d0             	movsxd rdx,eax
  40972f:	48 89 ee             	mov    rsi,rbp
  409732:	bf 01 00 00 00       	mov    edi,0x1
  409737:	e8 64 7a ff ff       	call   4011a0 <write@plt>
  40973c:	48 8d 3d 11 8a 00 00 	lea    rdi,[rip+0x8a11]        # 412154 <_IO_stdin_used+0x154>
  409743:	e8 48 7a ff ff       	call   401190 <puts@plt>
  409748:	48 8d 3d b5 88 00 00 	lea    rdi,[rip+0x88b5]        # 412004 <_IO_stdin_used+0x4>
  40974f:	31 f6                	xor    esi,esi
  409751:	31 c0                	xor    eax,eax
  409753:	e8 f8 7a ff ff       	call   401250 <open@plt>
  409758:	89 c7                	mov    edi,eax
  40975a:	85 c0                	test   eax,eax
  40975c:	79 34                	jns    409792 <win+0x821c>
  40975e:	e8 1d 7a ff ff       	call   401180 <__errno_location@plt>
  409763:	8b 38                	mov    edi,DWORD PTR [rax]
  409765:	e8 16 7b ff ff       	call   401280 <strerror@plt>
  40976a:	48 8d 35 99 88 00 00 	lea    rsi,[rip+0x8899]        # 41200a <_IO_stdin_used+0xa>
  409771:	bf 01 00 00 00       	mov    edi,0x1
  409776:	48 89 c2             	mov    rdx,rax
  409779:	31 c0                	xor    eax,eax
  40977b:	e8 b0 7a ff ff       	call   401230 <__printf_chk@plt>
  409780:	e8 5b 7a ff ff       	call   4011e0 <geteuid@plt>
  409785:	85 c0                	test   eax,eax
  409787:	0f 84 4c 7e ff ff    	je     4015d9 <win+0x63>
  40978d:	e9 2f 7e ff ff       	jmp    4015c1 <win+0x4b>
  409792:	ba 00 01 00 00       	mov    edx,0x100
  409797:	48 89 ee             	mov    rsi,rbp
  40979a:	e8 61 7a ff ff       	call   401200 <read@plt>
  40979f:	85 c0                	test   eax,eax
  4097a1:	7f 2a                	jg     4097cd <win+0x8257>
  4097a3:	e8 d8 79 ff ff       	call   401180 <__errno_location@plt>
  4097a8:	8b 38                	mov    edi,DWORD PTR [rax]
  4097aa:	e8 d1 7a ff ff       	call   401280 <strerror@plt>
  4097af:	bf 01 00 00 00       	mov    edi,0x1
  4097b4:	48 8d 35 ee 88 00 00 	lea    rsi,[rip+0x88ee]        # 4120a9 <_IO_stdin_used+0xa9>
  4097bb:	48 89 c2             	mov    rdx,rax
  4097be:	31 c0                	xor    eax,eax
  4097c0:	e8 6b 7a ff ff       	call   401230 <__printf_chk@plt>
  4097c5:	83 cf ff             	or     edi,0xffffffff
  4097c8:	e8 93 7a ff ff       	call   401260 <exit@plt>
  4097cd:	48 63 d0             	movsxd rdx,eax
  4097d0:	48 89 ee             	mov    rsi,rbp
  4097d3:	bf 01 00 00 00       	mov    edi,0x1
  4097d8:	e8 c3 79 ff ff       	call   4011a0 <write@plt>
  4097dd:	48 8d 3d 70 89 00 00 	lea    rdi,[rip+0x8970]        # 412154 <_IO_stdin_used+0x154>
  4097e4:	e8 a7 79 ff ff       	call   401190 <puts@plt>
  4097e9:	48 8d 3d 14 88 00 00 	lea    rdi,[rip+0x8814]        # 412004 <_IO_stdin_used+0x4>
  4097f0:	31 f6                	xor    esi,esi
  4097f2:	31 c0                	xor    eax,eax
  4097f4:	e8 57 7a ff ff       	call   401250 <open@plt>
  4097f9:	89 c7                	mov    edi,eax
  4097fb:	85 c0                	test   eax,eax
  4097fd:	79 34                	jns    409833 <win+0x82bd>
  4097ff:	e8 7c 79 ff ff       	call   401180 <__errno_location@plt>
  409804:	8b 38                	mov    edi,DWORD PTR [rax]
  409806:	e8 75 7a ff ff       	call   401280 <strerror@plt>
  40980b:	48 8d 35 f8 87 00 00 	lea    rsi,[rip+0x87f8]        # 41200a <_IO_stdin_used+0xa>
  409812:	bf 01 00 00 00       	mov    edi,0x1
  409817:	48 89 c2             	mov    rdx,rax
  40981a:	31 c0                	xor    eax,eax
  40981c:	e8 0f 7a ff ff       	call   401230 <__printf_chk@plt>
  409821:	e8 ba 79 ff ff       	call   4011e0 <geteuid@plt>
  409826:	85 c0                	test   eax,eax
  409828:	0f 84 ab 7d ff ff    	je     4015d9 <win+0x63>
  40982e:	e9 8e 7d ff ff       	jmp    4015c1 <win+0x4b>
  409833:	ba 00 01 00 00       	mov    edx,0x100
  409838:	48 89 ee             	mov    rsi,rbp
  40983b:	e8 c0 79 ff ff       	call   401200 <read@plt>
  409840:	85 c0                	test   eax,eax
  409842:	7f 2a                	jg     40986e <win+0x82f8>
  409844:	e8 37 79 ff ff       	call   401180 <__errno_location@plt>
  409849:	8b 38                	mov    edi,DWORD PTR [rax]
  40984b:	e8 30 7a ff ff       	call   401280 <strerror@plt>
  409850:	bf 01 00 00 00       	mov    edi,0x1
  409855:	48 8d 35 4d 88 00 00 	lea    rsi,[rip+0x884d]        # 4120a9 <_IO_stdin_used+0xa9>
  40985c:	48 89 c2             	mov    rdx,rax
  40985f:	31 c0                	xor    eax,eax
  409861:	e8 ca 79 ff ff       	call   401230 <__printf_chk@plt>
  409866:	83 cf ff             	or     edi,0xffffffff
  409869:	e8 f2 79 ff ff       	call   401260 <exit@plt>
  40986e:	48 63 d0             	movsxd rdx,eax
  409871:	48 89 ee             	mov    rsi,rbp
  409874:	bf 01 00 00 00       	mov    edi,0x1
  409879:	e8 22 79 ff ff       	call   4011a0 <write@plt>
  40987e:	48 8d 3d cf 88 00 00 	lea    rdi,[rip+0x88cf]        # 412154 <_IO_stdin_used+0x154>
  409885:	e8 06 79 ff ff       	call   401190 <puts@plt>
  40988a:	48 8d 3d 73 87 00 00 	lea    rdi,[rip+0x8773]        # 412004 <_IO_stdin_used+0x4>
  409891:	31 f6                	xor    esi,esi
  409893:	31 c0                	xor    eax,eax
  409895:	e8 b6 79 ff ff       	call   401250 <open@plt>
  40989a:	89 c7                	mov    edi,eax
  40989c:	85 c0                	test   eax,eax
  40989e:	79 34                	jns    4098d4 <win+0x835e>
  4098a0:	e8 db 78 ff ff       	call   401180 <__errno_location@plt>
  4098a5:	8b 38                	mov    edi,DWORD PTR [rax]
  4098a7:	e8 d4 79 ff ff       	call   401280 <strerror@plt>
  4098ac:	48 8d 35 57 87 00 00 	lea    rsi,[rip+0x8757]        # 41200a <_IO_stdin_used+0xa>
  4098b3:	bf 01 00 00 00       	mov    edi,0x1
  4098b8:	48 89 c2             	mov    rdx,rax
  4098bb:	31 c0                	xor    eax,eax
  4098bd:	e8 6e 79 ff ff       	call   401230 <__printf_chk@plt>
  4098c2:	e8 19 79 ff ff       	call   4011e0 <geteuid@plt>
  4098c7:	85 c0                	test   eax,eax
  4098c9:	0f 84 0a 7d ff ff    	je     4015d9 <win+0x63>
  4098cf:	e9 ed 7c ff ff       	jmp    4015c1 <win+0x4b>
  4098d4:	ba 00 01 00 00       	mov    edx,0x100
  4098d9:	48 89 ee             	mov    rsi,rbp
  4098dc:	e8 1f 79 ff ff       	call   401200 <read@plt>
  4098e1:	85 c0                	test   eax,eax
  4098e3:	7f 2a                	jg     40990f <win+0x8399>
  4098e5:	e8 96 78 ff ff       	call   401180 <__errno_location@plt>
  4098ea:	8b 38                	mov    edi,DWORD PTR [rax]
  4098ec:	e8 8f 79 ff ff       	call   401280 <strerror@plt>
  4098f1:	bf 01 00 00 00       	mov    edi,0x1
  4098f6:	48 8d 35 ac 87 00 00 	lea    rsi,[rip+0x87ac]        # 4120a9 <_IO_stdin_used+0xa9>
  4098fd:	48 89 c2             	mov    rdx,rax
  409900:	31 c0                	xor    eax,eax
  409902:	e8 29 79 ff ff       	call   401230 <__printf_chk@plt>
  409907:	83 cf ff             	or     edi,0xffffffff
  40990a:	e8 51 79 ff ff       	call   401260 <exit@plt>
  40990f:	48 63 d0             	movsxd rdx,eax
  409912:	48 89 ee             	mov    rsi,rbp
  409915:	bf 01 00 00 00       	mov    edi,0x1
  40991a:	e8 81 78 ff ff       	call   4011a0 <write@plt>
  40991f:	48 8d 3d 2e 88 00 00 	lea    rdi,[rip+0x882e]        # 412154 <_IO_stdin_used+0x154>
  409926:	e8 65 78 ff ff       	call   401190 <puts@plt>
  40992b:	48 8d 3d d2 86 00 00 	lea    rdi,[rip+0x86d2]        # 412004 <_IO_stdin_used+0x4>
  409932:	31 f6                	xor    esi,esi
  409934:	31 c0                	xor    eax,eax
  409936:	e8 15 79 ff ff       	call   401250 <open@plt>
  40993b:	89 c7                	mov    edi,eax
  40993d:	85 c0                	test   eax,eax
  40993f:	79 34                	jns    409975 <win+0x83ff>
  409941:	e8 3a 78 ff ff       	call   401180 <__errno_location@plt>
  409946:	8b 38                	mov    edi,DWORD PTR [rax]
  409948:	e8 33 79 ff ff       	call   401280 <strerror@plt>
  40994d:	48 8d 35 b6 86 00 00 	lea    rsi,[rip+0x86b6]        # 41200a <_IO_stdin_used+0xa>
  409954:	bf 01 00 00 00       	mov    edi,0x1
  409959:	48 89 c2             	mov    rdx,rax
  40995c:	31 c0                	xor    eax,eax
  40995e:	e8 cd 78 ff ff       	call   401230 <__printf_chk@plt>
  409963:	e8 78 78 ff ff       	call   4011e0 <geteuid@plt>
  409968:	85 c0                	test   eax,eax
  40996a:	0f 84 69 7c ff ff    	je     4015d9 <win+0x63>
  409970:	e9 4c 7c ff ff       	jmp    4015c1 <win+0x4b>
  409975:	ba 00 01 00 00       	mov    edx,0x100
  40997a:	48 89 ee             	mov    rsi,rbp
  40997d:	e8 7e 78 ff ff       	call   401200 <read@plt>
  409982:	85 c0                	test   eax,eax
  409984:	7f 2a                	jg     4099b0 <win+0x843a>
  409986:	e8 f5 77 ff ff       	call   401180 <__errno_location@plt>
  40998b:	8b 38                	mov    edi,DWORD PTR [rax]
  40998d:	e8 ee 78 ff ff       	call   401280 <strerror@plt>
  409992:	bf 01 00 00 00       	mov    edi,0x1
  409997:	48 8d 35 0b 87 00 00 	lea    rsi,[rip+0x870b]        # 4120a9 <_IO_stdin_used+0xa9>
  40999e:	48 89 c2             	mov    rdx,rax
  4099a1:	31 c0                	xor    eax,eax
  4099a3:	e8 88 78 ff ff       	call   401230 <__printf_chk@plt>
  4099a8:	83 cf ff             	or     edi,0xffffffff
  4099ab:	e8 b0 78 ff ff       	call   401260 <exit@plt>
  4099b0:	48 63 d0             	movsxd rdx,eax
  4099b3:	48 89 ee             	mov    rsi,rbp
  4099b6:	bf 01 00 00 00       	mov    edi,0x1
  4099bb:	e8 e0 77 ff ff       	call   4011a0 <write@plt>
  4099c0:	48 8d 3d 8d 87 00 00 	lea    rdi,[rip+0x878d]        # 412154 <_IO_stdin_used+0x154>
  4099c7:	e8 c4 77 ff ff       	call   401190 <puts@plt>
  4099cc:	48 8d 3d 31 86 00 00 	lea    rdi,[rip+0x8631]        # 412004 <_IO_stdin_used+0x4>
  4099d3:	31 f6                	xor    esi,esi
  4099d5:	31 c0                	xor    eax,eax
  4099d7:	e8 74 78 ff ff       	call   401250 <open@plt>
  4099dc:	89 c7                	mov    edi,eax
  4099de:	85 c0                	test   eax,eax
  4099e0:	79 34                	jns    409a16 <win+0x84a0>
  4099e2:	e8 99 77 ff ff       	call   401180 <__errno_location@plt>
  4099e7:	8b 38                	mov    edi,DWORD PTR [rax]
  4099e9:	e8 92 78 ff ff       	call   401280 <strerror@plt>
  4099ee:	48 8d 35 15 86 00 00 	lea    rsi,[rip+0x8615]        # 41200a <_IO_stdin_used+0xa>
  4099f5:	bf 01 00 00 00       	mov    edi,0x1
  4099fa:	48 89 c2             	mov    rdx,rax
  4099fd:	31 c0                	xor    eax,eax
  4099ff:	e8 2c 78 ff ff       	call   401230 <__printf_chk@plt>
  409a04:	e8 d7 77 ff ff       	call   4011e0 <geteuid@plt>
  409a09:	85 c0                	test   eax,eax
  409a0b:	0f 84 c8 7b ff ff    	je     4015d9 <win+0x63>
  409a11:	e9 ab 7b ff ff       	jmp    4015c1 <win+0x4b>
  409a16:	ba 00 01 00 00       	mov    edx,0x100
  409a1b:	48 89 ee             	mov    rsi,rbp
  409a1e:	e8 dd 77 ff ff       	call   401200 <read@plt>
  409a23:	85 c0                	test   eax,eax
  409a25:	7f 2a                	jg     409a51 <win+0x84db>
  409a27:	e8 54 77 ff ff       	call   401180 <__errno_location@plt>
  409a2c:	8b 38                	mov    edi,DWORD PTR [rax]
  409a2e:	e8 4d 78 ff ff       	call   401280 <strerror@plt>
  409a33:	bf 01 00 00 00       	mov    edi,0x1
  409a38:	48 8d 35 6a 86 00 00 	lea    rsi,[rip+0x866a]        # 4120a9 <_IO_stdin_used+0xa9>
  409a3f:	48 89 c2             	mov    rdx,rax
  409a42:	31 c0                	xor    eax,eax
  409a44:	e8 e7 77 ff ff       	call   401230 <__printf_chk@plt>
  409a49:	83 cf ff             	or     edi,0xffffffff
  409a4c:	e8 0f 78 ff ff       	call   401260 <exit@plt>
  409a51:	48 63 d0             	movsxd rdx,eax
  409a54:	48 89 ee             	mov    rsi,rbp
  409a57:	bf 01 00 00 00       	mov    edi,0x1
  409a5c:	e8 3f 77 ff ff       	call   4011a0 <write@plt>
  409a61:	48 8d 3d ec 86 00 00 	lea    rdi,[rip+0x86ec]        # 412154 <_IO_stdin_used+0x154>
  409a68:	e8 23 77 ff ff       	call   401190 <puts@plt>
  409a6d:	48 8d 3d 90 85 00 00 	lea    rdi,[rip+0x8590]        # 412004 <_IO_stdin_used+0x4>
  409a74:	31 f6                	xor    esi,esi
  409a76:	31 c0                	xor    eax,eax
  409a78:	e8 d3 77 ff ff       	call   401250 <open@plt>
  409a7d:	89 c7                	mov    edi,eax
  409a7f:	85 c0                	test   eax,eax
  409a81:	79 34                	jns    409ab7 <win+0x8541>
  409a83:	e8 f8 76 ff ff       	call   401180 <__errno_location@plt>
  409a88:	8b 38                	mov    edi,DWORD PTR [rax]
  409a8a:	e8 f1 77 ff ff       	call   401280 <strerror@plt>
  409a8f:	48 8d 35 74 85 00 00 	lea    rsi,[rip+0x8574]        # 41200a <_IO_stdin_used+0xa>
  409a96:	bf 01 00 00 00       	mov    edi,0x1
  409a9b:	48 89 c2             	mov    rdx,rax
  409a9e:	31 c0                	xor    eax,eax
  409aa0:	e8 8b 77 ff ff       	call   401230 <__printf_chk@plt>
  409aa5:	e8 36 77 ff ff       	call   4011e0 <geteuid@plt>
  409aaa:	85 c0                	test   eax,eax
  409aac:	0f 84 27 7b ff ff    	je     4015d9 <win+0x63>
  409ab2:	e9 0a 7b ff ff       	jmp    4015c1 <win+0x4b>
  409ab7:	ba 00 01 00 00       	mov    edx,0x100
  409abc:	48 89 ee             	mov    rsi,rbp
  409abf:	e8 3c 77 ff ff       	call   401200 <read@plt>
  409ac4:	85 c0                	test   eax,eax
  409ac6:	7f 2a                	jg     409af2 <win+0x857c>
  409ac8:	e8 b3 76 ff ff       	call   401180 <__errno_location@plt>
  409acd:	8b 38                	mov    edi,DWORD PTR [rax]
  409acf:	e8 ac 77 ff ff       	call   401280 <strerror@plt>
  409ad4:	bf 01 00 00 00       	mov    edi,0x1
  409ad9:	48 8d 35 c9 85 00 00 	lea    rsi,[rip+0x85c9]        # 4120a9 <_IO_stdin_used+0xa9>
  409ae0:	48 89 c2             	mov    rdx,rax
  409ae3:	31 c0                	xor    eax,eax
  409ae5:	e8 46 77 ff ff       	call   401230 <__printf_chk@plt>
  409aea:	83 cf ff             	or     edi,0xffffffff
  409aed:	e8 6e 77 ff ff       	call   401260 <exit@plt>
  409af2:	48 63 d0             	movsxd rdx,eax
  409af5:	48 89 ee             	mov    rsi,rbp
  409af8:	bf 01 00 00 00       	mov    edi,0x1
  409afd:	e8 9e 76 ff ff       	call   4011a0 <write@plt>
  409b02:	48 8d 3d 4b 86 00 00 	lea    rdi,[rip+0x864b]        # 412154 <_IO_stdin_used+0x154>
  409b09:	e8 82 76 ff ff       	call   401190 <puts@plt>
  409b0e:	48 8d 3d ef 84 00 00 	lea    rdi,[rip+0x84ef]        # 412004 <_IO_stdin_used+0x4>
  409b15:	31 f6                	xor    esi,esi
  409b17:	31 c0                	xor    eax,eax
  409b19:	e8 32 77 ff ff       	call   401250 <open@plt>
  409b1e:	89 c7                	mov    edi,eax
  409b20:	85 c0                	test   eax,eax
  409b22:	79 34                	jns    409b58 <win+0x85e2>
  409b24:	e8 57 76 ff ff       	call   401180 <__errno_location@plt>
  409b29:	8b 38                	mov    edi,DWORD PTR [rax]
  409b2b:	e8 50 77 ff ff       	call   401280 <strerror@plt>
  409b30:	48 8d 35 d3 84 00 00 	lea    rsi,[rip+0x84d3]        # 41200a <_IO_stdin_used+0xa>
  409b37:	bf 01 00 00 00       	mov    edi,0x1
  409b3c:	48 89 c2             	mov    rdx,rax
  409b3f:	31 c0                	xor    eax,eax
  409b41:	e8 ea 76 ff ff       	call   401230 <__printf_chk@plt>
  409b46:	e8 95 76 ff ff       	call   4011e0 <geteuid@plt>
  409b4b:	85 c0                	test   eax,eax
  409b4d:	0f 84 86 7a ff ff    	je     4015d9 <win+0x63>
  409b53:	e9 69 7a ff ff       	jmp    4015c1 <win+0x4b>
  409b58:	ba 00 01 00 00       	mov    edx,0x100
  409b5d:	48 89 ee             	mov    rsi,rbp
  409b60:	e8 9b 76 ff ff       	call   401200 <read@plt>
  409b65:	85 c0                	test   eax,eax
  409b67:	7f 2a                	jg     409b93 <win+0x861d>
  409b69:	e8 12 76 ff ff       	call   401180 <__errno_location@plt>
  409b6e:	8b 38                	mov    edi,DWORD PTR [rax]
  409b70:	e8 0b 77 ff ff       	call   401280 <strerror@plt>
  409b75:	bf 01 00 00 00       	mov    edi,0x1
  409b7a:	48 8d 35 28 85 00 00 	lea    rsi,[rip+0x8528]        # 4120a9 <_IO_stdin_used+0xa9>
  409b81:	48 89 c2             	mov    rdx,rax
  409b84:	31 c0                	xor    eax,eax
  409b86:	e8 a5 76 ff ff       	call   401230 <__printf_chk@plt>
  409b8b:	83 cf ff             	or     edi,0xffffffff
  409b8e:	e8 cd 76 ff ff       	call   401260 <exit@plt>
  409b93:	48 63 d0             	movsxd rdx,eax
  409b96:	48 89 ee             	mov    rsi,rbp
  409b99:	bf 01 00 00 00       	mov    edi,0x1
  409b9e:	e8 fd 75 ff ff       	call   4011a0 <write@plt>
  409ba3:	48 8d 3d aa 85 00 00 	lea    rdi,[rip+0x85aa]        # 412154 <_IO_stdin_used+0x154>
  409baa:	e8 e1 75 ff ff       	call   401190 <puts@plt>
  409baf:	48 8d 3d 4e 84 00 00 	lea    rdi,[rip+0x844e]        # 412004 <_IO_stdin_used+0x4>
  409bb6:	31 f6                	xor    esi,esi
  409bb8:	31 c0                	xor    eax,eax
  409bba:	e8 91 76 ff ff       	call   401250 <open@plt>
  409bbf:	89 c7                	mov    edi,eax
  409bc1:	85 c0                	test   eax,eax
  409bc3:	79 34                	jns    409bf9 <win+0x8683>
  409bc5:	e8 b6 75 ff ff       	call   401180 <__errno_location@plt>
  409bca:	8b 38                	mov    edi,DWORD PTR [rax]
  409bcc:	e8 af 76 ff ff       	call   401280 <strerror@plt>
  409bd1:	48 8d 35 32 84 00 00 	lea    rsi,[rip+0x8432]        # 41200a <_IO_stdin_used+0xa>
  409bd8:	bf 01 00 00 00       	mov    edi,0x1
  409bdd:	48 89 c2             	mov    rdx,rax
  409be0:	31 c0                	xor    eax,eax
  409be2:	e8 49 76 ff ff       	call   401230 <__printf_chk@plt>
  409be7:	e8 f4 75 ff ff       	call   4011e0 <geteuid@plt>
  409bec:	85 c0                	test   eax,eax
  409bee:	0f 84 e5 79 ff ff    	je     4015d9 <win+0x63>
  409bf4:	e9 c8 79 ff ff       	jmp    4015c1 <win+0x4b>
  409bf9:	ba 00 01 00 00       	mov    edx,0x100
  409bfe:	48 89 ee             	mov    rsi,rbp
  409c01:	e8 fa 75 ff ff       	call   401200 <read@plt>
  409c06:	85 c0                	test   eax,eax
  409c08:	7f 2a                	jg     409c34 <win+0x86be>
  409c0a:	e8 71 75 ff ff       	call   401180 <__errno_location@plt>
  409c0f:	8b 38                	mov    edi,DWORD PTR [rax]
  409c11:	e8 6a 76 ff ff       	call   401280 <strerror@plt>
  409c16:	bf 01 00 00 00       	mov    edi,0x1
  409c1b:	48 8d 35 87 84 00 00 	lea    rsi,[rip+0x8487]        # 4120a9 <_IO_stdin_used+0xa9>
  409c22:	48 89 c2             	mov    rdx,rax
  409c25:	31 c0                	xor    eax,eax
  409c27:	e8 04 76 ff ff       	call   401230 <__printf_chk@plt>
  409c2c:	83 cf ff             	or     edi,0xffffffff
  409c2f:	e8 2c 76 ff ff       	call   401260 <exit@plt>
  409c34:	48 63 d0             	movsxd rdx,eax
  409c37:	48 89 ee             	mov    rsi,rbp
  409c3a:	bf 01 00 00 00       	mov    edi,0x1
  409c3f:	e8 5c 75 ff ff       	call   4011a0 <write@plt>
  409c44:	48 8d 3d 09 85 00 00 	lea    rdi,[rip+0x8509]        # 412154 <_IO_stdin_used+0x154>
  409c4b:	e8 40 75 ff ff       	call   401190 <puts@plt>
  409c50:	48 8d 3d ad 83 00 00 	lea    rdi,[rip+0x83ad]        # 412004 <_IO_stdin_used+0x4>
  409c57:	31 f6                	xor    esi,esi
  409c59:	31 c0                	xor    eax,eax
  409c5b:	e8 f0 75 ff ff       	call   401250 <open@plt>
  409c60:	89 c7                	mov    edi,eax
  409c62:	85 c0                	test   eax,eax
  409c64:	79 34                	jns    409c9a <win+0x8724>
  409c66:	e8 15 75 ff ff       	call   401180 <__errno_location@plt>
  409c6b:	8b 38                	mov    edi,DWORD PTR [rax]
  409c6d:	e8 0e 76 ff ff       	call   401280 <strerror@plt>
  409c72:	48 8d 35 91 83 00 00 	lea    rsi,[rip+0x8391]        # 41200a <_IO_stdin_used+0xa>
  409c79:	bf 01 00 00 00       	mov    edi,0x1
  409c7e:	48 89 c2             	mov    rdx,rax
  409c81:	31 c0                	xor    eax,eax
  409c83:	e8 a8 75 ff ff       	call   401230 <__printf_chk@plt>
  409c88:	e8 53 75 ff ff       	call   4011e0 <geteuid@plt>
  409c8d:	85 c0                	test   eax,eax
  409c8f:	0f 84 44 79 ff ff    	je     4015d9 <win+0x63>
  409c95:	e9 27 79 ff ff       	jmp    4015c1 <win+0x4b>
  409c9a:	ba 00 01 00 00       	mov    edx,0x100
  409c9f:	48 89 ee             	mov    rsi,rbp
  409ca2:	e8 59 75 ff ff       	call   401200 <read@plt>
  409ca7:	85 c0                	test   eax,eax
  409ca9:	7f 2a                	jg     409cd5 <win+0x875f>
  409cab:	e8 d0 74 ff ff       	call   401180 <__errno_location@plt>
  409cb0:	8b 38                	mov    edi,DWORD PTR [rax]
  409cb2:	e8 c9 75 ff ff       	call   401280 <strerror@plt>
  409cb7:	bf 01 00 00 00       	mov    edi,0x1
  409cbc:	48 8d 35 e6 83 00 00 	lea    rsi,[rip+0x83e6]        # 4120a9 <_IO_stdin_used+0xa9>
  409cc3:	48 89 c2             	mov    rdx,rax
  409cc6:	31 c0                	xor    eax,eax
  409cc8:	e8 63 75 ff ff       	call   401230 <__printf_chk@plt>
  409ccd:	83 cf ff             	or     edi,0xffffffff
  409cd0:	e8 8b 75 ff ff       	call   401260 <exit@plt>
  409cd5:	48 63 d0             	movsxd rdx,eax
  409cd8:	48 89 ee             	mov    rsi,rbp
  409cdb:	bf 01 00 00 00       	mov    edi,0x1
  409ce0:	e8 bb 74 ff ff       	call   4011a0 <write@plt>
  409ce5:	48 8d 3d 68 84 00 00 	lea    rdi,[rip+0x8468]        # 412154 <_IO_stdin_used+0x154>
  409cec:	e8 9f 74 ff ff       	call   401190 <puts@plt>
  409cf1:	48 8d 3d 0c 83 00 00 	lea    rdi,[rip+0x830c]        # 412004 <_IO_stdin_used+0x4>
  409cf8:	31 f6                	xor    esi,esi
  409cfa:	31 c0                	xor    eax,eax
  409cfc:	e8 4f 75 ff ff       	call   401250 <open@plt>
  409d01:	89 c7                	mov    edi,eax
  409d03:	85 c0                	test   eax,eax
  409d05:	79 34                	jns    409d3b <win+0x87c5>
  409d07:	e8 74 74 ff ff       	call   401180 <__errno_location@plt>
  409d0c:	8b 38                	mov    edi,DWORD PTR [rax]
  409d0e:	e8 6d 75 ff ff       	call   401280 <strerror@plt>
  409d13:	48 8d 35 f0 82 00 00 	lea    rsi,[rip+0x82f0]        # 41200a <_IO_stdin_used+0xa>
  409d1a:	bf 01 00 00 00       	mov    edi,0x1
  409d1f:	48 89 c2             	mov    rdx,rax
  409d22:	31 c0                	xor    eax,eax
  409d24:	e8 07 75 ff ff       	call   401230 <__printf_chk@plt>
  409d29:	e8 b2 74 ff ff       	call   4011e0 <geteuid@plt>
  409d2e:	85 c0                	test   eax,eax
  409d30:	0f 84 a3 78 ff ff    	je     4015d9 <win+0x63>
  409d36:	e9 86 78 ff ff       	jmp    4015c1 <win+0x4b>
  409d3b:	ba 00 01 00 00       	mov    edx,0x100
  409d40:	48 89 ee             	mov    rsi,rbp
  409d43:	e8 b8 74 ff ff       	call   401200 <read@plt>
  409d48:	85 c0                	test   eax,eax
  409d4a:	7f 2a                	jg     409d76 <win+0x8800>
  409d4c:	e8 2f 74 ff ff       	call   401180 <__errno_location@plt>
  409d51:	8b 38                	mov    edi,DWORD PTR [rax]
  409d53:	e8 28 75 ff ff       	call   401280 <strerror@plt>
  409d58:	bf 01 00 00 00       	mov    edi,0x1
  409d5d:	48 8d 35 45 83 00 00 	lea    rsi,[rip+0x8345]        # 4120a9 <_IO_stdin_used+0xa9>
  409d64:	48 89 c2             	mov    rdx,rax
  409d67:	31 c0                	xor    eax,eax
  409d69:	e8 c2 74 ff ff       	call   401230 <__printf_chk@plt>
  409d6e:	83 cf ff             	or     edi,0xffffffff
  409d71:	e8 ea 74 ff ff       	call   401260 <exit@plt>
  409d76:	48 63 d0             	movsxd rdx,eax
  409d79:	48 89 ee             	mov    rsi,rbp
  409d7c:	bf 01 00 00 00       	mov    edi,0x1
  409d81:	e8 1a 74 ff ff       	call   4011a0 <write@plt>
  409d86:	48 8d 3d c7 83 00 00 	lea    rdi,[rip+0x83c7]        # 412154 <_IO_stdin_used+0x154>
  409d8d:	e8 fe 73 ff ff       	call   401190 <puts@plt>
  409d92:	48 8d 3d 6b 82 00 00 	lea    rdi,[rip+0x826b]        # 412004 <_IO_stdin_used+0x4>
  409d99:	31 f6                	xor    esi,esi
  409d9b:	31 c0                	xor    eax,eax
  409d9d:	e8 ae 74 ff ff       	call   401250 <open@plt>
  409da2:	89 c7                	mov    edi,eax
  409da4:	85 c0                	test   eax,eax
  409da6:	79 34                	jns    409ddc <win+0x8866>
  409da8:	e8 d3 73 ff ff       	call   401180 <__errno_location@plt>
  409dad:	8b 38                	mov    edi,DWORD PTR [rax]
  409daf:	e8 cc 74 ff ff       	call   401280 <strerror@plt>
  409db4:	48 8d 35 4f 82 00 00 	lea    rsi,[rip+0x824f]        # 41200a <_IO_stdin_used+0xa>
  409dbb:	bf 01 00 00 00       	mov    edi,0x1
  409dc0:	48 89 c2             	mov    rdx,rax
  409dc3:	31 c0                	xor    eax,eax
  409dc5:	e8 66 74 ff ff       	call   401230 <__printf_chk@plt>
  409dca:	e8 11 74 ff ff       	call   4011e0 <geteuid@plt>
  409dcf:	85 c0                	test   eax,eax
  409dd1:	0f 84 02 78 ff ff    	je     4015d9 <win+0x63>
  409dd7:	e9 e5 77 ff ff       	jmp    4015c1 <win+0x4b>
  409ddc:	ba 00 01 00 00       	mov    edx,0x100
  409de1:	48 89 ee             	mov    rsi,rbp
  409de4:	e8 17 74 ff ff       	call   401200 <read@plt>
  409de9:	85 c0                	test   eax,eax
  409deb:	7f 2a                	jg     409e17 <win+0x88a1>
  409ded:	e8 8e 73 ff ff       	call   401180 <__errno_location@plt>
  409df2:	8b 38                	mov    edi,DWORD PTR [rax]
  409df4:	e8 87 74 ff ff       	call   401280 <strerror@plt>
  409df9:	bf 01 00 00 00       	mov    edi,0x1
  409dfe:	48 8d 35 a4 82 00 00 	lea    rsi,[rip+0x82a4]        # 4120a9 <_IO_stdin_used+0xa9>
  409e05:	48 89 c2             	mov    rdx,rax
  409e08:	31 c0                	xor    eax,eax
  409e0a:	e8 21 74 ff ff       	call   401230 <__printf_chk@plt>
  409e0f:	83 cf ff             	or     edi,0xffffffff
  409e12:	e8 49 74 ff ff       	call   401260 <exit@plt>
  409e17:	48 63 d0             	movsxd rdx,eax
  409e1a:	48 89 ee             	mov    rsi,rbp
  409e1d:	bf 01 00 00 00       	mov    edi,0x1
  409e22:	e8 79 73 ff ff       	call   4011a0 <write@plt>
  409e27:	48 8d 3d 26 83 00 00 	lea    rdi,[rip+0x8326]        # 412154 <_IO_stdin_used+0x154>
  409e2e:	e8 5d 73 ff ff       	call   401190 <puts@plt>
  409e33:	48 8d 3d ca 81 00 00 	lea    rdi,[rip+0x81ca]        # 412004 <_IO_stdin_used+0x4>
  409e3a:	31 f6                	xor    esi,esi
  409e3c:	31 c0                	xor    eax,eax
  409e3e:	e8 0d 74 ff ff       	call   401250 <open@plt>
  409e43:	89 c7                	mov    edi,eax
  409e45:	85 c0                	test   eax,eax
  409e47:	79 34                	jns    409e7d <win+0x8907>
  409e49:	e8 32 73 ff ff       	call   401180 <__errno_location@plt>
  409e4e:	8b 38                	mov    edi,DWORD PTR [rax]
  409e50:	e8 2b 74 ff ff       	call   401280 <strerror@plt>
  409e55:	48 8d 35 ae 81 00 00 	lea    rsi,[rip+0x81ae]        # 41200a <_IO_stdin_used+0xa>
  409e5c:	bf 01 00 00 00       	mov    edi,0x1
  409e61:	48 89 c2             	mov    rdx,rax
  409e64:	31 c0                	xor    eax,eax
  409e66:	e8 c5 73 ff ff       	call   401230 <__printf_chk@plt>
  409e6b:	e8 70 73 ff ff       	call   4011e0 <geteuid@plt>
  409e70:	85 c0                	test   eax,eax
  409e72:	0f 84 61 77 ff ff    	je     4015d9 <win+0x63>
  409e78:	e9 44 77 ff ff       	jmp    4015c1 <win+0x4b>
  409e7d:	ba 00 01 00 00       	mov    edx,0x100
  409e82:	48 89 ee             	mov    rsi,rbp
  409e85:	e8 76 73 ff ff       	call   401200 <read@plt>
  409e8a:	85 c0                	test   eax,eax
  409e8c:	7f 2a                	jg     409eb8 <win+0x8942>
  409e8e:	e8 ed 72 ff ff       	call   401180 <__errno_location@plt>
  409e93:	8b 38                	mov    edi,DWORD PTR [rax]
  409e95:	e8 e6 73 ff ff       	call   401280 <strerror@plt>
  409e9a:	bf 01 00 00 00       	mov    edi,0x1
  409e9f:	48 8d 35 03 82 00 00 	lea    rsi,[rip+0x8203]        # 4120a9 <_IO_stdin_used+0xa9>
  409ea6:	48 89 c2             	mov    rdx,rax
  409ea9:	31 c0                	xor    eax,eax
  409eab:	e8 80 73 ff ff       	call   401230 <__printf_chk@plt>
  409eb0:	83 cf ff             	or     edi,0xffffffff
  409eb3:	e8 a8 73 ff ff       	call   401260 <exit@plt>
  409eb8:	48 63 d0             	movsxd rdx,eax
  409ebb:	48 89 ee             	mov    rsi,rbp
  409ebe:	bf 01 00 00 00       	mov    edi,0x1
  409ec3:	e8 d8 72 ff ff       	call   4011a0 <write@plt>
  409ec8:	48 8d 3d 85 82 00 00 	lea    rdi,[rip+0x8285]        # 412154 <_IO_stdin_used+0x154>
  409ecf:	e8 bc 72 ff ff       	call   401190 <puts@plt>
  409ed4:	48 8d 3d 29 81 00 00 	lea    rdi,[rip+0x8129]        # 412004 <_IO_stdin_used+0x4>
  409edb:	31 f6                	xor    esi,esi
  409edd:	31 c0                	xor    eax,eax
  409edf:	e8 6c 73 ff ff       	call   401250 <open@plt>
  409ee4:	89 c7                	mov    edi,eax
  409ee6:	85 c0                	test   eax,eax
  409ee8:	79 34                	jns    409f1e <win+0x89a8>
  409eea:	e8 91 72 ff ff       	call   401180 <__errno_location@plt>
  409eef:	8b 38                	mov    edi,DWORD PTR [rax]
  409ef1:	e8 8a 73 ff ff       	call   401280 <strerror@plt>
  409ef6:	48 8d 35 0d 81 00 00 	lea    rsi,[rip+0x810d]        # 41200a <_IO_stdin_used+0xa>
  409efd:	bf 01 00 00 00       	mov    edi,0x1
  409f02:	48 89 c2             	mov    rdx,rax
  409f05:	31 c0                	xor    eax,eax
  409f07:	e8 24 73 ff ff       	call   401230 <__printf_chk@plt>
  409f0c:	e8 cf 72 ff ff       	call   4011e0 <geteuid@plt>
  409f11:	85 c0                	test   eax,eax
  409f13:	0f 84 c0 76 ff ff    	je     4015d9 <win+0x63>
  409f19:	e9 a3 76 ff ff       	jmp    4015c1 <win+0x4b>
  409f1e:	ba 00 01 00 00       	mov    edx,0x100
  409f23:	48 89 ee             	mov    rsi,rbp
  409f26:	e8 d5 72 ff ff       	call   401200 <read@plt>
  409f2b:	85 c0                	test   eax,eax
  409f2d:	7f 2a                	jg     409f59 <win+0x89e3>
  409f2f:	e8 4c 72 ff ff       	call   401180 <__errno_location@plt>
  409f34:	8b 38                	mov    edi,DWORD PTR [rax]
  409f36:	e8 45 73 ff ff       	call   401280 <strerror@plt>
  409f3b:	bf 01 00 00 00       	mov    edi,0x1
  409f40:	48 8d 35 62 81 00 00 	lea    rsi,[rip+0x8162]        # 4120a9 <_IO_stdin_used+0xa9>
  409f47:	48 89 c2             	mov    rdx,rax
  409f4a:	31 c0                	xor    eax,eax
  409f4c:	e8 df 72 ff ff       	call   401230 <__printf_chk@plt>
  409f51:	83 cf ff             	or     edi,0xffffffff
  409f54:	e8 07 73 ff ff       	call   401260 <exit@plt>
  409f59:	48 63 d0             	movsxd rdx,eax
  409f5c:	48 89 ee             	mov    rsi,rbp
  409f5f:	bf 01 00 00 00       	mov    edi,0x1
  409f64:	e8 37 72 ff ff       	call   4011a0 <write@plt>
  409f69:	48 8d 3d e4 81 00 00 	lea    rdi,[rip+0x81e4]        # 412154 <_IO_stdin_used+0x154>
  409f70:	e8 1b 72 ff ff       	call   401190 <puts@plt>
  409f75:	48 8d 3d 88 80 00 00 	lea    rdi,[rip+0x8088]        # 412004 <_IO_stdin_used+0x4>
  409f7c:	31 f6                	xor    esi,esi
  409f7e:	31 c0                	xor    eax,eax
  409f80:	e8 cb 72 ff ff       	call   401250 <open@plt>
  409f85:	89 c7                	mov    edi,eax
  409f87:	85 c0                	test   eax,eax
  409f89:	79 34                	jns    409fbf <win+0x8a49>
  409f8b:	e8 f0 71 ff ff       	call   401180 <__errno_location@plt>
  409f90:	8b 38                	mov    edi,DWORD PTR [rax]
  409f92:	e8 e9 72 ff ff       	call   401280 <strerror@plt>
  409f97:	48 8d 35 6c 80 00 00 	lea    rsi,[rip+0x806c]        # 41200a <_IO_stdin_used+0xa>
  409f9e:	bf 01 00 00 00       	mov    edi,0x1
  409fa3:	48 89 c2             	mov    rdx,rax
  409fa6:	31 c0                	xor    eax,eax
  409fa8:	e8 83 72 ff ff       	call   401230 <__printf_chk@plt>
  409fad:	e8 2e 72 ff ff       	call   4011e0 <geteuid@plt>
  409fb2:	85 c0                	test   eax,eax
  409fb4:	0f 84 1f 76 ff ff    	je     4015d9 <win+0x63>
  409fba:	e9 02 76 ff ff       	jmp    4015c1 <win+0x4b>
  409fbf:	ba 00 01 00 00       	mov    edx,0x100
  409fc4:	48 89 ee             	mov    rsi,rbp
  409fc7:	e8 34 72 ff ff       	call   401200 <read@plt>
  409fcc:	85 c0                	test   eax,eax
  409fce:	7f 2a                	jg     409ffa <win+0x8a84>
  409fd0:	e8 ab 71 ff ff       	call   401180 <__errno_location@plt>
  409fd5:	8b 38                	mov    edi,DWORD PTR [rax]
  409fd7:	e8 a4 72 ff ff       	call   401280 <strerror@plt>
  409fdc:	bf 01 00 00 00       	mov    edi,0x1
  409fe1:	48 8d 35 c1 80 00 00 	lea    rsi,[rip+0x80c1]        # 4120a9 <_IO_stdin_used+0xa9>
  409fe8:	48 89 c2             	mov    rdx,rax
  409feb:	31 c0                	xor    eax,eax
  409fed:	e8 3e 72 ff ff       	call   401230 <__printf_chk@plt>
  409ff2:	83 cf ff             	or     edi,0xffffffff
  409ff5:	e8 66 72 ff ff       	call   401260 <exit@plt>
  409ffa:	48 89 e5             	mov    rbp,rsp
  409ffd:	48 63 d0             	movsxd rdx,eax
  40a000:	bf 01 00 00 00       	mov    edi,0x1
  40a005:	48 89 ee             	mov    rsi,rbp
  40a008:	e8 93 71 ff ff       	call   4011a0 <write@plt>
  40a00d:	48 8d 3d 40 81 00 00 	lea    rdi,[rip+0x8140]        # 412154 <_IO_stdin_used+0x154>
  40a014:	e8 77 71 ff ff       	call   401190 <puts@plt>
  40a019:	48 8d 3d e4 7f 00 00 	lea    rdi,[rip+0x7fe4]        # 412004 <_IO_stdin_used+0x4>
  40a020:	31 f6                	xor    esi,esi
  40a022:	31 c0                	xor    eax,eax
  40a024:	e8 27 72 ff ff       	call   401250 <open@plt>
  40a029:	89 c7                	mov    edi,eax
  40a02b:	85 c0                	test   eax,eax
  40a02d:	79 34                	jns    40a063 <win+0x8aed>
  40a02f:	e8 4c 71 ff ff       	call   401180 <__errno_location@plt>
  40a034:	8b 38                	mov    edi,DWORD PTR [rax]
  40a036:	e8 45 72 ff ff       	call   401280 <strerror@plt>
  40a03b:	48 8d 35 c8 7f 00 00 	lea    rsi,[rip+0x7fc8]        # 41200a <_IO_stdin_used+0xa>
  40a042:	bf 01 00 00 00       	mov    edi,0x1
  40a047:	48 89 c2             	mov    rdx,rax
  40a04a:	31 c0                	xor    eax,eax
  40a04c:	e8 df 71 ff ff       	call   401230 <__printf_chk@plt>
  40a051:	e8 8a 71 ff ff       	call   4011e0 <geteuid@plt>
  40a056:	85 c0                	test   eax,eax
  40a058:	0f 84 7b 75 ff ff    	je     4015d9 <win+0x63>
  40a05e:	e9 5e 75 ff ff       	jmp    4015c1 <win+0x4b>
  40a063:	ba 00 01 00 00       	mov    edx,0x100
  40a068:	48 89 ee             	mov    rsi,rbp
  40a06b:	e8 90 71 ff ff       	call   401200 <read@plt>
  40a070:	85 c0                	test   eax,eax
  40a072:	7f 2a                	jg     40a09e <win+0x8b28>
  40a074:	e8 07 71 ff ff       	call   401180 <__errno_location@plt>
  40a079:	8b 38                	mov    edi,DWORD PTR [rax]
  40a07b:	e8 00 72 ff ff       	call   401280 <strerror@plt>
  40a080:	bf 01 00 00 00       	mov    edi,0x1
  40a085:	48 8d 35 1d 80 00 00 	lea    rsi,[rip+0x801d]        # 4120a9 <_IO_stdin_used+0xa9>
  40a08c:	48 89 c2             	mov    rdx,rax
  40a08f:	31 c0                	xor    eax,eax
  40a091:	e8 9a 71 ff ff       	call   401230 <__printf_chk@plt>
  40a096:	83 cf ff             	or     edi,0xffffffff
  40a099:	e8 c2 71 ff ff       	call   401260 <exit@plt>
  40a09e:	48 63 d0             	movsxd rdx,eax
  40a0a1:	48 89 ee             	mov    rsi,rbp
  40a0a4:	bf 01 00 00 00       	mov    edi,0x1
  40a0a9:	e8 f2 70 ff ff       	call   4011a0 <write@plt>
  40a0ae:	48 8d 3d 9f 80 00 00 	lea    rdi,[rip+0x809f]        # 412154 <_IO_stdin_used+0x154>
  40a0b5:	e8 d6 70 ff ff       	call   401190 <puts@plt>
  40a0ba:	48 8d 3d 43 7f 00 00 	lea    rdi,[rip+0x7f43]        # 412004 <_IO_stdin_used+0x4>
  40a0c1:	31 f6                	xor    esi,esi
  40a0c3:	31 c0                	xor    eax,eax
  40a0c5:	e8 86 71 ff ff       	call   401250 <open@plt>
  40a0ca:	89 c7                	mov    edi,eax
  40a0cc:	85 c0                	test   eax,eax
  40a0ce:	79 34                	jns    40a104 <win+0x8b8e>
  40a0d0:	e8 ab 70 ff ff       	call   401180 <__errno_location@plt>
  40a0d5:	8b 38                	mov    edi,DWORD PTR [rax]
  40a0d7:	e8 a4 71 ff ff       	call   401280 <strerror@plt>
  40a0dc:	48 8d 35 27 7f 00 00 	lea    rsi,[rip+0x7f27]        # 41200a <_IO_stdin_used+0xa>
  40a0e3:	bf 01 00 00 00       	mov    edi,0x1
  40a0e8:	48 89 c2             	mov    rdx,rax
  40a0eb:	31 c0                	xor    eax,eax
  40a0ed:	e8 3e 71 ff ff       	call   401230 <__printf_chk@plt>
  40a0f2:	e8 e9 70 ff ff       	call   4011e0 <geteuid@plt>
  40a0f7:	85 c0                	test   eax,eax
  40a0f9:	0f 84 da 74 ff ff    	je     4015d9 <win+0x63>
  40a0ff:	e9 bd 74 ff ff       	jmp    4015c1 <win+0x4b>
  40a104:	ba 00 01 00 00       	mov    edx,0x100
  40a109:	48 89 ee             	mov    rsi,rbp
  40a10c:	e8 ef 70 ff ff       	call   401200 <read@plt>
  40a111:	85 c0                	test   eax,eax
  40a113:	7f 2a                	jg     40a13f <win+0x8bc9>
  40a115:	e8 66 70 ff ff       	call   401180 <__errno_location@plt>
  40a11a:	8b 38                	mov    edi,DWORD PTR [rax]
  40a11c:	e8 5f 71 ff ff       	call   401280 <strerror@plt>
  40a121:	bf 01 00 00 00       	mov    edi,0x1
  40a126:	48 8d 35 7c 7f 00 00 	lea    rsi,[rip+0x7f7c]        # 4120a9 <_IO_stdin_used+0xa9>
  40a12d:	48 89 c2             	mov    rdx,rax
  40a130:	31 c0                	xor    eax,eax
  40a132:	e8 f9 70 ff ff       	call   401230 <__printf_chk@plt>
  40a137:	83 cf ff             	or     edi,0xffffffff
  40a13a:	e8 21 71 ff ff       	call   401260 <exit@plt>
  40a13f:	48 63 d0             	movsxd rdx,eax
  40a142:	48 89 ee             	mov    rsi,rbp
  40a145:	bf 01 00 00 00       	mov    edi,0x1
  40a14a:	e8 51 70 ff ff       	call   4011a0 <write@plt>
  40a14f:	48 8d 3d fe 7f 00 00 	lea    rdi,[rip+0x7ffe]        # 412154 <_IO_stdin_used+0x154>
  40a156:	e8 35 70 ff ff       	call   401190 <puts@plt>
  40a15b:	48 8d 3d a2 7e 00 00 	lea    rdi,[rip+0x7ea2]        # 412004 <_IO_stdin_used+0x4>
  40a162:	31 f6                	xor    esi,esi
  40a164:	31 c0                	xor    eax,eax
  40a166:	e8 e5 70 ff ff       	call   401250 <open@plt>
  40a16b:	89 c7                	mov    edi,eax
  40a16d:	85 c0                	test   eax,eax
  40a16f:	79 34                	jns    40a1a5 <win+0x8c2f>
  40a171:	e8 0a 70 ff ff       	call   401180 <__errno_location@plt>
  40a176:	8b 38                	mov    edi,DWORD PTR [rax]
  40a178:	e8 03 71 ff ff       	call   401280 <strerror@plt>
  40a17d:	48 8d 35 86 7e 00 00 	lea    rsi,[rip+0x7e86]        # 41200a <_IO_stdin_used+0xa>
  40a184:	bf 01 00 00 00       	mov    edi,0x1
  40a189:	48 89 c2             	mov    rdx,rax
  40a18c:	31 c0                	xor    eax,eax
  40a18e:	e8 9d 70 ff ff       	call   401230 <__printf_chk@plt>
  40a193:	e8 48 70 ff ff       	call   4011e0 <geteuid@plt>
  40a198:	85 c0                	test   eax,eax
  40a19a:	0f 84 39 74 ff ff    	je     4015d9 <win+0x63>
  40a1a0:	e9 1c 74 ff ff       	jmp    4015c1 <win+0x4b>
  40a1a5:	ba 00 01 00 00       	mov    edx,0x100
  40a1aa:	48 89 ee             	mov    rsi,rbp
  40a1ad:	e8 4e 70 ff ff       	call   401200 <read@plt>
  40a1b2:	85 c0                	test   eax,eax
  40a1b4:	7f 2a                	jg     40a1e0 <win+0x8c6a>
  40a1b6:	e8 c5 6f ff ff       	call   401180 <__errno_location@plt>
  40a1bb:	8b 38                	mov    edi,DWORD PTR [rax]
  40a1bd:	e8 be 70 ff ff       	call   401280 <strerror@plt>
  40a1c2:	bf 01 00 00 00       	mov    edi,0x1
  40a1c7:	48 8d 35 db 7e 00 00 	lea    rsi,[rip+0x7edb]        # 4120a9 <_IO_stdin_used+0xa9>
  40a1ce:	48 89 c2             	mov    rdx,rax
  40a1d1:	31 c0                	xor    eax,eax
  40a1d3:	e8 58 70 ff ff       	call   401230 <__printf_chk@plt>
  40a1d8:	83 cf ff             	or     edi,0xffffffff
  40a1db:	e8 80 70 ff ff       	call   401260 <exit@plt>
  40a1e0:	48 63 d0             	movsxd rdx,eax
  40a1e3:	48 89 ee             	mov    rsi,rbp
  40a1e6:	bf 01 00 00 00       	mov    edi,0x1
  40a1eb:	e8 b0 6f ff ff       	call   4011a0 <write@plt>
  40a1f0:	48 8d 3d 5d 7f 00 00 	lea    rdi,[rip+0x7f5d]        # 412154 <_IO_stdin_used+0x154>
  40a1f7:	e8 94 6f ff ff       	call   401190 <puts@plt>
  40a1fc:	48 8d 3d 01 7e 00 00 	lea    rdi,[rip+0x7e01]        # 412004 <_IO_stdin_used+0x4>
  40a203:	31 f6                	xor    esi,esi
  40a205:	31 c0                	xor    eax,eax
  40a207:	e8 44 70 ff ff       	call   401250 <open@plt>
  40a20c:	89 c7                	mov    edi,eax
  40a20e:	85 c0                	test   eax,eax
  40a210:	79 34                	jns    40a246 <win+0x8cd0>
  40a212:	e8 69 6f ff ff       	call   401180 <__errno_location@plt>
  40a217:	8b 38                	mov    edi,DWORD PTR [rax]
  40a219:	e8 62 70 ff ff       	call   401280 <strerror@plt>
  40a21e:	48 8d 35 e5 7d 00 00 	lea    rsi,[rip+0x7de5]        # 41200a <_IO_stdin_used+0xa>
  40a225:	bf 01 00 00 00       	mov    edi,0x1
  40a22a:	48 89 c2             	mov    rdx,rax
  40a22d:	31 c0                	xor    eax,eax
  40a22f:	e8 fc 6f ff ff       	call   401230 <__printf_chk@plt>
  40a234:	e8 a7 6f ff ff       	call   4011e0 <geteuid@plt>
  40a239:	85 c0                	test   eax,eax
  40a23b:	0f 84 98 73 ff ff    	je     4015d9 <win+0x63>
  40a241:	e9 7b 73 ff ff       	jmp    4015c1 <win+0x4b>
  40a246:	ba 00 01 00 00       	mov    edx,0x100
  40a24b:	48 89 ee             	mov    rsi,rbp
  40a24e:	e8 ad 6f ff ff       	call   401200 <read@plt>
  40a253:	85 c0                	test   eax,eax
  40a255:	7f 2a                	jg     40a281 <win+0x8d0b>
  40a257:	e8 24 6f ff ff       	call   401180 <__errno_location@plt>
  40a25c:	8b 38                	mov    edi,DWORD PTR [rax]
  40a25e:	e8 1d 70 ff ff       	call   401280 <strerror@plt>
  40a263:	bf 01 00 00 00       	mov    edi,0x1
  40a268:	48 8d 35 3a 7e 00 00 	lea    rsi,[rip+0x7e3a]        # 4120a9 <_IO_stdin_used+0xa9>
  40a26f:	48 89 c2             	mov    rdx,rax
  40a272:	31 c0                	xor    eax,eax
  40a274:	e8 b7 6f ff ff       	call   401230 <__printf_chk@plt>
  40a279:	83 cf ff             	or     edi,0xffffffff
  40a27c:	e8 df 6f ff ff       	call   401260 <exit@plt>
  40a281:	48 63 d0             	movsxd rdx,eax
  40a284:	48 89 ee             	mov    rsi,rbp
  40a287:	bf 01 00 00 00       	mov    edi,0x1
  40a28c:	e8 0f 6f ff ff       	call   4011a0 <write@plt>
  40a291:	48 8d 3d bc 7e 00 00 	lea    rdi,[rip+0x7ebc]        # 412154 <_IO_stdin_used+0x154>
  40a298:	e8 f3 6e ff ff       	call   401190 <puts@plt>
  40a29d:	48 8d 3d 60 7d 00 00 	lea    rdi,[rip+0x7d60]        # 412004 <_IO_stdin_used+0x4>
  40a2a4:	31 f6                	xor    esi,esi
  40a2a6:	31 c0                	xor    eax,eax
  40a2a8:	e8 a3 6f ff ff       	call   401250 <open@plt>
  40a2ad:	89 c7                	mov    edi,eax
  40a2af:	85 c0                	test   eax,eax
  40a2b1:	79 34                	jns    40a2e7 <win+0x8d71>
  40a2b3:	e8 c8 6e ff ff       	call   401180 <__errno_location@plt>
  40a2b8:	8b 38                	mov    edi,DWORD PTR [rax]
  40a2ba:	e8 c1 6f ff ff       	call   401280 <strerror@plt>
  40a2bf:	48 8d 35 44 7d 00 00 	lea    rsi,[rip+0x7d44]        # 41200a <_IO_stdin_used+0xa>
  40a2c6:	bf 01 00 00 00       	mov    edi,0x1
  40a2cb:	48 89 c2             	mov    rdx,rax
  40a2ce:	31 c0                	xor    eax,eax
  40a2d0:	e8 5b 6f ff ff       	call   401230 <__printf_chk@plt>
  40a2d5:	e8 06 6f ff ff       	call   4011e0 <geteuid@plt>
  40a2da:	85 c0                	test   eax,eax
  40a2dc:	0f 84 f7 72 ff ff    	je     4015d9 <win+0x63>
  40a2e2:	e9 da 72 ff ff       	jmp    4015c1 <win+0x4b>
  40a2e7:	ba 00 01 00 00       	mov    edx,0x100
  40a2ec:	48 89 ee             	mov    rsi,rbp
  40a2ef:	e8 0c 6f ff ff       	call   401200 <read@plt>
  40a2f4:	85 c0                	test   eax,eax
  40a2f6:	7f 2a                	jg     40a322 <win+0x8dac>
  40a2f8:	e8 83 6e ff ff       	call   401180 <__errno_location@plt>
  40a2fd:	8b 38                	mov    edi,DWORD PTR [rax]
  40a2ff:	e8 7c 6f ff ff       	call   401280 <strerror@plt>
  40a304:	bf 01 00 00 00       	mov    edi,0x1
  40a309:	48 8d 35 99 7d 00 00 	lea    rsi,[rip+0x7d99]        # 4120a9 <_IO_stdin_used+0xa9>
  40a310:	48 89 c2             	mov    rdx,rax
  40a313:	31 c0                	xor    eax,eax
  40a315:	e8 16 6f ff ff       	call   401230 <__printf_chk@plt>
  40a31a:	83 cf ff             	or     edi,0xffffffff
  40a31d:	e8 3e 6f ff ff       	call   401260 <exit@plt>
  40a322:	48 63 d0             	movsxd rdx,eax
  40a325:	48 89 ee             	mov    rsi,rbp
  40a328:	bf 01 00 00 00       	mov    edi,0x1
  40a32d:	e8 6e 6e ff ff       	call   4011a0 <write@plt>
  40a332:	48 8d 3d 1b 7e 00 00 	lea    rdi,[rip+0x7e1b]        # 412154 <_IO_stdin_used+0x154>
  40a339:	e8 52 6e ff ff       	call   401190 <puts@plt>
  40a33e:	48 8d 3d bf 7c 00 00 	lea    rdi,[rip+0x7cbf]        # 412004 <_IO_stdin_used+0x4>
  40a345:	31 f6                	xor    esi,esi
  40a347:	31 c0                	xor    eax,eax
  40a349:	e8 02 6f ff ff       	call   401250 <open@plt>
  40a34e:	89 c7                	mov    edi,eax
  40a350:	85 c0                	test   eax,eax
  40a352:	79 34                	jns    40a388 <win+0x8e12>
  40a354:	e8 27 6e ff ff       	call   401180 <__errno_location@plt>
  40a359:	8b 38                	mov    edi,DWORD PTR [rax]
  40a35b:	e8 20 6f ff ff       	call   401280 <strerror@plt>
  40a360:	48 8d 35 a3 7c 00 00 	lea    rsi,[rip+0x7ca3]        # 41200a <_IO_stdin_used+0xa>
  40a367:	bf 01 00 00 00       	mov    edi,0x1
  40a36c:	48 89 c2             	mov    rdx,rax
  40a36f:	31 c0                	xor    eax,eax
  40a371:	e8 ba 6e ff ff       	call   401230 <__printf_chk@plt>
  40a376:	e8 65 6e ff ff       	call   4011e0 <geteuid@plt>
  40a37b:	85 c0                	test   eax,eax
  40a37d:	0f 84 56 72 ff ff    	je     4015d9 <win+0x63>
  40a383:	e9 39 72 ff ff       	jmp    4015c1 <win+0x4b>
  40a388:	ba 00 01 00 00       	mov    edx,0x100
  40a38d:	48 89 ee             	mov    rsi,rbp
  40a390:	e8 6b 6e ff ff       	call   401200 <read@plt>
  40a395:	85 c0                	test   eax,eax
  40a397:	7f 2a                	jg     40a3c3 <win+0x8e4d>
  40a399:	e8 e2 6d ff ff       	call   401180 <__errno_location@plt>
  40a39e:	8b 38                	mov    edi,DWORD PTR [rax]
  40a3a0:	e8 db 6e ff ff       	call   401280 <strerror@plt>
  40a3a5:	bf 01 00 00 00       	mov    edi,0x1
  40a3aa:	48 8d 35 f8 7c 00 00 	lea    rsi,[rip+0x7cf8]        # 4120a9 <_IO_stdin_used+0xa9>
  40a3b1:	48 89 c2             	mov    rdx,rax
  40a3b4:	31 c0                	xor    eax,eax
  40a3b6:	e8 75 6e ff ff       	call   401230 <__printf_chk@plt>
  40a3bb:	83 cf ff             	or     edi,0xffffffff
  40a3be:	e8 9d 6e ff ff       	call   401260 <exit@plt>
  40a3c3:	48 63 d0             	movsxd rdx,eax
  40a3c6:	48 89 ee             	mov    rsi,rbp
  40a3c9:	bf 01 00 00 00       	mov    edi,0x1
  40a3ce:	e8 cd 6d ff ff       	call   4011a0 <write@plt>
  40a3d3:	48 8d 3d 7a 7d 00 00 	lea    rdi,[rip+0x7d7a]        # 412154 <_IO_stdin_used+0x154>
  40a3da:	e8 b1 6d ff ff       	call   401190 <puts@plt>
  40a3df:	48 8d 3d 1e 7c 00 00 	lea    rdi,[rip+0x7c1e]        # 412004 <_IO_stdin_used+0x4>
  40a3e6:	31 f6                	xor    esi,esi
  40a3e8:	31 c0                	xor    eax,eax
  40a3ea:	e8 61 6e ff ff       	call   401250 <open@plt>
  40a3ef:	89 c7                	mov    edi,eax
  40a3f1:	85 c0                	test   eax,eax
  40a3f3:	79 34                	jns    40a429 <win+0x8eb3>
  40a3f5:	e8 86 6d ff ff       	call   401180 <__errno_location@plt>
  40a3fa:	8b 38                	mov    edi,DWORD PTR [rax]
  40a3fc:	e8 7f 6e ff ff       	call   401280 <strerror@plt>
  40a401:	48 8d 35 02 7c 00 00 	lea    rsi,[rip+0x7c02]        # 41200a <_IO_stdin_used+0xa>
  40a408:	bf 01 00 00 00       	mov    edi,0x1
  40a40d:	48 89 c2             	mov    rdx,rax
  40a410:	31 c0                	xor    eax,eax
  40a412:	e8 19 6e ff ff       	call   401230 <__printf_chk@plt>
  40a417:	e8 c4 6d ff ff       	call   4011e0 <geteuid@plt>
  40a41c:	85 c0                	test   eax,eax
  40a41e:	0f 84 b5 71 ff ff    	je     4015d9 <win+0x63>
  40a424:	e9 98 71 ff ff       	jmp    4015c1 <win+0x4b>
  40a429:	ba 00 01 00 00       	mov    edx,0x100
  40a42e:	48 89 ee             	mov    rsi,rbp
  40a431:	e8 ca 6d ff ff       	call   401200 <read@plt>
  40a436:	85 c0                	test   eax,eax
  40a438:	7f 2a                	jg     40a464 <win+0x8eee>
  40a43a:	e8 41 6d ff ff       	call   401180 <__errno_location@plt>
  40a43f:	8b 38                	mov    edi,DWORD PTR [rax]
  40a441:	e8 3a 6e ff ff       	call   401280 <strerror@plt>
  40a446:	bf 01 00 00 00       	mov    edi,0x1
  40a44b:	48 8d 35 57 7c 00 00 	lea    rsi,[rip+0x7c57]        # 4120a9 <_IO_stdin_used+0xa9>
  40a452:	48 89 c2             	mov    rdx,rax
  40a455:	31 c0                	xor    eax,eax
  40a457:	e8 d4 6d ff ff       	call   401230 <__printf_chk@plt>
  40a45c:	83 cf ff             	or     edi,0xffffffff
  40a45f:	e8 fc 6d ff ff       	call   401260 <exit@plt>
  40a464:	48 63 d0             	movsxd rdx,eax
  40a467:	48 89 ee             	mov    rsi,rbp
  40a46a:	bf 01 00 00 00       	mov    edi,0x1
  40a46f:	e8 2c 6d ff ff       	call   4011a0 <write@plt>
  40a474:	48 8d 3d d9 7c 00 00 	lea    rdi,[rip+0x7cd9]        # 412154 <_IO_stdin_used+0x154>
  40a47b:	e8 10 6d ff ff       	call   401190 <puts@plt>
  40a480:	48 8d 3d 7d 7b 00 00 	lea    rdi,[rip+0x7b7d]        # 412004 <_IO_stdin_used+0x4>
  40a487:	31 f6                	xor    esi,esi
  40a489:	31 c0                	xor    eax,eax
  40a48b:	e8 c0 6d ff ff       	call   401250 <open@plt>
  40a490:	89 c7                	mov    edi,eax
  40a492:	85 c0                	test   eax,eax
  40a494:	79 34                	jns    40a4ca <win+0x8f54>
  40a496:	e8 e5 6c ff ff       	call   401180 <__errno_location@plt>
  40a49b:	8b 38                	mov    edi,DWORD PTR [rax]
  40a49d:	e8 de 6d ff ff       	call   401280 <strerror@plt>
  40a4a2:	48 8d 35 61 7b 00 00 	lea    rsi,[rip+0x7b61]        # 41200a <_IO_stdin_used+0xa>
  40a4a9:	bf 01 00 00 00       	mov    edi,0x1
  40a4ae:	48 89 c2             	mov    rdx,rax
  40a4b1:	31 c0                	xor    eax,eax
  40a4b3:	e8 78 6d ff ff       	call   401230 <__printf_chk@plt>
  40a4b8:	e8 23 6d ff ff       	call   4011e0 <geteuid@plt>
  40a4bd:	85 c0                	test   eax,eax
  40a4bf:	0f 84 14 71 ff ff    	je     4015d9 <win+0x63>
  40a4c5:	e9 f7 70 ff ff       	jmp    4015c1 <win+0x4b>
  40a4ca:	ba 00 01 00 00       	mov    edx,0x100
  40a4cf:	48 89 ee             	mov    rsi,rbp
  40a4d2:	e8 29 6d ff ff       	call   401200 <read@plt>
  40a4d7:	85 c0                	test   eax,eax
  40a4d9:	7f 2a                	jg     40a505 <win+0x8f8f>
  40a4db:	e8 a0 6c ff ff       	call   401180 <__errno_location@plt>
  40a4e0:	8b 38                	mov    edi,DWORD PTR [rax]
  40a4e2:	e8 99 6d ff ff       	call   401280 <strerror@plt>
  40a4e7:	bf 01 00 00 00       	mov    edi,0x1
  40a4ec:	48 8d 35 b6 7b 00 00 	lea    rsi,[rip+0x7bb6]        # 4120a9 <_IO_stdin_used+0xa9>
  40a4f3:	48 89 c2             	mov    rdx,rax
  40a4f6:	31 c0                	xor    eax,eax
  40a4f8:	e8 33 6d ff ff       	call   401230 <__printf_chk@plt>
  40a4fd:	83 cf ff             	or     edi,0xffffffff
  40a500:	e8 5b 6d ff ff       	call   401260 <exit@plt>
  40a505:	48 63 d0             	movsxd rdx,eax
  40a508:	48 89 ee             	mov    rsi,rbp
  40a50b:	bf 01 00 00 00       	mov    edi,0x1
  40a510:	e8 8b 6c ff ff       	call   4011a0 <write@plt>
  40a515:	48 8d 3d 38 7c 00 00 	lea    rdi,[rip+0x7c38]        # 412154 <_IO_stdin_used+0x154>
  40a51c:	e8 6f 6c ff ff       	call   401190 <puts@plt>
  40a521:	48 8d 3d dc 7a 00 00 	lea    rdi,[rip+0x7adc]        # 412004 <_IO_stdin_used+0x4>
  40a528:	31 f6                	xor    esi,esi
  40a52a:	31 c0                	xor    eax,eax
  40a52c:	e8 1f 6d ff ff       	call   401250 <open@plt>
  40a531:	89 c7                	mov    edi,eax
  40a533:	85 c0                	test   eax,eax
  40a535:	79 34                	jns    40a56b <win+0x8ff5>
  40a537:	e8 44 6c ff ff       	call   401180 <__errno_location@plt>
  40a53c:	8b 38                	mov    edi,DWORD PTR [rax]
  40a53e:	e8 3d 6d ff ff       	call   401280 <strerror@plt>
  40a543:	48 8d 35 c0 7a 00 00 	lea    rsi,[rip+0x7ac0]        # 41200a <_IO_stdin_used+0xa>
  40a54a:	bf 01 00 00 00       	mov    edi,0x1
  40a54f:	48 89 c2             	mov    rdx,rax
  40a552:	31 c0                	xor    eax,eax
  40a554:	e8 d7 6c ff ff       	call   401230 <__printf_chk@plt>
  40a559:	e8 82 6c ff ff       	call   4011e0 <geteuid@plt>
  40a55e:	85 c0                	test   eax,eax
  40a560:	0f 84 73 70 ff ff    	je     4015d9 <win+0x63>
  40a566:	e9 56 70 ff ff       	jmp    4015c1 <win+0x4b>
  40a56b:	ba 00 01 00 00       	mov    edx,0x100
  40a570:	48 89 ee             	mov    rsi,rbp
  40a573:	e8 88 6c ff ff       	call   401200 <read@plt>
  40a578:	85 c0                	test   eax,eax
  40a57a:	7f 2a                	jg     40a5a6 <win+0x9030>
  40a57c:	e8 ff 6b ff ff       	call   401180 <__errno_location@plt>
  40a581:	8b 38                	mov    edi,DWORD PTR [rax]
  40a583:	e8 f8 6c ff ff       	call   401280 <strerror@plt>
  40a588:	bf 01 00 00 00       	mov    edi,0x1
  40a58d:	48 8d 35 15 7b 00 00 	lea    rsi,[rip+0x7b15]        # 4120a9 <_IO_stdin_used+0xa9>
  40a594:	48 89 c2             	mov    rdx,rax
  40a597:	31 c0                	xor    eax,eax
  40a599:	e8 92 6c ff ff       	call   401230 <__printf_chk@plt>
  40a59e:	83 cf ff             	or     edi,0xffffffff
  40a5a1:	e8 ba 6c ff ff       	call   401260 <exit@plt>
  40a5a6:	48 63 d0             	movsxd rdx,eax
  40a5a9:	48 89 ee             	mov    rsi,rbp
  40a5ac:	bf 01 00 00 00       	mov    edi,0x1
  40a5b1:	e8 ea 6b ff ff       	call   4011a0 <write@plt>
  40a5b6:	48 8d 3d 97 7b 00 00 	lea    rdi,[rip+0x7b97]        # 412154 <_IO_stdin_used+0x154>
  40a5bd:	e8 ce 6b ff ff       	call   401190 <puts@plt>
  40a5c2:	48 8d 3d 3b 7a 00 00 	lea    rdi,[rip+0x7a3b]        # 412004 <_IO_stdin_used+0x4>
  40a5c9:	31 f6                	xor    esi,esi
  40a5cb:	31 c0                	xor    eax,eax
  40a5cd:	e8 7e 6c ff ff       	call   401250 <open@plt>
  40a5d2:	89 c7                	mov    edi,eax
  40a5d4:	85 c0                	test   eax,eax
  40a5d6:	79 34                	jns    40a60c <win+0x9096>
  40a5d8:	e8 a3 6b ff ff       	call   401180 <__errno_location@plt>
  40a5dd:	8b 38                	mov    edi,DWORD PTR [rax]
  40a5df:	e8 9c 6c ff ff       	call   401280 <strerror@plt>
  40a5e4:	48 8d 35 1f 7a 00 00 	lea    rsi,[rip+0x7a1f]        # 41200a <_IO_stdin_used+0xa>
  40a5eb:	bf 01 00 00 00       	mov    edi,0x1
  40a5f0:	48 89 c2             	mov    rdx,rax
  40a5f3:	31 c0                	xor    eax,eax
  40a5f5:	e8 36 6c ff ff       	call   401230 <__printf_chk@plt>
  40a5fa:	e8 e1 6b ff ff       	call   4011e0 <geteuid@plt>
  40a5ff:	85 c0                	test   eax,eax
  40a601:	0f 84 d2 6f ff ff    	je     4015d9 <win+0x63>
  40a607:	e9 b5 6f ff ff       	jmp    4015c1 <win+0x4b>
  40a60c:	ba 00 01 00 00       	mov    edx,0x100
  40a611:	48 89 ee             	mov    rsi,rbp
  40a614:	e8 e7 6b ff ff       	call   401200 <read@plt>
  40a619:	85 c0                	test   eax,eax
  40a61b:	7f 2a                	jg     40a647 <win+0x90d1>
  40a61d:	e8 5e 6b ff ff       	call   401180 <__errno_location@plt>
  40a622:	8b 38                	mov    edi,DWORD PTR [rax]
  40a624:	e8 57 6c ff ff       	call   401280 <strerror@plt>
  40a629:	bf 01 00 00 00       	mov    edi,0x1
  40a62e:	48 8d 35 74 7a 00 00 	lea    rsi,[rip+0x7a74]        # 4120a9 <_IO_stdin_used+0xa9>
  40a635:	48 89 c2             	mov    rdx,rax
  40a638:	31 c0                	xor    eax,eax
  40a63a:	e8 f1 6b ff ff       	call   401230 <__printf_chk@plt>
  40a63f:	83 cf ff             	or     edi,0xffffffff
  40a642:	e8 19 6c ff ff       	call   401260 <exit@plt>
  40a647:	48 63 d0             	movsxd rdx,eax
  40a64a:	48 89 ee             	mov    rsi,rbp
  40a64d:	bf 01 00 00 00       	mov    edi,0x1
  40a652:	e8 49 6b ff ff       	call   4011a0 <write@plt>
  40a657:	48 8d 3d f6 7a 00 00 	lea    rdi,[rip+0x7af6]        # 412154 <_IO_stdin_used+0x154>
  40a65e:	e8 2d 6b ff ff       	call   401190 <puts@plt>
  40a663:	48 8d 3d 9a 79 00 00 	lea    rdi,[rip+0x799a]        # 412004 <_IO_stdin_used+0x4>
  40a66a:	31 f6                	xor    esi,esi
  40a66c:	31 c0                	xor    eax,eax
  40a66e:	e8 dd 6b ff ff       	call   401250 <open@plt>
  40a673:	89 c7                	mov    edi,eax
  40a675:	85 c0                	test   eax,eax
  40a677:	79 34                	jns    40a6ad <win+0x9137>
  40a679:	e8 02 6b ff ff       	call   401180 <__errno_location@plt>
  40a67e:	8b 38                	mov    edi,DWORD PTR [rax]
  40a680:	e8 fb 6b ff ff       	call   401280 <strerror@plt>
  40a685:	48 8d 35 7e 79 00 00 	lea    rsi,[rip+0x797e]        # 41200a <_IO_stdin_used+0xa>
  40a68c:	bf 01 00 00 00       	mov    edi,0x1
  40a691:	48 89 c2             	mov    rdx,rax
  40a694:	31 c0                	xor    eax,eax
  40a696:	e8 95 6b ff ff       	call   401230 <__printf_chk@plt>
  40a69b:	e8 40 6b ff ff       	call   4011e0 <geteuid@plt>
  40a6a0:	85 c0                	test   eax,eax
  40a6a2:	0f 84 31 6f ff ff    	je     4015d9 <win+0x63>
  40a6a8:	e9 14 6f ff ff       	jmp    4015c1 <win+0x4b>
  40a6ad:	ba 00 01 00 00       	mov    edx,0x100
  40a6b2:	48 89 ee             	mov    rsi,rbp
  40a6b5:	e8 46 6b ff ff       	call   401200 <read@plt>
  40a6ba:	85 c0                	test   eax,eax
  40a6bc:	7f 2a                	jg     40a6e8 <win+0x9172>
  40a6be:	e8 bd 6a ff ff       	call   401180 <__errno_location@plt>
  40a6c3:	8b 38                	mov    edi,DWORD PTR [rax]
  40a6c5:	e8 b6 6b ff ff       	call   401280 <strerror@plt>
  40a6ca:	bf 01 00 00 00       	mov    edi,0x1
  40a6cf:	48 8d 35 d3 79 00 00 	lea    rsi,[rip+0x79d3]        # 4120a9 <_IO_stdin_used+0xa9>
  40a6d6:	48 89 c2             	mov    rdx,rax
  40a6d9:	31 c0                	xor    eax,eax
  40a6db:	e8 50 6b ff ff       	call   401230 <__printf_chk@plt>
  40a6e0:	83 cf ff             	or     edi,0xffffffff
  40a6e3:	e8 78 6b ff ff       	call   401260 <exit@plt>
  40a6e8:	48 63 d0             	movsxd rdx,eax
  40a6eb:	48 89 ee             	mov    rsi,rbp
  40a6ee:	bf 01 00 00 00       	mov    edi,0x1
  40a6f3:	e8 a8 6a ff ff       	call   4011a0 <write@plt>
  40a6f8:	48 8d 3d 55 7a 00 00 	lea    rdi,[rip+0x7a55]        # 412154 <_IO_stdin_used+0x154>
  40a6ff:	e8 8c 6a ff ff       	call   401190 <puts@plt>
  40a704:	48 8d 3d f9 78 00 00 	lea    rdi,[rip+0x78f9]        # 412004 <_IO_stdin_used+0x4>
  40a70b:	31 f6                	xor    esi,esi
  40a70d:	31 c0                	xor    eax,eax
  40a70f:	e8 3c 6b ff ff       	call   401250 <open@plt>
  40a714:	89 c7                	mov    edi,eax
  40a716:	85 c0                	test   eax,eax
  40a718:	79 34                	jns    40a74e <win+0x91d8>
  40a71a:	e8 61 6a ff ff       	call   401180 <__errno_location@plt>
  40a71f:	8b 38                	mov    edi,DWORD PTR [rax]
  40a721:	e8 5a 6b ff ff       	call   401280 <strerror@plt>
  40a726:	48 8d 35 dd 78 00 00 	lea    rsi,[rip+0x78dd]        # 41200a <_IO_stdin_used+0xa>
  40a72d:	bf 01 00 00 00       	mov    edi,0x1
  40a732:	48 89 c2             	mov    rdx,rax
  40a735:	31 c0                	xor    eax,eax
  40a737:	e8 f4 6a ff ff       	call   401230 <__printf_chk@plt>
  40a73c:	e8 9f 6a ff ff       	call   4011e0 <geteuid@plt>
  40a741:	85 c0                	test   eax,eax
  40a743:	0f 84 90 6e ff ff    	je     4015d9 <win+0x63>
  40a749:	e9 73 6e ff ff       	jmp    4015c1 <win+0x4b>
  40a74e:	ba 00 01 00 00       	mov    edx,0x100
  40a753:	48 89 ee             	mov    rsi,rbp
  40a756:	e8 a5 6a ff ff       	call   401200 <read@plt>
  40a75b:	85 c0                	test   eax,eax
  40a75d:	7f 2a                	jg     40a789 <win+0x9213>
  40a75f:	e8 1c 6a ff ff       	call   401180 <__errno_location@plt>
  40a764:	8b 38                	mov    edi,DWORD PTR [rax]
  40a766:	e8 15 6b ff ff       	call   401280 <strerror@plt>
  40a76b:	bf 01 00 00 00       	mov    edi,0x1
  40a770:	48 8d 35 32 79 00 00 	lea    rsi,[rip+0x7932]        # 4120a9 <_IO_stdin_used+0xa9>
  40a777:	48 89 c2             	mov    rdx,rax
  40a77a:	31 c0                	xor    eax,eax
  40a77c:	e8 af 6a ff ff       	call   401230 <__printf_chk@plt>
  40a781:	83 cf ff             	or     edi,0xffffffff
  40a784:	e8 d7 6a ff ff       	call   401260 <exit@plt>
  40a789:	48 63 d0             	movsxd rdx,eax
  40a78c:	48 89 ee             	mov    rsi,rbp
  40a78f:	bf 01 00 00 00       	mov    edi,0x1
  40a794:	e8 07 6a ff ff       	call   4011a0 <write@plt>
  40a799:	48 8d 3d b4 79 00 00 	lea    rdi,[rip+0x79b4]        # 412154 <_IO_stdin_used+0x154>
  40a7a0:	e8 eb 69 ff ff       	call   401190 <puts@plt>
  40a7a5:	48 8d 3d 58 78 00 00 	lea    rdi,[rip+0x7858]        # 412004 <_IO_stdin_used+0x4>
  40a7ac:	31 f6                	xor    esi,esi
  40a7ae:	31 c0                	xor    eax,eax
  40a7b0:	e8 9b 6a ff ff       	call   401250 <open@plt>
  40a7b5:	89 c7                	mov    edi,eax
  40a7b7:	85 c0                	test   eax,eax
  40a7b9:	79 34                	jns    40a7ef <win+0x9279>
  40a7bb:	e8 c0 69 ff ff       	call   401180 <__errno_location@plt>
  40a7c0:	8b 38                	mov    edi,DWORD PTR [rax]
  40a7c2:	e8 b9 6a ff ff       	call   401280 <strerror@plt>
  40a7c7:	48 8d 35 3c 78 00 00 	lea    rsi,[rip+0x783c]        # 41200a <_IO_stdin_used+0xa>
  40a7ce:	bf 01 00 00 00       	mov    edi,0x1
  40a7d3:	48 89 c2             	mov    rdx,rax
  40a7d6:	31 c0                	xor    eax,eax
  40a7d8:	e8 53 6a ff ff       	call   401230 <__printf_chk@plt>
  40a7dd:	e8 fe 69 ff ff       	call   4011e0 <geteuid@plt>
  40a7e2:	85 c0                	test   eax,eax
  40a7e4:	0f 84 ef 6d ff ff    	je     4015d9 <win+0x63>
  40a7ea:	e9 d2 6d ff ff       	jmp    4015c1 <win+0x4b>
  40a7ef:	ba 00 01 00 00       	mov    edx,0x100
  40a7f4:	48 89 ee             	mov    rsi,rbp
  40a7f7:	e8 04 6a ff ff       	call   401200 <read@plt>
  40a7fc:	85 c0                	test   eax,eax
  40a7fe:	7f 2a                	jg     40a82a <win+0x92b4>
  40a800:	e8 7b 69 ff ff       	call   401180 <__errno_location@plt>
  40a805:	8b 38                	mov    edi,DWORD PTR [rax]
  40a807:	e8 74 6a ff ff       	call   401280 <strerror@plt>
  40a80c:	bf 01 00 00 00       	mov    edi,0x1
  40a811:	48 8d 35 91 78 00 00 	lea    rsi,[rip+0x7891]        # 4120a9 <_IO_stdin_used+0xa9>
  40a818:	48 89 c2             	mov    rdx,rax
  40a81b:	31 c0                	xor    eax,eax
  40a81d:	e8 0e 6a ff ff       	call   401230 <__printf_chk@plt>
  40a822:	83 cf ff             	or     edi,0xffffffff
  40a825:	e8 36 6a ff ff       	call   401260 <exit@plt>
  40a82a:	48 63 d0             	movsxd rdx,eax
  40a82d:	48 89 ee             	mov    rsi,rbp
  40a830:	bf 01 00 00 00       	mov    edi,0x1
  40a835:	e8 66 69 ff ff       	call   4011a0 <write@plt>
  40a83a:	48 8d 3d 13 79 00 00 	lea    rdi,[rip+0x7913]        # 412154 <_IO_stdin_used+0x154>
  40a841:	e8 4a 69 ff ff       	call   401190 <puts@plt>
  40a846:	48 8d 3d b7 77 00 00 	lea    rdi,[rip+0x77b7]        # 412004 <_IO_stdin_used+0x4>
  40a84d:	31 f6                	xor    esi,esi
  40a84f:	31 c0                	xor    eax,eax
  40a851:	e8 fa 69 ff ff       	call   401250 <open@plt>
  40a856:	89 c7                	mov    edi,eax
  40a858:	85 c0                	test   eax,eax
  40a85a:	79 34                	jns    40a890 <win+0x931a>
  40a85c:	e8 1f 69 ff ff       	call   401180 <__errno_location@plt>
  40a861:	8b 38                	mov    edi,DWORD PTR [rax]
  40a863:	e8 18 6a ff ff       	call   401280 <strerror@plt>
  40a868:	48 8d 35 9b 77 00 00 	lea    rsi,[rip+0x779b]        # 41200a <_IO_stdin_used+0xa>
  40a86f:	bf 01 00 00 00       	mov    edi,0x1
  40a874:	48 89 c2             	mov    rdx,rax
  40a877:	31 c0                	xor    eax,eax
  40a879:	e8 b2 69 ff ff       	call   401230 <__printf_chk@plt>
  40a87e:	e8 5d 69 ff ff       	call   4011e0 <geteuid@plt>
  40a883:	85 c0                	test   eax,eax
  40a885:	0f 84 4e 6d ff ff    	je     4015d9 <win+0x63>
  40a88b:	e9 31 6d ff ff       	jmp    4015c1 <win+0x4b>
  40a890:	ba 00 01 00 00       	mov    edx,0x100
  40a895:	48 89 ee             	mov    rsi,rbp
  40a898:	e8 63 69 ff ff       	call   401200 <read@plt>
  40a89d:	85 c0                	test   eax,eax
  40a89f:	7f 2a                	jg     40a8cb <win+0x9355>
  40a8a1:	e8 da 68 ff ff       	call   401180 <__errno_location@plt>
  40a8a6:	8b 38                	mov    edi,DWORD PTR [rax]
  40a8a8:	e8 d3 69 ff ff       	call   401280 <strerror@plt>
  40a8ad:	bf 01 00 00 00       	mov    edi,0x1
  40a8b2:	48 8d 35 f0 77 00 00 	lea    rsi,[rip+0x77f0]        # 4120a9 <_IO_stdin_used+0xa9>
  40a8b9:	48 89 c2             	mov    rdx,rax
  40a8bc:	31 c0                	xor    eax,eax
  40a8be:	e8 6d 69 ff ff       	call   401230 <__printf_chk@plt>
  40a8c3:	83 cf ff             	or     edi,0xffffffff
  40a8c6:	e8 95 69 ff ff       	call   401260 <exit@plt>
  40a8cb:	48 63 d0             	movsxd rdx,eax
  40a8ce:	48 89 ee             	mov    rsi,rbp
  40a8d1:	bf 01 00 00 00       	mov    edi,0x1
  40a8d6:	e8 c5 68 ff ff       	call   4011a0 <write@plt>
  40a8db:	48 8d 3d 72 78 00 00 	lea    rdi,[rip+0x7872]        # 412154 <_IO_stdin_used+0x154>
  40a8e2:	e8 a9 68 ff ff       	call   401190 <puts@plt>
  40a8e7:	48 8d 3d 16 77 00 00 	lea    rdi,[rip+0x7716]        # 412004 <_IO_stdin_used+0x4>
  40a8ee:	31 f6                	xor    esi,esi
  40a8f0:	31 c0                	xor    eax,eax
  40a8f2:	e8 59 69 ff ff       	call   401250 <open@plt>
  40a8f7:	89 c7                	mov    edi,eax
  40a8f9:	85 c0                	test   eax,eax
  40a8fb:	79 34                	jns    40a931 <win+0x93bb>
  40a8fd:	e8 7e 68 ff ff       	call   401180 <__errno_location@plt>
  40a902:	8b 38                	mov    edi,DWORD PTR [rax]
  40a904:	e8 77 69 ff ff       	call   401280 <strerror@plt>
  40a909:	48 8d 35 fa 76 00 00 	lea    rsi,[rip+0x76fa]        # 41200a <_IO_stdin_used+0xa>
  40a910:	bf 01 00 00 00       	mov    edi,0x1
  40a915:	48 89 c2             	mov    rdx,rax
  40a918:	31 c0                	xor    eax,eax
  40a91a:	e8 11 69 ff ff       	call   401230 <__printf_chk@plt>
  40a91f:	e8 bc 68 ff ff       	call   4011e0 <geteuid@plt>
  40a924:	85 c0                	test   eax,eax
  40a926:	0f 84 ad 6c ff ff    	je     4015d9 <win+0x63>
  40a92c:	e9 90 6c ff ff       	jmp    4015c1 <win+0x4b>
  40a931:	ba 00 01 00 00       	mov    edx,0x100
  40a936:	48 89 ee             	mov    rsi,rbp
  40a939:	e8 c2 68 ff ff       	call   401200 <read@plt>
  40a93e:	85 c0                	test   eax,eax
  40a940:	7f 2a                	jg     40a96c <win+0x93f6>
  40a942:	e8 39 68 ff ff       	call   401180 <__errno_location@plt>
  40a947:	8b 38                	mov    edi,DWORD PTR [rax]
  40a949:	e8 32 69 ff ff       	call   401280 <strerror@plt>
  40a94e:	bf 01 00 00 00       	mov    edi,0x1
  40a953:	48 8d 35 4f 77 00 00 	lea    rsi,[rip+0x774f]        # 4120a9 <_IO_stdin_used+0xa9>
  40a95a:	48 89 c2             	mov    rdx,rax
  40a95d:	31 c0                	xor    eax,eax
  40a95f:	e8 cc 68 ff ff       	call   401230 <__printf_chk@plt>
  40a964:	83 cf ff             	or     edi,0xffffffff
  40a967:	e8 f4 68 ff ff       	call   401260 <exit@plt>
  40a96c:	48 63 d0             	movsxd rdx,eax
  40a96f:	48 89 ee             	mov    rsi,rbp
  40a972:	bf 01 00 00 00       	mov    edi,0x1
  40a977:	e8 24 68 ff ff       	call   4011a0 <write@plt>
  40a97c:	48 8d 3d d1 77 00 00 	lea    rdi,[rip+0x77d1]        # 412154 <_IO_stdin_used+0x154>
  40a983:	e8 08 68 ff ff       	call   401190 <puts@plt>
  40a988:	48 8d 3d 75 76 00 00 	lea    rdi,[rip+0x7675]        # 412004 <_IO_stdin_used+0x4>
  40a98f:	31 f6                	xor    esi,esi
  40a991:	31 c0                	xor    eax,eax
  40a993:	e8 b8 68 ff ff       	call   401250 <open@plt>
  40a998:	89 c7                	mov    edi,eax
  40a99a:	85 c0                	test   eax,eax
  40a99c:	79 34                	jns    40a9d2 <win+0x945c>
  40a99e:	e8 dd 67 ff ff       	call   401180 <__errno_location@plt>
  40a9a3:	8b 38                	mov    edi,DWORD PTR [rax]
  40a9a5:	e8 d6 68 ff ff       	call   401280 <strerror@plt>
  40a9aa:	48 8d 35 59 76 00 00 	lea    rsi,[rip+0x7659]        # 41200a <_IO_stdin_used+0xa>
  40a9b1:	bf 01 00 00 00       	mov    edi,0x1
  40a9b6:	48 89 c2             	mov    rdx,rax
  40a9b9:	31 c0                	xor    eax,eax
  40a9bb:	e8 70 68 ff ff       	call   401230 <__printf_chk@plt>
  40a9c0:	e8 1b 68 ff ff       	call   4011e0 <geteuid@plt>
  40a9c5:	85 c0                	test   eax,eax
  40a9c7:	0f 84 0c 6c ff ff    	je     4015d9 <win+0x63>
  40a9cd:	e9 ef 6b ff ff       	jmp    4015c1 <win+0x4b>
  40a9d2:	ba 00 01 00 00       	mov    edx,0x100
  40a9d7:	48 89 ee             	mov    rsi,rbp
  40a9da:	e8 21 68 ff ff       	call   401200 <read@plt>
  40a9df:	85 c0                	test   eax,eax
  40a9e1:	7f 2a                	jg     40aa0d <win+0x9497>
  40a9e3:	e8 98 67 ff ff       	call   401180 <__errno_location@plt>
  40a9e8:	8b 38                	mov    edi,DWORD PTR [rax]
  40a9ea:	e8 91 68 ff ff       	call   401280 <strerror@plt>
  40a9ef:	bf 01 00 00 00       	mov    edi,0x1
  40a9f4:	48 8d 35 ae 76 00 00 	lea    rsi,[rip+0x76ae]        # 4120a9 <_IO_stdin_used+0xa9>
  40a9fb:	48 89 c2             	mov    rdx,rax
  40a9fe:	31 c0                	xor    eax,eax
  40aa00:	e8 2b 68 ff ff       	call   401230 <__printf_chk@plt>
  40aa05:	83 cf ff             	or     edi,0xffffffff
  40aa08:	e8 53 68 ff ff       	call   401260 <exit@plt>
  40aa0d:	48 63 d0             	movsxd rdx,eax
  40aa10:	48 89 ee             	mov    rsi,rbp
  40aa13:	bf 01 00 00 00       	mov    edi,0x1
  40aa18:	e8 83 67 ff ff       	call   4011a0 <write@plt>
  40aa1d:	48 8d 3d 30 77 00 00 	lea    rdi,[rip+0x7730]        # 412154 <_IO_stdin_used+0x154>
  40aa24:	e8 67 67 ff ff       	call   401190 <puts@plt>
  40aa29:	48 8d 3d d4 75 00 00 	lea    rdi,[rip+0x75d4]        # 412004 <_IO_stdin_used+0x4>
  40aa30:	31 f6                	xor    esi,esi
  40aa32:	31 c0                	xor    eax,eax
  40aa34:	e8 17 68 ff ff       	call   401250 <open@plt>
  40aa39:	89 c7                	mov    edi,eax
  40aa3b:	85 c0                	test   eax,eax
  40aa3d:	79 34                	jns    40aa73 <win+0x94fd>
  40aa3f:	e8 3c 67 ff ff       	call   401180 <__errno_location@plt>
  40aa44:	8b 38                	mov    edi,DWORD PTR [rax]
  40aa46:	e8 35 68 ff ff       	call   401280 <strerror@plt>
  40aa4b:	48 8d 35 b8 75 00 00 	lea    rsi,[rip+0x75b8]        # 41200a <_IO_stdin_used+0xa>
  40aa52:	bf 01 00 00 00       	mov    edi,0x1
  40aa57:	48 89 c2             	mov    rdx,rax
  40aa5a:	31 c0                	xor    eax,eax
  40aa5c:	e8 cf 67 ff ff       	call   401230 <__printf_chk@plt>
  40aa61:	e8 7a 67 ff ff       	call   4011e0 <geteuid@plt>
  40aa66:	85 c0                	test   eax,eax
  40aa68:	0f 84 6b 6b ff ff    	je     4015d9 <win+0x63>
  40aa6e:	e9 4e 6b ff ff       	jmp    4015c1 <win+0x4b>
  40aa73:	ba 00 01 00 00       	mov    edx,0x100
  40aa78:	48 89 ee             	mov    rsi,rbp
  40aa7b:	e8 80 67 ff ff       	call   401200 <read@plt>
  40aa80:	85 c0                	test   eax,eax
  40aa82:	7f 2a                	jg     40aaae <win+0x9538>
  40aa84:	e8 f7 66 ff ff       	call   401180 <__errno_location@plt>
  40aa89:	8b 38                	mov    edi,DWORD PTR [rax]
  40aa8b:	e8 f0 67 ff ff       	call   401280 <strerror@plt>
  40aa90:	bf 01 00 00 00       	mov    edi,0x1
  40aa95:	48 8d 35 0d 76 00 00 	lea    rsi,[rip+0x760d]        # 4120a9 <_IO_stdin_used+0xa9>
  40aa9c:	48 89 c2             	mov    rdx,rax
  40aa9f:	31 c0                	xor    eax,eax
  40aaa1:	e8 8a 67 ff ff       	call   401230 <__printf_chk@plt>
  40aaa6:	83 cf ff             	or     edi,0xffffffff
  40aaa9:	e8 b2 67 ff ff       	call   401260 <exit@plt>
  40aaae:	48 63 d0             	movsxd rdx,eax
  40aab1:	48 89 ee             	mov    rsi,rbp
  40aab4:	bf 01 00 00 00       	mov    edi,0x1
  40aab9:	e8 e2 66 ff ff       	call   4011a0 <write@plt>
  40aabe:	48 8d 3d 8f 76 00 00 	lea    rdi,[rip+0x768f]        # 412154 <_IO_stdin_used+0x154>
  40aac5:	e8 c6 66 ff ff       	call   401190 <puts@plt>
  40aaca:	48 8d 3d 33 75 00 00 	lea    rdi,[rip+0x7533]        # 412004 <_IO_stdin_used+0x4>
  40aad1:	31 f6                	xor    esi,esi
  40aad3:	31 c0                	xor    eax,eax
  40aad5:	e8 76 67 ff ff       	call   401250 <open@plt>
  40aada:	89 c7                	mov    edi,eax
  40aadc:	85 c0                	test   eax,eax
  40aade:	79 34                	jns    40ab14 <win+0x959e>
  40aae0:	e8 9b 66 ff ff       	call   401180 <__errno_location@plt>
  40aae5:	8b 38                	mov    edi,DWORD PTR [rax]
  40aae7:	e8 94 67 ff ff       	call   401280 <strerror@plt>
  40aaec:	48 8d 35 17 75 00 00 	lea    rsi,[rip+0x7517]        # 41200a <_IO_stdin_used+0xa>
  40aaf3:	bf 01 00 00 00       	mov    edi,0x1
  40aaf8:	48 89 c2             	mov    rdx,rax
  40aafb:	31 c0                	xor    eax,eax
  40aafd:	e8 2e 67 ff ff       	call   401230 <__printf_chk@plt>
  40ab02:	e8 d9 66 ff ff       	call   4011e0 <geteuid@plt>
  40ab07:	85 c0                	test   eax,eax
  40ab09:	0f 84 ca 6a ff ff    	je     4015d9 <win+0x63>
  40ab0f:	e9 ad 6a ff ff       	jmp    4015c1 <win+0x4b>
  40ab14:	ba 00 01 00 00       	mov    edx,0x100
  40ab19:	48 89 ee             	mov    rsi,rbp
  40ab1c:	e8 df 66 ff ff       	call   401200 <read@plt>
  40ab21:	85 c0                	test   eax,eax
  40ab23:	7f 2a                	jg     40ab4f <win+0x95d9>
  40ab25:	e8 56 66 ff ff       	call   401180 <__errno_location@plt>
  40ab2a:	8b 38                	mov    edi,DWORD PTR [rax]
  40ab2c:	e8 4f 67 ff ff       	call   401280 <strerror@plt>
  40ab31:	bf 01 00 00 00       	mov    edi,0x1
  40ab36:	48 8d 35 6c 75 00 00 	lea    rsi,[rip+0x756c]        # 4120a9 <_IO_stdin_used+0xa9>
  40ab3d:	48 89 c2             	mov    rdx,rax
  40ab40:	31 c0                	xor    eax,eax
  40ab42:	e8 e9 66 ff ff       	call   401230 <__printf_chk@plt>
  40ab47:	83 cf ff             	or     edi,0xffffffff
  40ab4a:	e8 11 67 ff ff       	call   401260 <exit@plt>
  40ab4f:	48 63 d0             	movsxd rdx,eax
  40ab52:	48 89 ee             	mov    rsi,rbp
  40ab55:	bf 01 00 00 00       	mov    edi,0x1
  40ab5a:	e8 41 66 ff ff       	call   4011a0 <write@plt>
  40ab5f:	48 8d 3d ee 75 00 00 	lea    rdi,[rip+0x75ee]        # 412154 <_IO_stdin_used+0x154>
  40ab66:	e8 25 66 ff ff       	call   401190 <puts@plt>
  40ab6b:	48 8d 3d 92 74 00 00 	lea    rdi,[rip+0x7492]        # 412004 <_IO_stdin_used+0x4>
  40ab72:	31 f6                	xor    esi,esi
  40ab74:	31 c0                	xor    eax,eax
  40ab76:	e8 d5 66 ff ff       	call   401250 <open@plt>
  40ab7b:	89 c7                	mov    edi,eax
  40ab7d:	85 c0                	test   eax,eax
  40ab7f:	79 34                	jns    40abb5 <win+0x963f>
  40ab81:	e8 fa 65 ff ff       	call   401180 <__errno_location@plt>
  40ab86:	8b 38                	mov    edi,DWORD PTR [rax]
  40ab88:	e8 f3 66 ff ff       	call   401280 <strerror@plt>
  40ab8d:	48 8d 35 76 74 00 00 	lea    rsi,[rip+0x7476]        # 41200a <_IO_stdin_used+0xa>
  40ab94:	bf 01 00 00 00       	mov    edi,0x1
  40ab99:	48 89 c2             	mov    rdx,rax
  40ab9c:	31 c0                	xor    eax,eax
  40ab9e:	e8 8d 66 ff ff       	call   401230 <__printf_chk@plt>
  40aba3:	e8 38 66 ff ff       	call   4011e0 <geteuid@plt>
  40aba8:	85 c0                	test   eax,eax
  40abaa:	0f 84 29 6a ff ff    	je     4015d9 <win+0x63>
  40abb0:	e9 0c 6a ff ff       	jmp    4015c1 <win+0x4b>
  40abb5:	ba 00 01 00 00       	mov    edx,0x100
  40abba:	48 89 ee             	mov    rsi,rbp
  40abbd:	e8 3e 66 ff ff       	call   401200 <read@plt>
  40abc2:	85 c0                	test   eax,eax
  40abc4:	7f 2a                	jg     40abf0 <win+0x967a>
  40abc6:	e8 b5 65 ff ff       	call   401180 <__errno_location@plt>
  40abcb:	8b 38                	mov    edi,DWORD PTR [rax]
  40abcd:	e8 ae 66 ff ff       	call   401280 <strerror@plt>
  40abd2:	bf 01 00 00 00       	mov    edi,0x1
  40abd7:	48 8d 35 cb 74 00 00 	lea    rsi,[rip+0x74cb]        # 4120a9 <_IO_stdin_used+0xa9>
  40abde:	48 89 c2             	mov    rdx,rax
  40abe1:	31 c0                	xor    eax,eax
  40abe3:	e8 48 66 ff ff       	call   401230 <__printf_chk@plt>
  40abe8:	83 cf ff             	or     edi,0xffffffff
  40abeb:	e8 70 66 ff ff       	call   401260 <exit@plt>
  40abf0:	48 63 d0             	movsxd rdx,eax
  40abf3:	48 89 ee             	mov    rsi,rbp
  40abf6:	bf 01 00 00 00       	mov    edi,0x1
  40abfb:	e8 a0 65 ff ff       	call   4011a0 <write@plt>
  40ac00:	48 8d 3d 4d 75 00 00 	lea    rdi,[rip+0x754d]        # 412154 <_IO_stdin_used+0x154>
  40ac07:	e8 84 65 ff ff       	call   401190 <puts@plt>
  40ac0c:	48 8d 3d f1 73 00 00 	lea    rdi,[rip+0x73f1]        # 412004 <_IO_stdin_used+0x4>
  40ac13:	31 f6                	xor    esi,esi
  40ac15:	31 c0                	xor    eax,eax
  40ac17:	e8 34 66 ff ff       	call   401250 <open@plt>
  40ac1c:	89 c7                	mov    edi,eax
  40ac1e:	85 c0                	test   eax,eax
  40ac20:	79 34                	jns    40ac56 <win+0x96e0>
  40ac22:	e8 59 65 ff ff       	call   401180 <__errno_location@plt>
  40ac27:	8b 38                	mov    edi,DWORD PTR [rax]
  40ac29:	e8 52 66 ff ff       	call   401280 <strerror@plt>
  40ac2e:	48 8d 35 d5 73 00 00 	lea    rsi,[rip+0x73d5]        # 41200a <_IO_stdin_used+0xa>
  40ac35:	bf 01 00 00 00       	mov    edi,0x1
  40ac3a:	48 89 c2             	mov    rdx,rax
  40ac3d:	31 c0                	xor    eax,eax
  40ac3f:	e8 ec 65 ff ff       	call   401230 <__printf_chk@plt>
  40ac44:	e8 97 65 ff ff       	call   4011e0 <geteuid@plt>
  40ac49:	85 c0                	test   eax,eax
  40ac4b:	0f 84 88 69 ff ff    	je     4015d9 <win+0x63>
  40ac51:	e9 6b 69 ff ff       	jmp    4015c1 <win+0x4b>
  40ac56:	ba 00 01 00 00       	mov    edx,0x100
  40ac5b:	48 89 ee             	mov    rsi,rbp
  40ac5e:	e8 9d 65 ff ff       	call   401200 <read@plt>
  40ac63:	85 c0                	test   eax,eax
  40ac65:	7f 2a                	jg     40ac91 <win+0x971b>
  40ac67:	e8 14 65 ff ff       	call   401180 <__errno_location@plt>
  40ac6c:	8b 38                	mov    edi,DWORD PTR [rax]
  40ac6e:	e8 0d 66 ff ff       	call   401280 <strerror@plt>
  40ac73:	bf 01 00 00 00       	mov    edi,0x1
  40ac78:	48 8d 35 2a 74 00 00 	lea    rsi,[rip+0x742a]        # 4120a9 <_IO_stdin_used+0xa9>
  40ac7f:	48 89 c2             	mov    rdx,rax
  40ac82:	31 c0                	xor    eax,eax
  40ac84:	e8 a7 65 ff ff       	call   401230 <__printf_chk@plt>
  40ac89:	83 cf ff             	or     edi,0xffffffff
  40ac8c:	e8 cf 65 ff ff       	call   401260 <exit@plt>
  40ac91:	48 89 e5             	mov    rbp,rsp
  40ac94:	48 63 d0             	movsxd rdx,eax
  40ac97:	bf 01 00 00 00       	mov    edi,0x1
  40ac9c:	48 89 ee             	mov    rsi,rbp
  40ac9f:	e8 fc 64 ff ff       	call   4011a0 <write@plt>
  40aca4:	48 8d 3d a9 74 00 00 	lea    rdi,[rip+0x74a9]        # 412154 <_IO_stdin_used+0x154>
  40acab:	e8 e0 64 ff ff       	call   401190 <puts@plt>
  40acb0:	48 8d 3d 4d 73 00 00 	lea    rdi,[rip+0x734d]        # 412004 <_IO_stdin_used+0x4>
  40acb7:	31 f6                	xor    esi,esi
  40acb9:	31 c0                	xor    eax,eax
  40acbb:	e8 90 65 ff ff       	call   401250 <open@plt>
  40acc0:	89 c7                	mov    edi,eax
  40acc2:	85 c0                	test   eax,eax
  40acc4:	79 34                	jns    40acfa <win+0x9784>
  40acc6:	e8 b5 64 ff ff       	call   401180 <__errno_location@plt>
  40accb:	8b 38                	mov    edi,DWORD PTR [rax]
  40accd:	e8 ae 65 ff ff       	call   401280 <strerror@plt>
  40acd2:	48 8d 35 31 73 00 00 	lea    rsi,[rip+0x7331]        # 41200a <_IO_stdin_used+0xa>
  40acd9:	bf 01 00 00 00       	mov    edi,0x1
  40acde:	48 89 c2             	mov    rdx,rax
  40ace1:	31 c0                	xor    eax,eax
  40ace3:	e8 48 65 ff ff       	call   401230 <__printf_chk@plt>
  40ace8:	e8 f3 64 ff ff       	call   4011e0 <geteuid@plt>
  40aced:	85 c0                	test   eax,eax
  40acef:	0f 84 e4 68 ff ff    	je     4015d9 <win+0x63>
  40acf5:	e9 c7 68 ff ff       	jmp    4015c1 <win+0x4b>
  40acfa:	ba 00 01 00 00       	mov    edx,0x100
  40acff:	48 89 ee             	mov    rsi,rbp
  40ad02:	e8 f9 64 ff ff       	call   401200 <read@plt>
  40ad07:	85 c0                	test   eax,eax
  40ad09:	7f 2a                	jg     40ad35 <win+0x97bf>
  40ad0b:	e8 70 64 ff ff       	call   401180 <__errno_location@plt>
  40ad10:	8b 38                	mov    edi,DWORD PTR [rax]
  40ad12:	e8 69 65 ff ff       	call   401280 <strerror@plt>
  40ad17:	bf 01 00 00 00       	mov    edi,0x1
  40ad1c:	48 8d 35 86 73 00 00 	lea    rsi,[rip+0x7386]        # 4120a9 <_IO_stdin_used+0xa9>
  40ad23:	48 89 c2             	mov    rdx,rax
  40ad26:	31 c0                	xor    eax,eax
  40ad28:	e8 03 65 ff ff       	call   401230 <__printf_chk@plt>
  40ad2d:	83 cf ff             	or     edi,0xffffffff
  40ad30:	e8 2b 65 ff ff       	call   401260 <exit@plt>
  40ad35:	48 63 d0             	movsxd rdx,eax
  40ad38:	48 89 ee             	mov    rsi,rbp
  40ad3b:	bf 01 00 00 00       	mov    edi,0x1
  40ad40:	e8 5b 64 ff ff       	call   4011a0 <write@plt>
  40ad45:	48 8d 3d 08 74 00 00 	lea    rdi,[rip+0x7408]        # 412154 <_IO_stdin_used+0x154>
  40ad4c:	e8 3f 64 ff ff       	call   401190 <puts@plt>
  40ad51:	48 8d 3d ac 72 00 00 	lea    rdi,[rip+0x72ac]        # 412004 <_IO_stdin_used+0x4>
  40ad58:	31 f6                	xor    esi,esi
  40ad5a:	31 c0                	xor    eax,eax
  40ad5c:	e8 ef 64 ff ff       	call   401250 <open@plt>
  40ad61:	89 c7                	mov    edi,eax
  40ad63:	85 c0                	test   eax,eax
  40ad65:	79 34                	jns    40ad9b <win+0x9825>
  40ad67:	e8 14 64 ff ff       	call   401180 <__errno_location@plt>
  40ad6c:	8b 38                	mov    edi,DWORD PTR [rax]
  40ad6e:	e8 0d 65 ff ff       	call   401280 <strerror@plt>
  40ad73:	48 8d 35 90 72 00 00 	lea    rsi,[rip+0x7290]        # 41200a <_IO_stdin_used+0xa>
  40ad7a:	bf 01 00 00 00       	mov    edi,0x1
  40ad7f:	48 89 c2             	mov    rdx,rax
  40ad82:	31 c0                	xor    eax,eax
  40ad84:	e8 a7 64 ff ff       	call   401230 <__printf_chk@plt>
  40ad89:	e8 52 64 ff ff       	call   4011e0 <geteuid@plt>
  40ad8e:	85 c0                	test   eax,eax
  40ad90:	0f 84 43 68 ff ff    	je     4015d9 <win+0x63>
  40ad96:	e9 26 68 ff ff       	jmp    4015c1 <win+0x4b>
  40ad9b:	ba 00 01 00 00       	mov    edx,0x100
  40ada0:	48 89 ee             	mov    rsi,rbp
  40ada3:	e8 58 64 ff ff       	call   401200 <read@plt>
  40ada8:	85 c0                	test   eax,eax
  40adaa:	7f 2a                	jg     40add6 <win+0x9860>
  40adac:	e8 cf 63 ff ff       	call   401180 <__errno_location@plt>
  40adb1:	8b 38                	mov    edi,DWORD PTR [rax]
  40adb3:	e8 c8 64 ff ff       	call   401280 <strerror@plt>
  40adb8:	bf 01 00 00 00       	mov    edi,0x1
  40adbd:	48 8d 35 e5 72 00 00 	lea    rsi,[rip+0x72e5]        # 4120a9 <_IO_stdin_used+0xa9>
  40adc4:	48 89 c2             	mov    rdx,rax
  40adc7:	31 c0                	xor    eax,eax
  40adc9:	e8 62 64 ff ff       	call   401230 <__printf_chk@plt>
  40adce:	83 cf ff             	or     edi,0xffffffff
  40add1:	e8 8a 64 ff ff       	call   401260 <exit@plt>
  40add6:	48 63 d0             	movsxd rdx,eax
  40add9:	48 89 ee             	mov    rsi,rbp
  40addc:	bf 01 00 00 00       	mov    edi,0x1
  40ade1:	e8 ba 63 ff ff       	call   4011a0 <write@plt>
  40ade6:	48 8d 3d 67 73 00 00 	lea    rdi,[rip+0x7367]        # 412154 <_IO_stdin_used+0x154>
  40aded:	e8 9e 63 ff ff       	call   401190 <puts@plt>
  40adf2:	48 8d 3d 0b 72 00 00 	lea    rdi,[rip+0x720b]        # 412004 <_IO_stdin_used+0x4>
  40adf9:	31 f6                	xor    esi,esi
  40adfb:	31 c0                	xor    eax,eax
  40adfd:	e8 4e 64 ff ff       	call   401250 <open@plt>
  40ae02:	89 c7                	mov    edi,eax
  40ae04:	85 c0                	test   eax,eax
  40ae06:	79 34                	jns    40ae3c <win+0x98c6>
  40ae08:	e8 73 63 ff ff       	call   401180 <__errno_location@plt>
  40ae0d:	8b 38                	mov    edi,DWORD PTR [rax]
  40ae0f:	e8 6c 64 ff ff       	call   401280 <strerror@plt>
  40ae14:	48 8d 35 ef 71 00 00 	lea    rsi,[rip+0x71ef]        # 41200a <_IO_stdin_used+0xa>
  40ae1b:	bf 01 00 00 00       	mov    edi,0x1
  40ae20:	48 89 c2             	mov    rdx,rax
  40ae23:	31 c0                	xor    eax,eax
  40ae25:	e8 06 64 ff ff       	call   401230 <__printf_chk@plt>
  40ae2a:	e8 b1 63 ff ff       	call   4011e0 <geteuid@plt>
  40ae2f:	85 c0                	test   eax,eax
  40ae31:	0f 84 a2 67 ff ff    	je     4015d9 <win+0x63>
  40ae37:	e9 85 67 ff ff       	jmp    4015c1 <win+0x4b>
  40ae3c:	ba 00 01 00 00       	mov    edx,0x100
  40ae41:	48 89 ee             	mov    rsi,rbp
  40ae44:	e8 b7 63 ff ff       	call   401200 <read@plt>
  40ae49:	85 c0                	test   eax,eax
  40ae4b:	7f 2a                	jg     40ae77 <win+0x9901>
  40ae4d:	e8 2e 63 ff ff       	call   401180 <__errno_location@plt>
  40ae52:	8b 38                	mov    edi,DWORD PTR [rax]
  40ae54:	e8 27 64 ff ff       	call   401280 <strerror@plt>
  40ae59:	bf 01 00 00 00       	mov    edi,0x1
  40ae5e:	48 8d 35 44 72 00 00 	lea    rsi,[rip+0x7244]        # 4120a9 <_IO_stdin_used+0xa9>
  40ae65:	48 89 c2             	mov    rdx,rax
  40ae68:	31 c0                	xor    eax,eax
  40ae6a:	e8 c1 63 ff ff       	call   401230 <__printf_chk@plt>
  40ae6f:	83 cf ff             	or     edi,0xffffffff
  40ae72:	e8 e9 63 ff ff       	call   401260 <exit@plt>
  40ae77:	48 63 d0             	movsxd rdx,eax
  40ae7a:	48 89 ee             	mov    rsi,rbp
  40ae7d:	bf 01 00 00 00       	mov    edi,0x1
  40ae82:	e8 19 63 ff ff       	call   4011a0 <write@plt>
  40ae87:	48 8d 3d c6 72 00 00 	lea    rdi,[rip+0x72c6]        # 412154 <_IO_stdin_used+0x154>
  40ae8e:	e8 fd 62 ff ff       	call   401190 <puts@plt>
  40ae93:	48 8d 3d 6a 71 00 00 	lea    rdi,[rip+0x716a]        # 412004 <_IO_stdin_used+0x4>
  40ae9a:	31 f6                	xor    esi,esi
  40ae9c:	31 c0                	xor    eax,eax
  40ae9e:	e8 ad 63 ff ff       	call   401250 <open@plt>
  40aea3:	89 c7                	mov    edi,eax
  40aea5:	85 c0                	test   eax,eax
  40aea7:	79 34                	jns    40aedd <win+0x9967>
  40aea9:	e8 d2 62 ff ff       	call   401180 <__errno_location@plt>
  40aeae:	8b 38                	mov    edi,DWORD PTR [rax]
  40aeb0:	e8 cb 63 ff ff       	call   401280 <strerror@plt>
  40aeb5:	48 8d 35 4e 71 00 00 	lea    rsi,[rip+0x714e]        # 41200a <_IO_stdin_used+0xa>
  40aebc:	bf 01 00 00 00       	mov    edi,0x1
  40aec1:	48 89 c2             	mov    rdx,rax
  40aec4:	31 c0                	xor    eax,eax
  40aec6:	e8 65 63 ff ff       	call   401230 <__printf_chk@plt>
  40aecb:	e8 10 63 ff ff       	call   4011e0 <geteuid@plt>
  40aed0:	85 c0                	test   eax,eax
  40aed2:	0f 84 01 67 ff ff    	je     4015d9 <win+0x63>
  40aed8:	e9 e4 66 ff ff       	jmp    4015c1 <win+0x4b>
  40aedd:	ba 00 01 00 00       	mov    edx,0x100
  40aee2:	48 89 ee             	mov    rsi,rbp
  40aee5:	e8 16 63 ff ff       	call   401200 <read@plt>
  40aeea:	85 c0                	test   eax,eax
  40aeec:	7f 2a                	jg     40af18 <win+0x99a2>
  40aeee:	e8 8d 62 ff ff       	call   401180 <__errno_location@plt>
  40aef3:	8b 38                	mov    edi,DWORD PTR [rax]
  40aef5:	e8 86 63 ff ff       	call   401280 <strerror@plt>
  40aefa:	bf 01 00 00 00       	mov    edi,0x1
  40aeff:	48 8d 35 a3 71 00 00 	lea    rsi,[rip+0x71a3]        # 4120a9 <_IO_stdin_used+0xa9>
  40af06:	48 89 c2             	mov    rdx,rax
  40af09:	31 c0                	xor    eax,eax
  40af0b:	e8 20 63 ff ff       	call   401230 <__printf_chk@plt>
  40af10:	83 cf ff             	or     edi,0xffffffff
  40af13:	e8 48 63 ff ff       	call   401260 <exit@plt>
  40af18:	48 63 d0             	movsxd rdx,eax
  40af1b:	48 89 ee             	mov    rsi,rbp
  40af1e:	bf 01 00 00 00       	mov    edi,0x1
  40af23:	e8 78 62 ff ff       	call   4011a0 <write@plt>
  40af28:	48 8d 3d 25 72 00 00 	lea    rdi,[rip+0x7225]        # 412154 <_IO_stdin_used+0x154>
  40af2f:	e8 5c 62 ff ff       	call   401190 <puts@plt>
  40af34:	48 8d 3d c9 70 00 00 	lea    rdi,[rip+0x70c9]        # 412004 <_IO_stdin_used+0x4>
  40af3b:	31 f6                	xor    esi,esi
  40af3d:	31 c0                	xor    eax,eax
  40af3f:	e8 0c 63 ff ff       	call   401250 <open@plt>
  40af44:	89 c7                	mov    edi,eax
  40af46:	85 c0                	test   eax,eax
  40af48:	79 34                	jns    40af7e <win+0x9a08>
  40af4a:	e8 31 62 ff ff       	call   401180 <__errno_location@plt>
  40af4f:	8b 38                	mov    edi,DWORD PTR [rax]
  40af51:	e8 2a 63 ff ff       	call   401280 <strerror@plt>
  40af56:	48 8d 35 ad 70 00 00 	lea    rsi,[rip+0x70ad]        # 41200a <_IO_stdin_used+0xa>
  40af5d:	bf 01 00 00 00       	mov    edi,0x1
  40af62:	48 89 c2             	mov    rdx,rax
  40af65:	31 c0                	xor    eax,eax
  40af67:	e8 c4 62 ff ff       	call   401230 <__printf_chk@plt>
  40af6c:	e8 6f 62 ff ff       	call   4011e0 <geteuid@plt>
  40af71:	85 c0                	test   eax,eax
  40af73:	0f 84 60 66 ff ff    	je     4015d9 <win+0x63>
  40af79:	e9 43 66 ff ff       	jmp    4015c1 <win+0x4b>
  40af7e:	ba 00 01 00 00       	mov    edx,0x100
  40af83:	48 89 ee             	mov    rsi,rbp
  40af86:	e8 75 62 ff ff       	call   401200 <read@plt>
  40af8b:	85 c0                	test   eax,eax
  40af8d:	7f 2a                	jg     40afb9 <win+0x9a43>
  40af8f:	e8 ec 61 ff ff       	call   401180 <__errno_location@plt>
  40af94:	8b 38                	mov    edi,DWORD PTR [rax]
  40af96:	e8 e5 62 ff ff       	call   401280 <strerror@plt>
  40af9b:	bf 01 00 00 00       	mov    edi,0x1
  40afa0:	48 8d 35 02 71 00 00 	lea    rsi,[rip+0x7102]        # 4120a9 <_IO_stdin_used+0xa9>
  40afa7:	48 89 c2             	mov    rdx,rax
  40afaa:	31 c0                	xor    eax,eax
  40afac:	e8 7f 62 ff ff       	call   401230 <__printf_chk@plt>
  40afb1:	83 cf ff             	or     edi,0xffffffff
  40afb4:	e8 a7 62 ff ff       	call   401260 <exit@plt>
  40afb9:	48 63 d0             	movsxd rdx,eax
  40afbc:	48 89 ee             	mov    rsi,rbp
  40afbf:	bf 01 00 00 00       	mov    edi,0x1
  40afc4:	e8 d7 61 ff ff       	call   4011a0 <write@plt>
  40afc9:	48 8d 3d 84 71 00 00 	lea    rdi,[rip+0x7184]        # 412154 <_IO_stdin_used+0x154>
  40afd0:	e8 bb 61 ff ff       	call   401190 <puts@plt>
  40afd5:	48 8d 3d 28 70 00 00 	lea    rdi,[rip+0x7028]        # 412004 <_IO_stdin_used+0x4>
  40afdc:	31 f6                	xor    esi,esi
  40afde:	31 c0                	xor    eax,eax
  40afe0:	e8 6b 62 ff ff       	call   401250 <open@plt>
  40afe5:	89 c7                	mov    edi,eax
  40afe7:	85 c0                	test   eax,eax
  40afe9:	79 34                	jns    40b01f <win+0x9aa9>
  40afeb:	e8 90 61 ff ff       	call   401180 <__errno_location@plt>
  40aff0:	8b 38                	mov    edi,DWORD PTR [rax]
  40aff2:	e8 89 62 ff ff       	call   401280 <strerror@plt>
  40aff7:	48 8d 35 0c 70 00 00 	lea    rsi,[rip+0x700c]        # 41200a <_IO_stdin_used+0xa>
  40affe:	bf 01 00 00 00       	mov    edi,0x1
  40b003:	48 89 c2             	mov    rdx,rax
  40b006:	31 c0                	xor    eax,eax
  40b008:	e8 23 62 ff ff       	call   401230 <__printf_chk@plt>
  40b00d:	e8 ce 61 ff ff       	call   4011e0 <geteuid@plt>
  40b012:	85 c0                	test   eax,eax
  40b014:	0f 84 bf 65 ff ff    	je     4015d9 <win+0x63>
  40b01a:	e9 a2 65 ff ff       	jmp    4015c1 <win+0x4b>
  40b01f:	ba 00 01 00 00       	mov    edx,0x100
  40b024:	48 89 ee             	mov    rsi,rbp
  40b027:	e8 d4 61 ff ff       	call   401200 <read@plt>
  40b02c:	85 c0                	test   eax,eax
  40b02e:	7f 2a                	jg     40b05a <win+0x9ae4>
  40b030:	e8 4b 61 ff ff       	call   401180 <__errno_location@plt>
  40b035:	8b 38                	mov    edi,DWORD PTR [rax]
  40b037:	e8 44 62 ff ff       	call   401280 <strerror@plt>
  40b03c:	bf 01 00 00 00       	mov    edi,0x1
  40b041:	48 8d 35 61 70 00 00 	lea    rsi,[rip+0x7061]        # 4120a9 <_IO_stdin_used+0xa9>
  40b048:	48 89 c2             	mov    rdx,rax
  40b04b:	31 c0                	xor    eax,eax
  40b04d:	e8 de 61 ff ff       	call   401230 <__printf_chk@plt>
  40b052:	83 cf ff             	or     edi,0xffffffff
  40b055:	e8 06 62 ff ff       	call   401260 <exit@plt>
  40b05a:	48 63 d0             	movsxd rdx,eax
  40b05d:	48 89 ee             	mov    rsi,rbp
  40b060:	bf 01 00 00 00       	mov    edi,0x1
  40b065:	e8 36 61 ff ff       	call   4011a0 <write@plt>
  40b06a:	48 8d 3d e3 70 00 00 	lea    rdi,[rip+0x70e3]        # 412154 <_IO_stdin_used+0x154>
  40b071:	e8 1a 61 ff ff       	call   401190 <puts@plt>
  40b076:	48 8d 3d 87 6f 00 00 	lea    rdi,[rip+0x6f87]        # 412004 <_IO_stdin_used+0x4>
  40b07d:	31 f6                	xor    esi,esi
  40b07f:	31 c0                	xor    eax,eax
  40b081:	e8 ca 61 ff ff       	call   401250 <open@plt>
  40b086:	89 c7                	mov    edi,eax
  40b088:	85 c0                	test   eax,eax
  40b08a:	79 34                	jns    40b0c0 <win+0x9b4a>
  40b08c:	e8 ef 60 ff ff       	call   401180 <__errno_location@plt>
  40b091:	8b 38                	mov    edi,DWORD PTR [rax]
  40b093:	e8 e8 61 ff ff       	call   401280 <strerror@plt>
  40b098:	48 8d 35 6b 6f 00 00 	lea    rsi,[rip+0x6f6b]        # 41200a <_IO_stdin_used+0xa>
  40b09f:	bf 01 00 00 00       	mov    edi,0x1
  40b0a4:	48 89 c2             	mov    rdx,rax
  40b0a7:	31 c0                	xor    eax,eax
  40b0a9:	e8 82 61 ff ff       	call   401230 <__printf_chk@plt>
  40b0ae:	e8 2d 61 ff ff       	call   4011e0 <geteuid@plt>
  40b0b3:	85 c0                	test   eax,eax
  40b0b5:	0f 84 1e 65 ff ff    	je     4015d9 <win+0x63>
  40b0bb:	e9 01 65 ff ff       	jmp    4015c1 <win+0x4b>
  40b0c0:	ba 00 01 00 00       	mov    edx,0x100
  40b0c5:	48 89 ee             	mov    rsi,rbp
  40b0c8:	e8 33 61 ff ff       	call   401200 <read@plt>
  40b0cd:	85 c0                	test   eax,eax
  40b0cf:	7f 2a                	jg     40b0fb <win+0x9b85>
  40b0d1:	e8 aa 60 ff ff       	call   401180 <__errno_location@plt>
  40b0d6:	8b 38                	mov    edi,DWORD PTR [rax]
  40b0d8:	e8 a3 61 ff ff       	call   401280 <strerror@plt>
  40b0dd:	bf 01 00 00 00       	mov    edi,0x1
  40b0e2:	48 8d 35 c0 6f 00 00 	lea    rsi,[rip+0x6fc0]        # 4120a9 <_IO_stdin_used+0xa9>
  40b0e9:	48 89 c2             	mov    rdx,rax
  40b0ec:	31 c0                	xor    eax,eax
  40b0ee:	e8 3d 61 ff ff       	call   401230 <__printf_chk@plt>
  40b0f3:	83 cf ff             	or     edi,0xffffffff
  40b0f6:	e8 65 61 ff ff       	call   401260 <exit@plt>
  40b0fb:	48 63 d0             	movsxd rdx,eax
  40b0fe:	48 89 ee             	mov    rsi,rbp
  40b101:	bf 01 00 00 00       	mov    edi,0x1
  40b106:	e8 95 60 ff ff       	call   4011a0 <write@plt>
  40b10b:	48 8d 3d 42 70 00 00 	lea    rdi,[rip+0x7042]        # 412154 <_IO_stdin_used+0x154>
  40b112:	e8 79 60 ff ff       	call   401190 <puts@plt>
  40b117:	48 8d 3d e6 6e 00 00 	lea    rdi,[rip+0x6ee6]        # 412004 <_IO_stdin_used+0x4>
  40b11e:	31 f6                	xor    esi,esi
  40b120:	31 c0                	xor    eax,eax
  40b122:	e8 29 61 ff ff       	call   401250 <open@plt>
  40b127:	89 c7                	mov    edi,eax
  40b129:	85 c0                	test   eax,eax
  40b12b:	79 34                	jns    40b161 <win+0x9beb>
  40b12d:	e8 4e 60 ff ff       	call   401180 <__errno_location@plt>
  40b132:	8b 38                	mov    edi,DWORD PTR [rax]
  40b134:	e8 47 61 ff ff       	call   401280 <strerror@plt>
  40b139:	48 8d 35 ca 6e 00 00 	lea    rsi,[rip+0x6eca]        # 41200a <_IO_stdin_used+0xa>
  40b140:	bf 01 00 00 00       	mov    edi,0x1
  40b145:	48 89 c2             	mov    rdx,rax
  40b148:	31 c0                	xor    eax,eax
  40b14a:	e8 e1 60 ff ff       	call   401230 <__printf_chk@plt>
  40b14f:	e8 8c 60 ff ff       	call   4011e0 <geteuid@plt>
  40b154:	85 c0                	test   eax,eax
  40b156:	0f 84 7d 64 ff ff    	je     4015d9 <win+0x63>
  40b15c:	e9 60 64 ff ff       	jmp    4015c1 <win+0x4b>
  40b161:	ba 00 01 00 00       	mov    edx,0x100
  40b166:	48 89 ee             	mov    rsi,rbp
  40b169:	e8 92 60 ff ff       	call   401200 <read@plt>
  40b16e:	85 c0                	test   eax,eax
  40b170:	7f 2a                	jg     40b19c <win+0x9c26>
  40b172:	e8 09 60 ff ff       	call   401180 <__errno_location@plt>
  40b177:	8b 38                	mov    edi,DWORD PTR [rax]
  40b179:	e8 02 61 ff ff       	call   401280 <strerror@plt>
  40b17e:	bf 01 00 00 00       	mov    edi,0x1
  40b183:	48 8d 35 1f 6f 00 00 	lea    rsi,[rip+0x6f1f]        # 4120a9 <_IO_stdin_used+0xa9>
  40b18a:	48 89 c2             	mov    rdx,rax
  40b18d:	31 c0                	xor    eax,eax
  40b18f:	e8 9c 60 ff ff       	call   401230 <__printf_chk@plt>
  40b194:	83 cf ff             	or     edi,0xffffffff
  40b197:	e8 c4 60 ff ff       	call   401260 <exit@plt>
  40b19c:	48 63 d0             	movsxd rdx,eax
  40b19f:	48 89 ee             	mov    rsi,rbp
  40b1a2:	bf 01 00 00 00       	mov    edi,0x1
  40b1a7:	e8 f4 5f ff ff       	call   4011a0 <write@plt>
  40b1ac:	48 8d 3d a1 6f 00 00 	lea    rdi,[rip+0x6fa1]        # 412154 <_IO_stdin_used+0x154>
  40b1b3:	e8 d8 5f ff ff       	call   401190 <puts@plt>
  40b1b8:	48 8d 3d 45 6e 00 00 	lea    rdi,[rip+0x6e45]        # 412004 <_IO_stdin_used+0x4>
  40b1bf:	31 f6                	xor    esi,esi
  40b1c1:	31 c0                	xor    eax,eax
  40b1c3:	e8 88 60 ff ff       	call   401250 <open@plt>
  40b1c8:	89 c7                	mov    edi,eax
  40b1ca:	85 c0                	test   eax,eax
  40b1cc:	79 34                	jns    40b202 <win+0x9c8c>
  40b1ce:	e8 ad 5f ff ff       	call   401180 <__errno_location@plt>
  40b1d3:	8b 38                	mov    edi,DWORD PTR [rax]
  40b1d5:	e8 a6 60 ff ff       	call   401280 <strerror@plt>
  40b1da:	48 8d 35 29 6e 00 00 	lea    rsi,[rip+0x6e29]        # 41200a <_IO_stdin_used+0xa>
  40b1e1:	bf 01 00 00 00       	mov    edi,0x1
  40b1e6:	48 89 c2             	mov    rdx,rax
  40b1e9:	31 c0                	xor    eax,eax
  40b1eb:	e8 40 60 ff ff       	call   401230 <__printf_chk@plt>
  40b1f0:	e8 eb 5f ff ff       	call   4011e0 <geteuid@plt>
  40b1f5:	85 c0                	test   eax,eax
  40b1f7:	0f 84 dc 63 ff ff    	je     4015d9 <win+0x63>
  40b1fd:	e9 bf 63 ff ff       	jmp    4015c1 <win+0x4b>
  40b202:	ba 00 01 00 00       	mov    edx,0x100
  40b207:	48 89 ee             	mov    rsi,rbp
  40b20a:	e8 f1 5f ff ff       	call   401200 <read@plt>
  40b20f:	85 c0                	test   eax,eax
  40b211:	7f 2a                	jg     40b23d <win+0x9cc7>
  40b213:	e8 68 5f ff ff       	call   401180 <__errno_location@plt>
  40b218:	8b 38                	mov    edi,DWORD PTR [rax]
  40b21a:	e8 61 60 ff ff       	call   401280 <strerror@plt>
  40b21f:	bf 01 00 00 00       	mov    edi,0x1
  40b224:	48 8d 35 7e 6e 00 00 	lea    rsi,[rip+0x6e7e]        # 4120a9 <_IO_stdin_used+0xa9>
  40b22b:	48 89 c2             	mov    rdx,rax
  40b22e:	31 c0                	xor    eax,eax
  40b230:	e8 fb 5f ff ff       	call   401230 <__printf_chk@plt>
  40b235:	83 cf ff             	or     edi,0xffffffff
  40b238:	e8 23 60 ff ff       	call   401260 <exit@plt>
  40b23d:	48 63 d0             	movsxd rdx,eax
  40b240:	48 89 ee             	mov    rsi,rbp
  40b243:	bf 01 00 00 00       	mov    edi,0x1
  40b248:	e8 53 5f ff ff       	call   4011a0 <write@plt>
  40b24d:	48 8d 3d 00 6f 00 00 	lea    rdi,[rip+0x6f00]        # 412154 <_IO_stdin_used+0x154>
  40b254:	e8 37 5f ff ff       	call   401190 <puts@plt>
  40b259:	48 8d 3d a4 6d 00 00 	lea    rdi,[rip+0x6da4]        # 412004 <_IO_stdin_used+0x4>
  40b260:	31 f6                	xor    esi,esi
  40b262:	31 c0                	xor    eax,eax
  40b264:	e8 e7 5f ff ff       	call   401250 <open@plt>
  40b269:	89 c7                	mov    edi,eax
  40b26b:	85 c0                	test   eax,eax
  40b26d:	79 34                	jns    40b2a3 <win+0x9d2d>
  40b26f:	e8 0c 5f ff ff       	call   401180 <__errno_location@plt>
  40b274:	8b 38                	mov    edi,DWORD PTR [rax]
  40b276:	e8 05 60 ff ff       	call   401280 <strerror@plt>
  40b27b:	48 8d 35 88 6d 00 00 	lea    rsi,[rip+0x6d88]        # 41200a <_IO_stdin_used+0xa>
  40b282:	bf 01 00 00 00       	mov    edi,0x1
  40b287:	48 89 c2             	mov    rdx,rax
  40b28a:	31 c0                	xor    eax,eax
  40b28c:	e8 9f 5f ff ff       	call   401230 <__printf_chk@plt>
  40b291:	e8 4a 5f ff ff       	call   4011e0 <geteuid@plt>
  40b296:	85 c0                	test   eax,eax
  40b298:	0f 84 3b 63 ff ff    	je     4015d9 <win+0x63>
  40b29e:	e9 1e 63 ff ff       	jmp    4015c1 <win+0x4b>
  40b2a3:	ba 00 01 00 00       	mov    edx,0x100
  40b2a8:	48 89 ee             	mov    rsi,rbp
  40b2ab:	e8 50 5f ff ff       	call   401200 <read@plt>
  40b2b0:	85 c0                	test   eax,eax
  40b2b2:	7f 2a                	jg     40b2de <win+0x9d68>
  40b2b4:	e8 c7 5e ff ff       	call   401180 <__errno_location@plt>
  40b2b9:	8b 38                	mov    edi,DWORD PTR [rax]
  40b2bb:	e8 c0 5f ff ff       	call   401280 <strerror@plt>
  40b2c0:	bf 01 00 00 00       	mov    edi,0x1
  40b2c5:	48 8d 35 dd 6d 00 00 	lea    rsi,[rip+0x6ddd]        # 4120a9 <_IO_stdin_used+0xa9>
  40b2cc:	48 89 c2             	mov    rdx,rax
  40b2cf:	31 c0                	xor    eax,eax
  40b2d1:	e8 5a 5f ff ff       	call   401230 <__printf_chk@plt>
  40b2d6:	83 cf ff             	or     edi,0xffffffff
  40b2d9:	e8 82 5f ff ff       	call   401260 <exit@plt>
  40b2de:	48 63 d0             	movsxd rdx,eax
  40b2e1:	48 89 ee             	mov    rsi,rbp
  40b2e4:	bf 01 00 00 00       	mov    edi,0x1
  40b2e9:	e8 b2 5e ff ff       	call   4011a0 <write@plt>
  40b2ee:	48 8d 3d 5f 6e 00 00 	lea    rdi,[rip+0x6e5f]        # 412154 <_IO_stdin_used+0x154>
  40b2f5:	e8 96 5e ff ff       	call   401190 <puts@plt>
  40b2fa:	48 8d 3d 03 6d 00 00 	lea    rdi,[rip+0x6d03]        # 412004 <_IO_stdin_used+0x4>
  40b301:	31 f6                	xor    esi,esi
  40b303:	31 c0                	xor    eax,eax
  40b305:	e8 46 5f ff ff       	call   401250 <open@plt>
  40b30a:	89 c7                	mov    edi,eax
  40b30c:	85 c0                	test   eax,eax
  40b30e:	79 34                	jns    40b344 <win+0x9dce>
  40b310:	e8 6b 5e ff ff       	call   401180 <__errno_location@plt>
  40b315:	8b 38                	mov    edi,DWORD PTR [rax]
  40b317:	e8 64 5f ff ff       	call   401280 <strerror@plt>
  40b31c:	48 8d 35 e7 6c 00 00 	lea    rsi,[rip+0x6ce7]        # 41200a <_IO_stdin_used+0xa>
  40b323:	bf 01 00 00 00       	mov    edi,0x1
  40b328:	48 89 c2             	mov    rdx,rax
  40b32b:	31 c0                	xor    eax,eax
  40b32d:	e8 fe 5e ff ff       	call   401230 <__printf_chk@plt>
  40b332:	e8 a9 5e ff ff       	call   4011e0 <geteuid@plt>
  40b337:	85 c0                	test   eax,eax
  40b339:	0f 84 9a 62 ff ff    	je     4015d9 <win+0x63>
  40b33f:	e9 7d 62 ff ff       	jmp    4015c1 <win+0x4b>
  40b344:	ba 00 01 00 00       	mov    edx,0x100
  40b349:	48 89 ee             	mov    rsi,rbp
  40b34c:	e8 af 5e ff ff       	call   401200 <read@plt>
  40b351:	85 c0                	test   eax,eax
  40b353:	7f 2a                	jg     40b37f <win+0x9e09>
  40b355:	e8 26 5e ff ff       	call   401180 <__errno_location@plt>
  40b35a:	8b 38                	mov    edi,DWORD PTR [rax]
  40b35c:	e8 1f 5f ff ff       	call   401280 <strerror@plt>
  40b361:	bf 01 00 00 00       	mov    edi,0x1
  40b366:	48 8d 35 3c 6d 00 00 	lea    rsi,[rip+0x6d3c]        # 4120a9 <_IO_stdin_used+0xa9>
  40b36d:	48 89 c2             	mov    rdx,rax
  40b370:	31 c0                	xor    eax,eax
  40b372:	e8 b9 5e ff ff       	call   401230 <__printf_chk@plt>
  40b377:	83 cf ff             	or     edi,0xffffffff
  40b37a:	e8 e1 5e ff ff       	call   401260 <exit@plt>
  40b37f:	48 63 d0             	movsxd rdx,eax
  40b382:	48 89 ee             	mov    rsi,rbp
  40b385:	bf 01 00 00 00       	mov    edi,0x1
  40b38a:	e8 11 5e ff ff       	call   4011a0 <write@plt>
  40b38f:	48 8d 3d be 6d 00 00 	lea    rdi,[rip+0x6dbe]        # 412154 <_IO_stdin_used+0x154>
  40b396:	e8 f5 5d ff ff       	call   401190 <puts@plt>
  40b39b:	48 8d 3d 62 6c 00 00 	lea    rdi,[rip+0x6c62]        # 412004 <_IO_stdin_used+0x4>
  40b3a2:	31 f6                	xor    esi,esi
  40b3a4:	31 c0                	xor    eax,eax
  40b3a6:	e8 a5 5e ff ff       	call   401250 <open@plt>
  40b3ab:	89 c7                	mov    edi,eax
  40b3ad:	85 c0                	test   eax,eax
  40b3af:	79 34                	jns    40b3e5 <win+0x9e6f>
  40b3b1:	e8 ca 5d ff ff       	call   401180 <__errno_location@plt>
  40b3b6:	8b 38                	mov    edi,DWORD PTR [rax]
  40b3b8:	e8 c3 5e ff ff       	call   401280 <strerror@plt>
  40b3bd:	48 8d 35 46 6c 00 00 	lea    rsi,[rip+0x6c46]        # 41200a <_IO_stdin_used+0xa>
  40b3c4:	bf 01 00 00 00       	mov    edi,0x1
  40b3c9:	48 89 c2             	mov    rdx,rax
  40b3cc:	31 c0                	xor    eax,eax
  40b3ce:	e8 5d 5e ff ff       	call   401230 <__printf_chk@plt>
  40b3d3:	e8 08 5e ff ff       	call   4011e0 <geteuid@plt>
  40b3d8:	85 c0                	test   eax,eax
  40b3da:	0f 84 f9 61 ff ff    	je     4015d9 <win+0x63>
  40b3e0:	e9 dc 61 ff ff       	jmp    4015c1 <win+0x4b>
  40b3e5:	ba 00 01 00 00       	mov    edx,0x100
  40b3ea:	48 89 ee             	mov    rsi,rbp
  40b3ed:	e8 0e 5e ff ff       	call   401200 <read@plt>
  40b3f2:	85 c0                	test   eax,eax
  40b3f4:	7f 2a                	jg     40b420 <win+0x9eaa>
  40b3f6:	e8 85 5d ff ff       	call   401180 <__errno_location@plt>
  40b3fb:	8b 38                	mov    edi,DWORD PTR [rax]
  40b3fd:	e8 7e 5e ff ff       	call   401280 <strerror@plt>
  40b402:	bf 01 00 00 00       	mov    edi,0x1
  40b407:	48 8d 35 9b 6c 00 00 	lea    rsi,[rip+0x6c9b]        # 4120a9 <_IO_stdin_used+0xa9>
  40b40e:	48 89 c2             	mov    rdx,rax
  40b411:	31 c0                	xor    eax,eax
  40b413:	e8 18 5e ff ff       	call   401230 <__printf_chk@plt>
  40b418:	83 cf ff             	or     edi,0xffffffff
  40b41b:	e8 40 5e ff ff       	call   401260 <exit@plt>
  40b420:	48 63 d0             	movsxd rdx,eax
  40b423:	48 89 ee             	mov    rsi,rbp
  40b426:	bf 01 00 00 00       	mov    edi,0x1
  40b42b:	e8 70 5d ff ff       	call   4011a0 <write@plt>
  40b430:	48 8d 3d 1d 6d 00 00 	lea    rdi,[rip+0x6d1d]        # 412154 <_IO_stdin_used+0x154>
  40b437:	e8 54 5d ff ff       	call   401190 <puts@plt>
  40b43c:	48 8d 3d c1 6b 00 00 	lea    rdi,[rip+0x6bc1]        # 412004 <_IO_stdin_used+0x4>
  40b443:	31 f6                	xor    esi,esi
  40b445:	31 c0                	xor    eax,eax
  40b447:	e8 04 5e ff ff       	call   401250 <open@plt>
  40b44c:	89 c7                	mov    edi,eax
  40b44e:	85 c0                	test   eax,eax
  40b450:	79 34                	jns    40b486 <win+0x9f10>
  40b452:	e8 29 5d ff ff       	call   401180 <__errno_location@plt>
  40b457:	8b 38                	mov    edi,DWORD PTR [rax]
  40b459:	e8 22 5e ff ff       	call   401280 <strerror@plt>
  40b45e:	48 8d 35 a5 6b 00 00 	lea    rsi,[rip+0x6ba5]        # 41200a <_IO_stdin_used+0xa>
  40b465:	bf 01 00 00 00       	mov    edi,0x1
  40b46a:	48 89 c2             	mov    rdx,rax
  40b46d:	31 c0                	xor    eax,eax
  40b46f:	e8 bc 5d ff ff       	call   401230 <__printf_chk@plt>
  40b474:	e8 67 5d ff ff       	call   4011e0 <geteuid@plt>
  40b479:	85 c0                	test   eax,eax
  40b47b:	0f 84 58 61 ff ff    	je     4015d9 <win+0x63>
  40b481:	e9 3b 61 ff ff       	jmp    4015c1 <win+0x4b>
  40b486:	ba 00 01 00 00       	mov    edx,0x100
  40b48b:	48 89 ee             	mov    rsi,rbp
  40b48e:	e8 6d 5d ff ff       	call   401200 <read@plt>
  40b493:	85 c0                	test   eax,eax
  40b495:	7f 2a                	jg     40b4c1 <win+0x9f4b>
  40b497:	e8 e4 5c ff ff       	call   401180 <__errno_location@plt>
  40b49c:	8b 38                	mov    edi,DWORD PTR [rax]
  40b49e:	e8 dd 5d ff ff       	call   401280 <strerror@plt>
  40b4a3:	bf 01 00 00 00       	mov    edi,0x1
  40b4a8:	48 8d 35 fa 6b 00 00 	lea    rsi,[rip+0x6bfa]        # 4120a9 <_IO_stdin_used+0xa9>
  40b4af:	48 89 c2             	mov    rdx,rax
  40b4b2:	31 c0                	xor    eax,eax
  40b4b4:	e8 77 5d ff ff       	call   401230 <__printf_chk@plt>
  40b4b9:	83 cf ff             	or     edi,0xffffffff
  40b4bc:	e8 9f 5d ff ff       	call   401260 <exit@plt>
  40b4c1:	48 63 d0             	movsxd rdx,eax
  40b4c4:	48 89 ee             	mov    rsi,rbp
  40b4c7:	bf 01 00 00 00       	mov    edi,0x1
  40b4cc:	e8 cf 5c ff ff       	call   4011a0 <write@plt>
  40b4d1:	48 8d 3d 7c 6c 00 00 	lea    rdi,[rip+0x6c7c]        # 412154 <_IO_stdin_used+0x154>
  40b4d8:	e8 b3 5c ff ff       	call   401190 <puts@plt>
  40b4dd:	48 8d 3d 20 6b 00 00 	lea    rdi,[rip+0x6b20]        # 412004 <_IO_stdin_used+0x4>
  40b4e4:	31 f6                	xor    esi,esi
  40b4e6:	31 c0                	xor    eax,eax
  40b4e8:	e8 63 5d ff ff       	call   401250 <open@plt>
  40b4ed:	89 c7                	mov    edi,eax
  40b4ef:	85 c0                	test   eax,eax
  40b4f1:	79 34                	jns    40b527 <win+0x9fb1>
  40b4f3:	e8 88 5c ff ff       	call   401180 <__errno_location@plt>
  40b4f8:	8b 38                	mov    edi,DWORD PTR [rax]
  40b4fa:	e8 81 5d ff ff       	call   401280 <strerror@plt>
  40b4ff:	48 8d 35 04 6b 00 00 	lea    rsi,[rip+0x6b04]        # 41200a <_IO_stdin_used+0xa>
  40b506:	bf 01 00 00 00       	mov    edi,0x1
  40b50b:	48 89 c2             	mov    rdx,rax
  40b50e:	31 c0                	xor    eax,eax
  40b510:	e8 1b 5d ff ff       	call   401230 <__printf_chk@plt>
  40b515:	e8 c6 5c ff ff       	call   4011e0 <geteuid@plt>
  40b51a:	85 c0                	test   eax,eax
  40b51c:	0f 84 b7 60 ff ff    	je     4015d9 <win+0x63>
  40b522:	e9 9a 60 ff ff       	jmp    4015c1 <win+0x4b>
  40b527:	ba 00 01 00 00       	mov    edx,0x100
  40b52c:	48 89 ee             	mov    rsi,rbp
  40b52f:	e8 cc 5c ff ff       	call   401200 <read@plt>
  40b534:	85 c0                	test   eax,eax
  40b536:	7f 2a                	jg     40b562 <win+0x9fec>
  40b538:	e8 43 5c ff ff       	call   401180 <__errno_location@plt>
  40b53d:	8b 38                	mov    edi,DWORD PTR [rax]
  40b53f:	e8 3c 5d ff ff       	call   401280 <strerror@plt>
  40b544:	bf 01 00 00 00       	mov    edi,0x1
  40b549:	48 8d 35 59 6b 00 00 	lea    rsi,[rip+0x6b59]        # 4120a9 <_IO_stdin_used+0xa9>
  40b550:	48 89 c2             	mov    rdx,rax
  40b553:	31 c0                	xor    eax,eax
  40b555:	e8 d6 5c ff ff       	call   401230 <__printf_chk@plt>
  40b55a:	83 cf ff             	or     edi,0xffffffff
  40b55d:	e8 fe 5c ff ff       	call   401260 <exit@plt>
  40b562:	48 63 d0             	movsxd rdx,eax
  40b565:	48 89 ee             	mov    rsi,rbp
  40b568:	bf 01 00 00 00       	mov    edi,0x1
  40b56d:	e8 2e 5c ff ff       	call   4011a0 <write@plt>
  40b572:	48 8d 3d db 6b 00 00 	lea    rdi,[rip+0x6bdb]        # 412154 <_IO_stdin_used+0x154>
  40b579:	e8 12 5c ff ff       	call   401190 <puts@plt>
  40b57e:	48 8d 3d 7f 6a 00 00 	lea    rdi,[rip+0x6a7f]        # 412004 <_IO_stdin_used+0x4>
  40b585:	31 f6                	xor    esi,esi
  40b587:	31 c0                	xor    eax,eax
  40b589:	e8 c2 5c ff ff       	call   401250 <open@plt>
  40b58e:	89 c7                	mov    edi,eax
  40b590:	85 c0                	test   eax,eax
  40b592:	79 34                	jns    40b5c8 <win+0xa052>
  40b594:	e8 e7 5b ff ff       	call   401180 <__errno_location@plt>
  40b599:	8b 38                	mov    edi,DWORD PTR [rax]
  40b59b:	e8 e0 5c ff ff       	call   401280 <strerror@plt>
  40b5a0:	48 8d 35 63 6a 00 00 	lea    rsi,[rip+0x6a63]        # 41200a <_IO_stdin_used+0xa>
  40b5a7:	bf 01 00 00 00       	mov    edi,0x1
  40b5ac:	48 89 c2             	mov    rdx,rax
  40b5af:	31 c0                	xor    eax,eax
  40b5b1:	e8 7a 5c ff ff       	call   401230 <__printf_chk@plt>
  40b5b6:	e8 25 5c ff ff       	call   4011e0 <geteuid@plt>
  40b5bb:	85 c0                	test   eax,eax
  40b5bd:	0f 84 16 60 ff ff    	je     4015d9 <win+0x63>
  40b5c3:	e9 f9 5f ff ff       	jmp    4015c1 <win+0x4b>
  40b5c8:	ba 00 01 00 00       	mov    edx,0x100
  40b5cd:	48 89 ee             	mov    rsi,rbp
  40b5d0:	e8 2b 5c ff ff       	call   401200 <read@plt>
  40b5d5:	85 c0                	test   eax,eax
  40b5d7:	7f 2a                	jg     40b603 <win+0xa08d>
  40b5d9:	e8 a2 5b ff ff       	call   401180 <__errno_location@plt>
  40b5de:	8b 38                	mov    edi,DWORD PTR [rax]
  40b5e0:	e8 9b 5c ff ff       	call   401280 <strerror@plt>
  40b5e5:	bf 01 00 00 00       	mov    edi,0x1
  40b5ea:	48 8d 35 b8 6a 00 00 	lea    rsi,[rip+0x6ab8]        # 4120a9 <_IO_stdin_used+0xa9>
  40b5f1:	48 89 c2             	mov    rdx,rax
  40b5f4:	31 c0                	xor    eax,eax
  40b5f6:	e8 35 5c ff ff       	call   401230 <__printf_chk@plt>
  40b5fb:	83 cf ff             	or     edi,0xffffffff
  40b5fe:	e8 5d 5c ff ff       	call   401260 <exit@plt>
  40b603:	48 63 d0             	movsxd rdx,eax
  40b606:	48 89 ee             	mov    rsi,rbp
  40b609:	bf 01 00 00 00       	mov    edi,0x1
  40b60e:	e8 8d 5b ff ff       	call   4011a0 <write@plt>
  40b613:	48 8d 3d 3a 6b 00 00 	lea    rdi,[rip+0x6b3a]        # 412154 <_IO_stdin_used+0x154>
  40b61a:	e8 71 5b ff ff       	call   401190 <puts@plt>
  40b61f:	48 8d 3d de 69 00 00 	lea    rdi,[rip+0x69de]        # 412004 <_IO_stdin_used+0x4>
  40b626:	31 f6                	xor    esi,esi
  40b628:	31 c0                	xor    eax,eax
  40b62a:	e8 21 5c ff ff       	call   401250 <open@plt>
  40b62f:	89 c7                	mov    edi,eax
  40b631:	85 c0                	test   eax,eax
  40b633:	79 34                	jns    40b669 <win+0xa0f3>
  40b635:	e8 46 5b ff ff       	call   401180 <__errno_location@plt>
  40b63a:	8b 38                	mov    edi,DWORD PTR [rax]
  40b63c:	e8 3f 5c ff ff       	call   401280 <strerror@plt>
  40b641:	48 8d 35 c2 69 00 00 	lea    rsi,[rip+0x69c2]        # 41200a <_IO_stdin_used+0xa>
  40b648:	bf 01 00 00 00       	mov    edi,0x1
  40b64d:	48 89 c2             	mov    rdx,rax
  40b650:	31 c0                	xor    eax,eax
  40b652:	e8 d9 5b ff ff       	call   401230 <__printf_chk@plt>
  40b657:	e8 84 5b ff ff       	call   4011e0 <geteuid@plt>
  40b65c:	85 c0                	test   eax,eax
  40b65e:	0f 84 75 5f ff ff    	je     4015d9 <win+0x63>
  40b664:	e9 58 5f ff ff       	jmp    4015c1 <win+0x4b>
  40b669:	ba 00 01 00 00       	mov    edx,0x100
  40b66e:	48 89 ee             	mov    rsi,rbp
  40b671:	e8 8a 5b ff ff       	call   401200 <read@plt>
  40b676:	85 c0                	test   eax,eax
  40b678:	7f 2a                	jg     40b6a4 <win+0xa12e>
  40b67a:	e8 01 5b ff ff       	call   401180 <__errno_location@plt>
  40b67f:	8b 38                	mov    edi,DWORD PTR [rax]
  40b681:	e8 fa 5b ff ff       	call   401280 <strerror@plt>
  40b686:	bf 01 00 00 00       	mov    edi,0x1
  40b68b:	48 8d 35 17 6a 00 00 	lea    rsi,[rip+0x6a17]        # 4120a9 <_IO_stdin_used+0xa9>
  40b692:	48 89 c2             	mov    rdx,rax
  40b695:	31 c0                	xor    eax,eax
  40b697:	e8 94 5b ff ff       	call   401230 <__printf_chk@plt>
  40b69c:	83 cf ff             	or     edi,0xffffffff
  40b69f:	e8 bc 5b ff ff       	call   401260 <exit@plt>
  40b6a4:	48 63 d0             	movsxd rdx,eax
  40b6a7:	48 89 ee             	mov    rsi,rbp
  40b6aa:	bf 01 00 00 00       	mov    edi,0x1
  40b6af:	e8 ec 5a ff ff       	call   4011a0 <write@plt>
  40b6b4:	48 8d 3d 99 6a 00 00 	lea    rdi,[rip+0x6a99]        # 412154 <_IO_stdin_used+0x154>
  40b6bb:	e8 d0 5a ff ff       	call   401190 <puts@plt>
  40b6c0:	48 8d 3d 3d 69 00 00 	lea    rdi,[rip+0x693d]        # 412004 <_IO_stdin_used+0x4>
  40b6c7:	31 f6                	xor    esi,esi
  40b6c9:	31 c0                	xor    eax,eax
  40b6cb:	e8 80 5b ff ff       	call   401250 <open@plt>
  40b6d0:	89 c7                	mov    edi,eax
  40b6d2:	85 c0                	test   eax,eax
  40b6d4:	79 34                	jns    40b70a <win+0xa194>
  40b6d6:	e8 a5 5a ff ff       	call   401180 <__errno_location@plt>
  40b6db:	8b 38                	mov    edi,DWORD PTR [rax]
  40b6dd:	e8 9e 5b ff ff       	call   401280 <strerror@plt>
  40b6e2:	48 8d 35 21 69 00 00 	lea    rsi,[rip+0x6921]        # 41200a <_IO_stdin_used+0xa>
  40b6e9:	bf 01 00 00 00       	mov    edi,0x1
  40b6ee:	48 89 c2             	mov    rdx,rax
  40b6f1:	31 c0                	xor    eax,eax
  40b6f3:	e8 38 5b ff ff       	call   401230 <__printf_chk@plt>
  40b6f8:	e8 e3 5a ff ff       	call   4011e0 <geteuid@plt>
  40b6fd:	85 c0                	test   eax,eax
  40b6ff:	0f 84 d4 5e ff ff    	je     4015d9 <win+0x63>
  40b705:	e9 b7 5e ff ff       	jmp    4015c1 <win+0x4b>
  40b70a:	ba 00 01 00 00       	mov    edx,0x100
  40b70f:	48 89 ee             	mov    rsi,rbp
  40b712:	e8 e9 5a ff ff       	call   401200 <read@plt>
  40b717:	85 c0                	test   eax,eax
  40b719:	7f 2a                	jg     40b745 <win+0xa1cf>
  40b71b:	e8 60 5a ff ff       	call   401180 <__errno_location@plt>
  40b720:	8b 38                	mov    edi,DWORD PTR [rax]
  40b722:	e8 59 5b ff ff       	call   401280 <strerror@plt>
  40b727:	bf 01 00 00 00       	mov    edi,0x1
  40b72c:	48 8d 35 76 69 00 00 	lea    rsi,[rip+0x6976]        # 4120a9 <_IO_stdin_used+0xa9>
  40b733:	48 89 c2             	mov    rdx,rax
  40b736:	31 c0                	xor    eax,eax
  40b738:	e8 f3 5a ff ff       	call   401230 <__printf_chk@plt>
  40b73d:	83 cf ff             	or     edi,0xffffffff
  40b740:	e8 1b 5b ff ff       	call   401260 <exit@plt>
  40b745:	48 63 d0             	movsxd rdx,eax
  40b748:	48 89 ee             	mov    rsi,rbp
  40b74b:	bf 01 00 00 00       	mov    edi,0x1
  40b750:	e8 4b 5a ff ff       	call   4011a0 <write@plt>
  40b755:	48 8d 3d f8 69 00 00 	lea    rdi,[rip+0x69f8]        # 412154 <_IO_stdin_used+0x154>
  40b75c:	e8 2f 5a ff ff       	call   401190 <puts@plt>
  40b761:	48 8d 3d 9c 68 00 00 	lea    rdi,[rip+0x689c]        # 412004 <_IO_stdin_used+0x4>
  40b768:	31 f6                	xor    esi,esi
  40b76a:	31 c0                	xor    eax,eax
  40b76c:	e8 df 5a ff ff       	call   401250 <open@plt>
  40b771:	89 c7                	mov    edi,eax
  40b773:	85 c0                	test   eax,eax
  40b775:	79 34                	jns    40b7ab <win+0xa235>
  40b777:	e8 04 5a ff ff       	call   401180 <__errno_location@plt>
  40b77c:	8b 38                	mov    edi,DWORD PTR [rax]
  40b77e:	e8 fd 5a ff ff       	call   401280 <strerror@plt>
  40b783:	48 8d 35 80 68 00 00 	lea    rsi,[rip+0x6880]        # 41200a <_IO_stdin_used+0xa>
  40b78a:	bf 01 00 00 00       	mov    edi,0x1
  40b78f:	48 89 c2             	mov    rdx,rax
  40b792:	31 c0                	xor    eax,eax
  40b794:	e8 97 5a ff ff       	call   401230 <__printf_chk@plt>
  40b799:	e8 42 5a ff ff       	call   4011e0 <geteuid@plt>
  40b79e:	85 c0                	test   eax,eax
  40b7a0:	0f 84 33 5e ff ff    	je     4015d9 <win+0x63>
  40b7a6:	e9 16 5e ff ff       	jmp    4015c1 <win+0x4b>
  40b7ab:	ba 00 01 00 00       	mov    edx,0x100
  40b7b0:	48 89 ee             	mov    rsi,rbp
  40b7b3:	e8 48 5a ff ff       	call   401200 <read@plt>
  40b7b8:	85 c0                	test   eax,eax
  40b7ba:	7f 2a                	jg     40b7e6 <win+0xa270>
  40b7bc:	e8 bf 59 ff ff       	call   401180 <__errno_location@plt>
  40b7c1:	8b 38                	mov    edi,DWORD PTR [rax]
  40b7c3:	e8 b8 5a ff ff       	call   401280 <strerror@plt>
  40b7c8:	bf 01 00 00 00       	mov    edi,0x1
  40b7cd:	48 8d 35 d5 68 00 00 	lea    rsi,[rip+0x68d5]        # 4120a9 <_IO_stdin_used+0xa9>
  40b7d4:	48 89 c2             	mov    rdx,rax
  40b7d7:	31 c0                	xor    eax,eax
  40b7d9:	e8 52 5a ff ff       	call   401230 <__printf_chk@plt>
  40b7de:	83 cf ff             	or     edi,0xffffffff
  40b7e1:	e8 7a 5a ff ff       	call   401260 <exit@plt>
  40b7e6:	48 63 d0             	movsxd rdx,eax
  40b7e9:	48 89 ee             	mov    rsi,rbp
  40b7ec:	bf 01 00 00 00       	mov    edi,0x1
  40b7f1:	e8 aa 59 ff ff       	call   4011a0 <write@plt>
  40b7f6:	48 8d 3d 57 69 00 00 	lea    rdi,[rip+0x6957]        # 412154 <_IO_stdin_used+0x154>
  40b7fd:	e8 8e 59 ff ff       	call   401190 <puts@plt>
  40b802:	48 8d 3d fb 67 00 00 	lea    rdi,[rip+0x67fb]        # 412004 <_IO_stdin_used+0x4>
  40b809:	31 f6                	xor    esi,esi
  40b80b:	31 c0                	xor    eax,eax
  40b80d:	e8 3e 5a ff ff       	call   401250 <open@plt>
  40b812:	89 c7                	mov    edi,eax
  40b814:	85 c0                	test   eax,eax
  40b816:	79 34                	jns    40b84c <win+0xa2d6>
  40b818:	e8 63 59 ff ff       	call   401180 <__errno_location@plt>
  40b81d:	8b 38                	mov    edi,DWORD PTR [rax]
  40b81f:	e8 5c 5a ff ff       	call   401280 <strerror@plt>
  40b824:	48 8d 35 df 67 00 00 	lea    rsi,[rip+0x67df]        # 41200a <_IO_stdin_used+0xa>
  40b82b:	bf 01 00 00 00       	mov    edi,0x1
  40b830:	48 89 c2             	mov    rdx,rax
  40b833:	31 c0                	xor    eax,eax
  40b835:	e8 f6 59 ff ff       	call   401230 <__printf_chk@plt>
  40b83a:	e8 a1 59 ff ff       	call   4011e0 <geteuid@plt>
  40b83f:	85 c0                	test   eax,eax
  40b841:	0f 84 92 5d ff ff    	je     4015d9 <win+0x63>
  40b847:	e9 75 5d ff ff       	jmp    4015c1 <win+0x4b>
  40b84c:	ba 00 01 00 00       	mov    edx,0x100
  40b851:	48 89 ee             	mov    rsi,rbp
  40b854:	e8 a7 59 ff ff       	call   401200 <read@plt>
  40b859:	85 c0                	test   eax,eax
  40b85b:	7f 2a                	jg     40b887 <win+0xa311>
  40b85d:	e8 1e 59 ff ff       	call   401180 <__errno_location@plt>
  40b862:	8b 38                	mov    edi,DWORD PTR [rax]
  40b864:	e8 17 5a ff ff       	call   401280 <strerror@plt>
  40b869:	bf 01 00 00 00       	mov    edi,0x1
  40b86e:	48 8d 35 34 68 00 00 	lea    rsi,[rip+0x6834]        # 4120a9 <_IO_stdin_used+0xa9>
  40b875:	48 89 c2             	mov    rdx,rax
  40b878:	31 c0                	xor    eax,eax
  40b87a:	e8 b1 59 ff ff       	call   401230 <__printf_chk@plt>
  40b87f:	83 cf ff             	or     edi,0xffffffff
  40b882:	e8 d9 59 ff ff       	call   401260 <exit@plt>
  40b887:	48 63 d0             	movsxd rdx,eax
  40b88a:	48 89 ee             	mov    rsi,rbp
  40b88d:	bf 01 00 00 00       	mov    edi,0x1
  40b892:	e8 09 59 ff ff       	call   4011a0 <write@plt>
  40b897:	48 8d 3d b6 68 00 00 	lea    rdi,[rip+0x68b6]        # 412154 <_IO_stdin_used+0x154>
  40b89e:	e8 ed 58 ff ff       	call   401190 <puts@plt>
  40b8a3:	48 8d 3d 5a 67 00 00 	lea    rdi,[rip+0x675a]        # 412004 <_IO_stdin_used+0x4>
  40b8aa:	31 f6                	xor    esi,esi
  40b8ac:	31 c0                	xor    eax,eax
  40b8ae:	e8 9d 59 ff ff       	call   401250 <open@plt>
  40b8b3:	89 c7                	mov    edi,eax
  40b8b5:	85 c0                	test   eax,eax
  40b8b7:	79 34                	jns    40b8ed <win+0xa377>
  40b8b9:	e8 c2 58 ff ff       	call   401180 <__errno_location@plt>
  40b8be:	8b 38                	mov    edi,DWORD PTR [rax]
  40b8c0:	e8 bb 59 ff ff       	call   401280 <strerror@plt>
  40b8c5:	48 8d 35 3e 67 00 00 	lea    rsi,[rip+0x673e]        # 41200a <_IO_stdin_used+0xa>
  40b8cc:	bf 01 00 00 00       	mov    edi,0x1
  40b8d1:	48 89 c2             	mov    rdx,rax
  40b8d4:	31 c0                	xor    eax,eax
  40b8d6:	e8 55 59 ff ff       	call   401230 <__printf_chk@plt>
  40b8db:	e8 00 59 ff ff       	call   4011e0 <geteuid@plt>
  40b8e0:	85 c0                	test   eax,eax
  40b8e2:	0f 84 f1 5c ff ff    	je     4015d9 <win+0x63>
  40b8e8:	e9 d4 5c ff ff       	jmp    4015c1 <win+0x4b>
  40b8ed:	ba 00 01 00 00       	mov    edx,0x100
  40b8f2:	48 89 ee             	mov    rsi,rbp
  40b8f5:	e8 06 59 ff ff       	call   401200 <read@plt>
  40b8fa:	85 c0                	test   eax,eax
  40b8fc:	7f 2a                	jg     40b928 <win+0xa3b2>
  40b8fe:	e8 7d 58 ff ff       	call   401180 <__errno_location@plt>
  40b903:	8b 38                	mov    edi,DWORD PTR [rax]
  40b905:	e8 76 59 ff ff       	call   401280 <strerror@plt>
  40b90a:	bf 01 00 00 00       	mov    edi,0x1
  40b90f:	48 8d 35 93 67 00 00 	lea    rsi,[rip+0x6793]        # 4120a9 <_IO_stdin_used+0xa9>
  40b916:	48 89 c2             	mov    rdx,rax
  40b919:	31 c0                	xor    eax,eax
  40b91b:	e8 10 59 ff ff       	call   401230 <__printf_chk@plt>
  40b920:	83 cf ff             	or     edi,0xffffffff
  40b923:	e8 38 59 ff ff       	call   401260 <exit@plt>
  40b928:	48 89 e5             	mov    rbp,rsp
  40b92b:	48 63 d0             	movsxd rdx,eax
  40b92e:	bf 01 00 00 00       	mov    edi,0x1
  40b933:	48 89 ee             	mov    rsi,rbp
  40b936:	e8 65 58 ff ff       	call   4011a0 <write@plt>
  40b93b:	48 8d 3d 12 68 00 00 	lea    rdi,[rip+0x6812]        # 412154 <_IO_stdin_used+0x154>
  40b942:	e8 49 58 ff ff       	call   401190 <puts@plt>
  40b947:	48 8d 3d b6 66 00 00 	lea    rdi,[rip+0x66b6]        # 412004 <_IO_stdin_used+0x4>
  40b94e:	31 f6                	xor    esi,esi
  40b950:	31 c0                	xor    eax,eax
  40b952:	e8 f9 58 ff ff       	call   401250 <open@plt>
  40b957:	89 c7                	mov    edi,eax
  40b959:	85 c0                	test   eax,eax
  40b95b:	79 34                	jns    40b991 <win+0xa41b>
  40b95d:	e8 1e 58 ff ff       	call   401180 <__errno_location@plt>
  40b962:	8b 38                	mov    edi,DWORD PTR [rax]
  40b964:	e8 17 59 ff ff       	call   401280 <strerror@plt>
  40b969:	48 8d 35 9a 66 00 00 	lea    rsi,[rip+0x669a]        # 41200a <_IO_stdin_used+0xa>
  40b970:	bf 01 00 00 00       	mov    edi,0x1
  40b975:	48 89 c2             	mov    rdx,rax
  40b978:	31 c0                	xor    eax,eax
  40b97a:	e8 b1 58 ff ff       	call   401230 <__printf_chk@plt>
  40b97f:	e8 5c 58 ff ff       	call   4011e0 <geteuid@plt>
  40b984:	85 c0                	test   eax,eax
  40b986:	0f 84 4d 5c ff ff    	je     4015d9 <win+0x63>
  40b98c:	e9 30 5c ff ff       	jmp    4015c1 <win+0x4b>
  40b991:	ba 00 01 00 00       	mov    edx,0x100
  40b996:	48 89 ee             	mov    rsi,rbp
  40b999:	e8 62 58 ff ff       	call   401200 <read@plt>
  40b99e:	85 c0                	test   eax,eax
  40b9a0:	7f 2a                	jg     40b9cc <win+0xa456>
  40b9a2:	e8 d9 57 ff ff       	call   401180 <__errno_location@plt>
  40b9a7:	8b 38                	mov    edi,DWORD PTR [rax]
  40b9a9:	e8 d2 58 ff ff       	call   401280 <strerror@plt>
  40b9ae:	bf 01 00 00 00       	mov    edi,0x1
  40b9b3:	48 8d 35 ef 66 00 00 	lea    rsi,[rip+0x66ef]        # 4120a9 <_IO_stdin_used+0xa9>
  40b9ba:	48 89 c2             	mov    rdx,rax
  40b9bd:	31 c0                	xor    eax,eax
  40b9bf:	e8 6c 58 ff ff       	call   401230 <__printf_chk@plt>
  40b9c4:	83 cf ff             	or     edi,0xffffffff
  40b9c7:	e8 94 58 ff ff       	call   401260 <exit@plt>
  40b9cc:	48 63 d0             	movsxd rdx,eax
  40b9cf:	48 89 ee             	mov    rsi,rbp
  40b9d2:	bf 01 00 00 00       	mov    edi,0x1
  40b9d7:	e8 c4 57 ff ff       	call   4011a0 <write@plt>
  40b9dc:	48 8d 3d 71 67 00 00 	lea    rdi,[rip+0x6771]        # 412154 <_IO_stdin_used+0x154>
  40b9e3:	e8 a8 57 ff ff       	call   401190 <puts@plt>
  40b9e8:	48 8d 3d 15 66 00 00 	lea    rdi,[rip+0x6615]        # 412004 <_IO_stdin_used+0x4>
  40b9ef:	31 f6                	xor    esi,esi
  40b9f1:	31 c0                	xor    eax,eax
  40b9f3:	e8 58 58 ff ff       	call   401250 <open@plt>
  40b9f8:	89 c7                	mov    edi,eax
  40b9fa:	85 c0                	test   eax,eax
  40b9fc:	79 34                	jns    40ba32 <win+0xa4bc>
  40b9fe:	e8 7d 57 ff ff       	call   401180 <__errno_location@plt>
  40ba03:	8b 38                	mov    edi,DWORD PTR [rax]
  40ba05:	e8 76 58 ff ff       	call   401280 <strerror@plt>
  40ba0a:	48 8d 35 f9 65 00 00 	lea    rsi,[rip+0x65f9]        # 41200a <_IO_stdin_used+0xa>
  40ba11:	bf 01 00 00 00       	mov    edi,0x1
  40ba16:	48 89 c2             	mov    rdx,rax
  40ba19:	31 c0                	xor    eax,eax
  40ba1b:	e8 10 58 ff ff       	call   401230 <__printf_chk@plt>
  40ba20:	e8 bb 57 ff ff       	call   4011e0 <geteuid@plt>
  40ba25:	85 c0                	test   eax,eax
  40ba27:	0f 84 ac 5b ff ff    	je     4015d9 <win+0x63>
  40ba2d:	e9 8f 5b ff ff       	jmp    4015c1 <win+0x4b>
  40ba32:	ba 00 01 00 00       	mov    edx,0x100
  40ba37:	48 89 ee             	mov    rsi,rbp
  40ba3a:	e8 c1 57 ff ff       	call   401200 <read@plt>
  40ba3f:	85 c0                	test   eax,eax
  40ba41:	7f 2a                	jg     40ba6d <win+0xa4f7>
  40ba43:	e8 38 57 ff ff       	call   401180 <__errno_location@plt>
  40ba48:	8b 38                	mov    edi,DWORD PTR [rax]
  40ba4a:	e8 31 58 ff ff       	call   401280 <strerror@plt>
  40ba4f:	bf 01 00 00 00       	mov    edi,0x1
  40ba54:	48 8d 35 4e 66 00 00 	lea    rsi,[rip+0x664e]        # 4120a9 <_IO_stdin_used+0xa9>
  40ba5b:	48 89 c2             	mov    rdx,rax
  40ba5e:	31 c0                	xor    eax,eax
  40ba60:	e8 cb 57 ff ff       	call   401230 <__printf_chk@plt>
  40ba65:	83 cf ff             	or     edi,0xffffffff
  40ba68:	e8 f3 57 ff ff       	call   401260 <exit@plt>
  40ba6d:	48 63 d0             	movsxd rdx,eax
  40ba70:	48 89 ee             	mov    rsi,rbp
  40ba73:	bf 01 00 00 00       	mov    edi,0x1
  40ba78:	e8 23 57 ff ff       	call   4011a0 <write@plt>
  40ba7d:	48 8d 3d d0 66 00 00 	lea    rdi,[rip+0x66d0]        # 412154 <_IO_stdin_used+0x154>
  40ba84:	e8 07 57 ff ff       	call   401190 <puts@plt>
  40ba89:	48 8d 3d 74 65 00 00 	lea    rdi,[rip+0x6574]        # 412004 <_IO_stdin_used+0x4>
  40ba90:	31 f6                	xor    esi,esi
  40ba92:	31 c0                	xor    eax,eax
  40ba94:	e8 b7 57 ff ff       	call   401250 <open@plt>
  40ba99:	89 c7                	mov    edi,eax
  40ba9b:	85 c0                	test   eax,eax
  40ba9d:	79 34                	jns    40bad3 <win+0xa55d>
  40ba9f:	e8 dc 56 ff ff       	call   401180 <__errno_location@plt>
  40baa4:	8b 38                	mov    edi,DWORD PTR [rax]
  40baa6:	e8 d5 57 ff ff       	call   401280 <strerror@plt>
  40baab:	48 8d 35 58 65 00 00 	lea    rsi,[rip+0x6558]        # 41200a <_IO_stdin_used+0xa>
  40bab2:	bf 01 00 00 00       	mov    edi,0x1
  40bab7:	48 89 c2             	mov    rdx,rax
  40baba:	31 c0                	xor    eax,eax
  40babc:	e8 6f 57 ff ff       	call   401230 <__printf_chk@plt>
  40bac1:	e8 1a 57 ff ff       	call   4011e0 <geteuid@plt>
  40bac6:	85 c0                	test   eax,eax
  40bac8:	0f 84 0b 5b ff ff    	je     4015d9 <win+0x63>
  40bace:	e9 ee 5a ff ff       	jmp    4015c1 <win+0x4b>
  40bad3:	ba 00 01 00 00       	mov    edx,0x100
  40bad8:	48 89 ee             	mov    rsi,rbp
  40badb:	e8 20 57 ff ff       	call   401200 <read@plt>
  40bae0:	85 c0                	test   eax,eax
  40bae2:	7f 2a                	jg     40bb0e <win+0xa598>
  40bae4:	e8 97 56 ff ff       	call   401180 <__errno_location@plt>
  40bae9:	8b 38                	mov    edi,DWORD PTR [rax]
  40baeb:	e8 90 57 ff ff       	call   401280 <strerror@plt>
  40baf0:	bf 01 00 00 00       	mov    edi,0x1
  40baf5:	48 8d 35 ad 65 00 00 	lea    rsi,[rip+0x65ad]        # 4120a9 <_IO_stdin_used+0xa9>
  40bafc:	48 89 c2             	mov    rdx,rax
  40baff:	31 c0                	xor    eax,eax
  40bb01:	e8 2a 57 ff ff       	call   401230 <__printf_chk@plt>
  40bb06:	83 cf ff             	or     edi,0xffffffff
  40bb09:	e8 52 57 ff ff       	call   401260 <exit@plt>
  40bb0e:	48 63 d0             	movsxd rdx,eax
  40bb11:	48 89 ee             	mov    rsi,rbp
  40bb14:	bf 01 00 00 00       	mov    edi,0x1
  40bb19:	e8 82 56 ff ff       	call   4011a0 <write@plt>
  40bb1e:	48 8d 3d 2f 66 00 00 	lea    rdi,[rip+0x662f]        # 412154 <_IO_stdin_used+0x154>
  40bb25:	e8 66 56 ff ff       	call   401190 <puts@plt>
  40bb2a:	48 8d 3d d3 64 00 00 	lea    rdi,[rip+0x64d3]        # 412004 <_IO_stdin_used+0x4>
  40bb31:	31 f6                	xor    esi,esi
  40bb33:	31 c0                	xor    eax,eax
  40bb35:	e8 16 57 ff ff       	call   401250 <open@plt>
  40bb3a:	89 c7                	mov    edi,eax
  40bb3c:	85 c0                	test   eax,eax
  40bb3e:	79 34                	jns    40bb74 <win+0xa5fe>
  40bb40:	e8 3b 56 ff ff       	call   401180 <__errno_location@plt>
  40bb45:	8b 38                	mov    edi,DWORD PTR [rax]
  40bb47:	e8 34 57 ff ff       	call   401280 <strerror@plt>
  40bb4c:	48 8d 35 b7 64 00 00 	lea    rsi,[rip+0x64b7]        # 41200a <_IO_stdin_used+0xa>
  40bb53:	bf 01 00 00 00       	mov    edi,0x1
  40bb58:	48 89 c2             	mov    rdx,rax
  40bb5b:	31 c0                	xor    eax,eax
  40bb5d:	e8 ce 56 ff ff       	call   401230 <__printf_chk@plt>
  40bb62:	e8 79 56 ff ff       	call   4011e0 <geteuid@plt>
  40bb67:	85 c0                	test   eax,eax
  40bb69:	0f 84 6a 5a ff ff    	je     4015d9 <win+0x63>
  40bb6f:	e9 4d 5a ff ff       	jmp    4015c1 <win+0x4b>
  40bb74:	ba 00 01 00 00       	mov    edx,0x100
  40bb79:	48 89 ee             	mov    rsi,rbp
  40bb7c:	e8 7f 56 ff ff       	call   401200 <read@plt>
  40bb81:	85 c0                	test   eax,eax
  40bb83:	7f 2a                	jg     40bbaf <win+0xa639>
  40bb85:	e8 f6 55 ff ff       	call   401180 <__errno_location@plt>
  40bb8a:	8b 38                	mov    edi,DWORD PTR [rax]
  40bb8c:	e8 ef 56 ff ff       	call   401280 <strerror@plt>
  40bb91:	bf 01 00 00 00       	mov    edi,0x1
  40bb96:	48 8d 35 0c 65 00 00 	lea    rsi,[rip+0x650c]        # 4120a9 <_IO_stdin_used+0xa9>
  40bb9d:	48 89 c2             	mov    rdx,rax
  40bba0:	31 c0                	xor    eax,eax
  40bba2:	e8 89 56 ff ff       	call   401230 <__printf_chk@plt>
  40bba7:	83 cf ff             	or     edi,0xffffffff
  40bbaa:	e8 b1 56 ff ff       	call   401260 <exit@plt>
  40bbaf:	48 63 d0             	movsxd rdx,eax
  40bbb2:	48 89 ee             	mov    rsi,rbp
  40bbb5:	bf 01 00 00 00       	mov    edi,0x1
  40bbba:	e8 e1 55 ff ff       	call   4011a0 <write@plt>
  40bbbf:	48 8d 3d 8e 65 00 00 	lea    rdi,[rip+0x658e]        # 412154 <_IO_stdin_used+0x154>
  40bbc6:	e8 c5 55 ff ff       	call   401190 <puts@plt>
  40bbcb:	48 8d 3d 32 64 00 00 	lea    rdi,[rip+0x6432]        # 412004 <_IO_stdin_used+0x4>
  40bbd2:	31 f6                	xor    esi,esi
  40bbd4:	31 c0                	xor    eax,eax
  40bbd6:	e8 75 56 ff ff       	call   401250 <open@plt>
  40bbdb:	89 c7                	mov    edi,eax
  40bbdd:	85 c0                	test   eax,eax
  40bbdf:	79 34                	jns    40bc15 <win+0xa69f>
  40bbe1:	e8 9a 55 ff ff       	call   401180 <__errno_location@plt>
  40bbe6:	8b 38                	mov    edi,DWORD PTR [rax]
  40bbe8:	e8 93 56 ff ff       	call   401280 <strerror@plt>
  40bbed:	48 8d 35 16 64 00 00 	lea    rsi,[rip+0x6416]        # 41200a <_IO_stdin_used+0xa>
  40bbf4:	bf 01 00 00 00       	mov    edi,0x1
  40bbf9:	48 89 c2             	mov    rdx,rax
  40bbfc:	31 c0                	xor    eax,eax
  40bbfe:	e8 2d 56 ff ff       	call   401230 <__printf_chk@plt>
  40bc03:	e8 d8 55 ff ff       	call   4011e0 <geteuid@plt>
  40bc08:	85 c0                	test   eax,eax
  40bc0a:	0f 84 c9 59 ff ff    	je     4015d9 <win+0x63>
  40bc10:	e9 ac 59 ff ff       	jmp    4015c1 <win+0x4b>
  40bc15:	ba 00 01 00 00       	mov    edx,0x100
  40bc1a:	48 89 ee             	mov    rsi,rbp
  40bc1d:	e8 de 55 ff ff       	call   401200 <read@plt>
  40bc22:	85 c0                	test   eax,eax
  40bc24:	7f 2a                	jg     40bc50 <win+0xa6da>
  40bc26:	e8 55 55 ff ff       	call   401180 <__errno_location@plt>
  40bc2b:	8b 38                	mov    edi,DWORD PTR [rax]
  40bc2d:	e8 4e 56 ff ff       	call   401280 <strerror@plt>
  40bc32:	bf 01 00 00 00       	mov    edi,0x1
  40bc37:	48 8d 35 6b 64 00 00 	lea    rsi,[rip+0x646b]        # 4120a9 <_IO_stdin_used+0xa9>
  40bc3e:	48 89 c2             	mov    rdx,rax
  40bc41:	31 c0                	xor    eax,eax
  40bc43:	e8 e8 55 ff ff       	call   401230 <__printf_chk@plt>
  40bc48:	83 cf ff             	or     edi,0xffffffff
  40bc4b:	e8 10 56 ff ff       	call   401260 <exit@plt>
  40bc50:	48 63 d0             	movsxd rdx,eax
  40bc53:	48 89 ee             	mov    rsi,rbp
  40bc56:	bf 01 00 00 00       	mov    edi,0x1
  40bc5b:	e8 40 55 ff ff       	call   4011a0 <write@plt>
  40bc60:	48 8d 3d ed 64 00 00 	lea    rdi,[rip+0x64ed]        # 412154 <_IO_stdin_used+0x154>
  40bc67:	e8 24 55 ff ff       	call   401190 <puts@plt>
  40bc6c:	48 8d 3d 91 63 00 00 	lea    rdi,[rip+0x6391]        # 412004 <_IO_stdin_used+0x4>
  40bc73:	31 f6                	xor    esi,esi
  40bc75:	31 c0                	xor    eax,eax
  40bc77:	e8 d4 55 ff ff       	call   401250 <open@plt>
  40bc7c:	89 c7                	mov    edi,eax
  40bc7e:	85 c0                	test   eax,eax
  40bc80:	79 34                	jns    40bcb6 <win+0xa740>
  40bc82:	e8 f9 54 ff ff       	call   401180 <__errno_location@plt>
  40bc87:	8b 38                	mov    edi,DWORD PTR [rax]
  40bc89:	e8 f2 55 ff ff       	call   401280 <strerror@plt>
  40bc8e:	48 8d 35 75 63 00 00 	lea    rsi,[rip+0x6375]        # 41200a <_IO_stdin_used+0xa>
  40bc95:	bf 01 00 00 00       	mov    edi,0x1
  40bc9a:	48 89 c2             	mov    rdx,rax
  40bc9d:	31 c0                	xor    eax,eax
  40bc9f:	e8 8c 55 ff ff       	call   401230 <__printf_chk@plt>
  40bca4:	e8 37 55 ff ff       	call   4011e0 <geteuid@plt>
  40bca9:	85 c0                	test   eax,eax
  40bcab:	0f 84 28 59 ff ff    	je     4015d9 <win+0x63>
  40bcb1:	e9 0b 59 ff ff       	jmp    4015c1 <win+0x4b>
  40bcb6:	ba 00 01 00 00       	mov    edx,0x100
  40bcbb:	48 89 ee             	mov    rsi,rbp
  40bcbe:	e8 3d 55 ff ff       	call   401200 <read@plt>
  40bcc3:	85 c0                	test   eax,eax
  40bcc5:	7f 2a                	jg     40bcf1 <win+0xa77b>
  40bcc7:	e8 b4 54 ff ff       	call   401180 <__errno_location@plt>
  40bccc:	8b 38                	mov    edi,DWORD PTR [rax]
  40bcce:	e8 ad 55 ff ff       	call   401280 <strerror@plt>
  40bcd3:	bf 01 00 00 00       	mov    edi,0x1
  40bcd8:	48 8d 35 ca 63 00 00 	lea    rsi,[rip+0x63ca]        # 4120a9 <_IO_stdin_used+0xa9>
  40bcdf:	48 89 c2             	mov    rdx,rax
  40bce2:	31 c0                	xor    eax,eax
  40bce4:	e8 47 55 ff ff       	call   401230 <__printf_chk@plt>
  40bce9:	83 cf ff             	or     edi,0xffffffff
  40bcec:	e8 6f 55 ff ff       	call   401260 <exit@plt>
  40bcf1:	48 63 d0             	movsxd rdx,eax
  40bcf4:	48 89 ee             	mov    rsi,rbp
  40bcf7:	bf 01 00 00 00       	mov    edi,0x1
  40bcfc:	e8 9f 54 ff ff       	call   4011a0 <write@plt>
  40bd01:	48 8d 3d 4c 64 00 00 	lea    rdi,[rip+0x644c]        # 412154 <_IO_stdin_used+0x154>
  40bd08:	e8 83 54 ff ff       	call   401190 <puts@plt>
  40bd0d:	48 8d 3d f0 62 00 00 	lea    rdi,[rip+0x62f0]        # 412004 <_IO_stdin_used+0x4>
  40bd14:	31 f6                	xor    esi,esi
  40bd16:	31 c0                	xor    eax,eax
  40bd18:	e8 33 55 ff ff       	call   401250 <open@plt>
  40bd1d:	89 c7                	mov    edi,eax
  40bd1f:	85 c0                	test   eax,eax
  40bd21:	79 34                	jns    40bd57 <win+0xa7e1>
  40bd23:	e8 58 54 ff ff       	call   401180 <__errno_location@plt>
  40bd28:	8b 38                	mov    edi,DWORD PTR [rax]
  40bd2a:	e8 51 55 ff ff       	call   401280 <strerror@plt>
  40bd2f:	48 8d 35 d4 62 00 00 	lea    rsi,[rip+0x62d4]        # 41200a <_IO_stdin_used+0xa>
  40bd36:	bf 01 00 00 00       	mov    edi,0x1
  40bd3b:	48 89 c2             	mov    rdx,rax
  40bd3e:	31 c0                	xor    eax,eax
  40bd40:	e8 eb 54 ff ff       	call   401230 <__printf_chk@plt>
  40bd45:	e8 96 54 ff ff       	call   4011e0 <geteuid@plt>
  40bd4a:	85 c0                	test   eax,eax
  40bd4c:	0f 84 87 58 ff ff    	je     4015d9 <win+0x63>
  40bd52:	e9 6a 58 ff ff       	jmp    4015c1 <win+0x4b>
  40bd57:	ba 00 01 00 00       	mov    edx,0x100
  40bd5c:	48 89 ee             	mov    rsi,rbp
  40bd5f:	e8 9c 54 ff ff       	call   401200 <read@plt>
  40bd64:	85 c0                	test   eax,eax
  40bd66:	7f 2a                	jg     40bd92 <win+0xa81c>
  40bd68:	e8 13 54 ff ff       	call   401180 <__errno_location@plt>
  40bd6d:	8b 38                	mov    edi,DWORD PTR [rax]
  40bd6f:	e8 0c 55 ff ff       	call   401280 <strerror@plt>
  40bd74:	bf 01 00 00 00       	mov    edi,0x1
  40bd79:	48 8d 35 29 63 00 00 	lea    rsi,[rip+0x6329]        # 4120a9 <_IO_stdin_used+0xa9>
  40bd80:	48 89 c2             	mov    rdx,rax
  40bd83:	31 c0                	xor    eax,eax
  40bd85:	e8 a6 54 ff ff       	call   401230 <__printf_chk@plt>
  40bd8a:	83 cf ff             	or     edi,0xffffffff
  40bd8d:	e8 ce 54 ff ff       	call   401260 <exit@plt>
  40bd92:	48 63 d0             	movsxd rdx,eax
  40bd95:	48 89 ee             	mov    rsi,rbp
  40bd98:	bf 01 00 00 00       	mov    edi,0x1
  40bd9d:	e8 fe 53 ff ff       	call   4011a0 <write@plt>
  40bda2:	48 8d 3d ab 63 00 00 	lea    rdi,[rip+0x63ab]        # 412154 <_IO_stdin_used+0x154>
  40bda9:	e8 e2 53 ff ff       	call   401190 <puts@plt>
  40bdae:	48 8d 3d 4f 62 00 00 	lea    rdi,[rip+0x624f]        # 412004 <_IO_stdin_used+0x4>
  40bdb5:	31 f6                	xor    esi,esi
  40bdb7:	31 c0                	xor    eax,eax
  40bdb9:	e8 92 54 ff ff       	call   401250 <open@plt>
  40bdbe:	89 c7                	mov    edi,eax
  40bdc0:	85 c0                	test   eax,eax
  40bdc2:	79 34                	jns    40bdf8 <win+0xa882>
  40bdc4:	e8 b7 53 ff ff       	call   401180 <__errno_location@plt>
  40bdc9:	8b 38                	mov    edi,DWORD PTR [rax]
  40bdcb:	e8 b0 54 ff ff       	call   401280 <strerror@plt>
  40bdd0:	48 8d 35 33 62 00 00 	lea    rsi,[rip+0x6233]        # 41200a <_IO_stdin_used+0xa>
  40bdd7:	bf 01 00 00 00       	mov    edi,0x1
  40bddc:	48 89 c2             	mov    rdx,rax
  40bddf:	31 c0                	xor    eax,eax
  40bde1:	e8 4a 54 ff ff       	call   401230 <__printf_chk@plt>
  40bde6:	e8 f5 53 ff ff       	call   4011e0 <geteuid@plt>
  40bdeb:	85 c0                	test   eax,eax
  40bded:	0f 84 e6 57 ff ff    	je     4015d9 <win+0x63>
  40bdf3:	e9 c9 57 ff ff       	jmp    4015c1 <win+0x4b>
  40bdf8:	ba 00 01 00 00       	mov    edx,0x100
  40bdfd:	48 89 ee             	mov    rsi,rbp
  40be00:	e8 fb 53 ff ff       	call   401200 <read@plt>
  40be05:	85 c0                	test   eax,eax
  40be07:	7f 2a                	jg     40be33 <win+0xa8bd>
  40be09:	e8 72 53 ff ff       	call   401180 <__errno_location@plt>
  40be0e:	8b 38                	mov    edi,DWORD PTR [rax]
  40be10:	e8 6b 54 ff ff       	call   401280 <strerror@plt>
  40be15:	bf 01 00 00 00       	mov    edi,0x1
  40be1a:	48 8d 35 88 62 00 00 	lea    rsi,[rip+0x6288]        # 4120a9 <_IO_stdin_used+0xa9>
  40be21:	48 89 c2             	mov    rdx,rax
  40be24:	31 c0                	xor    eax,eax
  40be26:	e8 05 54 ff ff       	call   401230 <__printf_chk@plt>
  40be2b:	83 cf ff             	or     edi,0xffffffff
  40be2e:	e8 2d 54 ff ff       	call   401260 <exit@plt>
  40be33:	48 63 d0             	movsxd rdx,eax
  40be36:	48 89 ee             	mov    rsi,rbp
  40be39:	bf 01 00 00 00       	mov    edi,0x1
  40be3e:	e8 5d 53 ff ff       	call   4011a0 <write@plt>
  40be43:	48 8d 3d 0a 63 00 00 	lea    rdi,[rip+0x630a]        # 412154 <_IO_stdin_used+0x154>
  40be4a:	e8 41 53 ff ff       	call   401190 <puts@plt>
  40be4f:	48 8d 3d ae 61 00 00 	lea    rdi,[rip+0x61ae]        # 412004 <_IO_stdin_used+0x4>
  40be56:	31 f6                	xor    esi,esi
  40be58:	31 c0                	xor    eax,eax
  40be5a:	e8 f1 53 ff ff       	call   401250 <open@plt>
  40be5f:	89 c7                	mov    edi,eax
  40be61:	85 c0                	test   eax,eax
  40be63:	79 34                	jns    40be99 <win+0xa923>
  40be65:	e8 16 53 ff ff       	call   401180 <__errno_location@plt>
  40be6a:	8b 38                	mov    edi,DWORD PTR [rax]
  40be6c:	e8 0f 54 ff ff       	call   401280 <strerror@plt>
  40be71:	48 8d 35 92 61 00 00 	lea    rsi,[rip+0x6192]        # 41200a <_IO_stdin_used+0xa>
  40be78:	bf 01 00 00 00       	mov    edi,0x1
  40be7d:	48 89 c2             	mov    rdx,rax
  40be80:	31 c0                	xor    eax,eax
  40be82:	e8 a9 53 ff ff       	call   401230 <__printf_chk@plt>
  40be87:	e8 54 53 ff ff       	call   4011e0 <geteuid@plt>
  40be8c:	85 c0                	test   eax,eax
  40be8e:	0f 84 45 57 ff ff    	je     4015d9 <win+0x63>
  40be94:	e9 28 57 ff ff       	jmp    4015c1 <win+0x4b>
  40be99:	ba 00 01 00 00       	mov    edx,0x100
  40be9e:	48 89 ee             	mov    rsi,rbp
  40bea1:	e8 5a 53 ff ff       	call   401200 <read@plt>
  40bea6:	85 c0                	test   eax,eax
  40bea8:	7f 2a                	jg     40bed4 <win+0xa95e>
  40beaa:	e8 d1 52 ff ff       	call   401180 <__errno_location@plt>
  40beaf:	8b 38                	mov    edi,DWORD PTR [rax]
  40beb1:	e8 ca 53 ff ff       	call   401280 <strerror@plt>
  40beb6:	bf 01 00 00 00       	mov    edi,0x1
  40bebb:	48 8d 35 e7 61 00 00 	lea    rsi,[rip+0x61e7]        # 4120a9 <_IO_stdin_used+0xa9>
  40bec2:	48 89 c2             	mov    rdx,rax
  40bec5:	31 c0                	xor    eax,eax
  40bec7:	e8 64 53 ff ff       	call   401230 <__printf_chk@plt>
  40becc:	83 cf ff             	or     edi,0xffffffff
  40becf:	e8 8c 53 ff ff       	call   401260 <exit@plt>
  40bed4:	48 63 d0             	movsxd rdx,eax
  40bed7:	48 89 ee             	mov    rsi,rbp
  40beda:	bf 01 00 00 00       	mov    edi,0x1
  40bedf:	e8 bc 52 ff ff       	call   4011a0 <write@plt>
  40bee4:	48 8d 3d 69 62 00 00 	lea    rdi,[rip+0x6269]        # 412154 <_IO_stdin_used+0x154>
  40beeb:	e8 a0 52 ff ff       	call   401190 <puts@plt>
  40bef0:	48 8d 3d 0d 61 00 00 	lea    rdi,[rip+0x610d]        # 412004 <_IO_stdin_used+0x4>
  40bef7:	31 f6                	xor    esi,esi
  40bef9:	31 c0                	xor    eax,eax
  40befb:	e8 50 53 ff ff       	call   401250 <open@plt>
  40bf00:	89 c7                	mov    edi,eax
  40bf02:	85 c0                	test   eax,eax
  40bf04:	79 34                	jns    40bf3a <win+0xa9c4>
  40bf06:	e8 75 52 ff ff       	call   401180 <__errno_location@plt>
  40bf0b:	8b 38                	mov    edi,DWORD PTR [rax]
  40bf0d:	e8 6e 53 ff ff       	call   401280 <strerror@plt>
  40bf12:	48 8d 35 f1 60 00 00 	lea    rsi,[rip+0x60f1]        # 41200a <_IO_stdin_used+0xa>
  40bf19:	bf 01 00 00 00       	mov    edi,0x1
  40bf1e:	48 89 c2             	mov    rdx,rax
  40bf21:	31 c0                	xor    eax,eax
  40bf23:	e8 08 53 ff ff       	call   401230 <__printf_chk@plt>
  40bf28:	e8 b3 52 ff ff       	call   4011e0 <geteuid@plt>
  40bf2d:	85 c0                	test   eax,eax
  40bf2f:	0f 84 a4 56 ff ff    	je     4015d9 <win+0x63>
  40bf35:	e9 87 56 ff ff       	jmp    4015c1 <win+0x4b>
  40bf3a:	ba 00 01 00 00       	mov    edx,0x100
  40bf3f:	48 89 ee             	mov    rsi,rbp
  40bf42:	e8 b9 52 ff ff       	call   401200 <read@plt>
  40bf47:	85 c0                	test   eax,eax
  40bf49:	7f 2a                	jg     40bf75 <win+0xa9ff>
  40bf4b:	e8 30 52 ff ff       	call   401180 <__errno_location@plt>
  40bf50:	8b 38                	mov    edi,DWORD PTR [rax]
  40bf52:	e8 29 53 ff ff       	call   401280 <strerror@plt>
  40bf57:	bf 01 00 00 00       	mov    edi,0x1
  40bf5c:	48 8d 35 46 61 00 00 	lea    rsi,[rip+0x6146]        # 4120a9 <_IO_stdin_used+0xa9>
  40bf63:	48 89 c2             	mov    rdx,rax
  40bf66:	31 c0                	xor    eax,eax
  40bf68:	e8 c3 52 ff ff       	call   401230 <__printf_chk@plt>
  40bf6d:	83 cf ff             	or     edi,0xffffffff
  40bf70:	e8 eb 52 ff ff       	call   401260 <exit@plt>
  40bf75:	48 63 d0             	movsxd rdx,eax
  40bf78:	48 89 ee             	mov    rsi,rbp
  40bf7b:	bf 01 00 00 00       	mov    edi,0x1
  40bf80:	e8 1b 52 ff ff       	call   4011a0 <write@plt>
  40bf85:	48 8d 3d c8 61 00 00 	lea    rdi,[rip+0x61c8]        # 412154 <_IO_stdin_used+0x154>
  40bf8c:	e8 ff 51 ff ff       	call   401190 <puts@plt>
  40bf91:	48 8d 3d 6c 60 00 00 	lea    rdi,[rip+0x606c]        # 412004 <_IO_stdin_used+0x4>
  40bf98:	31 f6                	xor    esi,esi
  40bf9a:	31 c0                	xor    eax,eax
  40bf9c:	e8 af 52 ff ff       	call   401250 <open@plt>
  40bfa1:	89 c7                	mov    edi,eax
  40bfa3:	85 c0                	test   eax,eax
  40bfa5:	79 34                	jns    40bfdb <win+0xaa65>
  40bfa7:	e8 d4 51 ff ff       	call   401180 <__errno_location@plt>
  40bfac:	8b 38                	mov    edi,DWORD PTR [rax]
  40bfae:	e8 cd 52 ff ff       	call   401280 <strerror@plt>
  40bfb3:	48 8d 35 50 60 00 00 	lea    rsi,[rip+0x6050]        # 41200a <_IO_stdin_used+0xa>
  40bfba:	bf 01 00 00 00       	mov    edi,0x1
  40bfbf:	48 89 c2             	mov    rdx,rax
  40bfc2:	31 c0                	xor    eax,eax
  40bfc4:	e8 67 52 ff ff       	call   401230 <__printf_chk@plt>
  40bfc9:	e8 12 52 ff ff       	call   4011e0 <geteuid@plt>
  40bfce:	85 c0                	test   eax,eax
  40bfd0:	0f 84 03 56 ff ff    	je     4015d9 <win+0x63>
  40bfd6:	e9 e6 55 ff ff       	jmp    4015c1 <win+0x4b>
  40bfdb:	ba 00 01 00 00       	mov    edx,0x100
  40bfe0:	48 89 ee             	mov    rsi,rbp
  40bfe3:	e8 18 52 ff ff       	call   401200 <read@plt>
  40bfe8:	85 c0                	test   eax,eax
  40bfea:	7f 2a                	jg     40c016 <win+0xaaa0>
  40bfec:	e8 8f 51 ff ff       	call   401180 <__errno_location@plt>
  40bff1:	8b 38                	mov    edi,DWORD PTR [rax]
  40bff3:	e8 88 52 ff ff       	call   401280 <strerror@plt>
  40bff8:	bf 01 00 00 00       	mov    edi,0x1
  40bffd:	48 8d 35 a5 60 00 00 	lea    rsi,[rip+0x60a5]        # 4120a9 <_IO_stdin_used+0xa9>
  40c004:	48 89 c2             	mov    rdx,rax
  40c007:	31 c0                	xor    eax,eax
  40c009:	e8 22 52 ff ff       	call   401230 <__printf_chk@plt>
  40c00e:	83 cf ff             	or     edi,0xffffffff
  40c011:	e8 4a 52 ff ff       	call   401260 <exit@plt>
  40c016:	48 63 d0             	movsxd rdx,eax
  40c019:	48 89 ee             	mov    rsi,rbp
  40c01c:	bf 01 00 00 00       	mov    edi,0x1
  40c021:	e8 7a 51 ff ff       	call   4011a0 <write@plt>
  40c026:	48 8d 3d 27 61 00 00 	lea    rdi,[rip+0x6127]        # 412154 <_IO_stdin_used+0x154>
  40c02d:	e8 5e 51 ff ff       	call   401190 <puts@plt>
  40c032:	48 8d 3d cb 5f 00 00 	lea    rdi,[rip+0x5fcb]        # 412004 <_IO_stdin_used+0x4>
  40c039:	31 f6                	xor    esi,esi
  40c03b:	31 c0                	xor    eax,eax
  40c03d:	e8 0e 52 ff ff       	call   401250 <open@plt>
  40c042:	89 c7                	mov    edi,eax
  40c044:	85 c0                	test   eax,eax
  40c046:	79 34                	jns    40c07c <win+0xab06>
  40c048:	e8 33 51 ff ff       	call   401180 <__errno_location@plt>
  40c04d:	8b 38                	mov    edi,DWORD PTR [rax]
  40c04f:	e8 2c 52 ff ff       	call   401280 <strerror@plt>
  40c054:	48 8d 35 af 5f 00 00 	lea    rsi,[rip+0x5faf]        # 41200a <_IO_stdin_used+0xa>
  40c05b:	bf 01 00 00 00       	mov    edi,0x1
  40c060:	48 89 c2             	mov    rdx,rax
  40c063:	31 c0                	xor    eax,eax
  40c065:	e8 c6 51 ff ff       	call   401230 <__printf_chk@plt>
  40c06a:	e8 71 51 ff ff       	call   4011e0 <geteuid@plt>
  40c06f:	85 c0                	test   eax,eax
  40c071:	0f 84 62 55 ff ff    	je     4015d9 <win+0x63>
  40c077:	e9 45 55 ff ff       	jmp    4015c1 <win+0x4b>
  40c07c:	ba 00 01 00 00       	mov    edx,0x100
  40c081:	48 89 ee             	mov    rsi,rbp
  40c084:	e8 77 51 ff ff       	call   401200 <read@plt>
  40c089:	85 c0                	test   eax,eax
  40c08b:	7f 2a                	jg     40c0b7 <win+0xab41>
  40c08d:	e8 ee 50 ff ff       	call   401180 <__errno_location@plt>
  40c092:	8b 38                	mov    edi,DWORD PTR [rax]
  40c094:	e8 e7 51 ff ff       	call   401280 <strerror@plt>
  40c099:	bf 01 00 00 00       	mov    edi,0x1
  40c09e:	48 8d 35 04 60 00 00 	lea    rsi,[rip+0x6004]        # 4120a9 <_IO_stdin_used+0xa9>
  40c0a5:	48 89 c2             	mov    rdx,rax
  40c0a8:	31 c0                	xor    eax,eax
  40c0aa:	e8 81 51 ff ff       	call   401230 <__printf_chk@plt>
  40c0af:	83 cf ff             	or     edi,0xffffffff
  40c0b2:	e8 a9 51 ff ff       	call   401260 <exit@plt>
  40c0b7:	48 63 d0             	movsxd rdx,eax
  40c0ba:	48 89 ee             	mov    rsi,rbp
  40c0bd:	bf 01 00 00 00       	mov    edi,0x1
  40c0c2:	e8 d9 50 ff ff       	call   4011a0 <write@plt>
  40c0c7:	48 8d 3d 86 60 00 00 	lea    rdi,[rip+0x6086]        # 412154 <_IO_stdin_used+0x154>
  40c0ce:	e8 bd 50 ff ff       	call   401190 <puts@plt>
  40c0d3:	48 8d 3d 2a 5f 00 00 	lea    rdi,[rip+0x5f2a]        # 412004 <_IO_stdin_used+0x4>
  40c0da:	31 f6                	xor    esi,esi
  40c0dc:	31 c0                	xor    eax,eax
  40c0de:	e8 6d 51 ff ff       	call   401250 <open@plt>
  40c0e3:	89 c7                	mov    edi,eax
  40c0e5:	85 c0                	test   eax,eax
  40c0e7:	79 34                	jns    40c11d <win+0xaba7>
  40c0e9:	e8 92 50 ff ff       	call   401180 <__errno_location@plt>
  40c0ee:	8b 38                	mov    edi,DWORD PTR [rax]
  40c0f0:	e8 8b 51 ff ff       	call   401280 <strerror@plt>
  40c0f5:	48 8d 35 0e 5f 00 00 	lea    rsi,[rip+0x5f0e]        # 41200a <_IO_stdin_used+0xa>
  40c0fc:	bf 01 00 00 00       	mov    edi,0x1
  40c101:	48 89 c2             	mov    rdx,rax
  40c104:	31 c0                	xor    eax,eax
  40c106:	e8 25 51 ff ff       	call   401230 <__printf_chk@plt>
  40c10b:	e8 d0 50 ff ff       	call   4011e0 <geteuid@plt>
  40c110:	85 c0                	test   eax,eax
  40c112:	0f 84 c1 54 ff ff    	je     4015d9 <win+0x63>
  40c118:	e9 a4 54 ff ff       	jmp    4015c1 <win+0x4b>
  40c11d:	ba 00 01 00 00       	mov    edx,0x100
  40c122:	48 89 ee             	mov    rsi,rbp
  40c125:	e8 d6 50 ff ff       	call   401200 <read@plt>
  40c12a:	85 c0                	test   eax,eax
  40c12c:	7f 2a                	jg     40c158 <win+0xabe2>
  40c12e:	e8 4d 50 ff ff       	call   401180 <__errno_location@plt>
  40c133:	8b 38                	mov    edi,DWORD PTR [rax]
  40c135:	e8 46 51 ff ff       	call   401280 <strerror@plt>
  40c13a:	bf 01 00 00 00       	mov    edi,0x1
  40c13f:	48 8d 35 63 5f 00 00 	lea    rsi,[rip+0x5f63]        # 4120a9 <_IO_stdin_used+0xa9>
  40c146:	48 89 c2             	mov    rdx,rax
  40c149:	31 c0                	xor    eax,eax
  40c14b:	e8 e0 50 ff ff       	call   401230 <__printf_chk@plt>
  40c150:	83 cf ff             	or     edi,0xffffffff
  40c153:	e8 08 51 ff ff       	call   401260 <exit@plt>
  40c158:	48 63 d0             	movsxd rdx,eax
  40c15b:	48 89 ee             	mov    rsi,rbp
  40c15e:	bf 01 00 00 00       	mov    edi,0x1
  40c163:	e8 38 50 ff ff       	call   4011a0 <write@plt>
  40c168:	48 8d 3d e5 5f 00 00 	lea    rdi,[rip+0x5fe5]        # 412154 <_IO_stdin_used+0x154>
  40c16f:	e8 1c 50 ff ff       	call   401190 <puts@plt>
  40c174:	48 8d 3d 89 5e 00 00 	lea    rdi,[rip+0x5e89]        # 412004 <_IO_stdin_used+0x4>
  40c17b:	31 f6                	xor    esi,esi
  40c17d:	31 c0                	xor    eax,eax
  40c17f:	e8 cc 50 ff ff       	call   401250 <open@plt>
  40c184:	89 c7                	mov    edi,eax
  40c186:	85 c0                	test   eax,eax
  40c188:	79 34                	jns    40c1be <win+0xac48>
  40c18a:	e8 f1 4f ff ff       	call   401180 <__errno_location@plt>
  40c18f:	8b 38                	mov    edi,DWORD PTR [rax]
  40c191:	e8 ea 50 ff ff       	call   401280 <strerror@plt>
  40c196:	48 8d 35 6d 5e 00 00 	lea    rsi,[rip+0x5e6d]        # 41200a <_IO_stdin_used+0xa>
  40c19d:	bf 01 00 00 00       	mov    edi,0x1
  40c1a2:	48 89 c2             	mov    rdx,rax
  40c1a5:	31 c0                	xor    eax,eax
  40c1a7:	e8 84 50 ff ff       	call   401230 <__printf_chk@plt>
  40c1ac:	e8 2f 50 ff ff       	call   4011e0 <geteuid@plt>
  40c1b1:	85 c0                	test   eax,eax
  40c1b3:	0f 84 20 54 ff ff    	je     4015d9 <win+0x63>
  40c1b9:	e9 03 54 ff ff       	jmp    4015c1 <win+0x4b>
  40c1be:	ba 00 01 00 00       	mov    edx,0x100
  40c1c3:	48 89 ee             	mov    rsi,rbp
  40c1c6:	e8 35 50 ff ff       	call   401200 <read@plt>
  40c1cb:	85 c0                	test   eax,eax
  40c1cd:	7f 2a                	jg     40c1f9 <win+0xac83>
  40c1cf:	e8 ac 4f ff ff       	call   401180 <__errno_location@plt>
  40c1d4:	8b 38                	mov    edi,DWORD PTR [rax]
  40c1d6:	e8 a5 50 ff ff       	call   401280 <strerror@plt>
  40c1db:	bf 01 00 00 00       	mov    edi,0x1
  40c1e0:	48 8d 35 c2 5e 00 00 	lea    rsi,[rip+0x5ec2]        # 4120a9 <_IO_stdin_used+0xa9>
  40c1e7:	48 89 c2             	mov    rdx,rax
  40c1ea:	31 c0                	xor    eax,eax
  40c1ec:	e8 3f 50 ff ff       	call   401230 <__printf_chk@plt>
  40c1f1:	83 cf ff             	or     edi,0xffffffff
  40c1f4:	e8 67 50 ff ff       	call   401260 <exit@plt>
  40c1f9:	48 63 d0             	movsxd rdx,eax
  40c1fc:	48 89 ee             	mov    rsi,rbp
  40c1ff:	bf 01 00 00 00       	mov    edi,0x1
  40c204:	e8 97 4f ff ff       	call   4011a0 <write@plt>
  40c209:	48 8d 3d 44 5f 00 00 	lea    rdi,[rip+0x5f44]        # 412154 <_IO_stdin_used+0x154>
  40c210:	e8 7b 4f ff ff       	call   401190 <puts@plt>
  40c215:	48 8d 3d e8 5d 00 00 	lea    rdi,[rip+0x5de8]        # 412004 <_IO_stdin_used+0x4>
  40c21c:	31 f6                	xor    esi,esi
  40c21e:	31 c0                	xor    eax,eax
  40c220:	e8 2b 50 ff ff       	call   401250 <open@plt>
  40c225:	89 c7                	mov    edi,eax
  40c227:	85 c0                	test   eax,eax
  40c229:	79 34                	jns    40c25f <win+0xace9>
  40c22b:	e8 50 4f ff ff       	call   401180 <__errno_location@plt>
  40c230:	8b 38                	mov    edi,DWORD PTR [rax]
  40c232:	e8 49 50 ff ff       	call   401280 <strerror@plt>
  40c237:	48 8d 35 cc 5d 00 00 	lea    rsi,[rip+0x5dcc]        # 41200a <_IO_stdin_used+0xa>
  40c23e:	bf 01 00 00 00       	mov    edi,0x1
  40c243:	48 89 c2             	mov    rdx,rax
  40c246:	31 c0                	xor    eax,eax
  40c248:	e8 e3 4f ff ff       	call   401230 <__printf_chk@plt>
  40c24d:	e8 8e 4f ff ff       	call   4011e0 <geteuid@plt>
  40c252:	85 c0                	test   eax,eax
  40c254:	0f 84 7f 53 ff ff    	je     4015d9 <win+0x63>
  40c25a:	e9 62 53 ff ff       	jmp    4015c1 <win+0x4b>
  40c25f:	ba 00 01 00 00       	mov    edx,0x100
  40c264:	48 89 ee             	mov    rsi,rbp
  40c267:	e8 94 4f ff ff       	call   401200 <read@plt>
  40c26c:	85 c0                	test   eax,eax
  40c26e:	7f 2a                	jg     40c29a <win+0xad24>
  40c270:	e8 0b 4f ff ff       	call   401180 <__errno_location@plt>
  40c275:	8b 38                	mov    edi,DWORD PTR [rax]
  40c277:	e8 04 50 ff ff       	call   401280 <strerror@plt>
  40c27c:	bf 01 00 00 00       	mov    edi,0x1
  40c281:	48 8d 35 21 5e 00 00 	lea    rsi,[rip+0x5e21]        # 4120a9 <_IO_stdin_used+0xa9>
  40c288:	48 89 c2             	mov    rdx,rax
  40c28b:	31 c0                	xor    eax,eax
  40c28d:	e8 9e 4f ff ff       	call   401230 <__printf_chk@plt>
  40c292:	83 cf ff             	or     edi,0xffffffff
  40c295:	e8 c6 4f ff ff       	call   401260 <exit@plt>
  40c29a:	48 63 d0             	movsxd rdx,eax
  40c29d:	48 89 ee             	mov    rsi,rbp
  40c2a0:	bf 01 00 00 00       	mov    edi,0x1
  40c2a5:	e8 f6 4e ff ff       	call   4011a0 <write@plt>
  40c2aa:	48 8d 3d a3 5e 00 00 	lea    rdi,[rip+0x5ea3]        # 412154 <_IO_stdin_used+0x154>
  40c2b1:	e8 da 4e ff ff       	call   401190 <puts@plt>
  40c2b6:	48 8d 3d 47 5d 00 00 	lea    rdi,[rip+0x5d47]        # 412004 <_IO_stdin_used+0x4>
  40c2bd:	31 f6                	xor    esi,esi
  40c2bf:	31 c0                	xor    eax,eax
  40c2c1:	e8 8a 4f ff ff       	call   401250 <open@plt>
  40c2c6:	89 c7                	mov    edi,eax
  40c2c8:	85 c0                	test   eax,eax
  40c2ca:	79 34                	jns    40c300 <win+0xad8a>
  40c2cc:	e8 af 4e ff ff       	call   401180 <__errno_location@plt>
  40c2d1:	8b 38                	mov    edi,DWORD PTR [rax]
  40c2d3:	e8 a8 4f ff ff       	call   401280 <strerror@plt>
  40c2d8:	48 8d 35 2b 5d 00 00 	lea    rsi,[rip+0x5d2b]        # 41200a <_IO_stdin_used+0xa>
  40c2df:	bf 01 00 00 00       	mov    edi,0x1
  40c2e4:	48 89 c2             	mov    rdx,rax
  40c2e7:	31 c0                	xor    eax,eax
  40c2e9:	e8 42 4f ff ff       	call   401230 <__printf_chk@plt>
  40c2ee:	e8 ed 4e ff ff       	call   4011e0 <geteuid@plt>
  40c2f3:	85 c0                	test   eax,eax
  40c2f5:	0f 84 de 52 ff ff    	je     4015d9 <win+0x63>
  40c2fb:	e9 c1 52 ff ff       	jmp    4015c1 <win+0x4b>
  40c300:	ba 00 01 00 00       	mov    edx,0x100
  40c305:	48 89 ee             	mov    rsi,rbp
  40c308:	e8 f3 4e ff ff       	call   401200 <read@plt>
  40c30d:	85 c0                	test   eax,eax
  40c30f:	7f 2a                	jg     40c33b <win+0xadc5>
  40c311:	e8 6a 4e ff ff       	call   401180 <__errno_location@plt>
  40c316:	8b 38                	mov    edi,DWORD PTR [rax]
  40c318:	e8 63 4f ff ff       	call   401280 <strerror@plt>
  40c31d:	bf 01 00 00 00       	mov    edi,0x1
  40c322:	48 8d 35 80 5d 00 00 	lea    rsi,[rip+0x5d80]        # 4120a9 <_IO_stdin_used+0xa9>
  40c329:	48 89 c2             	mov    rdx,rax
  40c32c:	31 c0                	xor    eax,eax
  40c32e:	e8 fd 4e ff ff       	call   401230 <__printf_chk@plt>
  40c333:	83 cf ff             	or     edi,0xffffffff
  40c336:	e8 25 4f ff ff       	call   401260 <exit@plt>
  40c33b:	48 63 d0             	movsxd rdx,eax
  40c33e:	48 89 ee             	mov    rsi,rbp
  40c341:	bf 01 00 00 00       	mov    edi,0x1
  40c346:	e8 55 4e ff ff       	call   4011a0 <write@plt>
  40c34b:	48 8d 3d 02 5e 00 00 	lea    rdi,[rip+0x5e02]        # 412154 <_IO_stdin_used+0x154>
  40c352:	e8 39 4e ff ff       	call   401190 <puts@plt>
  40c357:	48 8d 3d a6 5c 00 00 	lea    rdi,[rip+0x5ca6]        # 412004 <_IO_stdin_used+0x4>
  40c35e:	31 f6                	xor    esi,esi
  40c360:	31 c0                	xor    eax,eax
  40c362:	e8 e9 4e ff ff       	call   401250 <open@plt>
  40c367:	89 c7                	mov    edi,eax
  40c369:	85 c0                	test   eax,eax
  40c36b:	79 34                	jns    40c3a1 <win+0xae2b>
  40c36d:	e8 0e 4e ff ff       	call   401180 <__errno_location@plt>
  40c372:	8b 38                	mov    edi,DWORD PTR [rax]
  40c374:	e8 07 4f ff ff       	call   401280 <strerror@plt>
  40c379:	48 8d 35 8a 5c 00 00 	lea    rsi,[rip+0x5c8a]        # 41200a <_IO_stdin_used+0xa>
  40c380:	bf 01 00 00 00       	mov    edi,0x1
  40c385:	48 89 c2             	mov    rdx,rax
  40c388:	31 c0                	xor    eax,eax
  40c38a:	e8 a1 4e ff ff       	call   401230 <__printf_chk@plt>
  40c38f:	e8 4c 4e ff ff       	call   4011e0 <geteuid@plt>
  40c394:	85 c0                	test   eax,eax
  40c396:	0f 84 3d 52 ff ff    	je     4015d9 <win+0x63>
  40c39c:	e9 20 52 ff ff       	jmp    4015c1 <win+0x4b>
  40c3a1:	ba 00 01 00 00       	mov    edx,0x100
  40c3a6:	48 89 ee             	mov    rsi,rbp
  40c3a9:	e8 52 4e ff ff       	call   401200 <read@plt>
  40c3ae:	85 c0                	test   eax,eax
  40c3b0:	7f 2a                	jg     40c3dc <win+0xae66>
  40c3b2:	e8 c9 4d ff ff       	call   401180 <__errno_location@plt>
  40c3b7:	8b 38                	mov    edi,DWORD PTR [rax]
  40c3b9:	e8 c2 4e ff ff       	call   401280 <strerror@plt>
  40c3be:	bf 01 00 00 00       	mov    edi,0x1
  40c3c3:	48 8d 35 df 5c 00 00 	lea    rsi,[rip+0x5cdf]        # 4120a9 <_IO_stdin_used+0xa9>
  40c3ca:	48 89 c2             	mov    rdx,rax
  40c3cd:	31 c0                	xor    eax,eax
  40c3cf:	e8 5c 4e ff ff       	call   401230 <__printf_chk@plt>
  40c3d4:	83 cf ff             	or     edi,0xffffffff
  40c3d7:	e8 84 4e ff ff       	call   401260 <exit@plt>
  40c3dc:	48 63 d0             	movsxd rdx,eax
  40c3df:	48 89 ee             	mov    rsi,rbp
  40c3e2:	bf 01 00 00 00       	mov    edi,0x1
  40c3e7:	e8 b4 4d ff ff       	call   4011a0 <write@plt>
  40c3ec:	48 8d 3d 61 5d 00 00 	lea    rdi,[rip+0x5d61]        # 412154 <_IO_stdin_used+0x154>
  40c3f3:	e8 98 4d ff ff       	call   401190 <puts@plt>
  40c3f8:	48 8d 3d 05 5c 00 00 	lea    rdi,[rip+0x5c05]        # 412004 <_IO_stdin_used+0x4>
  40c3ff:	31 f6                	xor    esi,esi
  40c401:	31 c0                	xor    eax,eax
  40c403:	e8 48 4e ff ff       	call   401250 <open@plt>
  40c408:	89 c7                	mov    edi,eax
  40c40a:	85 c0                	test   eax,eax
  40c40c:	79 34                	jns    40c442 <win+0xaecc>
  40c40e:	e8 6d 4d ff ff       	call   401180 <__errno_location@plt>
  40c413:	8b 38                	mov    edi,DWORD PTR [rax]
  40c415:	e8 66 4e ff ff       	call   401280 <strerror@plt>
  40c41a:	48 8d 35 e9 5b 00 00 	lea    rsi,[rip+0x5be9]        # 41200a <_IO_stdin_used+0xa>
  40c421:	bf 01 00 00 00       	mov    edi,0x1
  40c426:	48 89 c2             	mov    rdx,rax
  40c429:	31 c0                	xor    eax,eax
  40c42b:	e8 00 4e ff ff       	call   401230 <__printf_chk@plt>
  40c430:	e8 ab 4d ff ff       	call   4011e0 <geteuid@plt>
  40c435:	85 c0                	test   eax,eax
  40c437:	0f 84 9c 51 ff ff    	je     4015d9 <win+0x63>
  40c43d:	e9 7f 51 ff ff       	jmp    4015c1 <win+0x4b>
  40c442:	ba 00 01 00 00       	mov    edx,0x100
  40c447:	48 89 ee             	mov    rsi,rbp
  40c44a:	e8 b1 4d ff ff       	call   401200 <read@plt>
  40c44f:	85 c0                	test   eax,eax
  40c451:	7f 2a                	jg     40c47d <win+0xaf07>
  40c453:	e8 28 4d ff ff       	call   401180 <__errno_location@plt>
  40c458:	8b 38                	mov    edi,DWORD PTR [rax]
  40c45a:	e8 21 4e ff ff       	call   401280 <strerror@plt>
  40c45f:	bf 01 00 00 00       	mov    edi,0x1
  40c464:	48 8d 35 3e 5c 00 00 	lea    rsi,[rip+0x5c3e]        # 4120a9 <_IO_stdin_used+0xa9>
  40c46b:	48 89 c2             	mov    rdx,rax
  40c46e:	31 c0                	xor    eax,eax
  40c470:	e8 bb 4d ff ff       	call   401230 <__printf_chk@plt>
  40c475:	83 cf ff             	or     edi,0xffffffff
  40c478:	e8 e3 4d ff ff       	call   401260 <exit@plt>
  40c47d:	48 63 d0             	movsxd rdx,eax
  40c480:	48 89 ee             	mov    rsi,rbp
  40c483:	bf 01 00 00 00       	mov    edi,0x1
  40c488:	e8 13 4d ff ff       	call   4011a0 <write@plt>
  40c48d:	48 8d 3d c0 5c 00 00 	lea    rdi,[rip+0x5cc0]        # 412154 <_IO_stdin_used+0x154>
  40c494:	e8 f7 4c ff ff       	call   401190 <puts@plt>
  40c499:	48 8d 3d 64 5b 00 00 	lea    rdi,[rip+0x5b64]        # 412004 <_IO_stdin_used+0x4>
  40c4a0:	31 f6                	xor    esi,esi
  40c4a2:	31 c0                	xor    eax,eax
  40c4a4:	e8 a7 4d ff ff       	call   401250 <open@plt>
  40c4a9:	89 c7                	mov    edi,eax
  40c4ab:	85 c0                	test   eax,eax
  40c4ad:	79 34                	jns    40c4e3 <win+0xaf6d>
  40c4af:	e8 cc 4c ff ff       	call   401180 <__errno_location@plt>
  40c4b4:	8b 38                	mov    edi,DWORD PTR [rax]
  40c4b6:	e8 c5 4d ff ff       	call   401280 <strerror@plt>
  40c4bb:	48 8d 35 48 5b 00 00 	lea    rsi,[rip+0x5b48]        # 41200a <_IO_stdin_used+0xa>
  40c4c2:	bf 01 00 00 00       	mov    edi,0x1
  40c4c7:	48 89 c2             	mov    rdx,rax
  40c4ca:	31 c0                	xor    eax,eax
  40c4cc:	e8 5f 4d ff ff       	call   401230 <__printf_chk@plt>
  40c4d1:	e8 0a 4d ff ff       	call   4011e0 <geteuid@plt>
  40c4d6:	85 c0                	test   eax,eax
  40c4d8:	0f 84 fb 50 ff ff    	je     4015d9 <win+0x63>
  40c4de:	e9 de 50 ff ff       	jmp    4015c1 <win+0x4b>
  40c4e3:	ba 00 01 00 00       	mov    edx,0x100
  40c4e8:	48 89 ee             	mov    rsi,rbp
  40c4eb:	e8 10 4d ff ff       	call   401200 <read@plt>
  40c4f0:	85 c0                	test   eax,eax
  40c4f2:	7f 2a                	jg     40c51e <win+0xafa8>
  40c4f4:	e8 87 4c ff ff       	call   401180 <__errno_location@plt>
  40c4f9:	8b 38                	mov    edi,DWORD PTR [rax]
  40c4fb:	e8 80 4d ff ff       	call   401280 <strerror@plt>
  40c500:	bf 01 00 00 00       	mov    edi,0x1
  40c505:	48 8d 35 9d 5b 00 00 	lea    rsi,[rip+0x5b9d]        # 4120a9 <_IO_stdin_used+0xa9>
  40c50c:	48 89 c2             	mov    rdx,rax
  40c50f:	31 c0                	xor    eax,eax
  40c511:	e8 1a 4d ff ff       	call   401230 <__printf_chk@plt>
  40c516:	83 cf ff             	or     edi,0xffffffff
  40c519:	e8 42 4d ff ff       	call   401260 <exit@plt>
  40c51e:	48 63 d0             	movsxd rdx,eax
  40c521:	48 89 ee             	mov    rsi,rbp
  40c524:	bf 01 00 00 00       	mov    edi,0x1
  40c529:	e8 72 4c ff ff       	call   4011a0 <write@plt>
  40c52e:	48 8d 3d 1f 5c 00 00 	lea    rdi,[rip+0x5c1f]        # 412154 <_IO_stdin_used+0x154>
  40c535:	e8 56 4c ff ff       	call   401190 <puts@plt>
  40c53a:	48 8d 3d c3 5a 00 00 	lea    rdi,[rip+0x5ac3]        # 412004 <_IO_stdin_used+0x4>
  40c541:	31 f6                	xor    esi,esi
  40c543:	31 c0                	xor    eax,eax
  40c545:	e8 06 4d ff ff       	call   401250 <open@plt>
  40c54a:	89 c7                	mov    edi,eax
  40c54c:	85 c0                	test   eax,eax
  40c54e:	79 34                	jns    40c584 <win+0xb00e>
  40c550:	e8 2b 4c ff ff       	call   401180 <__errno_location@plt>
  40c555:	8b 38                	mov    edi,DWORD PTR [rax]
  40c557:	e8 24 4d ff ff       	call   401280 <strerror@plt>
  40c55c:	48 8d 35 a7 5a 00 00 	lea    rsi,[rip+0x5aa7]        # 41200a <_IO_stdin_used+0xa>
  40c563:	bf 01 00 00 00       	mov    edi,0x1
  40c568:	48 89 c2             	mov    rdx,rax
  40c56b:	31 c0                	xor    eax,eax
  40c56d:	e8 be 4c ff ff       	call   401230 <__printf_chk@plt>
  40c572:	e8 69 4c ff ff       	call   4011e0 <geteuid@plt>
  40c577:	85 c0                	test   eax,eax
  40c579:	0f 84 5a 50 ff ff    	je     4015d9 <win+0x63>
  40c57f:	e9 3d 50 ff ff       	jmp    4015c1 <win+0x4b>
  40c584:	ba 00 01 00 00       	mov    edx,0x100
  40c589:	48 89 ee             	mov    rsi,rbp
  40c58c:	e8 6f 4c ff ff       	call   401200 <read@plt>
  40c591:	85 c0                	test   eax,eax
  40c593:	7f 2a                	jg     40c5bf <win+0xb049>
  40c595:	e8 e6 4b ff ff       	call   401180 <__errno_location@plt>
  40c59a:	8b 38                	mov    edi,DWORD PTR [rax]
  40c59c:	e8 df 4c ff ff       	call   401280 <strerror@plt>
  40c5a1:	bf 01 00 00 00       	mov    edi,0x1
  40c5a6:	48 8d 35 fc 5a 00 00 	lea    rsi,[rip+0x5afc]        # 4120a9 <_IO_stdin_used+0xa9>
  40c5ad:	48 89 c2             	mov    rdx,rax
  40c5b0:	31 c0                	xor    eax,eax
  40c5b2:	e8 79 4c ff ff       	call   401230 <__printf_chk@plt>
  40c5b7:	83 cf ff             	or     edi,0xffffffff
  40c5ba:	e8 a1 4c ff ff       	call   401260 <exit@plt>
  40c5bf:	48 89 e5             	mov    rbp,rsp
  40c5c2:	48 63 d0             	movsxd rdx,eax
  40c5c5:	bf 01 00 00 00       	mov    edi,0x1
  40c5ca:	48 89 ee             	mov    rsi,rbp
  40c5cd:	e8 ce 4b ff ff       	call   4011a0 <write@plt>
  40c5d2:	48 8d 3d 7b 5b 00 00 	lea    rdi,[rip+0x5b7b]        # 412154 <_IO_stdin_used+0x154>
  40c5d9:	e8 b2 4b ff ff       	call   401190 <puts@plt>
  40c5de:	48 8d 3d 1f 5a 00 00 	lea    rdi,[rip+0x5a1f]        # 412004 <_IO_stdin_used+0x4>
  40c5e5:	31 f6                	xor    esi,esi
  40c5e7:	31 c0                	xor    eax,eax
  40c5e9:	e8 62 4c ff ff       	call   401250 <open@plt>
  40c5ee:	89 c7                	mov    edi,eax
  40c5f0:	85 c0                	test   eax,eax
  40c5f2:	79 34                	jns    40c628 <win+0xb0b2>
  40c5f4:	e8 87 4b ff ff       	call   401180 <__errno_location@plt>
  40c5f9:	8b 38                	mov    edi,DWORD PTR [rax]
  40c5fb:	e8 80 4c ff ff       	call   401280 <strerror@plt>
  40c600:	48 8d 35 03 5a 00 00 	lea    rsi,[rip+0x5a03]        # 41200a <_IO_stdin_used+0xa>
  40c607:	bf 01 00 00 00       	mov    edi,0x1
  40c60c:	48 89 c2             	mov    rdx,rax
  40c60f:	31 c0                	xor    eax,eax
  40c611:	e8 1a 4c ff ff       	call   401230 <__printf_chk@plt>
  40c616:	e8 c5 4b ff ff       	call   4011e0 <geteuid@plt>
  40c61b:	85 c0                	test   eax,eax
  40c61d:	0f 84 b6 4f ff ff    	je     4015d9 <win+0x63>
  40c623:	e9 99 4f ff ff       	jmp    4015c1 <win+0x4b>
  40c628:	ba 00 01 00 00       	mov    edx,0x100
  40c62d:	48 89 ee             	mov    rsi,rbp
  40c630:	e8 cb 4b ff ff       	call   401200 <read@plt>
  40c635:	85 c0                	test   eax,eax
  40c637:	7f 2a                	jg     40c663 <win+0xb0ed>
  40c639:	e8 42 4b ff ff       	call   401180 <__errno_location@plt>
  40c63e:	8b 38                	mov    edi,DWORD PTR [rax]
  40c640:	e8 3b 4c ff ff       	call   401280 <strerror@plt>
  40c645:	bf 01 00 00 00       	mov    edi,0x1
  40c64a:	48 8d 35 58 5a 00 00 	lea    rsi,[rip+0x5a58]        # 4120a9 <_IO_stdin_used+0xa9>
  40c651:	48 89 c2             	mov    rdx,rax
  40c654:	31 c0                	xor    eax,eax
  40c656:	e8 d5 4b ff ff       	call   401230 <__printf_chk@plt>
  40c65b:	83 cf ff             	or     edi,0xffffffff
  40c65e:	e8 fd 4b ff ff       	call   401260 <exit@plt>
  40c663:	48 63 d0             	movsxd rdx,eax
  40c666:	48 89 ee             	mov    rsi,rbp
  40c669:	bf 01 00 00 00       	mov    edi,0x1
  40c66e:	e8 2d 4b ff ff       	call   4011a0 <write@plt>
  40c673:	48 8d 3d da 5a 00 00 	lea    rdi,[rip+0x5ada]        # 412154 <_IO_stdin_used+0x154>
  40c67a:	e8 11 4b ff ff       	call   401190 <puts@plt>
  40c67f:	48 8d 3d 7e 59 00 00 	lea    rdi,[rip+0x597e]        # 412004 <_IO_stdin_used+0x4>
  40c686:	31 f6                	xor    esi,esi
  40c688:	31 c0                	xor    eax,eax
  40c68a:	e8 c1 4b ff ff       	call   401250 <open@plt>
  40c68f:	89 c7                	mov    edi,eax
  40c691:	85 c0                	test   eax,eax
  40c693:	79 34                	jns    40c6c9 <win+0xb153>
  40c695:	e8 e6 4a ff ff       	call   401180 <__errno_location@plt>
  40c69a:	8b 38                	mov    edi,DWORD PTR [rax]
  40c69c:	e8 df 4b ff ff       	call   401280 <strerror@plt>
  40c6a1:	48 8d 35 62 59 00 00 	lea    rsi,[rip+0x5962]        # 41200a <_IO_stdin_used+0xa>
  40c6a8:	bf 01 00 00 00       	mov    edi,0x1
  40c6ad:	48 89 c2             	mov    rdx,rax
  40c6b0:	31 c0                	xor    eax,eax
  40c6b2:	e8 79 4b ff ff       	call   401230 <__printf_chk@plt>
  40c6b7:	e8 24 4b ff ff       	call   4011e0 <geteuid@plt>
  40c6bc:	85 c0                	test   eax,eax
  40c6be:	0f 84 15 4f ff ff    	je     4015d9 <win+0x63>
  40c6c4:	e9 f8 4e ff ff       	jmp    4015c1 <win+0x4b>
  40c6c9:	ba 00 01 00 00       	mov    edx,0x100
  40c6ce:	48 89 ee             	mov    rsi,rbp
  40c6d1:	e8 2a 4b ff ff       	call   401200 <read@plt>
  40c6d6:	85 c0                	test   eax,eax
  40c6d8:	7f 2a                	jg     40c704 <win+0xb18e>
  40c6da:	e8 a1 4a ff ff       	call   401180 <__errno_location@plt>
  40c6df:	8b 38                	mov    edi,DWORD PTR [rax]
  40c6e1:	e8 9a 4b ff ff       	call   401280 <strerror@plt>
  40c6e6:	bf 01 00 00 00       	mov    edi,0x1
  40c6eb:	48 8d 35 b7 59 00 00 	lea    rsi,[rip+0x59b7]        # 4120a9 <_IO_stdin_used+0xa9>
  40c6f2:	48 89 c2             	mov    rdx,rax
  40c6f5:	31 c0                	xor    eax,eax
  40c6f7:	e8 34 4b ff ff       	call   401230 <__printf_chk@plt>
  40c6fc:	83 cf ff             	or     edi,0xffffffff
  40c6ff:	e8 5c 4b ff ff       	call   401260 <exit@plt>
  40c704:	48 63 d0             	movsxd rdx,eax
  40c707:	48 89 ee             	mov    rsi,rbp
  40c70a:	bf 01 00 00 00       	mov    edi,0x1
  40c70f:	e8 8c 4a ff ff       	call   4011a0 <write@plt>
  40c714:	48 8d 3d 39 5a 00 00 	lea    rdi,[rip+0x5a39]        # 412154 <_IO_stdin_used+0x154>
  40c71b:	e8 70 4a ff ff       	call   401190 <puts@plt>
  40c720:	48 8d 3d dd 58 00 00 	lea    rdi,[rip+0x58dd]        # 412004 <_IO_stdin_used+0x4>
  40c727:	31 f6                	xor    esi,esi
  40c729:	31 c0                	xor    eax,eax
  40c72b:	e8 20 4b ff ff       	call   401250 <open@plt>
  40c730:	89 c7                	mov    edi,eax
  40c732:	85 c0                	test   eax,eax
  40c734:	79 34                	jns    40c76a <win+0xb1f4>
  40c736:	e8 45 4a ff ff       	call   401180 <__errno_location@plt>
  40c73b:	8b 38                	mov    edi,DWORD PTR [rax]
  40c73d:	e8 3e 4b ff ff       	call   401280 <strerror@plt>
  40c742:	48 8d 35 c1 58 00 00 	lea    rsi,[rip+0x58c1]        # 41200a <_IO_stdin_used+0xa>
  40c749:	bf 01 00 00 00       	mov    edi,0x1
  40c74e:	48 89 c2             	mov    rdx,rax
  40c751:	31 c0                	xor    eax,eax
  40c753:	e8 d8 4a ff ff       	call   401230 <__printf_chk@plt>
  40c758:	e8 83 4a ff ff       	call   4011e0 <geteuid@plt>
  40c75d:	85 c0                	test   eax,eax
  40c75f:	0f 84 74 4e ff ff    	je     4015d9 <win+0x63>
  40c765:	e9 57 4e ff ff       	jmp    4015c1 <win+0x4b>
  40c76a:	ba 00 01 00 00       	mov    edx,0x100
  40c76f:	48 89 ee             	mov    rsi,rbp
  40c772:	e8 89 4a ff ff       	call   401200 <read@plt>
  40c777:	85 c0                	test   eax,eax
  40c779:	7f 2a                	jg     40c7a5 <win+0xb22f>
  40c77b:	e8 00 4a ff ff       	call   401180 <__errno_location@plt>
  40c780:	8b 38                	mov    edi,DWORD PTR [rax]
  40c782:	e8 f9 4a ff ff       	call   401280 <strerror@plt>
  40c787:	bf 01 00 00 00       	mov    edi,0x1
  40c78c:	48 8d 35 16 59 00 00 	lea    rsi,[rip+0x5916]        # 4120a9 <_IO_stdin_used+0xa9>
  40c793:	48 89 c2             	mov    rdx,rax
  40c796:	31 c0                	xor    eax,eax
  40c798:	e8 93 4a ff ff       	call   401230 <__printf_chk@plt>
  40c79d:	83 cf ff             	or     edi,0xffffffff
  40c7a0:	e8 bb 4a ff ff       	call   401260 <exit@plt>
  40c7a5:	48 63 d0             	movsxd rdx,eax
  40c7a8:	48 89 ee             	mov    rsi,rbp
  40c7ab:	bf 01 00 00 00       	mov    edi,0x1
  40c7b0:	e8 eb 49 ff ff       	call   4011a0 <write@plt>
  40c7b5:	48 8d 3d 98 59 00 00 	lea    rdi,[rip+0x5998]        # 412154 <_IO_stdin_used+0x154>
  40c7bc:	e8 cf 49 ff ff       	call   401190 <puts@plt>
  40c7c1:	48 8d 3d 3c 58 00 00 	lea    rdi,[rip+0x583c]        # 412004 <_IO_stdin_used+0x4>
  40c7c8:	31 f6                	xor    esi,esi
  40c7ca:	31 c0                	xor    eax,eax
  40c7cc:	e8 7f 4a ff ff       	call   401250 <open@plt>
  40c7d1:	89 c7                	mov    edi,eax
  40c7d3:	85 c0                	test   eax,eax
  40c7d5:	79 34                	jns    40c80b <win+0xb295>
  40c7d7:	e8 a4 49 ff ff       	call   401180 <__errno_location@plt>
  40c7dc:	8b 38                	mov    edi,DWORD PTR [rax]
  40c7de:	e8 9d 4a ff ff       	call   401280 <strerror@plt>
  40c7e3:	48 8d 35 20 58 00 00 	lea    rsi,[rip+0x5820]        # 41200a <_IO_stdin_used+0xa>
  40c7ea:	bf 01 00 00 00       	mov    edi,0x1
  40c7ef:	48 89 c2             	mov    rdx,rax
  40c7f2:	31 c0                	xor    eax,eax
  40c7f4:	e8 37 4a ff ff       	call   401230 <__printf_chk@plt>
  40c7f9:	e8 e2 49 ff ff       	call   4011e0 <geteuid@plt>
  40c7fe:	85 c0                	test   eax,eax
  40c800:	0f 84 d3 4d ff ff    	je     4015d9 <win+0x63>
  40c806:	e9 b6 4d ff ff       	jmp    4015c1 <win+0x4b>
  40c80b:	ba 00 01 00 00       	mov    edx,0x100
  40c810:	48 89 ee             	mov    rsi,rbp
  40c813:	e8 e8 49 ff ff       	call   401200 <read@plt>
  40c818:	85 c0                	test   eax,eax
  40c81a:	7f 2a                	jg     40c846 <win+0xb2d0>
  40c81c:	e8 5f 49 ff ff       	call   401180 <__errno_location@plt>
  40c821:	8b 38                	mov    edi,DWORD PTR [rax]
  40c823:	e8 58 4a ff ff       	call   401280 <strerror@plt>
  40c828:	bf 01 00 00 00       	mov    edi,0x1
  40c82d:	48 8d 35 75 58 00 00 	lea    rsi,[rip+0x5875]        # 4120a9 <_IO_stdin_used+0xa9>
  40c834:	48 89 c2             	mov    rdx,rax
  40c837:	31 c0                	xor    eax,eax
  40c839:	e8 f2 49 ff ff       	call   401230 <__printf_chk@plt>
  40c83e:	83 cf ff             	or     edi,0xffffffff
  40c841:	e8 1a 4a ff ff       	call   401260 <exit@plt>
  40c846:	48 63 d0             	movsxd rdx,eax
  40c849:	48 89 ee             	mov    rsi,rbp
  40c84c:	bf 01 00 00 00       	mov    edi,0x1
  40c851:	e8 4a 49 ff ff       	call   4011a0 <write@plt>
  40c856:	48 8d 3d f7 58 00 00 	lea    rdi,[rip+0x58f7]        # 412154 <_IO_stdin_used+0x154>
  40c85d:	e8 2e 49 ff ff       	call   401190 <puts@plt>
  40c862:	48 8d 3d 9b 57 00 00 	lea    rdi,[rip+0x579b]        # 412004 <_IO_stdin_used+0x4>
  40c869:	31 f6                	xor    esi,esi
  40c86b:	31 c0                	xor    eax,eax
  40c86d:	e8 de 49 ff ff       	call   401250 <open@plt>
  40c872:	89 c7                	mov    edi,eax
  40c874:	85 c0                	test   eax,eax
  40c876:	79 34                	jns    40c8ac <win+0xb336>
  40c878:	e8 03 49 ff ff       	call   401180 <__errno_location@plt>
  40c87d:	8b 38                	mov    edi,DWORD PTR [rax]
  40c87f:	e8 fc 49 ff ff       	call   401280 <strerror@plt>
  40c884:	48 8d 35 7f 57 00 00 	lea    rsi,[rip+0x577f]        # 41200a <_IO_stdin_used+0xa>
  40c88b:	bf 01 00 00 00       	mov    edi,0x1
  40c890:	48 89 c2             	mov    rdx,rax
  40c893:	31 c0                	xor    eax,eax
  40c895:	e8 96 49 ff ff       	call   401230 <__printf_chk@plt>
  40c89a:	e8 41 49 ff ff       	call   4011e0 <geteuid@plt>
  40c89f:	85 c0                	test   eax,eax
  40c8a1:	0f 84 32 4d ff ff    	je     4015d9 <win+0x63>
  40c8a7:	e9 15 4d ff ff       	jmp    4015c1 <win+0x4b>
  40c8ac:	ba 00 01 00 00       	mov    edx,0x100
  40c8b1:	48 89 ee             	mov    rsi,rbp
  40c8b4:	e8 47 49 ff ff       	call   401200 <read@plt>
  40c8b9:	85 c0                	test   eax,eax
  40c8bb:	7f 2a                	jg     40c8e7 <win+0xb371>
  40c8bd:	e8 be 48 ff ff       	call   401180 <__errno_location@plt>
  40c8c2:	8b 38                	mov    edi,DWORD PTR [rax]
  40c8c4:	e8 b7 49 ff ff       	call   401280 <strerror@plt>
  40c8c9:	bf 01 00 00 00       	mov    edi,0x1
  40c8ce:	48 8d 35 d4 57 00 00 	lea    rsi,[rip+0x57d4]        # 4120a9 <_IO_stdin_used+0xa9>
  40c8d5:	48 89 c2             	mov    rdx,rax
  40c8d8:	31 c0                	xor    eax,eax
  40c8da:	e8 51 49 ff ff       	call   401230 <__printf_chk@plt>
  40c8df:	83 cf ff             	or     edi,0xffffffff
  40c8e2:	e8 79 49 ff ff       	call   401260 <exit@plt>
  40c8e7:	48 63 d0             	movsxd rdx,eax
  40c8ea:	48 89 ee             	mov    rsi,rbp
  40c8ed:	bf 01 00 00 00       	mov    edi,0x1
  40c8f2:	e8 a9 48 ff ff       	call   4011a0 <write@plt>
  40c8f7:	48 8d 3d 56 58 00 00 	lea    rdi,[rip+0x5856]        # 412154 <_IO_stdin_used+0x154>
  40c8fe:	e8 8d 48 ff ff       	call   401190 <puts@plt>
  40c903:	48 8d 3d fa 56 00 00 	lea    rdi,[rip+0x56fa]        # 412004 <_IO_stdin_used+0x4>
  40c90a:	31 f6                	xor    esi,esi
  40c90c:	31 c0                	xor    eax,eax
  40c90e:	e8 3d 49 ff ff       	call   401250 <open@plt>
  40c913:	89 c7                	mov    edi,eax
  40c915:	85 c0                	test   eax,eax
  40c917:	79 34                	jns    40c94d <win+0xb3d7>
  40c919:	e8 62 48 ff ff       	call   401180 <__errno_location@plt>
  40c91e:	8b 38                	mov    edi,DWORD PTR [rax]
  40c920:	e8 5b 49 ff ff       	call   401280 <strerror@plt>
  40c925:	48 8d 35 de 56 00 00 	lea    rsi,[rip+0x56de]        # 41200a <_IO_stdin_used+0xa>
  40c92c:	bf 01 00 00 00       	mov    edi,0x1
  40c931:	48 89 c2             	mov    rdx,rax
  40c934:	31 c0                	xor    eax,eax
  40c936:	e8 f5 48 ff ff       	call   401230 <__printf_chk@plt>
  40c93b:	e8 a0 48 ff ff       	call   4011e0 <geteuid@plt>
  40c940:	85 c0                	test   eax,eax
  40c942:	0f 84 91 4c ff ff    	je     4015d9 <win+0x63>
  40c948:	e9 74 4c ff ff       	jmp    4015c1 <win+0x4b>
  40c94d:	ba 00 01 00 00       	mov    edx,0x100
  40c952:	48 89 ee             	mov    rsi,rbp
  40c955:	e8 a6 48 ff ff       	call   401200 <read@plt>
  40c95a:	85 c0                	test   eax,eax
  40c95c:	7f 2a                	jg     40c988 <win+0xb412>
  40c95e:	e8 1d 48 ff ff       	call   401180 <__errno_location@plt>
  40c963:	8b 38                	mov    edi,DWORD PTR [rax]
  40c965:	e8 16 49 ff ff       	call   401280 <strerror@plt>
  40c96a:	bf 01 00 00 00       	mov    edi,0x1
  40c96f:	48 8d 35 33 57 00 00 	lea    rsi,[rip+0x5733]        # 4120a9 <_IO_stdin_used+0xa9>
  40c976:	48 89 c2             	mov    rdx,rax
  40c979:	31 c0                	xor    eax,eax
  40c97b:	e8 b0 48 ff ff       	call   401230 <__printf_chk@plt>
  40c980:	83 cf ff             	or     edi,0xffffffff
  40c983:	e8 d8 48 ff ff       	call   401260 <exit@plt>
  40c988:	48 63 d0             	movsxd rdx,eax
  40c98b:	48 89 ee             	mov    rsi,rbp
  40c98e:	bf 01 00 00 00       	mov    edi,0x1
  40c993:	e8 08 48 ff ff       	call   4011a0 <write@plt>
  40c998:	48 8d 3d b5 57 00 00 	lea    rdi,[rip+0x57b5]        # 412154 <_IO_stdin_used+0x154>
  40c99f:	e8 ec 47 ff ff       	call   401190 <puts@plt>
  40c9a4:	48 8d 3d 59 56 00 00 	lea    rdi,[rip+0x5659]        # 412004 <_IO_stdin_used+0x4>
  40c9ab:	31 f6                	xor    esi,esi
  40c9ad:	31 c0                	xor    eax,eax
  40c9af:	e8 9c 48 ff ff       	call   401250 <open@plt>
  40c9b4:	89 c7                	mov    edi,eax
  40c9b6:	85 c0                	test   eax,eax
  40c9b8:	79 34                	jns    40c9ee <win+0xb478>
  40c9ba:	e8 c1 47 ff ff       	call   401180 <__errno_location@plt>
  40c9bf:	8b 38                	mov    edi,DWORD PTR [rax]
  40c9c1:	e8 ba 48 ff ff       	call   401280 <strerror@plt>
  40c9c6:	48 8d 35 3d 56 00 00 	lea    rsi,[rip+0x563d]        # 41200a <_IO_stdin_used+0xa>
  40c9cd:	bf 01 00 00 00       	mov    edi,0x1
  40c9d2:	48 89 c2             	mov    rdx,rax
  40c9d5:	31 c0                	xor    eax,eax
  40c9d7:	e8 54 48 ff ff       	call   401230 <__printf_chk@plt>
  40c9dc:	e8 ff 47 ff ff       	call   4011e0 <geteuid@plt>
  40c9e1:	85 c0                	test   eax,eax
  40c9e3:	0f 84 f0 4b ff ff    	je     4015d9 <win+0x63>
  40c9e9:	e9 d3 4b ff ff       	jmp    4015c1 <win+0x4b>
  40c9ee:	ba 00 01 00 00       	mov    edx,0x100
  40c9f3:	48 89 ee             	mov    rsi,rbp
  40c9f6:	e8 05 48 ff ff       	call   401200 <read@plt>
  40c9fb:	85 c0                	test   eax,eax
  40c9fd:	7f 2a                	jg     40ca29 <win+0xb4b3>
  40c9ff:	e8 7c 47 ff ff       	call   401180 <__errno_location@plt>
  40ca04:	8b 38                	mov    edi,DWORD PTR [rax]
  40ca06:	e8 75 48 ff ff       	call   401280 <strerror@plt>
  40ca0b:	bf 01 00 00 00       	mov    edi,0x1
  40ca10:	48 8d 35 92 56 00 00 	lea    rsi,[rip+0x5692]        # 4120a9 <_IO_stdin_used+0xa9>
  40ca17:	48 89 c2             	mov    rdx,rax
  40ca1a:	31 c0                	xor    eax,eax
  40ca1c:	e8 0f 48 ff ff       	call   401230 <__printf_chk@plt>
  40ca21:	83 cf ff             	or     edi,0xffffffff
  40ca24:	e8 37 48 ff ff       	call   401260 <exit@plt>
  40ca29:	48 63 d0             	movsxd rdx,eax
  40ca2c:	48 89 ee             	mov    rsi,rbp
  40ca2f:	bf 01 00 00 00       	mov    edi,0x1
  40ca34:	e8 67 47 ff ff       	call   4011a0 <write@plt>
  40ca39:	48 8d 3d 14 57 00 00 	lea    rdi,[rip+0x5714]        # 412154 <_IO_stdin_used+0x154>
  40ca40:	e8 4b 47 ff ff       	call   401190 <puts@plt>
  40ca45:	48 8d 3d b8 55 00 00 	lea    rdi,[rip+0x55b8]        # 412004 <_IO_stdin_used+0x4>
  40ca4c:	31 f6                	xor    esi,esi
  40ca4e:	31 c0                	xor    eax,eax
  40ca50:	e8 fb 47 ff ff       	call   401250 <open@plt>
  40ca55:	89 c7                	mov    edi,eax
  40ca57:	85 c0                	test   eax,eax
  40ca59:	79 34                	jns    40ca8f <win+0xb519>
  40ca5b:	e8 20 47 ff ff       	call   401180 <__errno_location@plt>
  40ca60:	8b 38                	mov    edi,DWORD PTR [rax]
  40ca62:	e8 19 48 ff ff       	call   401280 <strerror@plt>
  40ca67:	48 8d 35 9c 55 00 00 	lea    rsi,[rip+0x559c]        # 41200a <_IO_stdin_used+0xa>
  40ca6e:	bf 01 00 00 00       	mov    edi,0x1
  40ca73:	48 89 c2             	mov    rdx,rax
  40ca76:	31 c0                	xor    eax,eax
  40ca78:	e8 b3 47 ff ff       	call   401230 <__printf_chk@plt>
  40ca7d:	e8 5e 47 ff ff       	call   4011e0 <geteuid@plt>
  40ca82:	85 c0                	test   eax,eax
  40ca84:	0f 84 4f 4b ff ff    	je     4015d9 <win+0x63>
  40ca8a:	e9 32 4b ff ff       	jmp    4015c1 <win+0x4b>
  40ca8f:	ba 00 01 00 00       	mov    edx,0x100
  40ca94:	48 89 ee             	mov    rsi,rbp
  40ca97:	e8 64 47 ff ff       	call   401200 <read@plt>
  40ca9c:	85 c0                	test   eax,eax
  40ca9e:	7f 2a                	jg     40caca <win+0xb554>
  40caa0:	e8 db 46 ff ff       	call   401180 <__errno_location@plt>
  40caa5:	8b 38                	mov    edi,DWORD PTR [rax]
  40caa7:	e8 d4 47 ff ff       	call   401280 <strerror@plt>
  40caac:	bf 01 00 00 00       	mov    edi,0x1
  40cab1:	48 8d 35 f1 55 00 00 	lea    rsi,[rip+0x55f1]        # 4120a9 <_IO_stdin_used+0xa9>
  40cab8:	48 89 c2             	mov    rdx,rax
  40cabb:	31 c0                	xor    eax,eax
  40cabd:	e8 6e 47 ff ff       	call   401230 <__printf_chk@plt>
  40cac2:	83 cf ff             	or     edi,0xffffffff
  40cac5:	e8 96 47 ff ff       	call   401260 <exit@plt>
  40caca:	48 63 d0             	movsxd rdx,eax
  40cacd:	48 89 ee             	mov    rsi,rbp
  40cad0:	bf 01 00 00 00       	mov    edi,0x1
  40cad5:	e8 c6 46 ff ff       	call   4011a0 <write@plt>
  40cada:	48 8d 3d 73 56 00 00 	lea    rdi,[rip+0x5673]        # 412154 <_IO_stdin_used+0x154>
  40cae1:	e8 aa 46 ff ff       	call   401190 <puts@plt>
  40cae6:	48 8d 3d 17 55 00 00 	lea    rdi,[rip+0x5517]        # 412004 <_IO_stdin_used+0x4>
  40caed:	31 f6                	xor    esi,esi
  40caef:	31 c0                	xor    eax,eax
  40caf1:	e8 5a 47 ff ff       	call   401250 <open@plt>
  40caf6:	89 c7                	mov    edi,eax
  40caf8:	85 c0                	test   eax,eax
  40cafa:	79 34                	jns    40cb30 <win+0xb5ba>
  40cafc:	e8 7f 46 ff ff       	call   401180 <__errno_location@plt>
  40cb01:	8b 38                	mov    edi,DWORD PTR [rax]
  40cb03:	e8 78 47 ff ff       	call   401280 <strerror@plt>
  40cb08:	48 8d 35 fb 54 00 00 	lea    rsi,[rip+0x54fb]        # 41200a <_IO_stdin_used+0xa>
  40cb0f:	bf 01 00 00 00       	mov    edi,0x1
  40cb14:	48 89 c2             	mov    rdx,rax
  40cb17:	31 c0                	xor    eax,eax
  40cb19:	e8 12 47 ff ff       	call   401230 <__printf_chk@plt>
  40cb1e:	e8 bd 46 ff ff       	call   4011e0 <geteuid@plt>
  40cb23:	85 c0                	test   eax,eax
  40cb25:	0f 84 ae 4a ff ff    	je     4015d9 <win+0x63>
  40cb2b:	e9 91 4a ff ff       	jmp    4015c1 <win+0x4b>
  40cb30:	ba 00 01 00 00       	mov    edx,0x100
  40cb35:	48 89 ee             	mov    rsi,rbp
  40cb38:	e8 c3 46 ff ff       	call   401200 <read@plt>
  40cb3d:	85 c0                	test   eax,eax
  40cb3f:	7f 2a                	jg     40cb6b <win+0xb5f5>
  40cb41:	e8 3a 46 ff ff       	call   401180 <__errno_location@plt>
  40cb46:	8b 38                	mov    edi,DWORD PTR [rax]
  40cb48:	e8 33 47 ff ff       	call   401280 <strerror@plt>
  40cb4d:	bf 01 00 00 00       	mov    edi,0x1
  40cb52:	48 8d 35 50 55 00 00 	lea    rsi,[rip+0x5550]        # 4120a9 <_IO_stdin_used+0xa9>
  40cb59:	48 89 c2             	mov    rdx,rax
  40cb5c:	31 c0                	xor    eax,eax
  40cb5e:	e8 cd 46 ff ff       	call   401230 <__printf_chk@plt>
  40cb63:	83 cf ff             	or     edi,0xffffffff
  40cb66:	e8 f5 46 ff ff       	call   401260 <exit@plt>
  40cb6b:	48 63 d0             	movsxd rdx,eax
  40cb6e:	48 89 ee             	mov    rsi,rbp
  40cb71:	bf 01 00 00 00       	mov    edi,0x1
  40cb76:	e8 25 46 ff ff       	call   4011a0 <write@plt>
  40cb7b:	48 8d 3d d2 55 00 00 	lea    rdi,[rip+0x55d2]        # 412154 <_IO_stdin_used+0x154>
  40cb82:	e8 09 46 ff ff       	call   401190 <puts@plt>
  40cb87:	48 8d 3d 76 54 00 00 	lea    rdi,[rip+0x5476]        # 412004 <_IO_stdin_used+0x4>
  40cb8e:	31 f6                	xor    esi,esi
  40cb90:	31 c0                	xor    eax,eax
  40cb92:	e8 b9 46 ff ff       	call   401250 <open@plt>
  40cb97:	89 c7                	mov    edi,eax
  40cb99:	85 c0                	test   eax,eax
  40cb9b:	79 34                	jns    40cbd1 <win+0xb65b>
  40cb9d:	e8 de 45 ff ff       	call   401180 <__errno_location@plt>
  40cba2:	8b 38                	mov    edi,DWORD PTR [rax]
  40cba4:	e8 d7 46 ff ff       	call   401280 <strerror@plt>
  40cba9:	48 8d 35 5a 54 00 00 	lea    rsi,[rip+0x545a]        # 41200a <_IO_stdin_used+0xa>
  40cbb0:	bf 01 00 00 00       	mov    edi,0x1
  40cbb5:	48 89 c2             	mov    rdx,rax
  40cbb8:	31 c0                	xor    eax,eax
  40cbba:	e8 71 46 ff ff       	call   401230 <__printf_chk@plt>
  40cbbf:	e8 1c 46 ff ff       	call   4011e0 <geteuid@plt>
  40cbc4:	85 c0                	test   eax,eax
  40cbc6:	0f 84 0d 4a ff ff    	je     4015d9 <win+0x63>
  40cbcc:	e9 f0 49 ff ff       	jmp    4015c1 <win+0x4b>
  40cbd1:	ba 00 01 00 00       	mov    edx,0x100
  40cbd6:	48 89 ee             	mov    rsi,rbp
  40cbd9:	e8 22 46 ff ff       	call   401200 <read@plt>
  40cbde:	85 c0                	test   eax,eax
  40cbe0:	7f 2a                	jg     40cc0c <win+0xb696>
  40cbe2:	e8 99 45 ff ff       	call   401180 <__errno_location@plt>
  40cbe7:	8b 38                	mov    edi,DWORD PTR [rax]
  40cbe9:	e8 92 46 ff ff       	call   401280 <strerror@plt>
  40cbee:	bf 01 00 00 00       	mov    edi,0x1
  40cbf3:	48 8d 35 af 54 00 00 	lea    rsi,[rip+0x54af]        # 4120a9 <_IO_stdin_used+0xa9>
  40cbfa:	48 89 c2             	mov    rdx,rax
  40cbfd:	31 c0                	xor    eax,eax
  40cbff:	e8 2c 46 ff ff       	call   401230 <__printf_chk@plt>
  40cc04:	83 cf ff             	or     edi,0xffffffff
  40cc07:	e8 54 46 ff ff       	call   401260 <exit@plt>
  40cc0c:	48 63 d0             	movsxd rdx,eax
  40cc0f:	48 89 ee             	mov    rsi,rbp
  40cc12:	bf 01 00 00 00       	mov    edi,0x1
  40cc17:	e8 84 45 ff ff       	call   4011a0 <write@plt>
  40cc1c:	48 8d 3d 31 55 00 00 	lea    rdi,[rip+0x5531]        # 412154 <_IO_stdin_used+0x154>
  40cc23:	e8 68 45 ff ff       	call   401190 <puts@plt>
  40cc28:	48 8d 3d d5 53 00 00 	lea    rdi,[rip+0x53d5]        # 412004 <_IO_stdin_used+0x4>
  40cc2f:	31 f6                	xor    esi,esi
  40cc31:	31 c0                	xor    eax,eax
  40cc33:	e8 18 46 ff ff       	call   401250 <open@plt>
  40cc38:	89 c7                	mov    edi,eax
  40cc3a:	85 c0                	test   eax,eax
  40cc3c:	79 34                	jns    40cc72 <win+0xb6fc>
  40cc3e:	e8 3d 45 ff ff       	call   401180 <__errno_location@plt>
  40cc43:	8b 38                	mov    edi,DWORD PTR [rax]
  40cc45:	e8 36 46 ff ff       	call   401280 <strerror@plt>
  40cc4a:	48 8d 35 b9 53 00 00 	lea    rsi,[rip+0x53b9]        # 41200a <_IO_stdin_used+0xa>
  40cc51:	bf 01 00 00 00       	mov    edi,0x1
  40cc56:	48 89 c2             	mov    rdx,rax
  40cc59:	31 c0                	xor    eax,eax
  40cc5b:	e8 d0 45 ff ff       	call   401230 <__printf_chk@plt>
  40cc60:	e8 7b 45 ff ff       	call   4011e0 <geteuid@plt>
  40cc65:	85 c0                	test   eax,eax
  40cc67:	0f 84 6c 49 ff ff    	je     4015d9 <win+0x63>
  40cc6d:	e9 4f 49 ff ff       	jmp    4015c1 <win+0x4b>
  40cc72:	ba 00 01 00 00       	mov    edx,0x100
  40cc77:	48 89 ee             	mov    rsi,rbp
  40cc7a:	e8 81 45 ff ff       	call   401200 <read@plt>
  40cc7f:	85 c0                	test   eax,eax
  40cc81:	7f 2a                	jg     40ccad <win+0xb737>
  40cc83:	e8 f8 44 ff ff       	call   401180 <__errno_location@plt>
  40cc88:	8b 38                	mov    edi,DWORD PTR [rax]
  40cc8a:	e8 f1 45 ff ff       	call   401280 <strerror@plt>
  40cc8f:	bf 01 00 00 00       	mov    edi,0x1
  40cc94:	48 8d 35 0e 54 00 00 	lea    rsi,[rip+0x540e]        # 4120a9 <_IO_stdin_used+0xa9>
  40cc9b:	48 89 c2             	mov    rdx,rax
  40cc9e:	31 c0                	xor    eax,eax
  40cca0:	e8 8b 45 ff ff       	call   401230 <__printf_chk@plt>
  40cca5:	83 cf ff             	or     edi,0xffffffff
  40cca8:	e8 b3 45 ff ff       	call   401260 <exit@plt>
  40ccad:	48 63 d0             	movsxd rdx,eax
  40ccb0:	48 89 ee             	mov    rsi,rbp
  40ccb3:	bf 01 00 00 00       	mov    edi,0x1
  40ccb8:	e8 e3 44 ff ff       	call   4011a0 <write@plt>
  40ccbd:	48 8d 3d 90 54 00 00 	lea    rdi,[rip+0x5490]        # 412154 <_IO_stdin_used+0x154>
  40ccc4:	e8 c7 44 ff ff       	call   401190 <puts@plt>
  40ccc9:	48 8d 3d 34 53 00 00 	lea    rdi,[rip+0x5334]        # 412004 <_IO_stdin_used+0x4>
  40ccd0:	31 f6                	xor    esi,esi
  40ccd2:	31 c0                	xor    eax,eax
  40ccd4:	e8 77 45 ff ff       	call   401250 <open@plt>
  40ccd9:	89 c7                	mov    edi,eax
  40ccdb:	85 c0                	test   eax,eax
  40ccdd:	79 34                	jns    40cd13 <win+0xb79d>
  40ccdf:	e8 9c 44 ff ff       	call   401180 <__errno_location@plt>
  40cce4:	8b 38                	mov    edi,DWORD PTR [rax]
  40cce6:	e8 95 45 ff ff       	call   401280 <strerror@plt>
  40cceb:	48 8d 35 18 53 00 00 	lea    rsi,[rip+0x5318]        # 41200a <_IO_stdin_used+0xa>
  40ccf2:	bf 01 00 00 00       	mov    edi,0x1
  40ccf7:	48 89 c2             	mov    rdx,rax
  40ccfa:	31 c0                	xor    eax,eax
  40ccfc:	e8 2f 45 ff ff       	call   401230 <__printf_chk@plt>
  40cd01:	e8 da 44 ff ff       	call   4011e0 <geteuid@plt>
  40cd06:	85 c0                	test   eax,eax
  40cd08:	0f 84 cb 48 ff ff    	je     4015d9 <win+0x63>
  40cd0e:	e9 ae 48 ff ff       	jmp    4015c1 <win+0x4b>
  40cd13:	ba 00 01 00 00       	mov    edx,0x100
  40cd18:	48 89 ee             	mov    rsi,rbp
  40cd1b:	e8 e0 44 ff ff       	call   401200 <read@plt>
  40cd20:	85 c0                	test   eax,eax
  40cd22:	7f 2a                	jg     40cd4e <win+0xb7d8>
  40cd24:	e8 57 44 ff ff       	call   401180 <__errno_location@plt>
  40cd29:	8b 38                	mov    edi,DWORD PTR [rax]
  40cd2b:	e8 50 45 ff ff       	call   401280 <strerror@plt>
  40cd30:	bf 01 00 00 00       	mov    edi,0x1
  40cd35:	48 8d 35 6d 53 00 00 	lea    rsi,[rip+0x536d]        # 4120a9 <_IO_stdin_used+0xa9>
  40cd3c:	48 89 c2             	mov    rdx,rax
  40cd3f:	31 c0                	xor    eax,eax
  40cd41:	e8 ea 44 ff ff       	call   401230 <__printf_chk@plt>
  40cd46:	83 cf ff             	or     edi,0xffffffff
  40cd49:	e8 12 45 ff ff       	call   401260 <exit@plt>
  40cd4e:	48 63 d0             	movsxd rdx,eax
  40cd51:	48 89 ee             	mov    rsi,rbp
  40cd54:	bf 01 00 00 00       	mov    edi,0x1
  40cd59:	e8 42 44 ff ff       	call   4011a0 <write@plt>
  40cd5e:	48 8d 3d ef 53 00 00 	lea    rdi,[rip+0x53ef]        # 412154 <_IO_stdin_used+0x154>
  40cd65:	e8 26 44 ff ff       	call   401190 <puts@plt>
  40cd6a:	48 8d 3d 93 52 00 00 	lea    rdi,[rip+0x5293]        # 412004 <_IO_stdin_used+0x4>
  40cd71:	31 f6                	xor    esi,esi
  40cd73:	31 c0                	xor    eax,eax
  40cd75:	e8 d6 44 ff ff       	call   401250 <open@plt>
  40cd7a:	89 c7                	mov    edi,eax
  40cd7c:	85 c0                	test   eax,eax
  40cd7e:	79 34                	jns    40cdb4 <win+0xb83e>
  40cd80:	e8 fb 43 ff ff       	call   401180 <__errno_location@plt>
  40cd85:	8b 38                	mov    edi,DWORD PTR [rax]
  40cd87:	e8 f4 44 ff ff       	call   401280 <strerror@plt>
  40cd8c:	48 8d 35 77 52 00 00 	lea    rsi,[rip+0x5277]        # 41200a <_IO_stdin_used+0xa>
  40cd93:	bf 01 00 00 00       	mov    edi,0x1
  40cd98:	48 89 c2             	mov    rdx,rax
  40cd9b:	31 c0                	xor    eax,eax
  40cd9d:	e8 8e 44 ff ff       	call   401230 <__printf_chk@plt>
  40cda2:	e8 39 44 ff ff       	call   4011e0 <geteuid@plt>
  40cda7:	85 c0                	test   eax,eax
  40cda9:	0f 84 2a 48 ff ff    	je     4015d9 <win+0x63>
  40cdaf:	e9 0d 48 ff ff       	jmp    4015c1 <win+0x4b>
  40cdb4:	ba 00 01 00 00       	mov    edx,0x100
  40cdb9:	48 89 ee             	mov    rsi,rbp
  40cdbc:	e8 3f 44 ff ff       	call   401200 <read@plt>
  40cdc1:	85 c0                	test   eax,eax
  40cdc3:	7f 2a                	jg     40cdef <win+0xb879>
  40cdc5:	e8 b6 43 ff ff       	call   401180 <__errno_location@plt>
  40cdca:	8b 38                	mov    edi,DWORD PTR [rax]
  40cdcc:	e8 af 44 ff ff       	call   401280 <strerror@plt>
  40cdd1:	bf 01 00 00 00       	mov    edi,0x1
  40cdd6:	48 8d 35 cc 52 00 00 	lea    rsi,[rip+0x52cc]        # 4120a9 <_IO_stdin_used+0xa9>
  40cddd:	48 89 c2             	mov    rdx,rax
  40cde0:	31 c0                	xor    eax,eax
  40cde2:	e8 49 44 ff ff       	call   401230 <__printf_chk@plt>
  40cde7:	83 cf ff             	or     edi,0xffffffff
  40cdea:	e8 71 44 ff ff       	call   401260 <exit@plt>
  40cdef:	48 63 d0             	movsxd rdx,eax
  40cdf2:	48 89 ee             	mov    rsi,rbp
  40cdf5:	bf 01 00 00 00       	mov    edi,0x1
  40cdfa:	e8 a1 43 ff ff       	call   4011a0 <write@plt>
  40cdff:	48 8d 3d 4e 53 00 00 	lea    rdi,[rip+0x534e]        # 412154 <_IO_stdin_used+0x154>
  40ce06:	e8 85 43 ff ff       	call   401190 <puts@plt>
  40ce0b:	48 8d 3d f2 51 00 00 	lea    rdi,[rip+0x51f2]        # 412004 <_IO_stdin_used+0x4>
  40ce12:	31 f6                	xor    esi,esi
  40ce14:	31 c0                	xor    eax,eax
  40ce16:	e8 35 44 ff ff       	call   401250 <open@plt>
  40ce1b:	89 c7                	mov    edi,eax
  40ce1d:	85 c0                	test   eax,eax
  40ce1f:	79 34                	jns    40ce55 <win+0xb8df>
  40ce21:	e8 5a 43 ff ff       	call   401180 <__errno_location@plt>
  40ce26:	8b 38                	mov    edi,DWORD PTR [rax]
  40ce28:	e8 53 44 ff ff       	call   401280 <strerror@plt>
  40ce2d:	48 8d 35 d6 51 00 00 	lea    rsi,[rip+0x51d6]        # 41200a <_IO_stdin_used+0xa>
  40ce34:	bf 01 00 00 00       	mov    edi,0x1
  40ce39:	48 89 c2             	mov    rdx,rax
  40ce3c:	31 c0                	xor    eax,eax
  40ce3e:	e8 ed 43 ff ff       	call   401230 <__printf_chk@plt>
  40ce43:	e8 98 43 ff ff       	call   4011e0 <geteuid@plt>
  40ce48:	85 c0                	test   eax,eax
  40ce4a:	0f 84 89 47 ff ff    	je     4015d9 <win+0x63>
  40ce50:	e9 6c 47 ff ff       	jmp    4015c1 <win+0x4b>
  40ce55:	ba 00 01 00 00       	mov    edx,0x100
  40ce5a:	48 89 ee             	mov    rsi,rbp
  40ce5d:	e8 9e 43 ff ff       	call   401200 <read@plt>
  40ce62:	85 c0                	test   eax,eax
  40ce64:	7f 2a                	jg     40ce90 <win+0xb91a>
  40ce66:	e8 15 43 ff ff       	call   401180 <__errno_location@plt>
  40ce6b:	8b 38                	mov    edi,DWORD PTR [rax]
  40ce6d:	e8 0e 44 ff ff       	call   401280 <strerror@plt>
  40ce72:	bf 01 00 00 00       	mov    edi,0x1
  40ce77:	48 8d 35 2b 52 00 00 	lea    rsi,[rip+0x522b]        # 4120a9 <_IO_stdin_used+0xa9>
  40ce7e:	48 89 c2             	mov    rdx,rax
  40ce81:	31 c0                	xor    eax,eax
  40ce83:	e8 a8 43 ff ff       	call   401230 <__printf_chk@plt>
  40ce88:	83 cf ff             	or     edi,0xffffffff
  40ce8b:	e8 d0 43 ff ff       	call   401260 <exit@plt>
  40ce90:	48 63 d0             	movsxd rdx,eax
  40ce93:	48 89 ee             	mov    rsi,rbp
  40ce96:	bf 01 00 00 00       	mov    edi,0x1
  40ce9b:	e8 00 43 ff ff       	call   4011a0 <write@plt>
  40cea0:	48 8d 3d ad 52 00 00 	lea    rdi,[rip+0x52ad]        # 412154 <_IO_stdin_used+0x154>
  40cea7:	e8 e4 42 ff ff       	call   401190 <puts@plt>
  40ceac:	48 8d 3d 51 51 00 00 	lea    rdi,[rip+0x5151]        # 412004 <_IO_stdin_used+0x4>
  40ceb3:	31 f6                	xor    esi,esi
  40ceb5:	31 c0                	xor    eax,eax
  40ceb7:	e8 94 43 ff ff       	call   401250 <open@plt>
  40cebc:	89 c7                	mov    edi,eax
  40cebe:	85 c0                	test   eax,eax
  40cec0:	79 34                	jns    40cef6 <win+0xb980>
  40cec2:	e8 b9 42 ff ff       	call   401180 <__errno_location@plt>
  40cec7:	8b 38                	mov    edi,DWORD PTR [rax]
  40cec9:	e8 b2 43 ff ff       	call   401280 <strerror@plt>
  40cece:	48 8d 35 35 51 00 00 	lea    rsi,[rip+0x5135]        # 41200a <_IO_stdin_used+0xa>
  40ced5:	bf 01 00 00 00       	mov    edi,0x1
  40ceda:	48 89 c2             	mov    rdx,rax
  40cedd:	31 c0                	xor    eax,eax
  40cedf:	e8 4c 43 ff ff       	call   401230 <__printf_chk@plt>
  40cee4:	e8 f7 42 ff ff       	call   4011e0 <geteuid@plt>
  40cee9:	85 c0                	test   eax,eax
  40ceeb:	0f 84 e8 46 ff ff    	je     4015d9 <win+0x63>
  40cef1:	e9 cb 46 ff ff       	jmp    4015c1 <win+0x4b>
  40cef6:	ba 00 01 00 00       	mov    edx,0x100
  40cefb:	48 89 ee             	mov    rsi,rbp
  40cefe:	e8 fd 42 ff ff       	call   401200 <read@plt>
  40cf03:	85 c0                	test   eax,eax
  40cf05:	7f 2a                	jg     40cf31 <win+0xb9bb>
  40cf07:	e8 74 42 ff ff       	call   401180 <__errno_location@plt>
  40cf0c:	8b 38                	mov    edi,DWORD PTR [rax]
  40cf0e:	e8 6d 43 ff ff       	call   401280 <strerror@plt>
  40cf13:	bf 01 00 00 00       	mov    edi,0x1
  40cf18:	48 8d 35 8a 51 00 00 	lea    rsi,[rip+0x518a]        # 4120a9 <_IO_stdin_used+0xa9>
  40cf1f:	48 89 c2             	mov    rdx,rax
  40cf22:	31 c0                	xor    eax,eax
  40cf24:	e8 07 43 ff ff       	call   401230 <__printf_chk@plt>
  40cf29:	83 cf ff             	or     edi,0xffffffff
  40cf2c:	e8 2f 43 ff ff       	call   401260 <exit@plt>
  40cf31:	48 63 d0             	movsxd rdx,eax
  40cf34:	48 89 ee             	mov    rsi,rbp
  40cf37:	bf 01 00 00 00       	mov    edi,0x1
  40cf3c:	e8 5f 42 ff ff       	call   4011a0 <write@plt>
  40cf41:	48 8d 3d 0c 52 00 00 	lea    rdi,[rip+0x520c]        # 412154 <_IO_stdin_used+0x154>
  40cf48:	e8 43 42 ff ff       	call   401190 <puts@plt>
  40cf4d:	48 8d 3d b0 50 00 00 	lea    rdi,[rip+0x50b0]        # 412004 <_IO_stdin_used+0x4>
  40cf54:	31 f6                	xor    esi,esi
  40cf56:	31 c0                	xor    eax,eax
  40cf58:	e8 f3 42 ff ff       	call   401250 <open@plt>
  40cf5d:	89 c7                	mov    edi,eax
  40cf5f:	85 c0                	test   eax,eax
  40cf61:	79 34                	jns    40cf97 <win+0xba21>
  40cf63:	e8 18 42 ff ff       	call   401180 <__errno_location@plt>
  40cf68:	8b 38                	mov    edi,DWORD PTR [rax]
  40cf6a:	e8 11 43 ff ff       	call   401280 <strerror@plt>
  40cf6f:	48 8d 35 94 50 00 00 	lea    rsi,[rip+0x5094]        # 41200a <_IO_stdin_used+0xa>
  40cf76:	bf 01 00 00 00       	mov    edi,0x1
  40cf7b:	48 89 c2             	mov    rdx,rax
  40cf7e:	31 c0                	xor    eax,eax
  40cf80:	e8 ab 42 ff ff       	call   401230 <__printf_chk@plt>
  40cf85:	e8 56 42 ff ff       	call   4011e0 <geteuid@plt>
  40cf8a:	85 c0                	test   eax,eax
  40cf8c:	0f 84 47 46 ff ff    	je     4015d9 <win+0x63>
  40cf92:	e9 2a 46 ff ff       	jmp    4015c1 <win+0x4b>
  40cf97:	ba 00 01 00 00       	mov    edx,0x100
  40cf9c:	48 89 ee             	mov    rsi,rbp
  40cf9f:	e8 5c 42 ff ff       	call   401200 <read@plt>
  40cfa4:	85 c0                	test   eax,eax
  40cfa6:	7f 2a                	jg     40cfd2 <win+0xba5c>
  40cfa8:	e8 d3 41 ff ff       	call   401180 <__errno_location@plt>
  40cfad:	8b 38                	mov    edi,DWORD PTR [rax]
  40cfaf:	e8 cc 42 ff ff       	call   401280 <strerror@plt>
  40cfb4:	bf 01 00 00 00       	mov    edi,0x1
  40cfb9:	48 8d 35 e9 50 00 00 	lea    rsi,[rip+0x50e9]        # 4120a9 <_IO_stdin_used+0xa9>
  40cfc0:	48 89 c2             	mov    rdx,rax
  40cfc3:	31 c0                	xor    eax,eax
  40cfc5:	e8 66 42 ff ff       	call   401230 <__printf_chk@plt>
  40cfca:	83 cf ff             	or     edi,0xffffffff
  40cfcd:	e8 8e 42 ff ff       	call   401260 <exit@plt>
  40cfd2:	48 63 d0             	movsxd rdx,eax
  40cfd5:	48 89 ee             	mov    rsi,rbp
  40cfd8:	bf 01 00 00 00       	mov    edi,0x1
  40cfdd:	e8 be 41 ff ff       	call   4011a0 <write@plt>
  40cfe2:	48 8d 3d 6b 51 00 00 	lea    rdi,[rip+0x516b]        # 412154 <_IO_stdin_used+0x154>
  40cfe9:	e8 a2 41 ff ff       	call   401190 <puts@plt>
  40cfee:	48 8d 3d 0f 50 00 00 	lea    rdi,[rip+0x500f]        # 412004 <_IO_stdin_used+0x4>
  40cff5:	31 f6                	xor    esi,esi
  40cff7:	31 c0                	xor    eax,eax
  40cff9:	e8 52 42 ff ff       	call   401250 <open@plt>
  40cffe:	89 c7                	mov    edi,eax
  40d000:	85 c0                	test   eax,eax
  40d002:	79 34                	jns    40d038 <win+0xbac2>
  40d004:	e8 77 41 ff ff       	call   401180 <__errno_location@plt>
  40d009:	8b 38                	mov    edi,DWORD PTR [rax]
  40d00b:	e8 70 42 ff ff       	call   401280 <strerror@plt>
  40d010:	48 8d 35 f3 4f 00 00 	lea    rsi,[rip+0x4ff3]        # 41200a <_IO_stdin_used+0xa>
  40d017:	bf 01 00 00 00       	mov    edi,0x1
  40d01c:	48 89 c2             	mov    rdx,rax
  40d01f:	31 c0                	xor    eax,eax
  40d021:	e8 0a 42 ff ff       	call   401230 <__printf_chk@plt>
  40d026:	e8 b5 41 ff ff       	call   4011e0 <geteuid@plt>
  40d02b:	85 c0                	test   eax,eax
  40d02d:	0f 84 a6 45 ff ff    	je     4015d9 <win+0x63>
  40d033:	e9 89 45 ff ff       	jmp    4015c1 <win+0x4b>
  40d038:	ba 00 01 00 00       	mov    edx,0x100
  40d03d:	48 89 ee             	mov    rsi,rbp
  40d040:	e8 bb 41 ff ff       	call   401200 <read@plt>
  40d045:	85 c0                	test   eax,eax
  40d047:	7f 2a                	jg     40d073 <win+0xbafd>
  40d049:	e8 32 41 ff ff       	call   401180 <__errno_location@plt>
  40d04e:	8b 38                	mov    edi,DWORD PTR [rax]
  40d050:	e8 2b 42 ff ff       	call   401280 <strerror@plt>
  40d055:	bf 01 00 00 00       	mov    edi,0x1
  40d05a:	48 8d 35 48 50 00 00 	lea    rsi,[rip+0x5048]        # 4120a9 <_IO_stdin_used+0xa9>
  40d061:	48 89 c2             	mov    rdx,rax
  40d064:	31 c0                	xor    eax,eax
  40d066:	e8 c5 41 ff ff       	call   401230 <__printf_chk@plt>
  40d06b:	83 cf ff             	or     edi,0xffffffff
  40d06e:	e8 ed 41 ff ff       	call   401260 <exit@plt>
  40d073:	48 63 d0             	movsxd rdx,eax
  40d076:	48 89 ee             	mov    rsi,rbp
  40d079:	bf 01 00 00 00       	mov    edi,0x1
  40d07e:	e8 1d 41 ff ff       	call   4011a0 <write@plt>
  40d083:	48 8d 3d ca 50 00 00 	lea    rdi,[rip+0x50ca]        # 412154 <_IO_stdin_used+0x154>
  40d08a:	e8 01 41 ff ff       	call   401190 <puts@plt>
  40d08f:	48 8d 3d 6e 4f 00 00 	lea    rdi,[rip+0x4f6e]        # 412004 <_IO_stdin_used+0x4>
  40d096:	31 f6                	xor    esi,esi
  40d098:	31 c0                	xor    eax,eax
  40d09a:	e8 b1 41 ff ff       	call   401250 <open@plt>
  40d09f:	89 c7                	mov    edi,eax
  40d0a1:	85 c0                	test   eax,eax
  40d0a3:	79 34                	jns    40d0d9 <win+0xbb63>
  40d0a5:	e8 d6 40 ff ff       	call   401180 <__errno_location@plt>
  40d0aa:	8b 38                	mov    edi,DWORD PTR [rax]
  40d0ac:	e8 cf 41 ff ff       	call   401280 <strerror@plt>
  40d0b1:	48 8d 35 52 4f 00 00 	lea    rsi,[rip+0x4f52]        # 41200a <_IO_stdin_used+0xa>
  40d0b8:	bf 01 00 00 00       	mov    edi,0x1
  40d0bd:	48 89 c2             	mov    rdx,rax
  40d0c0:	31 c0                	xor    eax,eax
  40d0c2:	e8 69 41 ff ff       	call   401230 <__printf_chk@plt>
  40d0c7:	e8 14 41 ff ff       	call   4011e0 <geteuid@plt>
  40d0cc:	85 c0                	test   eax,eax
  40d0ce:	0f 84 05 45 ff ff    	je     4015d9 <win+0x63>
  40d0d4:	e9 e8 44 ff ff       	jmp    4015c1 <win+0x4b>
  40d0d9:	ba 00 01 00 00       	mov    edx,0x100
  40d0de:	48 89 ee             	mov    rsi,rbp
  40d0e1:	e8 1a 41 ff ff       	call   401200 <read@plt>
  40d0e6:	85 c0                	test   eax,eax
  40d0e8:	7f 2a                	jg     40d114 <win+0xbb9e>
  40d0ea:	e8 91 40 ff ff       	call   401180 <__errno_location@plt>
  40d0ef:	8b 38                	mov    edi,DWORD PTR [rax]
  40d0f1:	e8 8a 41 ff ff       	call   401280 <strerror@plt>
  40d0f6:	bf 01 00 00 00       	mov    edi,0x1
  40d0fb:	48 8d 35 a7 4f 00 00 	lea    rsi,[rip+0x4fa7]        # 4120a9 <_IO_stdin_used+0xa9>
  40d102:	48 89 c2             	mov    rdx,rax
  40d105:	31 c0                	xor    eax,eax
  40d107:	e8 24 41 ff ff       	call   401230 <__printf_chk@plt>
  40d10c:	83 cf ff             	or     edi,0xffffffff
  40d10f:	e8 4c 41 ff ff       	call   401260 <exit@plt>
  40d114:	48 63 d0             	movsxd rdx,eax
  40d117:	48 89 ee             	mov    rsi,rbp
  40d11a:	bf 01 00 00 00       	mov    edi,0x1
  40d11f:	e8 7c 40 ff ff       	call   4011a0 <write@plt>
  40d124:	48 8d 3d 29 50 00 00 	lea    rdi,[rip+0x5029]        # 412154 <_IO_stdin_used+0x154>
  40d12b:	e8 60 40 ff ff       	call   401190 <puts@plt>
  40d130:	48 8d 3d cd 4e 00 00 	lea    rdi,[rip+0x4ecd]        # 412004 <_IO_stdin_used+0x4>
  40d137:	31 f6                	xor    esi,esi
  40d139:	31 c0                	xor    eax,eax
  40d13b:	e8 10 41 ff ff       	call   401250 <open@plt>
  40d140:	89 c7                	mov    edi,eax
  40d142:	85 c0                	test   eax,eax
  40d144:	79 34                	jns    40d17a <win+0xbc04>
  40d146:	e8 35 40 ff ff       	call   401180 <__errno_location@plt>
  40d14b:	8b 38                	mov    edi,DWORD PTR [rax]
  40d14d:	e8 2e 41 ff ff       	call   401280 <strerror@plt>
  40d152:	48 8d 35 b1 4e 00 00 	lea    rsi,[rip+0x4eb1]        # 41200a <_IO_stdin_used+0xa>
  40d159:	bf 01 00 00 00       	mov    edi,0x1
  40d15e:	48 89 c2             	mov    rdx,rax
  40d161:	31 c0                	xor    eax,eax
  40d163:	e8 c8 40 ff ff       	call   401230 <__printf_chk@plt>
  40d168:	e8 73 40 ff ff       	call   4011e0 <geteuid@plt>
  40d16d:	85 c0                	test   eax,eax
  40d16f:	0f 84 64 44 ff ff    	je     4015d9 <win+0x63>
  40d175:	e9 47 44 ff ff       	jmp    4015c1 <win+0x4b>
  40d17a:	ba 00 01 00 00       	mov    edx,0x100
  40d17f:	48 89 ee             	mov    rsi,rbp
  40d182:	e8 79 40 ff ff       	call   401200 <read@plt>
  40d187:	85 c0                	test   eax,eax
  40d189:	7f 2a                	jg     40d1b5 <win+0xbc3f>
  40d18b:	e8 f0 3f ff ff       	call   401180 <__errno_location@plt>
  40d190:	8b 38                	mov    edi,DWORD PTR [rax]
  40d192:	e8 e9 40 ff ff       	call   401280 <strerror@plt>
  40d197:	bf 01 00 00 00       	mov    edi,0x1
  40d19c:	48 8d 35 06 4f 00 00 	lea    rsi,[rip+0x4f06]        # 4120a9 <_IO_stdin_used+0xa9>
  40d1a3:	48 89 c2             	mov    rdx,rax
  40d1a6:	31 c0                	xor    eax,eax
  40d1a8:	e8 83 40 ff ff       	call   401230 <__printf_chk@plt>
  40d1ad:	83 cf ff             	or     edi,0xffffffff
  40d1b0:	e8 ab 40 ff ff       	call   401260 <exit@plt>
  40d1b5:	48 63 d0             	movsxd rdx,eax
  40d1b8:	48 89 ee             	mov    rsi,rbp
  40d1bb:	bf 01 00 00 00       	mov    edi,0x1
  40d1c0:	e8 db 3f ff ff       	call   4011a0 <write@plt>
  40d1c5:	48 8d 3d 88 4f 00 00 	lea    rdi,[rip+0x4f88]        # 412154 <_IO_stdin_used+0x154>
  40d1cc:	e8 bf 3f ff ff       	call   401190 <puts@plt>
  40d1d1:	48 8d 3d 2c 4e 00 00 	lea    rdi,[rip+0x4e2c]        # 412004 <_IO_stdin_used+0x4>
  40d1d8:	31 f6                	xor    esi,esi
  40d1da:	31 c0                	xor    eax,eax
  40d1dc:	e8 6f 40 ff ff       	call   401250 <open@plt>
  40d1e1:	89 c7                	mov    edi,eax
  40d1e3:	85 c0                	test   eax,eax
  40d1e5:	79 34                	jns    40d21b <win+0xbca5>
  40d1e7:	e8 94 3f ff ff       	call   401180 <__errno_location@plt>
  40d1ec:	8b 38                	mov    edi,DWORD PTR [rax]
  40d1ee:	e8 8d 40 ff ff       	call   401280 <strerror@plt>
  40d1f3:	48 8d 35 10 4e 00 00 	lea    rsi,[rip+0x4e10]        # 41200a <_IO_stdin_used+0xa>
  40d1fa:	bf 01 00 00 00       	mov    edi,0x1
  40d1ff:	48 89 c2             	mov    rdx,rax
  40d202:	31 c0                	xor    eax,eax
  40d204:	e8 27 40 ff ff       	call   401230 <__printf_chk@plt>
  40d209:	e8 d2 3f ff ff       	call   4011e0 <geteuid@plt>
  40d20e:	85 c0                	test   eax,eax
  40d210:	0f 84 c3 43 ff ff    	je     4015d9 <win+0x63>
  40d216:	e9 a6 43 ff ff       	jmp    4015c1 <win+0x4b>
  40d21b:	ba 00 01 00 00       	mov    edx,0x100
  40d220:	48 89 ee             	mov    rsi,rbp
  40d223:	e8 d8 3f ff ff       	call   401200 <read@plt>
  40d228:	85 c0                	test   eax,eax
  40d22a:	7f 2a                	jg     40d256 <win+0xbce0>
  40d22c:	e8 4f 3f ff ff       	call   401180 <__errno_location@plt>
  40d231:	8b 38                	mov    edi,DWORD PTR [rax]
  40d233:	e8 48 40 ff ff       	call   401280 <strerror@plt>
  40d238:	bf 01 00 00 00       	mov    edi,0x1
  40d23d:	48 8d 35 65 4e 00 00 	lea    rsi,[rip+0x4e65]        # 4120a9 <_IO_stdin_used+0xa9>
  40d244:	48 89 c2             	mov    rdx,rax
  40d247:	31 c0                	xor    eax,eax
  40d249:	e8 e2 3f ff ff       	call   401230 <__printf_chk@plt>
  40d24e:	83 cf ff             	or     edi,0xffffffff
  40d251:	e8 0a 40 ff ff       	call   401260 <exit@plt>
  40d256:	48 89 e5             	mov    rbp,rsp
  40d259:	48 63 d0             	movsxd rdx,eax
  40d25c:	bf 01 00 00 00       	mov    edi,0x1
  40d261:	48 89 ee             	mov    rsi,rbp
  40d264:	e8 37 3f ff ff       	call   4011a0 <write@plt>
  40d269:	48 8d 3d e4 4e 00 00 	lea    rdi,[rip+0x4ee4]        # 412154 <_IO_stdin_used+0x154>
  40d270:	e8 1b 3f ff ff       	call   401190 <puts@plt>
  40d275:	48 8d 3d 88 4d 00 00 	lea    rdi,[rip+0x4d88]        # 412004 <_IO_stdin_used+0x4>
  40d27c:	31 f6                	xor    esi,esi
  40d27e:	31 c0                	xor    eax,eax
  40d280:	e8 cb 3f ff ff       	call   401250 <open@plt>
  40d285:	89 c7                	mov    edi,eax
  40d287:	85 c0                	test   eax,eax
  40d289:	79 34                	jns    40d2bf <win+0xbd49>
  40d28b:	e8 f0 3e ff ff       	call   401180 <__errno_location@plt>
  40d290:	8b 38                	mov    edi,DWORD PTR [rax]
  40d292:	e8 e9 3f ff ff       	call   401280 <strerror@plt>
  40d297:	48 8d 35 6c 4d 00 00 	lea    rsi,[rip+0x4d6c]        # 41200a <_IO_stdin_used+0xa>
  40d29e:	bf 01 00 00 00       	mov    edi,0x1
  40d2a3:	48 89 c2             	mov    rdx,rax
  40d2a6:	31 c0                	xor    eax,eax
  40d2a8:	e8 83 3f ff ff       	call   401230 <__printf_chk@plt>
  40d2ad:	e8 2e 3f ff ff       	call   4011e0 <geteuid@plt>
  40d2b2:	85 c0                	test   eax,eax
  40d2b4:	0f 84 1f 43 ff ff    	je     4015d9 <win+0x63>
  40d2ba:	e9 02 43 ff ff       	jmp    4015c1 <win+0x4b>
  40d2bf:	ba 00 01 00 00       	mov    edx,0x100
  40d2c4:	48 89 ee             	mov    rsi,rbp
  40d2c7:	e8 34 3f ff ff       	call   401200 <read@plt>
  40d2cc:	85 c0                	test   eax,eax
  40d2ce:	7f 2a                	jg     40d2fa <win+0xbd84>
  40d2d0:	e8 ab 3e ff ff       	call   401180 <__errno_location@plt>
  40d2d5:	8b 38                	mov    edi,DWORD PTR [rax]
  40d2d7:	e8 a4 3f ff ff       	call   401280 <strerror@plt>
  40d2dc:	bf 01 00 00 00       	mov    edi,0x1
  40d2e1:	48 8d 35 c1 4d 00 00 	lea    rsi,[rip+0x4dc1]        # 4120a9 <_IO_stdin_used+0xa9>
  40d2e8:	48 89 c2             	mov    rdx,rax
  40d2eb:	31 c0                	xor    eax,eax
  40d2ed:	e8 3e 3f ff ff       	call   401230 <__printf_chk@plt>
  40d2f2:	83 cf ff             	or     edi,0xffffffff
  40d2f5:	e8 66 3f ff ff       	call   401260 <exit@plt>
  40d2fa:	48 63 d0             	movsxd rdx,eax
  40d2fd:	48 89 ee             	mov    rsi,rbp
  40d300:	bf 01 00 00 00       	mov    edi,0x1
  40d305:	e8 96 3e ff ff       	call   4011a0 <write@plt>
  40d30a:	48 8d 3d 43 4e 00 00 	lea    rdi,[rip+0x4e43]        # 412154 <_IO_stdin_used+0x154>
  40d311:	e8 7a 3e ff ff       	call   401190 <puts@plt>
  40d316:	48 8d 3d e7 4c 00 00 	lea    rdi,[rip+0x4ce7]        # 412004 <_IO_stdin_used+0x4>
  40d31d:	31 f6                	xor    esi,esi
  40d31f:	31 c0                	xor    eax,eax
  40d321:	e8 2a 3f ff ff       	call   401250 <open@plt>
  40d326:	89 c7                	mov    edi,eax
  40d328:	85 c0                	test   eax,eax
  40d32a:	79 34                	jns    40d360 <win+0xbdea>
  40d32c:	e8 4f 3e ff ff       	call   401180 <__errno_location@plt>
  40d331:	8b 38                	mov    edi,DWORD PTR [rax]
  40d333:	e8 48 3f ff ff       	call   401280 <strerror@plt>
  40d338:	48 8d 35 cb 4c 00 00 	lea    rsi,[rip+0x4ccb]        # 41200a <_IO_stdin_used+0xa>
  40d33f:	bf 01 00 00 00       	mov    edi,0x1
  40d344:	48 89 c2             	mov    rdx,rax
  40d347:	31 c0                	xor    eax,eax
  40d349:	e8 e2 3e ff ff       	call   401230 <__printf_chk@plt>
  40d34e:	e8 8d 3e ff ff       	call   4011e0 <geteuid@plt>
  40d353:	85 c0                	test   eax,eax
  40d355:	0f 84 7e 42 ff ff    	je     4015d9 <win+0x63>
  40d35b:	e9 61 42 ff ff       	jmp    4015c1 <win+0x4b>
  40d360:	ba 00 01 00 00       	mov    edx,0x100
  40d365:	48 89 ee             	mov    rsi,rbp
  40d368:	e8 93 3e ff ff       	call   401200 <read@plt>
  40d36d:	85 c0                	test   eax,eax
  40d36f:	7f 2a                	jg     40d39b <win+0xbe25>
  40d371:	e8 0a 3e ff ff       	call   401180 <__errno_location@plt>
  40d376:	8b 38                	mov    edi,DWORD PTR [rax]
  40d378:	e8 03 3f ff ff       	call   401280 <strerror@plt>
  40d37d:	bf 01 00 00 00       	mov    edi,0x1
  40d382:	48 8d 35 20 4d 00 00 	lea    rsi,[rip+0x4d20]        # 4120a9 <_IO_stdin_used+0xa9>
  40d389:	48 89 c2             	mov    rdx,rax
  40d38c:	31 c0                	xor    eax,eax
  40d38e:	e8 9d 3e ff ff       	call   401230 <__printf_chk@plt>
  40d393:	83 cf ff             	or     edi,0xffffffff
  40d396:	e8 c5 3e ff ff       	call   401260 <exit@plt>
  40d39b:	48 63 d0             	movsxd rdx,eax
  40d39e:	48 89 ee             	mov    rsi,rbp
  40d3a1:	bf 01 00 00 00       	mov    edi,0x1
  40d3a6:	e8 f5 3d ff ff       	call   4011a0 <write@plt>
  40d3ab:	48 8d 3d a2 4d 00 00 	lea    rdi,[rip+0x4da2]        # 412154 <_IO_stdin_used+0x154>
  40d3b2:	e8 d9 3d ff ff       	call   401190 <puts@plt>
  40d3b7:	48 8d 3d 46 4c 00 00 	lea    rdi,[rip+0x4c46]        # 412004 <_IO_stdin_used+0x4>
  40d3be:	31 f6                	xor    esi,esi
  40d3c0:	31 c0                	xor    eax,eax
  40d3c2:	e8 89 3e ff ff       	call   401250 <open@plt>
  40d3c7:	89 c7                	mov    edi,eax
  40d3c9:	85 c0                	test   eax,eax
  40d3cb:	79 34                	jns    40d401 <win+0xbe8b>
  40d3cd:	e8 ae 3d ff ff       	call   401180 <__errno_location@plt>
  40d3d2:	8b 38                	mov    edi,DWORD PTR [rax]
  40d3d4:	e8 a7 3e ff ff       	call   401280 <strerror@plt>
  40d3d9:	48 8d 35 2a 4c 00 00 	lea    rsi,[rip+0x4c2a]        # 41200a <_IO_stdin_used+0xa>
  40d3e0:	bf 01 00 00 00       	mov    edi,0x1
  40d3e5:	48 89 c2             	mov    rdx,rax
  40d3e8:	31 c0                	xor    eax,eax
  40d3ea:	e8 41 3e ff ff       	call   401230 <__printf_chk@plt>
  40d3ef:	e8 ec 3d ff ff       	call   4011e0 <geteuid@plt>
  40d3f4:	85 c0                	test   eax,eax
  40d3f6:	0f 84 dd 41 ff ff    	je     4015d9 <win+0x63>
  40d3fc:	e9 c0 41 ff ff       	jmp    4015c1 <win+0x4b>
  40d401:	ba 00 01 00 00       	mov    edx,0x100
  40d406:	48 89 ee             	mov    rsi,rbp
  40d409:	e8 f2 3d ff ff       	call   401200 <read@plt>
  40d40e:	85 c0                	test   eax,eax
  40d410:	7f 2a                	jg     40d43c <win+0xbec6>
  40d412:	e8 69 3d ff ff       	call   401180 <__errno_location@plt>
  40d417:	8b 38                	mov    edi,DWORD PTR [rax]
  40d419:	e8 62 3e ff ff       	call   401280 <strerror@plt>
  40d41e:	bf 01 00 00 00       	mov    edi,0x1
  40d423:	48 8d 35 7f 4c 00 00 	lea    rsi,[rip+0x4c7f]        # 4120a9 <_IO_stdin_used+0xa9>
  40d42a:	48 89 c2             	mov    rdx,rax
  40d42d:	31 c0                	xor    eax,eax
  40d42f:	e8 fc 3d ff ff       	call   401230 <__printf_chk@plt>
  40d434:	83 cf ff             	or     edi,0xffffffff
  40d437:	e8 24 3e ff ff       	call   401260 <exit@plt>
  40d43c:	48 63 d0             	movsxd rdx,eax
  40d43f:	48 89 ee             	mov    rsi,rbp
  40d442:	bf 01 00 00 00       	mov    edi,0x1
  40d447:	e8 54 3d ff ff       	call   4011a0 <write@plt>
  40d44c:	48 8d 3d 01 4d 00 00 	lea    rdi,[rip+0x4d01]        # 412154 <_IO_stdin_used+0x154>
  40d453:	e8 38 3d ff ff       	call   401190 <puts@plt>
  40d458:	48 8d 3d a5 4b 00 00 	lea    rdi,[rip+0x4ba5]        # 412004 <_IO_stdin_used+0x4>
  40d45f:	31 f6                	xor    esi,esi
  40d461:	31 c0                	xor    eax,eax
  40d463:	e8 e8 3d ff ff       	call   401250 <open@plt>
  40d468:	89 c7                	mov    edi,eax
  40d46a:	85 c0                	test   eax,eax
  40d46c:	79 34                	jns    40d4a2 <win+0xbf2c>
  40d46e:	e8 0d 3d ff ff       	call   401180 <__errno_location@plt>
  40d473:	8b 38                	mov    edi,DWORD PTR [rax]
  40d475:	e8 06 3e ff ff       	call   401280 <strerror@plt>
  40d47a:	48 8d 35 89 4b 00 00 	lea    rsi,[rip+0x4b89]        # 41200a <_IO_stdin_used+0xa>
  40d481:	bf 01 00 00 00       	mov    edi,0x1
  40d486:	48 89 c2             	mov    rdx,rax
  40d489:	31 c0                	xor    eax,eax
  40d48b:	e8 a0 3d ff ff       	call   401230 <__printf_chk@plt>
  40d490:	e8 4b 3d ff ff       	call   4011e0 <geteuid@plt>
  40d495:	85 c0                	test   eax,eax
  40d497:	0f 84 3c 41 ff ff    	je     4015d9 <win+0x63>
  40d49d:	e9 1f 41 ff ff       	jmp    4015c1 <win+0x4b>
  40d4a2:	ba 00 01 00 00       	mov    edx,0x100
  40d4a7:	48 89 ee             	mov    rsi,rbp
  40d4aa:	e8 51 3d ff ff       	call   401200 <read@plt>
  40d4af:	85 c0                	test   eax,eax
  40d4b1:	7f 2a                	jg     40d4dd <win+0xbf67>
  40d4b3:	e8 c8 3c ff ff       	call   401180 <__errno_location@plt>
  40d4b8:	8b 38                	mov    edi,DWORD PTR [rax]
  40d4ba:	e8 c1 3d ff ff       	call   401280 <strerror@plt>
  40d4bf:	bf 01 00 00 00       	mov    edi,0x1
  40d4c4:	48 8d 35 de 4b 00 00 	lea    rsi,[rip+0x4bde]        # 4120a9 <_IO_stdin_used+0xa9>
  40d4cb:	48 89 c2             	mov    rdx,rax
  40d4ce:	31 c0                	xor    eax,eax
  40d4d0:	e8 5b 3d ff ff       	call   401230 <__printf_chk@plt>
  40d4d5:	83 cf ff             	or     edi,0xffffffff
  40d4d8:	e8 83 3d ff ff       	call   401260 <exit@plt>
  40d4dd:	48 63 d0             	movsxd rdx,eax
  40d4e0:	48 89 ee             	mov    rsi,rbp
  40d4e3:	bf 01 00 00 00       	mov    edi,0x1
  40d4e8:	e8 b3 3c ff ff       	call   4011a0 <write@plt>
  40d4ed:	48 8d 3d 60 4c 00 00 	lea    rdi,[rip+0x4c60]        # 412154 <_IO_stdin_used+0x154>
  40d4f4:	e8 97 3c ff ff       	call   401190 <puts@plt>
  40d4f9:	48 8d 3d 04 4b 00 00 	lea    rdi,[rip+0x4b04]        # 412004 <_IO_stdin_used+0x4>
  40d500:	31 f6                	xor    esi,esi
  40d502:	31 c0                	xor    eax,eax
  40d504:	e8 47 3d ff ff       	call   401250 <open@plt>
  40d509:	89 c7                	mov    edi,eax
  40d50b:	85 c0                	test   eax,eax
  40d50d:	79 34                	jns    40d543 <win+0xbfcd>
  40d50f:	e8 6c 3c ff ff       	call   401180 <__errno_location@plt>
  40d514:	8b 38                	mov    edi,DWORD PTR [rax]
  40d516:	e8 65 3d ff ff       	call   401280 <strerror@plt>
  40d51b:	48 8d 35 e8 4a 00 00 	lea    rsi,[rip+0x4ae8]        # 41200a <_IO_stdin_used+0xa>
  40d522:	bf 01 00 00 00       	mov    edi,0x1
  40d527:	48 89 c2             	mov    rdx,rax
  40d52a:	31 c0                	xor    eax,eax
  40d52c:	e8 ff 3c ff ff       	call   401230 <__printf_chk@plt>
  40d531:	e8 aa 3c ff ff       	call   4011e0 <geteuid@plt>
  40d536:	85 c0                	test   eax,eax
  40d538:	0f 84 9b 40 ff ff    	je     4015d9 <win+0x63>
  40d53e:	e9 7e 40 ff ff       	jmp    4015c1 <win+0x4b>
  40d543:	ba 00 01 00 00       	mov    edx,0x100
  40d548:	48 89 ee             	mov    rsi,rbp
  40d54b:	e8 b0 3c ff ff       	call   401200 <read@plt>
  40d550:	85 c0                	test   eax,eax
  40d552:	7f 2a                	jg     40d57e <win+0xc008>
  40d554:	e8 27 3c ff ff       	call   401180 <__errno_location@plt>
  40d559:	8b 38                	mov    edi,DWORD PTR [rax]
  40d55b:	e8 20 3d ff ff       	call   401280 <strerror@plt>
  40d560:	bf 01 00 00 00       	mov    edi,0x1
  40d565:	48 8d 35 3d 4b 00 00 	lea    rsi,[rip+0x4b3d]        # 4120a9 <_IO_stdin_used+0xa9>
  40d56c:	48 89 c2             	mov    rdx,rax
  40d56f:	31 c0                	xor    eax,eax
  40d571:	e8 ba 3c ff ff       	call   401230 <__printf_chk@plt>
  40d576:	83 cf ff             	or     edi,0xffffffff
  40d579:	e8 e2 3c ff ff       	call   401260 <exit@plt>
  40d57e:	48 63 d0             	movsxd rdx,eax
  40d581:	48 89 ee             	mov    rsi,rbp
  40d584:	bf 01 00 00 00       	mov    edi,0x1
  40d589:	e8 12 3c ff ff       	call   4011a0 <write@plt>
  40d58e:	48 8d 3d bf 4b 00 00 	lea    rdi,[rip+0x4bbf]        # 412154 <_IO_stdin_used+0x154>
  40d595:	e8 f6 3b ff ff       	call   401190 <puts@plt>
  40d59a:	48 8d 3d 63 4a 00 00 	lea    rdi,[rip+0x4a63]        # 412004 <_IO_stdin_used+0x4>
  40d5a1:	31 f6                	xor    esi,esi
  40d5a3:	31 c0                	xor    eax,eax
  40d5a5:	e8 a6 3c ff ff       	call   401250 <open@plt>
  40d5aa:	89 c7                	mov    edi,eax
  40d5ac:	85 c0                	test   eax,eax
  40d5ae:	79 34                	jns    40d5e4 <win+0xc06e>
  40d5b0:	e8 cb 3b ff ff       	call   401180 <__errno_location@plt>
  40d5b5:	8b 38                	mov    edi,DWORD PTR [rax]
  40d5b7:	e8 c4 3c ff ff       	call   401280 <strerror@plt>
  40d5bc:	48 8d 35 47 4a 00 00 	lea    rsi,[rip+0x4a47]        # 41200a <_IO_stdin_used+0xa>
  40d5c3:	bf 01 00 00 00       	mov    edi,0x1
  40d5c8:	48 89 c2             	mov    rdx,rax
  40d5cb:	31 c0                	xor    eax,eax
  40d5cd:	e8 5e 3c ff ff       	call   401230 <__printf_chk@plt>
  40d5d2:	e8 09 3c ff ff       	call   4011e0 <geteuid@plt>
  40d5d7:	85 c0                	test   eax,eax
  40d5d9:	0f 84 fa 3f ff ff    	je     4015d9 <win+0x63>
  40d5df:	e9 dd 3f ff ff       	jmp    4015c1 <win+0x4b>
  40d5e4:	ba 00 01 00 00       	mov    edx,0x100
  40d5e9:	48 89 ee             	mov    rsi,rbp
  40d5ec:	e8 0f 3c ff ff       	call   401200 <read@plt>
  40d5f1:	85 c0                	test   eax,eax
  40d5f3:	7f 2a                	jg     40d61f <win+0xc0a9>
  40d5f5:	e8 86 3b ff ff       	call   401180 <__errno_location@plt>
  40d5fa:	8b 38                	mov    edi,DWORD PTR [rax]
  40d5fc:	e8 7f 3c ff ff       	call   401280 <strerror@plt>
  40d601:	bf 01 00 00 00       	mov    edi,0x1
  40d606:	48 8d 35 9c 4a 00 00 	lea    rsi,[rip+0x4a9c]        # 4120a9 <_IO_stdin_used+0xa9>
  40d60d:	48 89 c2             	mov    rdx,rax
  40d610:	31 c0                	xor    eax,eax
  40d612:	e8 19 3c ff ff       	call   401230 <__printf_chk@plt>
  40d617:	83 cf ff             	or     edi,0xffffffff
  40d61a:	e8 41 3c ff ff       	call   401260 <exit@plt>
  40d61f:	48 63 d0             	movsxd rdx,eax
  40d622:	48 89 ee             	mov    rsi,rbp
  40d625:	bf 01 00 00 00       	mov    edi,0x1
  40d62a:	e8 71 3b ff ff       	call   4011a0 <write@plt>
  40d62f:	48 8d 3d 1e 4b 00 00 	lea    rdi,[rip+0x4b1e]        # 412154 <_IO_stdin_used+0x154>
  40d636:	e8 55 3b ff ff       	call   401190 <puts@plt>
  40d63b:	48 8d 3d c2 49 00 00 	lea    rdi,[rip+0x49c2]        # 412004 <_IO_stdin_used+0x4>
  40d642:	31 f6                	xor    esi,esi
  40d644:	31 c0                	xor    eax,eax
  40d646:	e8 05 3c ff ff       	call   401250 <open@plt>
  40d64b:	89 c7                	mov    edi,eax
  40d64d:	85 c0                	test   eax,eax
  40d64f:	79 34                	jns    40d685 <win+0xc10f>
  40d651:	e8 2a 3b ff ff       	call   401180 <__errno_location@plt>
  40d656:	8b 38                	mov    edi,DWORD PTR [rax]
  40d658:	e8 23 3c ff ff       	call   401280 <strerror@plt>
  40d65d:	48 8d 35 a6 49 00 00 	lea    rsi,[rip+0x49a6]        # 41200a <_IO_stdin_used+0xa>
  40d664:	bf 01 00 00 00       	mov    edi,0x1
  40d669:	48 89 c2             	mov    rdx,rax
  40d66c:	31 c0                	xor    eax,eax
  40d66e:	e8 bd 3b ff ff       	call   401230 <__printf_chk@plt>
  40d673:	e8 68 3b ff ff       	call   4011e0 <geteuid@plt>
  40d678:	85 c0                	test   eax,eax
  40d67a:	0f 84 59 3f ff ff    	je     4015d9 <win+0x63>
  40d680:	e9 3c 3f ff ff       	jmp    4015c1 <win+0x4b>
  40d685:	ba 00 01 00 00       	mov    edx,0x100
  40d68a:	48 89 ee             	mov    rsi,rbp
  40d68d:	e8 6e 3b ff ff       	call   401200 <read@plt>
  40d692:	85 c0                	test   eax,eax
  40d694:	7f 2a                	jg     40d6c0 <win+0xc14a>
  40d696:	e8 e5 3a ff ff       	call   401180 <__errno_location@plt>
  40d69b:	8b 38                	mov    edi,DWORD PTR [rax]
  40d69d:	e8 de 3b ff ff       	call   401280 <strerror@plt>
  40d6a2:	bf 01 00 00 00       	mov    edi,0x1
  40d6a7:	48 8d 35 fb 49 00 00 	lea    rsi,[rip+0x49fb]        # 4120a9 <_IO_stdin_used+0xa9>
  40d6ae:	48 89 c2             	mov    rdx,rax
  40d6b1:	31 c0                	xor    eax,eax
  40d6b3:	e8 78 3b ff ff       	call   401230 <__printf_chk@plt>
  40d6b8:	83 cf ff             	or     edi,0xffffffff
  40d6bb:	e8 a0 3b ff ff       	call   401260 <exit@plt>
  40d6c0:	48 63 d0             	movsxd rdx,eax
  40d6c3:	48 89 ee             	mov    rsi,rbp
  40d6c6:	bf 01 00 00 00       	mov    edi,0x1
  40d6cb:	e8 d0 3a ff ff       	call   4011a0 <write@plt>
  40d6d0:	48 8d 3d 7d 4a 00 00 	lea    rdi,[rip+0x4a7d]        # 412154 <_IO_stdin_used+0x154>
  40d6d7:	e8 b4 3a ff ff       	call   401190 <puts@plt>
  40d6dc:	48 8d 3d 21 49 00 00 	lea    rdi,[rip+0x4921]        # 412004 <_IO_stdin_used+0x4>
  40d6e3:	31 f6                	xor    esi,esi
  40d6e5:	31 c0                	xor    eax,eax
  40d6e7:	e8 64 3b ff ff       	call   401250 <open@plt>
  40d6ec:	89 c7                	mov    edi,eax
  40d6ee:	85 c0                	test   eax,eax
  40d6f0:	79 34                	jns    40d726 <win+0xc1b0>
  40d6f2:	e8 89 3a ff ff       	call   401180 <__errno_location@plt>
  40d6f7:	8b 38                	mov    edi,DWORD PTR [rax]
  40d6f9:	e8 82 3b ff ff       	call   401280 <strerror@plt>
  40d6fe:	48 8d 35 05 49 00 00 	lea    rsi,[rip+0x4905]        # 41200a <_IO_stdin_used+0xa>
  40d705:	bf 01 00 00 00       	mov    edi,0x1
  40d70a:	48 89 c2             	mov    rdx,rax
  40d70d:	31 c0                	xor    eax,eax
  40d70f:	e8 1c 3b ff ff       	call   401230 <__printf_chk@plt>
  40d714:	e8 c7 3a ff ff       	call   4011e0 <geteuid@plt>
  40d719:	85 c0                	test   eax,eax
  40d71b:	0f 84 b8 3e ff ff    	je     4015d9 <win+0x63>
  40d721:	e9 9b 3e ff ff       	jmp    4015c1 <win+0x4b>
  40d726:	ba 00 01 00 00       	mov    edx,0x100
  40d72b:	48 89 ee             	mov    rsi,rbp
  40d72e:	e8 cd 3a ff ff       	call   401200 <read@plt>
  40d733:	85 c0                	test   eax,eax
  40d735:	7f 2a                	jg     40d761 <win+0xc1eb>
  40d737:	e8 44 3a ff ff       	call   401180 <__errno_location@plt>
  40d73c:	8b 38                	mov    edi,DWORD PTR [rax]
  40d73e:	e8 3d 3b ff ff       	call   401280 <strerror@plt>
  40d743:	bf 01 00 00 00       	mov    edi,0x1
  40d748:	48 8d 35 5a 49 00 00 	lea    rsi,[rip+0x495a]        # 4120a9 <_IO_stdin_used+0xa9>
  40d74f:	48 89 c2             	mov    rdx,rax
  40d752:	31 c0                	xor    eax,eax
  40d754:	e8 d7 3a ff ff       	call   401230 <__printf_chk@plt>
  40d759:	83 cf ff             	or     edi,0xffffffff
  40d75c:	e8 ff 3a ff ff       	call   401260 <exit@plt>
  40d761:	48 63 d0             	movsxd rdx,eax
  40d764:	48 89 ee             	mov    rsi,rbp
  40d767:	bf 01 00 00 00       	mov    edi,0x1
  40d76c:	e8 2f 3a ff ff       	call   4011a0 <write@plt>
  40d771:	48 8d 3d dc 49 00 00 	lea    rdi,[rip+0x49dc]        # 412154 <_IO_stdin_used+0x154>
  40d778:	e8 13 3a ff ff       	call   401190 <puts@plt>
  40d77d:	48 8d 3d 80 48 00 00 	lea    rdi,[rip+0x4880]        # 412004 <_IO_stdin_used+0x4>
  40d784:	31 f6                	xor    esi,esi
  40d786:	31 c0                	xor    eax,eax
  40d788:	e8 c3 3a ff ff       	call   401250 <open@plt>
  40d78d:	89 c7                	mov    edi,eax
  40d78f:	85 c0                	test   eax,eax
  40d791:	79 34                	jns    40d7c7 <win+0xc251>
  40d793:	e8 e8 39 ff ff       	call   401180 <__errno_location@plt>
  40d798:	8b 38                	mov    edi,DWORD PTR [rax]
  40d79a:	e8 e1 3a ff ff       	call   401280 <strerror@plt>
  40d79f:	48 8d 35 64 48 00 00 	lea    rsi,[rip+0x4864]        # 41200a <_IO_stdin_used+0xa>
  40d7a6:	bf 01 00 00 00       	mov    edi,0x1
  40d7ab:	48 89 c2             	mov    rdx,rax
  40d7ae:	31 c0                	xor    eax,eax
  40d7b0:	e8 7b 3a ff ff       	call   401230 <__printf_chk@plt>
  40d7b5:	e8 26 3a ff ff       	call   4011e0 <geteuid@plt>
  40d7ba:	85 c0                	test   eax,eax
  40d7bc:	0f 84 17 3e ff ff    	je     4015d9 <win+0x63>
  40d7c2:	e9 fa 3d ff ff       	jmp    4015c1 <win+0x4b>
  40d7c7:	ba 00 01 00 00       	mov    edx,0x100
  40d7cc:	48 89 ee             	mov    rsi,rbp
  40d7cf:	e8 2c 3a ff ff       	call   401200 <read@plt>
  40d7d4:	85 c0                	test   eax,eax
  40d7d6:	7f 2a                	jg     40d802 <win+0xc28c>
  40d7d8:	e8 a3 39 ff ff       	call   401180 <__errno_location@plt>
  40d7dd:	8b 38                	mov    edi,DWORD PTR [rax]
  40d7df:	e8 9c 3a ff ff       	call   401280 <strerror@plt>
  40d7e4:	bf 01 00 00 00       	mov    edi,0x1
  40d7e9:	48 8d 35 b9 48 00 00 	lea    rsi,[rip+0x48b9]        # 4120a9 <_IO_stdin_used+0xa9>
  40d7f0:	48 89 c2             	mov    rdx,rax
  40d7f3:	31 c0                	xor    eax,eax
  40d7f5:	e8 36 3a ff ff       	call   401230 <__printf_chk@plt>
  40d7fa:	83 cf ff             	or     edi,0xffffffff
  40d7fd:	e8 5e 3a ff ff       	call   401260 <exit@plt>
  40d802:	48 63 d0             	movsxd rdx,eax
  40d805:	48 89 ee             	mov    rsi,rbp
  40d808:	bf 01 00 00 00       	mov    edi,0x1
  40d80d:	e8 8e 39 ff ff       	call   4011a0 <write@plt>
  40d812:	48 8d 3d 3b 49 00 00 	lea    rdi,[rip+0x493b]        # 412154 <_IO_stdin_used+0x154>
  40d819:	e8 72 39 ff ff       	call   401190 <puts@plt>
  40d81e:	48 8d 3d df 47 00 00 	lea    rdi,[rip+0x47df]        # 412004 <_IO_stdin_used+0x4>
  40d825:	31 f6                	xor    esi,esi
  40d827:	31 c0                	xor    eax,eax
  40d829:	e8 22 3a ff ff       	call   401250 <open@plt>
  40d82e:	89 c7                	mov    edi,eax
  40d830:	85 c0                	test   eax,eax
  40d832:	79 34                	jns    40d868 <win+0xc2f2>
  40d834:	e8 47 39 ff ff       	call   401180 <__errno_location@plt>
  40d839:	8b 38                	mov    edi,DWORD PTR [rax]
  40d83b:	e8 40 3a ff ff       	call   401280 <strerror@plt>
  40d840:	48 8d 35 c3 47 00 00 	lea    rsi,[rip+0x47c3]        # 41200a <_IO_stdin_used+0xa>
  40d847:	bf 01 00 00 00       	mov    edi,0x1
  40d84c:	48 89 c2             	mov    rdx,rax
  40d84f:	31 c0                	xor    eax,eax
  40d851:	e8 da 39 ff ff       	call   401230 <__printf_chk@plt>
  40d856:	e8 85 39 ff ff       	call   4011e0 <geteuid@plt>
  40d85b:	85 c0                	test   eax,eax
  40d85d:	0f 84 76 3d ff ff    	je     4015d9 <win+0x63>
  40d863:	e9 59 3d ff ff       	jmp    4015c1 <win+0x4b>
  40d868:	ba 00 01 00 00       	mov    edx,0x100
  40d86d:	48 89 ee             	mov    rsi,rbp
  40d870:	e8 8b 39 ff ff       	call   401200 <read@plt>
  40d875:	85 c0                	test   eax,eax
  40d877:	7f 2a                	jg     40d8a3 <win+0xc32d>
  40d879:	e8 02 39 ff ff       	call   401180 <__errno_location@plt>
  40d87e:	8b 38                	mov    edi,DWORD PTR [rax]
  40d880:	e8 fb 39 ff ff       	call   401280 <strerror@plt>
  40d885:	bf 01 00 00 00       	mov    edi,0x1
  40d88a:	48 8d 35 18 48 00 00 	lea    rsi,[rip+0x4818]        # 4120a9 <_IO_stdin_used+0xa9>
  40d891:	48 89 c2             	mov    rdx,rax
  40d894:	31 c0                	xor    eax,eax
  40d896:	e8 95 39 ff ff       	call   401230 <__printf_chk@plt>
  40d89b:	83 cf ff             	or     edi,0xffffffff
  40d89e:	e8 bd 39 ff ff       	call   401260 <exit@plt>
  40d8a3:	48 63 d0             	movsxd rdx,eax
  40d8a6:	48 89 ee             	mov    rsi,rbp
  40d8a9:	bf 01 00 00 00       	mov    edi,0x1
  40d8ae:	e8 ed 38 ff ff       	call   4011a0 <write@plt>
  40d8b3:	48 8d 3d 9a 48 00 00 	lea    rdi,[rip+0x489a]        # 412154 <_IO_stdin_used+0x154>
  40d8ba:	e8 d1 38 ff ff       	call   401190 <puts@plt>
  40d8bf:	48 8d 3d 3e 47 00 00 	lea    rdi,[rip+0x473e]        # 412004 <_IO_stdin_used+0x4>
  40d8c6:	31 f6                	xor    esi,esi
  40d8c8:	31 c0                	xor    eax,eax
  40d8ca:	e8 81 39 ff ff       	call   401250 <open@plt>
  40d8cf:	89 c7                	mov    edi,eax
  40d8d1:	85 c0                	test   eax,eax
  40d8d3:	79 34                	jns    40d909 <win+0xc393>
  40d8d5:	e8 a6 38 ff ff       	call   401180 <__errno_location@plt>
  40d8da:	8b 38                	mov    edi,DWORD PTR [rax]
  40d8dc:	e8 9f 39 ff ff       	call   401280 <strerror@plt>
  40d8e1:	48 8d 35 22 47 00 00 	lea    rsi,[rip+0x4722]        # 41200a <_IO_stdin_used+0xa>
  40d8e8:	bf 01 00 00 00       	mov    edi,0x1
  40d8ed:	48 89 c2             	mov    rdx,rax
  40d8f0:	31 c0                	xor    eax,eax
  40d8f2:	e8 39 39 ff ff       	call   401230 <__printf_chk@plt>
  40d8f7:	e8 e4 38 ff ff       	call   4011e0 <geteuid@plt>
  40d8fc:	85 c0                	test   eax,eax
  40d8fe:	0f 84 d5 3c ff ff    	je     4015d9 <win+0x63>
  40d904:	e9 b8 3c ff ff       	jmp    4015c1 <win+0x4b>
  40d909:	ba 00 01 00 00       	mov    edx,0x100
  40d90e:	48 89 ee             	mov    rsi,rbp
  40d911:	e8 ea 38 ff ff       	call   401200 <read@plt>
  40d916:	85 c0                	test   eax,eax
  40d918:	7f 2a                	jg     40d944 <win+0xc3ce>
  40d91a:	e8 61 38 ff ff       	call   401180 <__errno_location@plt>
  40d91f:	8b 38                	mov    edi,DWORD PTR [rax]
  40d921:	e8 5a 39 ff ff       	call   401280 <strerror@plt>
  40d926:	bf 01 00 00 00       	mov    edi,0x1
  40d92b:	48 8d 35 77 47 00 00 	lea    rsi,[rip+0x4777]        # 4120a9 <_IO_stdin_used+0xa9>
  40d932:	48 89 c2             	mov    rdx,rax
  40d935:	31 c0                	xor    eax,eax
  40d937:	e8 f4 38 ff ff       	call   401230 <__printf_chk@plt>
  40d93c:	83 cf ff             	or     edi,0xffffffff
  40d93f:	e8 1c 39 ff ff       	call   401260 <exit@plt>
  40d944:	48 63 d0             	movsxd rdx,eax
  40d947:	48 89 ee             	mov    rsi,rbp
  40d94a:	bf 01 00 00 00       	mov    edi,0x1
  40d94f:	e8 4c 38 ff ff       	call   4011a0 <write@plt>
  40d954:	48 8d 3d f9 47 00 00 	lea    rdi,[rip+0x47f9]        # 412154 <_IO_stdin_used+0x154>
  40d95b:	e8 30 38 ff ff       	call   401190 <puts@plt>
  40d960:	48 8d 3d 9d 46 00 00 	lea    rdi,[rip+0x469d]        # 412004 <_IO_stdin_used+0x4>
  40d967:	31 f6                	xor    esi,esi
  40d969:	31 c0                	xor    eax,eax
  40d96b:	e8 e0 38 ff ff       	call   401250 <open@plt>
  40d970:	89 c7                	mov    edi,eax
  40d972:	85 c0                	test   eax,eax
  40d974:	79 34                	jns    40d9aa <win+0xc434>
  40d976:	e8 05 38 ff ff       	call   401180 <__errno_location@plt>
  40d97b:	8b 38                	mov    edi,DWORD PTR [rax]
  40d97d:	e8 fe 38 ff ff       	call   401280 <strerror@plt>
  40d982:	48 8d 35 81 46 00 00 	lea    rsi,[rip+0x4681]        # 41200a <_IO_stdin_used+0xa>
  40d989:	bf 01 00 00 00       	mov    edi,0x1
  40d98e:	48 89 c2             	mov    rdx,rax
  40d991:	31 c0                	xor    eax,eax
  40d993:	e8 98 38 ff ff       	call   401230 <__printf_chk@plt>
  40d998:	e8 43 38 ff ff       	call   4011e0 <geteuid@plt>
  40d99d:	85 c0                	test   eax,eax
  40d99f:	0f 84 34 3c ff ff    	je     4015d9 <win+0x63>
  40d9a5:	e9 17 3c ff ff       	jmp    4015c1 <win+0x4b>
  40d9aa:	ba 00 01 00 00       	mov    edx,0x100
  40d9af:	48 89 ee             	mov    rsi,rbp
  40d9b2:	e8 49 38 ff ff       	call   401200 <read@plt>
  40d9b7:	85 c0                	test   eax,eax
  40d9b9:	7f 2a                	jg     40d9e5 <win+0xc46f>
  40d9bb:	e8 c0 37 ff ff       	call   401180 <__errno_location@plt>
  40d9c0:	8b 38                	mov    edi,DWORD PTR [rax]
  40d9c2:	e8 b9 38 ff ff       	call   401280 <strerror@plt>
  40d9c7:	bf 01 00 00 00       	mov    edi,0x1
  40d9cc:	48 8d 35 d6 46 00 00 	lea    rsi,[rip+0x46d6]        # 4120a9 <_IO_stdin_used+0xa9>
  40d9d3:	48 89 c2             	mov    rdx,rax
  40d9d6:	31 c0                	xor    eax,eax
  40d9d8:	e8 53 38 ff ff       	call   401230 <__printf_chk@plt>
  40d9dd:	83 cf ff             	or     edi,0xffffffff
  40d9e0:	e8 7b 38 ff ff       	call   401260 <exit@plt>
  40d9e5:	48 63 d0             	movsxd rdx,eax
  40d9e8:	48 89 ee             	mov    rsi,rbp
  40d9eb:	bf 01 00 00 00       	mov    edi,0x1
  40d9f0:	e8 ab 37 ff ff       	call   4011a0 <write@plt>
  40d9f5:	48 8d 3d 58 47 00 00 	lea    rdi,[rip+0x4758]        # 412154 <_IO_stdin_used+0x154>
  40d9fc:	e8 8f 37 ff ff       	call   401190 <puts@plt>
  40da01:	48 8d 3d fc 45 00 00 	lea    rdi,[rip+0x45fc]        # 412004 <_IO_stdin_used+0x4>
  40da08:	31 f6                	xor    esi,esi
  40da0a:	31 c0                	xor    eax,eax
  40da0c:	e8 3f 38 ff ff       	call   401250 <open@plt>
  40da11:	89 c7                	mov    edi,eax
  40da13:	85 c0                	test   eax,eax
  40da15:	79 34                	jns    40da4b <win+0xc4d5>
  40da17:	e8 64 37 ff ff       	call   401180 <__errno_location@plt>
  40da1c:	8b 38                	mov    edi,DWORD PTR [rax]
  40da1e:	e8 5d 38 ff ff       	call   401280 <strerror@plt>
  40da23:	48 8d 35 e0 45 00 00 	lea    rsi,[rip+0x45e0]        # 41200a <_IO_stdin_used+0xa>
  40da2a:	bf 01 00 00 00       	mov    edi,0x1
  40da2f:	48 89 c2             	mov    rdx,rax
  40da32:	31 c0                	xor    eax,eax
  40da34:	e8 f7 37 ff ff       	call   401230 <__printf_chk@plt>
  40da39:	e8 a2 37 ff ff       	call   4011e0 <geteuid@plt>
  40da3e:	85 c0                	test   eax,eax
  40da40:	0f 84 93 3b ff ff    	je     4015d9 <win+0x63>
  40da46:	e9 76 3b ff ff       	jmp    4015c1 <win+0x4b>
  40da4b:	ba 00 01 00 00       	mov    edx,0x100
  40da50:	48 89 ee             	mov    rsi,rbp
  40da53:	e8 a8 37 ff ff       	call   401200 <read@plt>
  40da58:	85 c0                	test   eax,eax
  40da5a:	7f 2a                	jg     40da86 <win+0xc510>
  40da5c:	e8 1f 37 ff ff       	call   401180 <__errno_location@plt>
  40da61:	8b 38                	mov    edi,DWORD PTR [rax]
  40da63:	e8 18 38 ff ff       	call   401280 <strerror@plt>
  40da68:	bf 01 00 00 00       	mov    edi,0x1
  40da6d:	48 8d 35 35 46 00 00 	lea    rsi,[rip+0x4635]        # 4120a9 <_IO_stdin_used+0xa9>
  40da74:	48 89 c2             	mov    rdx,rax
  40da77:	31 c0                	xor    eax,eax
  40da79:	e8 b2 37 ff ff       	call   401230 <__printf_chk@plt>
  40da7e:	83 cf ff             	or     edi,0xffffffff
  40da81:	e8 da 37 ff ff       	call   401260 <exit@plt>
  40da86:	48 63 d0             	movsxd rdx,eax
  40da89:	48 89 ee             	mov    rsi,rbp
  40da8c:	bf 01 00 00 00       	mov    edi,0x1
  40da91:	e8 0a 37 ff ff       	call   4011a0 <write@plt>
  40da96:	48 8d 3d b7 46 00 00 	lea    rdi,[rip+0x46b7]        # 412154 <_IO_stdin_used+0x154>
  40da9d:	e8 ee 36 ff ff       	call   401190 <puts@plt>
  40daa2:	48 8d 3d 5b 45 00 00 	lea    rdi,[rip+0x455b]        # 412004 <_IO_stdin_used+0x4>
  40daa9:	31 f6                	xor    esi,esi
  40daab:	31 c0                	xor    eax,eax
  40daad:	e8 9e 37 ff ff       	call   401250 <open@plt>
  40dab2:	89 c7                	mov    edi,eax
  40dab4:	85 c0                	test   eax,eax
  40dab6:	79 34                	jns    40daec <win+0xc576>
  40dab8:	e8 c3 36 ff ff       	call   401180 <__errno_location@plt>
  40dabd:	8b 38                	mov    edi,DWORD PTR [rax]
  40dabf:	e8 bc 37 ff ff       	call   401280 <strerror@plt>
  40dac4:	48 8d 35 3f 45 00 00 	lea    rsi,[rip+0x453f]        # 41200a <_IO_stdin_used+0xa>
  40dacb:	bf 01 00 00 00       	mov    edi,0x1
  40dad0:	48 89 c2             	mov    rdx,rax
  40dad3:	31 c0                	xor    eax,eax
  40dad5:	e8 56 37 ff ff       	call   401230 <__printf_chk@plt>
  40dada:	e8 01 37 ff ff       	call   4011e0 <geteuid@plt>
  40dadf:	85 c0                	test   eax,eax
  40dae1:	0f 84 f2 3a ff ff    	je     4015d9 <win+0x63>
  40dae7:	e9 d5 3a ff ff       	jmp    4015c1 <win+0x4b>
  40daec:	ba 00 01 00 00       	mov    edx,0x100
  40daf1:	48 89 ee             	mov    rsi,rbp
  40daf4:	e8 07 37 ff ff       	call   401200 <read@plt>
  40daf9:	85 c0                	test   eax,eax
  40dafb:	7f 2a                	jg     40db27 <win+0xc5b1>
  40dafd:	e8 7e 36 ff ff       	call   401180 <__errno_location@plt>
  40db02:	8b 38                	mov    edi,DWORD PTR [rax]
  40db04:	e8 77 37 ff ff       	call   401280 <strerror@plt>
  40db09:	bf 01 00 00 00       	mov    edi,0x1
  40db0e:	48 8d 35 94 45 00 00 	lea    rsi,[rip+0x4594]        # 4120a9 <_IO_stdin_used+0xa9>
  40db15:	48 89 c2             	mov    rdx,rax
  40db18:	31 c0                	xor    eax,eax
  40db1a:	e8 11 37 ff ff       	call   401230 <__printf_chk@plt>
  40db1f:	83 cf ff             	or     edi,0xffffffff
  40db22:	e8 39 37 ff ff       	call   401260 <exit@plt>
  40db27:	48 63 d0             	movsxd rdx,eax
  40db2a:	48 89 ee             	mov    rsi,rbp
  40db2d:	bf 01 00 00 00       	mov    edi,0x1
  40db32:	e8 69 36 ff ff       	call   4011a0 <write@plt>
  40db37:	48 8d 3d 16 46 00 00 	lea    rdi,[rip+0x4616]        # 412154 <_IO_stdin_used+0x154>
  40db3e:	e8 4d 36 ff ff       	call   401190 <puts@plt>
  40db43:	48 8d 3d ba 44 00 00 	lea    rdi,[rip+0x44ba]        # 412004 <_IO_stdin_used+0x4>
  40db4a:	31 f6                	xor    esi,esi
  40db4c:	31 c0                	xor    eax,eax
  40db4e:	e8 fd 36 ff ff       	call   401250 <open@plt>
  40db53:	89 c7                	mov    edi,eax
  40db55:	85 c0                	test   eax,eax
  40db57:	79 34                	jns    40db8d <win+0xc617>
  40db59:	e8 22 36 ff ff       	call   401180 <__errno_location@plt>
  40db5e:	8b 38                	mov    edi,DWORD PTR [rax]
  40db60:	e8 1b 37 ff ff       	call   401280 <strerror@plt>
  40db65:	48 8d 35 9e 44 00 00 	lea    rsi,[rip+0x449e]        # 41200a <_IO_stdin_used+0xa>
  40db6c:	bf 01 00 00 00       	mov    edi,0x1
  40db71:	48 89 c2             	mov    rdx,rax
  40db74:	31 c0                	xor    eax,eax
  40db76:	e8 b5 36 ff ff       	call   401230 <__printf_chk@plt>
  40db7b:	e8 60 36 ff ff       	call   4011e0 <geteuid@plt>
  40db80:	85 c0                	test   eax,eax
  40db82:	0f 84 51 3a ff ff    	je     4015d9 <win+0x63>
  40db88:	e9 34 3a ff ff       	jmp    4015c1 <win+0x4b>
  40db8d:	ba 00 01 00 00       	mov    edx,0x100
  40db92:	48 89 ee             	mov    rsi,rbp
  40db95:	e8 66 36 ff ff       	call   401200 <read@plt>
  40db9a:	85 c0                	test   eax,eax
  40db9c:	7f 2a                	jg     40dbc8 <win+0xc652>
  40db9e:	e8 dd 35 ff ff       	call   401180 <__errno_location@plt>
  40dba3:	8b 38                	mov    edi,DWORD PTR [rax]
  40dba5:	e8 d6 36 ff ff       	call   401280 <strerror@plt>
  40dbaa:	bf 01 00 00 00       	mov    edi,0x1
  40dbaf:	48 8d 35 f3 44 00 00 	lea    rsi,[rip+0x44f3]        # 4120a9 <_IO_stdin_used+0xa9>
  40dbb6:	48 89 c2             	mov    rdx,rax
  40dbb9:	31 c0                	xor    eax,eax
  40dbbb:	e8 70 36 ff ff       	call   401230 <__printf_chk@plt>
  40dbc0:	83 cf ff             	or     edi,0xffffffff
  40dbc3:	e8 98 36 ff ff       	call   401260 <exit@plt>
  40dbc8:	48 63 d0             	movsxd rdx,eax
  40dbcb:	48 89 ee             	mov    rsi,rbp
  40dbce:	bf 01 00 00 00       	mov    edi,0x1
  40dbd3:	e8 c8 35 ff ff       	call   4011a0 <write@plt>
  40dbd8:	48 8d 3d 75 45 00 00 	lea    rdi,[rip+0x4575]        # 412154 <_IO_stdin_used+0x154>
  40dbdf:	e8 ac 35 ff ff       	call   401190 <puts@plt>
  40dbe4:	48 8d 3d 19 44 00 00 	lea    rdi,[rip+0x4419]        # 412004 <_IO_stdin_used+0x4>
  40dbeb:	31 f6                	xor    esi,esi
  40dbed:	31 c0                	xor    eax,eax
  40dbef:	e8 5c 36 ff ff       	call   401250 <open@plt>
  40dbf4:	89 c7                	mov    edi,eax
  40dbf6:	85 c0                	test   eax,eax
  40dbf8:	79 34                	jns    40dc2e <win+0xc6b8>
  40dbfa:	e8 81 35 ff ff       	call   401180 <__errno_location@plt>
  40dbff:	8b 38                	mov    edi,DWORD PTR [rax]
  40dc01:	e8 7a 36 ff ff       	call   401280 <strerror@plt>
  40dc06:	48 8d 35 fd 43 00 00 	lea    rsi,[rip+0x43fd]        # 41200a <_IO_stdin_used+0xa>
  40dc0d:	bf 01 00 00 00       	mov    edi,0x1
  40dc12:	48 89 c2             	mov    rdx,rax
  40dc15:	31 c0                	xor    eax,eax
  40dc17:	e8 14 36 ff ff       	call   401230 <__printf_chk@plt>
  40dc1c:	e8 bf 35 ff ff       	call   4011e0 <geteuid@plt>
  40dc21:	85 c0                	test   eax,eax
  40dc23:	0f 84 b0 39 ff ff    	je     4015d9 <win+0x63>
  40dc29:	e9 93 39 ff ff       	jmp    4015c1 <win+0x4b>
  40dc2e:	ba 00 01 00 00       	mov    edx,0x100
  40dc33:	48 89 ee             	mov    rsi,rbp
  40dc36:	e8 c5 35 ff ff       	call   401200 <read@plt>
  40dc3b:	85 c0                	test   eax,eax
  40dc3d:	7f 2a                	jg     40dc69 <win+0xc6f3>
  40dc3f:	e8 3c 35 ff ff       	call   401180 <__errno_location@plt>
  40dc44:	8b 38                	mov    edi,DWORD PTR [rax]
  40dc46:	e8 35 36 ff ff       	call   401280 <strerror@plt>
  40dc4b:	bf 01 00 00 00       	mov    edi,0x1
  40dc50:	48 8d 35 52 44 00 00 	lea    rsi,[rip+0x4452]        # 4120a9 <_IO_stdin_used+0xa9>
  40dc57:	48 89 c2             	mov    rdx,rax
  40dc5a:	31 c0                	xor    eax,eax
  40dc5c:	e8 cf 35 ff ff       	call   401230 <__printf_chk@plt>
  40dc61:	83 cf ff             	or     edi,0xffffffff
  40dc64:	e8 f7 35 ff ff       	call   401260 <exit@plt>
  40dc69:	48 63 d0             	movsxd rdx,eax
  40dc6c:	48 89 ee             	mov    rsi,rbp
  40dc6f:	bf 01 00 00 00       	mov    edi,0x1
  40dc74:	e8 27 35 ff ff       	call   4011a0 <write@plt>
  40dc79:	48 8d 3d d4 44 00 00 	lea    rdi,[rip+0x44d4]        # 412154 <_IO_stdin_used+0x154>
  40dc80:	e8 0b 35 ff ff       	call   401190 <puts@plt>
  40dc85:	48 8d 3d 78 43 00 00 	lea    rdi,[rip+0x4378]        # 412004 <_IO_stdin_used+0x4>
  40dc8c:	31 f6                	xor    esi,esi
  40dc8e:	31 c0                	xor    eax,eax
  40dc90:	e8 bb 35 ff ff       	call   401250 <open@plt>
  40dc95:	89 c7                	mov    edi,eax
  40dc97:	85 c0                	test   eax,eax
  40dc99:	79 34                	jns    40dccf <win+0xc759>
  40dc9b:	e8 e0 34 ff ff       	call   401180 <__errno_location@plt>
  40dca0:	8b 38                	mov    edi,DWORD PTR [rax]
  40dca2:	e8 d9 35 ff ff       	call   401280 <strerror@plt>
  40dca7:	48 8d 35 5c 43 00 00 	lea    rsi,[rip+0x435c]        # 41200a <_IO_stdin_used+0xa>
  40dcae:	bf 01 00 00 00       	mov    edi,0x1
  40dcb3:	48 89 c2             	mov    rdx,rax
  40dcb6:	31 c0                	xor    eax,eax
  40dcb8:	e8 73 35 ff ff       	call   401230 <__printf_chk@plt>
  40dcbd:	e8 1e 35 ff ff       	call   4011e0 <geteuid@plt>
  40dcc2:	85 c0                	test   eax,eax
  40dcc4:	0f 84 0f 39 ff ff    	je     4015d9 <win+0x63>
  40dcca:	e9 f2 38 ff ff       	jmp    4015c1 <win+0x4b>
  40dccf:	ba 00 01 00 00       	mov    edx,0x100
  40dcd4:	48 89 ee             	mov    rsi,rbp
  40dcd7:	e8 24 35 ff ff       	call   401200 <read@plt>
  40dcdc:	85 c0                	test   eax,eax
  40dcde:	7f 2a                	jg     40dd0a <win+0xc794>
  40dce0:	e8 9b 34 ff ff       	call   401180 <__errno_location@plt>
  40dce5:	8b 38                	mov    edi,DWORD PTR [rax]
  40dce7:	e8 94 35 ff ff       	call   401280 <strerror@plt>
  40dcec:	bf 01 00 00 00       	mov    edi,0x1
  40dcf1:	48 8d 35 b1 43 00 00 	lea    rsi,[rip+0x43b1]        # 4120a9 <_IO_stdin_used+0xa9>
  40dcf8:	48 89 c2             	mov    rdx,rax
  40dcfb:	31 c0                	xor    eax,eax
  40dcfd:	e8 2e 35 ff ff       	call   401230 <__printf_chk@plt>
  40dd02:	83 cf ff             	or     edi,0xffffffff
  40dd05:	e8 56 35 ff ff       	call   401260 <exit@plt>
  40dd0a:	48 63 d0             	movsxd rdx,eax
  40dd0d:	48 89 ee             	mov    rsi,rbp
  40dd10:	bf 01 00 00 00       	mov    edi,0x1
  40dd15:	e8 86 34 ff ff       	call   4011a0 <write@plt>
  40dd1a:	48 8d 3d 33 44 00 00 	lea    rdi,[rip+0x4433]        # 412154 <_IO_stdin_used+0x154>
  40dd21:	e8 6a 34 ff ff       	call   401190 <puts@plt>
  40dd26:	48 8d 3d d7 42 00 00 	lea    rdi,[rip+0x42d7]        # 412004 <_IO_stdin_used+0x4>
  40dd2d:	31 f6                	xor    esi,esi
  40dd2f:	31 c0                	xor    eax,eax
  40dd31:	e8 1a 35 ff ff       	call   401250 <open@plt>
  40dd36:	89 c7                	mov    edi,eax
  40dd38:	85 c0                	test   eax,eax
  40dd3a:	79 34                	jns    40dd70 <win+0xc7fa>
  40dd3c:	e8 3f 34 ff ff       	call   401180 <__errno_location@plt>
  40dd41:	8b 38                	mov    edi,DWORD PTR [rax]
  40dd43:	e8 38 35 ff ff       	call   401280 <strerror@plt>
  40dd48:	48 8d 35 bb 42 00 00 	lea    rsi,[rip+0x42bb]        # 41200a <_IO_stdin_used+0xa>
  40dd4f:	bf 01 00 00 00       	mov    edi,0x1
  40dd54:	48 89 c2             	mov    rdx,rax
  40dd57:	31 c0                	xor    eax,eax
  40dd59:	e8 d2 34 ff ff       	call   401230 <__printf_chk@plt>
  40dd5e:	e8 7d 34 ff ff       	call   4011e0 <geteuid@plt>
  40dd63:	85 c0                	test   eax,eax
  40dd65:	0f 84 6e 38 ff ff    	je     4015d9 <win+0x63>
  40dd6b:	e9 51 38 ff ff       	jmp    4015c1 <win+0x4b>
  40dd70:	ba 00 01 00 00       	mov    edx,0x100
  40dd75:	48 89 ee             	mov    rsi,rbp
  40dd78:	e8 83 34 ff ff       	call   401200 <read@plt>
  40dd7d:	85 c0                	test   eax,eax
  40dd7f:	7f 2a                	jg     40ddab <win+0xc835>
  40dd81:	e8 fa 33 ff ff       	call   401180 <__errno_location@plt>
  40dd86:	8b 38                	mov    edi,DWORD PTR [rax]
  40dd88:	e8 f3 34 ff ff       	call   401280 <strerror@plt>
  40dd8d:	bf 01 00 00 00       	mov    edi,0x1
  40dd92:	48 8d 35 10 43 00 00 	lea    rsi,[rip+0x4310]        # 4120a9 <_IO_stdin_used+0xa9>
  40dd99:	48 89 c2             	mov    rdx,rax
  40dd9c:	31 c0                	xor    eax,eax
  40dd9e:	e8 8d 34 ff ff       	call   401230 <__printf_chk@plt>
  40dda3:	83 cf ff             	or     edi,0xffffffff
  40dda6:	e8 b5 34 ff ff       	call   401260 <exit@plt>
  40ddab:	48 63 d0             	movsxd rdx,eax
  40ddae:	48 89 ee             	mov    rsi,rbp
  40ddb1:	bf 01 00 00 00       	mov    edi,0x1
  40ddb6:	e8 e5 33 ff ff       	call   4011a0 <write@plt>
  40ddbb:	48 8d 3d 92 43 00 00 	lea    rdi,[rip+0x4392]        # 412154 <_IO_stdin_used+0x154>
  40ddc2:	e8 c9 33 ff ff       	call   401190 <puts@plt>
  40ddc7:	48 8d 3d 36 42 00 00 	lea    rdi,[rip+0x4236]        # 412004 <_IO_stdin_used+0x4>
  40ddce:	31 f6                	xor    esi,esi
  40ddd0:	31 c0                	xor    eax,eax
  40ddd2:	e8 79 34 ff ff       	call   401250 <open@plt>
  40ddd7:	89 c7                	mov    edi,eax
  40ddd9:	85 c0                	test   eax,eax
  40dddb:	79 34                	jns    40de11 <win+0xc89b>
  40dddd:	e8 9e 33 ff ff       	call   401180 <__errno_location@plt>
  40dde2:	8b 38                	mov    edi,DWORD PTR [rax]
  40dde4:	e8 97 34 ff ff       	call   401280 <strerror@plt>
  40dde9:	48 8d 35 1a 42 00 00 	lea    rsi,[rip+0x421a]        # 41200a <_IO_stdin_used+0xa>
  40ddf0:	bf 01 00 00 00       	mov    edi,0x1
  40ddf5:	48 89 c2             	mov    rdx,rax
  40ddf8:	31 c0                	xor    eax,eax
  40ddfa:	e8 31 34 ff ff       	call   401230 <__printf_chk@plt>
  40ddff:	e8 dc 33 ff ff       	call   4011e0 <geteuid@plt>
  40de04:	85 c0                	test   eax,eax
  40de06:	0f 84 cd 37 ff ff    	je     4015d9 <win+0x63>
  40de0c:	e9 b0 37 ff ff       	jmp    4015c1 <win+0x4b>
  40de11:	ba 00 01 00 00       	mov    edx,0x100
  40de16:	48 89 ee             	mov    rsi,rbp
  40de19:	e8 e2 33 ff ff       	call   401200 <read@plt>
  40de1e:	85 c0                	test   eax,eax
  40de20:	7f 2a                	jg     40de4c <win+0xc8d6>
  40de22:	e8 59 33 ff ff       	call   401180 <__errno_location@plt>
  40de27:	8b 38                	mov    edi,DWORD PTR [rax]
  40de29:	e8 52 34 ff ff       	call   401280 <strerror@plt>
  40de2e:	bf 01 00 00 00       	mov    edi,0x1
  40de33:	48 8d 35 6f 42 00 00 	lea    rsi,[rip+0x426f]        # 4120a9 <_IO_stdin_used+0xa9>
  40de3a:	48 89 c2             	mov    rdx,rax
  40de3d:	31 c0                	xor    eax,eax
  40de3f:	e8 ec 33 ff ff       	call   401230 <__printf_chk@plt>
  40de44:	83 cf ff             	or     edi,0xffffffff
  40de47:	e8 14 34 ff ff       	call   401260 <exit@plt>
  40de4c:	48 63 d0             	movsxd rdx,eax
  40de4f:	48 89 ee             	mov    rsi,rbp
  40de52:	bf 01 00 00 00       	mov    edi,0x1
  40de57:	e8 44 33 ff ff       	call   4011a0 <write@plt>
  40de5c:	48 8d 3d f1 42 00 00 	lea    rdi,[rip+0x42f1]        # 412154 <_IO_stdin_used+0x154>
  40de63:	e8 28 33 ff ff       	call   401190 <puts@plt>
  40de68:	48 8d 3d 95 41 00 00 	lea    rdi,[rip+0x4195]        # 412004 <_IO_stdin_used+0x4>
  40de6f:	31 f6                	xor    esi,esi
  40de71:	31 c0                	xor    eax,eax
  40de73:	e8 d8 33 ff ff       	call   401250 <open@plt>
  40de78:	89 c7                	mov    edi,eax
  40de7a:	85 c0                	test   eax,eax
  40de7c:	79 34                	jns    40deb2 <win+0xc93c>
  40de7e:	e8 fd 32 ff ff       	call   401180 <__errno_location@plt>
  40de83:	8b 38                	mov    edi,DWORD PTR [rax]
  40de85:	e8 f6 33 ff ff       	call   401280 <strerror@plt>
  40de8a:	48 8d 35 79 41 00 00 	lea    rsi,[rip+0x4179]        # 41200a <_IO_stdin_used+0xa>
  40de91:	bf 01 00 00 00       	mov    edi,0x1
  40de96:	48 89 c2             	mov    rdx,rax
  40de99:	31 c0                	xor    eax,eax
  40de9b:	e8 90 33 ff ff       	call   401230 <__printf_chk@plt>
  40dea0:	e8 3b 33 ff ff       	call   4011e0 <geteuid@plt>
  40dea5:	85 c0                	test   eax,eax
  40dea7:	0f 84 2c 37 ff ff    	je     4015d9 <win+0x63>
  40dead:	e9 0f 37 ff ff       	jmp    4015c1 <win+0x4b>
  40deb2:	ba 00 01 00 00       	mov    edx,0x100
  40deb7:	48 89 ee             	mov    rsi,rbp
  40deba:	e8 41 33 ff ff       	call   401200 <read@plt>
  40debf:	85 c0                	test   eax,eax
  40dec1:	7f 2a                	jg     40deed <win+0xc977>
  40dec3:	e8 b8 32 ff ff       	call   401180 <__errno_location@plt>
  40dec8:	8b 38                	mov    edi,DWORD PTR [rax]
  40deca:	e8 b1 33 ff ff       	call   401280 <strerror@plt>
  40decf:	bf 01 00 00 00       	mov    edi,0x1
  40ded4:	48 8d 35 ce 41 00 00 	lea    rsi,[rip+0x41ce]        # 4120a9 <_IO_stdin_used+0xa9>
  40dedb:	48 89 c2             	mov    rdx,rax
  40dede:	31 c0                	xor    eax,eax
  40dee0:	e8 4b 33 ff ff       	call   401230 <__printf_chk@plt>
  40dee5:	83 cf ff             	or     edi,0xffffffff
  40dee8:	e8 73 33 ff ff       	call   401260 <exit@plt>
  40deed:	48 89 e5             	mov    rbp,rsp
  40def0:	48 63 d0             	movsxd rdx,eax
  40def3:	bf 01 00 00 00       	mov    edi,0x1
  40def8:	48 89 ee             	mov    rsi,rbp
  40defb:	e8 a0 32 ff ff       	call   4011a0 <write@plt>
  40df00:	48 8d 3d 4d 42 00 00 	lea    rdi,[rip+0x424d]        # 412154 <_IO_stdin_used+0x154>
  40df07:	e8 84 32 ff ff       	call   401190 <puts@plt>
  40df0c:	48 8d 3d f1 40 00 00 	lea    rdi,[rip+0x40f1]        # 412004 <_IO_stdin_used+0x4>
  40df13:	31 f6                	xor    esi,esi
  40df15:	31 c0                	xor    eax,eax
  40df17:	e8 34 33 ff ff       	call   401250 <open@plt>
  40df1c:	89 c7                	mov    edi,eax
  40df1e:	85 c0                	test   eax,eax
  40df20:	79 34                	jns    40df56 <win+0xc9e0>
  40df22:	e8 59 32 ff ff       	call   401180 <__errno_location@plt>
  40df27:	8b 38                	mov    edi,DWORD PTR [rax]
  40df29:	e8 52 33 ff ff       	call   401280 <strerror@plt>
  40df2e:	48 8d 35 d5 40 00 00 	lea    rsi,[rip+0x40d5]        # 41200a <_IO_stdin_used+0xa>
  40df35:	bf 01 00 00 00       	mov    edi,0x1
  40df3a:	48 89 c2             	mov    rdx,rax
  40df3d:	31 c0                	xor    eax,eax
  40df3f:	e8 ec 32 ff ff       	call   401230 <__printf_chk@plt>
  40df44:	e8 97 32 ff ff       	call   4011e0 <geteuid@plt>
  40df49:	85 c0                	test   eax,eax
  40df4b:	0f 84 88 36 ff ff    	je     4015d9 <win+0x63>
  40df51:	e9 6b 36 ff ff       	jmp    4015c1 <win+0x4b>
  40df56:	ba 00 01 00 00       	mov    edx,0x100
  40df5b:	48 89 ee             	mov    rsi,rbp
  40df5e:	e8 9d 32 ff ff       	call   401200 <read@plt>
  40df63:	85 c0                	test   eax,eax
  40df65:	7f 2a                	jg     40df91 <win+0xca1b>
  40df67:	e8 14 32 ff ff       	call   401180 <__errno_location@plt>
  40df6c:	8b 38                	mov    edi,DWORD PTR [rax]
  40df6e:	e8 0d 33 ff ff       	call   401280 <strerror@plt>
  40df73:	bf 01 00 00 00       	mov    edi,0x1
  40df78:	48 8d 35 2a 41 00 00 	lea    rsi,[rip+0x412a]        # 4120a9 <_IO_stdin_used+0xa9>
  40df7f:	48 89 c2             	mov    rdx,rax
  40df82:	31 c0                	xor    eax,eax
  40df84:	e8 a7 32 ff ff       	call   401230 <__printf_chk@plt>
  40df89:	83 cf ff             	or     edi,0xffffffff
  40df8c:	e8 cf 32 ff ff       	call   401260 <exit@plt>
  40df91:	48 63 d0             	movsxd rdx,eax
  40df94:	48 89 ee             	mov    rsi,rbp
  40df97:	bf 01 00 00 00       	mov    edi,0x1
  40df9c:	e8 ff 31 ff ff       	call   4011a0 <write@plt>
  40dfa1:	48 8d 3d ac 41 00 00 	lea    rdi,[rip+0x41ac]        # 412154 <_IO_stdin_used+0x154>
  40dfa8:	e8 e3 31 ff ff       	call   401190 <puts@plt>
  40dfad:	48 8d 3d 50 40 00 00 	lea    rdi,[rip+0x4050]        # 412004 <_IO_stdin_used+0x4>
  40dfb4:	31 f6                	xor    esi,esi
  40dfb6:	31 c0                	xor    eax,eax
  40dfb8:	e8 93 32 ff ff       	call   401250 <open@plt>
  40dfbd:	89 c7                	mov    edi,eax
  40dfbf:	85 c0                	test   eax,eax
  40dfc1:	79 34                	jns    40dff7 <win+0xca81>
  40dfc3:	e8 b8 31 ff ff       	call   401180 <__errno_location@plt>
  40dfc8:	8b 38                	mov    edi,DWORD PTR [rax]
  40dfca:	e8 b1 32 ff ff       	call   401280 <strerror@plt>
  40dfcf:	48 8d 35 34 40 00 00 	lea    rsi,[rip+0x4034]        # 41200a <_IO_stdin_used+0xa>
  40dfd6:	bf 01 00 00 00       	mov    edi,0x1
  40dfdb:	48 89 c2             	mov    rdx,rax
  40dfde:	31 c0                	xor    eax,eax
  40dfe0:	e8 4b 32 ff ff       	call   401230 <__printf_chk@plt>
  40dfe5:	e8 f6 31 ff ff       	call   4011e0 <geteuid@plt>
  40dfea:	85 c0                	test   eax,eax
  40dfec:	0f 84 e7 35 ff ff    	je     4015d9 <win+0x63>
  40dff2:	e9 ca 35 ff ff       	jmp    4015c1 <win+0x4b>
  40dff7:	ba 00 01 00 00       	mov    edx,0x100
  40dffc:	48 89 ee             	mov    rsi,rbp
  40dfff:	e8 fc 31 ff ff       	call   401200 <read@plt>
  40e004:	85 c0                	test   eax,eax
  40e006:	7f 2a                	jg     40e032 <win+0xcabc>
  40e008:	e8 73 31 ff ff       	call   401180 <__errno_location@plt>
  40e00d:	8b 38                	mov    edi,DWORD PTR [rax]
  40e00f:	e8 6c 32 ff ff       	call   401280 <strerror@plt>
  40e014:	bf 01 00 00 00       	mov    edi,0x1
  40e019:	48 8d 35 89 40 00 00 	lea    rsi,[rip+0x4089]        # 4120a9 <_IO_stdin_used+0xa9>
  40e020:	48 89 c2             	mov    rdx,rax
  40e023:	31 c0                	xor    eax,eax
  40e025:	e8 06 32 ff ff       	call   401230 <__printf_chk@plt>
  40e02a:	83 cf ff             	or     edi,0xffffffff
  40e02d:	e8 2e 32 ff ff       	call   401260 <exit@plt>
  40e032:	48 63 d0             	movsxd rdx,eax
  40e035:	48 89 ee             	mov    rsi,rbp
  40e038:	bf 01 00 00 00       	mov    edi,0x1
  40e03d:	e8 5e 31 ff ff       	call   4011a0 <write@plt>
  40e042:	48 8d 3d 0b 41 00 00 	lea    rdi,[rip+0x410b]        # 412154 <_IO_stdin_used+0x154>
  40e049:	e8 42 31 ff ff       	call   401190 <puts@plt>
  40e04e:	48 8d 3d af 3f 00 00 	lea    rdi,[rip+0x3faf]        # 412004 <_IO_stdin_used+0x4>
  40e055:	31 f6                	xor    esi,esi
  40e057:	31 c0                	xor    eax,eax
  40e059:	e8 f2 31 ff ff       	call   401250 <open@plt>
  40e05e:	89 c7                	mov    edi,eax
  40e060:	85 c0                	test   eax,eax
  40e062:	79 34                	jns    40e098 <win+0xcb22>
  40e064:	e8 17 31 ff ff       	call   401180 <__errno_location@plt>
  40e069:	8b 38                	mov    edi,DWORD PTR [rax]
  40e06b:	e8 10 32 ff ff       	call   401280 <strerror@plt>
  40e070:	48 8d 35 93 3f 00 00 	lea    rsi,[rip+0x3f93]        # 41200a <_IO_stdin_used+0xa>
  40e077:	bf 01 00 00 00       	mov    edi,0x1
  40e07c:	48 89 c2             	mov    rdx,rax
  40e07f:	31 c0                	xor    eax,eax
  40e081:	e8 aa 31 ff ff       	call   401230 <__printf_chk@plt>
  40e086:	e8 55 31 ff ff       	call   4011e0 <geteuid@plt>
  40e08b:	85 c0                	test   eax,eax
  40e08d:	0f 84 46 35 ff ff    	je     4015d9 <win+0x63>
  40e093:	e9 29 35 ff ff       	jmp    4015c1 <win+0x4b>
  40e098:	ba 00 01 00 00       	mov    edx,0x100
  40e09d:	48 89 ee             	mov    rsi,rbp
  40e0a0:	e8 5b 31 ff ff       	call   401200 <read@plt>
  40e0a5:	85 c0                	test   eax,eax
  40e0a7:	7f 2a                	jg     40e0d3 <win+0xcb5d>
  40e0a9:	e8 d2 30 ff ff       	call   401180 <__errno_location@plt>
  40e0ae:	8b 38                	mov    edi,DWORD PTR [rax]
  40e0b0:	e8 cb 31 ff ff       	call   401280 <strerror@plt>
  40e0b5:	bf 01 00 00 00       	mov    edi,0x1
  40e0ba:	48 8d 35 e8 3f 00 00 	lea    rsi,[rip+0x3fe8]        # 4120a9 <_IO_stdin_used+0xa9>
  40e0c1:	48 89 c2             	mov    rdx,rax
  40e0c4:	31 c0                	xor    eax,eax
  40e0c6:	e8 65 31 ff ff       	call   401230 <__printf_chk@plt>
  40e0cb:	83 cf ff             	or     edi,0xffffffff
  40e0ce:	e8 8d 31 ff ff       	call   401260 <exit@plt>
  40e0d3:	48 63 d0             	movsxd rdx,eax
  40e0d6:	48 89 ee             	mov    rsi,rbp
  40e0d9:	bf 01 00 00 00       	mov    edi,0x1
  40e0de:	e8 bd 30 ff ff       	call   4011a0 <write@plt>
  40e0e3:	48 8d 3d 6a 40 00 00 	lea    rdi,[rip+0x406a]        # 412154 <_IO_stdin_used+0x154>
  40e0ea:	e8 a1 30 ff ff       	call   401190 <puts@plt>
  40e0ef:	48 8d 3d 0e 3f 00 00 	lea    rdi,[rip+0x3f0e]        # 412004 <_IO_stdin_used+0x4>
  40e0f6:	31 f6                	xor    esi,esi
  40e0f8:	31 c0                	xor    eax,eax
  40e0fa:	e8 51 31 ff ff       	call   401250 <open@plt>
  40e0ff:	89 c7                	mov    edi,eax
  40e101:	85 c0                	test   eax,eax
  40e103:	79 34                	jns    40e139 <win+0xcbc3>
  40e105:	e8 76 30 ff ff       	call   401180 <__errno_location@plt>
  40e10a:	8b 38                	mov    edi,DWORD PTR [rax]
  40e10c:	e8 6f 31 ff ff       	call   401280 <strerror@plt>
  40e111:	48 8d 35 f2 3e 00 00 	lea    rsi,[rip+0x3ef2]        # 41200a <_IO_stdin_used+0xa>
  40e118:	bf 01 00 00 00       	mov    edi,0x1
  40e11d:	48 89 c2             	mov    rdx,rax
  40e120:	31 c0                	xor    eax,eax
  40e122:	e8 09 31 ff ff       	call   401230 <__printf_chk@plt>
  40e127:	e8 b4 30 ff ff       	call   4011e0 <geteuid@plt>
  40e12c:	85 c0                	test   eax,eax
  40e12e:	0f 84 a5 34 ff ff    	je     4015d9 <win+0x63>
  40e134:	e9 88 34 ff ff       	jmp    4015c1 <win+0x4b>
  40e139:	ba 00 01 00 00       	mov    edx,0x100
  40e13e:	48 89 ee             	mov    rsi,rbp
  40e141:	e8 ba 30 ff ff       	call   401200 <read@plt>
  40e146:	85 c0                	test   eax,eax
  40e148:	7f 2a                	jg     40e174 <win+0xcbfe>
  40e14a:	e8 31 30 ff ff       	call   401180 <__errno_location@plt>
  40e14f:	8b 38                	mov    edi,DWORD PTR [rax]
  40e151:	e8 2a 31 ff ff       	call   401280 <strerror@plt>
  40e156:	bf 01 00 00 00       	mov    edi,0x1
  40e15b:	48 8d 35 47 3f 00 00 	lea    rsi,[rip+0x3f47]        # 4120a9 <_IO_stdin_used+0xa9>
  40e162:	48 89 c2             	mov    rdx,rax
  40e165:	31 c0                	xor    eax,eax
  40e167:	e8 c4 30 ff ff       	call   401230 <__printf_chk@plt>
  40e16c:	83 cf ff             	or     edi,0xffffffff
  40e16f:	e8 ec 30 ff ff       	call   401260 <exit@plt>
  40e174:	48 63 d0             	movsxd rdx,eax
  40e177:	48 89 ee             	mov    rsi,rbp
  40e17a:	bf 01 00 00 00       	mov    edi,0x1
  40e17f:	e8 1c 30 ff ff       	call   4011a0 <write@plt>
  40e184:	48 8d 3d c9 3f 00 00 	lea    rdi,[rip+0x3fc9]        # 412154 <_IO_stdin_used+0x154>
  40e18b:	e8 00 30 ff ff       	call   401190 <puts@plt>
  40e190:	48 8d 3d 6d 3e 00 00 	lea    rdi,[rip+0x3e6d]        # 412004 <_IO_stdin_used+0x4>
  40e197:	31 f6                	xor    esi,esi
  40e199:	31 c0                	xor    eax,eax
  40e19b:	e8 b0 30 ff ff       	call   401250 <open@plt>
  40e1a0:	89 c7                	mov    edi,eax
  40e1a2:	85 c0                	test   eax,eax
  40e1a4:	79 34                	jns    40e1da <win+0xcc64>
  40e1a6:	e8 d5 2f ff ff       	call   401180 <__errno_location@plt>
  40e1ab:	8b 38                	mov    edi,DWORD PTR [rax]
  40e1ad:	e8 ce 30 ff ff       	call   401280 <strerror@plt>
  40e1b2:	48 8d 35 51 3e 00 00 	lea    rsi,[rip+0x3e51]        # 41200a <_IO_stdin_used+0xa>
  40e1b9:	bf 01 00 00 00       	mov    edi,0x1
  40e1be:	48 89 c2             	mov    rdx,rax
  40e1c1:	31 c0                	xor    eax,eax
  40e1c3:	e8 68 30 ff ff       	call   401230 <__printf_chk@plt>
  40e1c8:	e8 13 30 ff ff       	call   4011e0 <geteuid@plt>
  40e1cd:	85 c0                	test   eax,eax
  40e1cf:	0f 84 04 34 ff ff    	je     4015d9 <win+0x63>
  40e1d5:	e9 e7 33 ff ff       	jmp    4015c1 <win+0x4b>
  40e1da:	ba 00 01 00 00       	mov    edx,0x100
  40e1df:	48 89 ee             	mov    rsi,rbp
  40e1e2:	e8 19 30 ff ff       	call   401200 <read@plt>
  40e1e7:	85 c0                	test   eax,eax
  40e1e9:	7f 2a                	jg     40e215 <win+0xcc9f>
  40e1eb:	e8 90 2f ff ff       	call   401180 <__errno_location@plt>
  40e1f0:	8b 38                	mov    edi,DWORD PTR [rax]
  40e1f2:	e8 89 30 ff ff       	call   401280 <strerror@plt>
  40e1f7:	bf 01 00 00 00       	mov    edi,0x1
  40e1fc:	48 8d 35 a6 3e 00 00 	lea    rsi,[rip+0x3ea6]        # 4120a9 <_IO_stdin_used+0xa9>
  40e203:	48 89 c2             	mov    rdx,rax
  40e206:	31 c0                	xor    eax,eax
  40e208:	e8 23 30 ff ff       	call   401230 <__printf_chk@plt>
  40e20d:	83 cf ff             	or     edi,0xffffffff
  40e210:	e8 4b 30 ff ff       	call   401260 <exit@plt>
  40e215:	48 63 d0             	movsxd rdx,eax
  40e218:	48 89 ee             	mov    rsi,rbp
  40e21b:	bf 01 00 00 00       	mov    edi,0x1
  40e220:	e8 7b 2f ff ff       	call   4011a0 <write@plt>
  40e225:	48 8d 3d 28 3f 00 00 	lea    rdi,[rip+0x3f28]        # 412154 <_IO_stdin_used+0x154>
  40e22c:	e8 5f 2f ff ff       	call   401190 <puts@plt>
  40e231:	48 8d 3d cc 3d 00 00 	lea    rdi,[rip+0x3dcc]        # 412004 <_IO_stdin_used+0x4>
  40e238:	31 f6                	xor    esi,esi
  40e23a:	31 c0                	xor    eax,eax
  40e23c:	e8 0f 30 ff ff       	call   401250 <open@plt>
  40e241:	89 c7                	mov    edi,eax
  40e243:	85 c0                	test   eax,eax
  40e245:	79 34                	jns    40e27b <win+0xcd05>
  40e247:	e8 34 2f ff ff       	call   401180 <__errno_location@plt>
  40e24c:	8b 38                	mov    edi,DWORD PTR [rax]
  40e24e:	e8 2d 30 ff ff       	call   401280 <strerror@plt>
  40e253:	48 8d 35 b0 3d 00 00 	lea    rsi,[rip+0x3db0]        # 41200a <_IO_stdin_used+0xa>
  40e25a:	bf 01 00 00 00       	mov    edi,0x1
  40e25f:	48 89 c2             	mov    rdx,rax
  40e262:	31 c0                	xor    eax,eax
  40e264:	e8 c7 2f ff ff       	call   401230 <__printf_chk@plt>
  40e269:	e8 72 2f ff ff       	call   4011e0 <geteuid@plt>
  40e26e:	85 c0                	test   eax,eax
  40e270:	0f 84 63 33 ff ff    	je     4015d9 <win+0x63>
  40e276:	e9 46 33 ff ff       	jmp    4015c1 <win+0x4b>
  40e27b:	ba 00 01 00 00       	mov    edx,0x100
  40e280:	48 89 ee             	mov    rsi,rbp
  40e283:	e8 78 2f ff ff       	call   401200 <read@plt>
  40e288:	85 c0                	test   eax,eax
  40e28a:	7f 2a                	jg     40e2b6 <win+0xcd40>
  40e28c:	e8 ef 2e ff ff       	call   401180 <__errno_location@plt>
  40e291:	8b 38                	mov    edi,DWORD PTR [rax]
  40e293:	e8 e8 2f ff ff       	call   401280 <strerror@plt>
  40e298:	bf 01 00 00 00       	mov    edi,0x1
  40e29d:	48 8d 35 05 3e 00 00 	lea    rsi,[rip+0x3e05]        # 4120a9 <_IO_stdin_used+0xa9>
  40e2a4:	48 89 c2             	mov    rdx,rax
  40e2a7:	31 c0                	xor    eax,eax
  40e2a9:	e8 82 2f ff ff       	call   401230 <__printf_chk@plt>
  40e2ae:	83 cf ff             	or     edi,0xffffffff
  40e2b1:	e8 aa 2f ff ff       	call   401260 <exit@plt>
  40e2b6:	48 63 d0             	movsxd rdx,eax
  40e2b9:	48 89 ee             	mov    rsi,rbp
  40e2bc:	bf 01 00 00 00       	mov    edi,0x1
  40e2c1:	e8 da 2e ff ff       	call   4011a0 <write@plt>
  40e2c6:	48 8d 3d 87 3e 00 00 	lea    rdi,[rip+0x3e87]        # 412154 <_IO_stdin_used+0x154>
  40e2cd:	e8 be 2e ff ff       	call   401190 <puts@plt>
  40e2d2:	48 8d 3d 2b 3d 00 00 	lea    rdi,[rip+0x3d2b]        # 412004 <_IO_stdin_used+0x4>
  40e2d9:	31 f6                	xor    esi,esi
  40e2db:	31 c0                	xor    eax,eax
  40e2dd:	e8 6e 2f ff ff       	call   401250 <open@plt>
  40e2e2:	89 c7                	mov    edi,eax
  40e2e4:	85 c0                	test   eax,eax
  40e2e6:	79 34                	jns    40e31c <win+0xcda6>
  40e2e8:	e8 93 2e ff ff       	call   401180 <__errno_location@plt>
  40e2ed:	8b 38                	mov    edi,DWORD PTR [rax]
  40e2ef:	e8 8c 2f ff ff       	call   401280 <strerror@plt>
  40e2f4:	48 8d 35 0f 3d 00 00 	lea    rsi,[rip+0x3d0f]        # 41200a <_IO_stdin_used+0xa>
  40e2fb:	bf 01 00 00 00       	mov    edi,0x1
  40e300:	48 89 c2             	mov    rdx,rax
  40e303:	31 c0                	xor    eax,eax
  40e305:	e8 26 2f ff ff       	call   401230 <__printf_chk@plt>
  40e30a:	e8 d1 2e ff ff       	call   4011e0 <geteuid@plt>
  40e30f:	85 c0                	test   eax,eax
  40e311:	0f 84 c2 32 ff ff    	je     4015d9 <win+0x63>
  40e317:	e9 a5 32 ff ff       	jmp    4015c1 <win+0x4b>
  40e31c:	ba 00 01 00 00       	mov    edx,0x100
  40e321:	48 89 ee             	mov    rsi,rbp
  40e324:	e8 d7 2e ff ff       	call   401200 <read@plt>
  40e329:	85 c0                	test   eax,eax
  40e32b:	7f 2a                	jg     40e357 <win+0xcde1>
  40e32d:	e8 4e 2e ff ff       	call   401180 <__errno_location@plt>
  40e332:	8b 38                	mov    edi,DWORD PTR [rax]
  40e334:	e8 47 2f ff ff       	call   401280 <strerror@plt>
  40e339:	bf 01 00 00 00       	mov    edi,0x1
  40e33e:	48 8d 35 64 3d 00 00 	lea    rsi,[rip+0x3d64]        # 4120a9 <_IO_stdin_used+0xa9>
  40e345:	48 89 c2             	mov    rdx,rax
  40e348:	31 c0                	xor    eax,eax
  40e34a:	e8 e1 2e ff ff       	call   401230 <__printf_chk@plt>
  40e34f:	83 cf ff             	or     edi,0xffffffff
  40e352:	e8 09 2f ff ff       	call   401260 <exit@plt>
  40e357:	48 63 d0             	movsxd rdx,eax
  40e35a:	48 89 ee             	mov    rsi,rbp
  40e35d:	bf 01 00 00 00       	mov    edi,0x1
  40e362:	e8 39 2e ff ff       	call   4011a0 <write@plt>
  40e367:	48 8d 3d e6 3d 00 00 	lea    rdi,[rip+0x3de6]        # 412154 <_IO_stdin_used+0x154>
  40e36e:	e8 1d 2e ff ff       	call   401190 <puts@plt>
  40e373:	48 8d 3d 8a 3c 00 00 	lea    rdi,[rip+0x3c8a]        # 412004 <_IO_stdin_used+0x4>
  40e37a:	31 f6                	xor    esi,esi
  40e37c:	31 c0                	xor    eax,eax
  40e37e:	e8 cd 2e ff ff       	call   401250 <open@plt>
  40e383:	89 c7                	mov    edi,eax
  40e385:	85 c0                	test   eax,eax
  40e387:	79 34                	jns    40e3bd <win+0xce47>
  40e389:	e8 f2 2d ff ff       	call   401180 <__errno_location@plt>
  40e38e:	8b 38                	mov    edi,DWORD PTR [rax]
  40e390:	e8 eb 2e ff ff       	call   401280 <strerror@plt>
  40e395:	48 8d 35 6e 3c 00 00 	lea    rsi,[rip+0x3c6e]        # 41200a <_IO_stdin_used+0xa>
  40e39c:	bf 01 00 00 00       	mov    edi,0x1
  40e3a1:	48 89 c2             	mov    rdx,rax
  40e3a4:	31 c0                	xor    eax,eax
  40e3a6:	e8 85 2e ff ff       	call   401230 <__printf_chk@plt>
  40e3ab:	e8 30 2e ff ff       	call   4011e0 <geteuid@plt>
  40e3b0:	85 c0                	test   eax,eax
  40e3b2:	0f 84 21 32 ff ff    	je     4015d9 <win+0x63>
  40e3b8:	e9 04 32 ff ff       	jmp    4015c1 <win+0x4b>
  40e3bd:	ba 00 01 00 00       	mov    edx,0x100
  40e3c2:	48 89 ee             	mov    rsi,rbp
  40e3c5:	e8 36 2e ff ff       	call   401200 <read@plt>
  40e3ca:	85 c0                	test   eax,eax
  40e3cc:	7f 2a                	jg     40e3f8 <win+0xce82>
  40e3ce:	e8 ad 2d ff ff       	call   401180 <__errno_location@plt>
  40e3d3:	8b 38                	mov    edi,DWORD PTR [rax]
  40e3d5:	e8 a6 2e ff ff       	call   401280 <strerror@plt>
  40e3da:	bf 01 00 00 00       	mov    edi,0x1
  40e3df:	48 8d 35 c3 3c 00 00 	lea    rsi,[rip+0x3cc3]        # 4120a9 <_IO_stdin_used+0xa9>
  40e3e6:	48 89 c2             	mov    rdx,rax
  40e3e9:	31 c0                	xor    eax,eax
  40e3eb:	e8 40 2e ff ff       	call   401230 <__printf_chk@plt>
  40e3f0:	83 cf ff             	or     edi,0xffffffff
  40e3f3:	e8 68 2e ff ff       	call   401260 <exit@plt>
  40e3f8:	48 63 d0             	movsxd rdx,eax
  40e3fb:	48 89 ee             	mov    rsi,rbp
  40e3fe:	bf 01 00 00 00       	mov    edi,0x1
  40e403:	e8 98 2d ff ff       	call   4011a0 <write@plt>
  40e408:	48 8d 3d 45 3d 00 00 	lea    rdi,[rip+0x3d45]        # 412154 <_IO_stdin_used+0x154>
  40e40f:	e8 7c 2d ff ff       	call   401190 <puts@plt>
  40e414:	48 8d 3d e9 3b 00 00 	lea    rdi,[rip+0x3be9]        # 412004 <_IO_stdin_used+0x4>
  40e41b:	31 f6                	xor    esi,esi
  40e41d:	31 c0                	xor    eax,eax
  40e41f:	e8 2c 2e ff ff       	call   401250 <open@plt>
  40e424:	89 c7                	mov    edi,eax
  40e426:	85 c0                	test   eax,eax
  40e428:	79 34                	jns    40e45e <win+0xcee8>
  40e42a:	e8 51 2d ff ff       	call   401180 <__errno_location@plt>
  40e42f:	8b 38                	mov    edi,DWORD PTR [rax]
  40e431:	e8 4a 2e ff ff       	call   401280 <strerror@plt>
  40e436:	48 8d 35 cd 3b 00 00 	lea    rsi,[rip+0x3bcd]        # 41200a <_IO_stdin_used+0xa>
  40e43d:	bf 01 00 00 00       	mov    edi,0x1
  40e442:	48 89 c2             	mov    rdx,rax
  40e445:	31 c0                	xor    eax,eax
  40e447:	e8 e4 2d ff ff       	call   401230 <__printf_chk@plt>
  40e44c:	e8 8f 2d ff ff       	call   4011e0 <geteuid@plt>
  40e451:	85 c0                	test   eax,eax
  40e453:	0f 84 80 31 ff ff    	je     4015d9 <win+0x63>
  40e459:	e9 63 31 ff ff       	jmp    4015c1 <win+0x4b>
  40e45e:	ba 00 01 00 00       	mov    edx,0x100
  40e463:	48 89 ee             	mov    rsi,rbp
  40e466:	e8 95 2d ff ff       	call   401200 <read@plt>
  40e46b:	85 c0                	test   eax,eax
  40e46d:	7f 2a                	jg     40e499 <win+0xcf23>
  40e46f:	e8 0c 2d ff ff       	call   401180 <__errno_location@plt>
  40e474:	8b 38                	mov    edi,DWORD PTR [rax]
  40e476:	e8 05 2e ff ff       	call   401280 <strerror@plt>
  40e47b:	bf 01 00 00 00       	mov    edi,0x1
  40e480:	48 8d 35 22 3c 00 00 	lea    rsi,[rip+0x3c22]        # 4120a9 <_IO_stdin_used+0xa9>
  40e487:	48 89 c2             	mov    rdx,rax
  40e48a:	31 c0                	xor    eax,eax
  40e48c:	e8 9f 2d ff ff       	call   401230 <__printf_chk@plt>
  40e491:	83 cf ff             	or     edi,0xffffffff
  40e494:	e8 c7 2d ff ff       	call   401260 <exit@plt>
  40e499:	48 63 d0             	movsxd rdx,eax
  40e49c:	48 89 ee             	mov    rsi,rbp
  40e49f:	bf 01 00 00 00       	mov    edi,0x1
  40e4a4:	e8 f7 2c ff ff       	call   4011a0 <write@plt>
  40e4a9:	48 8d 3d a4 3c 00 00 	lea    rdi,[rip+0x3ca4]        # 412154 <_IO_stdin_used+0x154>
  40e4b0:	e8 db 2c ff ff       	call   401190 <puts@plt>
  40e4b5:	48 8d 3d 48 3b 00 00 	lea    rdi,[rip+0x3b48]        # 412004 <_IO_stdin_used+0x4>
  40e4bc:	31 f6                	xor    esi,esi
  40e4be:	31 c0                	xor    eax,eax
  40e4c0:	e8 8b 2d ff ff       	call   401250 <open@plt>
  40e4c5:	89 c7                	mov    edi,eax
  40e4c7:	85 c0                	test   eax,eax
  40e4c9:	79 34                	jns    40e4ff <win+0xcf89>
  40e4cb:	e8 b0 2c ff ff       	call   401180 <__errno_location@plt>
  40e4d0:	8b 38                	mov    edi,DWORD PTR [rax]
  40e4d2:	e8 a9 2d ff ff       	call   401280 <strerror@plt>
  40e4d7:	48 8d 35 2c 3b 00 00 	lea    rsi,[rip+0x3b2c]        # 41200a <_IO_stdin_used+0xa>
  40e4de:	bf 01 00 00 00       	mov    edi,0x1
  40e4e3:	48 89 c2             	mov    rdx,rax
  40e4e6:	31 c0                	xor    eax,eax
  40e4e8:	e8 43 2d ff ff       	call   401230 <__printf_chk@plt>
  40e4ed:	e8 ee 2c ff ff       	call   4011e0 <geteuid@plt>
  40e4f2:	85 c0                	test   eax,eax
  40e4f4:	0f 84 df 30 ff ff    	je     4015d9 <win+0x63>
  40e4fa:	e9 c2 30 ff ff       	jmp    4015c1 <win+0x4b>
  40e4ff:	ba 00 01 00 00       	mov    edx,0x100
  40e504:	48 89 ee             	mov    rsi,rbp
  40e507:	e8 f4 2c ff ff       	call   401200 <read@plt>
  40e50c:	85 c0                	test   eax,eax
  40e50e:	7f 2a                	jg     40e53a <win+0xcfc4>
  40e510:	e8 6b 2c ff ff       	call   401180 <__errno_location@plt>
  40e515:	8b 38                	mov    edi,DWORD PTR [rax]
  40e517:	e8 64 2d ff ff       	call   401280 <strerror@plt>
  40e51c:	bf 01 00 00 00       	mov    edi,0x1
  40e521:	48 8d 35 81 3b 00 00 	lea    rsi,[rip+0x3b81]        # 4120a9 <_IO_stdin_used+0xa9>
  40e528:	48 89 c2             	mov    rdx,rax
  40e52b:	31 c0                	xor    eax,eax
  40e52d:	e8 fe 2c ff ff       	call   401230 <__printf_chk@plt>
  40e532:	83 cf ff             	or     edi,0xffffffff
  40e535:	e8 26 2d ff ff       	call   401260 <exit@plt>
  40e53a:	48 63 d0             	movsxd rdx,eax
  40e53d:	48 89 ee             	mov    rsi,rbp
  40e540:	bf 01 00 00 00       	mov    edi,0x1
  40e545:	e8 56 2c ff ff       	call   4011a0 <write@plt>
  40e54a:	48 8d 3d 03 3c 00 00 	lea    rdi,[rip+0x3c03]        # 412154 <_IO_stdin_used+0x154>
  40e551:	e8 3a 2c ff ff       	call   401190 <puts@plt>
  40e556:	48 8d 3d a7 3a 00 00 	lea    rdi,[rip+0x3aa7]        # 412004 <_IO_stdin_used+0x4>
  40e55d:	31 f6                	xor    esi,esi
  40e55f:	31 c0                	xor    eax,eax
  40e561:	e8 ea 2c ff ff       	call   401250 <open@plt>
  40e566:	89 c7                	mov    edi,eax
  40e568:	85 c0                	test   eax,eax
  40e56a:	79 34                	jns    40e5a0 <win+0xd02a>
  40e56c:	e8 0f 2c ff ff       	call   401180 <__errno_location@plt>
  40e571:	8b 38                	mov    edi,DWORD PTR [rax]
  40e573:	e8 08 2d ff ff       	call   401280 <strerror@plt>
  40e578:	48 8d 35 8b 3a 00 00 	lea    rsi,[rip+0x3a8b]        # 41200a <_IO_stdin_used+0xa>
  40e57f:	bf 01 00 00 00       	mov    edi,0x1
  40e584:	48 89 c2             	mov    rdx,rax
  40e587:	31 c0                	xor    eax,eax
  40e589:	e8 a2 2c ff ff       	call   401230 <__printf_chk@plt>
  40e58e:	e8 4d 2c ff ff       	call   4011e0 <geteuid@plt>
  40e593:	85 c0                	test   eax,eax
  40e595:	0f 84 3e 30 ff ff    	je     4015d9 <win+0x63>
  40e59b:	e9 21 30 ff ff       	jmp    4015c1 <win+0x4b>
  40e5a0:	ba 00 01 00 00       	mov    edx,0x100
  40e5a5:	48 89 ee             	mov    rsi,rbp
  40e5a8:	e8 53 2c ff ff       	call   401200 <read@plt>
  40e5ad:	85 c0                	test   eax,eax
  40e5af:	7f 2a                	jg     40e5db <win+0xd065>
  40e5b1:	e8 ca 2b ff ff       	call   401180 <__errno_location@plt>
  40e5b6:	8b 38                	mov    edi,DWORD PTR [rax]
  40e5b8:	e8 c3 2c ff ff       	call   401280 <strerror@plt>
  40e5bd:	bf 01 00 00 00       	mov    edi,0x1
  40e5c2:	48 8d 35 e0 3a 00 00 	lea    rsi,[rip+0x3ae0]        # 4120a9 <_IO_stdin_used+0xa9>
  40e5c9:	48 89 c2             	mov    rdx,rax
  40e5cc:	31 c0                	xor    eax,eax
  40e5ce:	e8 5d 2c ff ff       	call   401230 <__printf_chk@plt>
  40e5d3:	83 cf ff             	or     edi,0xffffffff
  40e5d6:	e8 85 2c ff ff       	call   401260 <exit@plt>
  40e5db:	48 63 d0             	movsxd rdx,eax
  40e5de:	48 89 ee             	mov    rsi,rbp
  40e5e1:	bf 01 00 00 00       	mov    edi,0x1
  40e5e6:	e8 b5 2b ff ff       	call   4011a0 <write@plt>
  40e5eb:	48 8d 3d 62 3b 00 00 	lea    rdi,[rip+0x3b62]        # 412154 <_IO_stdin_used+0x154>
  40e5f2:	e8 99 2b ff ff       	call   401190 <puts@plt>
  40e5f7:	48 8d 3d 06 3a 00 00 	lea    rdi,[rip+0x3a06]        # 412004 <_IO_stdin_used+0x4>
  40e5fe:	31 f6                	xor    esi,esi
  40e600:	31 c0                	xor    eax,eax
  40e602:	e8 49 2c ff ff       	call   401250 <open@plt>
  40e607:	89 c7                	mov    edi,eax
  40e609:	85 c0                	test   eax,eax
  40e60b:	79 34                	jns    40e641 <win+0xd0cb>
  40e60d:	e8 6e 2b ff ff       	call   401180 <__errno_location@plt>
  40e612:	8b 38                	mov    edi,DWORD PTR [rax]
  40e614:	e8 67 2c ff ff       	call   401280 <strerror@plt>
  40e619:	48 8d 35 ea 39 00 00 	lea    rsi,[rip+0x39ea]        # 41200a <_IO_stdin_used+0xa>
  40e620:	bf 01 00 00 00       	mov    edi,0x1
  40e625:	48 89 c2             	mov    rdx,rax
  40e628:	31 c0                	xor    eax,eax
  40e62a:	e8 01 2c ff ff       	call   401230 <__printf_chk@plt>
  40e62f:	e8 ac 2b ff ff       	call   4011e0 <geteuid@plt>
  40e634:	85 c0                	test   eax,eax
  40e636:	0f 84 9d 2f ff ff    	je     4015d9 <win+0x63>
  40e63c:	e9 80 2f ff ff       	jmp    4015c1 <win+0x4b>
  40e641:	ba 00 01 00 00       	mov    edx,0x100
  40e646:	48 89 ee             	mov    rsi,rbp
  40e649:	e8 b2 2b ff ff       	call   401200 <read@plt>
  40e64e:	85 c0                	test   eax,eax
  40e650:	7f 2a                	jg     40e67c <win+0xd106>
  40e652:	e8 29 2b ff ff       	call   401180 <__errno_location@plt>
  40e657:	8b 38                	mov    edi,DWORD PTR [rax]
  40e659:	e8 22 2c ff ff       	call   401280 <strerror@plt>
  40e65e:	bf 01 00 00 00       	mov    edi,0x1
  40e663:	48 8d 35 3f 3a 00 00 	lea    rsi,[rip+0x3a3f]        # 4120a9 <_IO_stdin_used+0xa9>
  40e66a:	48 89 c2             	mov    rdx,rax
  40e66d:	31 c0                	xor    eax,eax
  40e66f:	e8 bc 2b ff ff       	call   401230 <__printf_chk@plt>
  40e674:	83 cf ff             	or     edi,0xffffffff
  40e677:	e8 e4 2b ff ff       	call   401260 <exit@plt>
  40e67c:	48 63 d0             	movsxd rdx,eax
  40e67f:	48 89 ee             	mov    rsi,rbp
  40e682:	bf 01 00 00 00       	mov    edi,0x1
  40e687:	e8 14 2b ff ff       	call   4011a0 <write@plt>
  40e68c:	48 8d 3d c1 3a 00 00 	lea    rdi,[rip+0x3ac1]        # 412154 <_IO_stdin_used+0x154>
  40e693:	e8 f8 2a ff ff       	call   401190 <puts@plt>
  40e698:	48 8d 3d 65 39 00 00 	lea    rdi,[rip+0x3965]        # 412004 <_IO_stdin_used+0x4>
  40e69f:	31 f6                	xor    esi,esi
  40e6a1:	31 c0                	xor    eax,eax
  40e6a3:	e8 a8 2b ff ff       	call   401250 <open@plt>
  40e6a8:	89 c7                	mov    edi,eax
  40e6aa:	85 c0                	test   eax,eax
  40e6ac:	79 34                	jns    40e6e2 <win+0xd16c>
  40e6ae:	e8 cd 2a ff ff       	call   401180 <__errno_location@plt>
  40e6b3:	8b 38                	mov    edi,DWORD PTR [rax]
  40e6b5:	e8 c6 2b ff ff       	call   401280 <strerror@plt>
  40e6ba:	48 8d 35 49 39 00 00 	lea    rsi,[rip+0x3949]        # 41200a <_IO_stdin_used+0xa>
  40e6c1:	bf 01 00 00 00       	mov    edi,0x1
  40e6c6:	48 89 c2             	mov    rdx,rax
  40e6c9:	31 c0                	xor    eax,eax
  40e6cb:	e8 60 2b ff ff       	call   401230 <__printf_chk@plt>
  40e6d0:	e8 0b 2b ff ff       	call   4011e0 <geteuid@plt>
  40e6d5:	85 c0                	test   eax,eax
  40e6d7:	0f 84 fc 2e ff ff    	je     4015d9 <win+0x63>
  40e6dd:	e9 df 2e ff ff       	jmp    4015c1 <win+0x4b>
  40e6e2:	ba 00 01 00 00       	mov    edx,0x100
  40e6e7:	48 89 ee             	mov    rsi,rbp
  40e6ea:	e8 11 2b ff ff       	call   401200 <read@plt>
  40e6ef:	85 c0                	test   eax,eax
  40e6f1:	7f 2a                	jg     40e71d <win+0xd1a7>
  40e6f3:	e8 88 2a ff ff       	call   401180 <__errno_location@plt>
  40e6f8:	8b 38                	mov    edi,DWORD PTR [rax]
  40e6fa:	e8 81 2b ff ff       	call   401280 <strerror@plt>
  40e6ff:	bf 01 00 00 00       	mov    edi,0x1
  40e704:	48 8d 35 9e 39 00 00 	lea    rsi,[rip+0x399e]        # 4120a9 <_IO_stdin_used+0xa9>
  40e70b:	48 89 c2             	mov    rdx,rax
  40e70e:	31 c0                	xor    eax,eax
  40e710:	e8 1b 2b ff ff       	call   401230 <__printf_chk@plt>
  40e715:	83 cf ff             	or     edi,0xffffffff
  40e718:	e8 43 2b ff ff       	call   401260 <exit@plt>
  40e71d:	48 63 d0             	movsxd rdx,eax
  40e720:	48 89 ee             	mov    rsi,rbp
  40e723:	bf 01 00 00 00       	mov    edi,0x1
  40e728:	e8 73 2a ff ff       	call   4011a0 <write@plt>
  40e72d:	48 8d 3d 20 3a 00 00 	lea    rdi,[rip+0x3a20]        # 412154 <_IO_stdin_used+0x154>
  40e734:	e8 57 2a ff ff       	call   401190 <puts@plt>
  40e739:	48 8d 3d c4 38 00 00 	lea    rdi,[rip+0x38c4]        # 412004 <_IO_stdin_used+0x4>
  40e740:	31 f6                	xor    esi,esi
  40e742:	31 c0                	xor    eax,eax
  40e744:	e8 07 2b ff ff       	call   401250 <open@plt>
  40e749:	89 c7                	mov    edi,eax
  40e74b:	85 c0                	test   eax,eax
  40e74d:	79 34                	jns    40e783 <win+0xd20d>
  40e74f:	e8 2c 2a ff ff       	call   401180 <__errno_location@plt>
  40e754:	8b 38                	mov    edi,DWORD PTR [rax]
  40e756:	e8 25 2b ff ff       	call   401280 <strerror@plt>
  40e75b:	48 8d 35 a8 38 00 00 	lea    rsi,[rip+0x38a8]        # 41200a <_IO_stdin_used+0xa>
  40e762:	bf 01 00 00 00       	mov    edi,0x1
  40e767:	48 89 c2             	mov    rdx,rax
  40e76a:	31 c0                	xor    eax,eax
  40e76c:	e8 bf 2a ff ff       	call   401230 <__printf_chk@plt>
  40e771:	e8 6a 2a ff ff       	call   4011e0 <geteuid@plt>
  40e776:	85 c0                	test   eax,eax
  40e778:	0f 84 5b 2e ff ff    	je     4015d9 <win+0x63>
  40e77e:	e9 3e 2e ff ff       	jmp    4015c1 <win+0x4b>
  40e783:	ba 00 01 00 00       	mov    edx,0x100
  40e788:	48 89 ee             	mov    rsi,rbp
  40e78b:	e8 70 2a ff ff       	call   401200 <read@plt>
  40e790:	85 c0                	test   eax,eax
  40e792:	7f 2a                	jg     40e7be <win+0xd248>
  40e794:	e8 e7 29 ff ff       	call   401180 <__errno_location@plt>
  40e799:	8b 38                	mov    edi,DWORD PTR [rax]
  40e79b:	e8 e0 2a ff ff       	call   401280 <strerror@plt>
  40e7a0:	bf 01 00 00 00       	mov    edi,0x1
  40e7a5:	48 8d 35 fd 38 00 00 	lea    rsi,[rip+0x38fd]        # 4120a9 <_IO_stdin_used+0xa9>
  40e7ac:	48 89 c2             	mov    rdx,rax
  40e7af:	31 c0                	xor    eax,eax
  40e7b1:	e8 7a 2a ff ff       	call   401230 <__printf_chk@plt>
  40e7b6:	83 cf ff             	or     edi,0xffffffff
  40e7b9:	e8 a2 2a ff ff       	call   401260 <exit@plt>
  40e7be:	48 63 d0             	movsxd rdx,eax
  40e7c1:	48 89 ee             	mov    rsi,rbp
  40e7c4:	bf 01 00 00 00       	mov    edi,0x1
  40e7c9:	e8 d2 29 ff ff       	call   4011a0 <write@plt>
  40e7ce:	48 8d 3d 7f 39 00 00 	lea    rdi,[rip+0x397f]        # 412154 <_IO_stdin_used+0x154>
  40e7d5:	e8 b6 29 ff ff       	call   401190 <puts@plt>
  40e7da:	48 8d 3d 23 38 00 00 	lea    rdi,[rip+0x3823]        # 412004 <_IO_stdin_used+0x4>
  40e7e1:	31 f6                	xor    esi,esi
  40e7e3:	31 c0                	xor    eax,eax
  40e7e5:	e8 66 2a ff ff       	call   401250 <open@plt>
  40e7ea:	89 c7                	mov    edi,eax
  40e7ec:	85 c0                	test   eax,eax
  40e7ee:	79 34                	jns    40e824 <win+0xd2ae>
  40e7f0:	e8 8b 29 ff ff       	call   401180 <__errno_location@plt>
  40e7f5:	8b 38                	mov    edi,DWORD PTR [rax]
  40e7f7:	e8 84 2a ff ff       	call   401280 <strerror@plt>
  40e7fc:	48 8d 35 07 38 00 00 	lea    rsi,[rip+0x3807]        # 41200a <_IO_stdin_used+0xa>
  40e803:	bf 01 00 00 00       	mov    edi,0x1
  40e808:	48 89 c2             	mov    rdx,rax
  40e80b:	31 c0                	xor    eax,eax
  40e80d:	e8 1e 2a ff ff       	call   401230 <__printf_chk@plt>
  40e812:	e8 c9 29 ff ff       	call   4011e0 <geteuid@plt>
  40e817:	85 c0                	test   eax,eax
  40e819:	0f 84 ba 2d ff ff    	je     4015d9 <win+0x63>
  40e81f:	e9 9d 2d ff ff       	jmp    4015c1 <win+0x4b>
  40e824:	ba 00 01 00 00       	mov    edx,0x100
  40e829:	48 89 ee             	mov    rsi,rbp
  40e82c:	e8 cf 29 ff ff       	call   401200 <read@plt>
  40e831:	85 c0                	test   eax,eax
  40e833:	7f 2a                	jg     40e85f <win+0xd2e9>
  40e835:	e8 46 29 ff ff       	call   401180 <__errno_location@plt>
  40e83a:	8b 38                	mov    edi,DWORD PTR [rax]
  40e83c:	e8 3f 2a ff ff       	call   401280 <strerror@plt>
  40e841:	bf 01 00 00 00       	mov    edi,0x1
  40e846:	48 8d 35 5c 38 00 00 	lea    rsi,[rip+0x385c]        # 4120a9 <_IO_stdin_used+0xa9>
  40e84d:	48 89 c2             	mov    rdx,rax
  40e850:	31 c0                	xor    eax,eax
  40e852:	e8 d9 29 ff ff       	call   401230 <__printf_chk@plt>
  40e857:	83 cf ff             	or     edi,0xffffffff
  40e85a:	e8 01 2a ff ff       	call   401260 <exit@plt>
  40e85f:	48 63 d0             	movsxd rdx,eax
  40e862:	48 89 ee             	mov    rsi,rbp
  40e865:	bf 01 00 00 00       	mov    edi,0x1
  40e86a:	e8 31 29 ff ff       	call   4011a0 <write@plt>
  40e86f:	48 8d 3d de 38 00 00 	lea    rdi,[rip+0x38de]        # 412154 <_IO_stdin_used+0x154>
  40e876:	e8 15 29 ff ff       	call   401190 <puts@plt>
  40e87b:	48 8d 3d 82 37 00 00 	lea    rdi,[rip+0x3782]        # 412004 <_IO_stdin_used+0x4>
  40e882:	31 f6                	xor    esi,esi
  40e884:	31 c0                	xor    eax,eax
  40e886:	e8 c5 29 ff ff       	call   401250 <open@plt>
  40e88b:	89 c7                	mov    edi,eax
  40e88d:	85 c0                	test   eax,eax
  40e88f:	79 34                	jns    40e8c5 <win+0xd34f>
  40e891:	e8 ea 28 ff ff       	call   401180 <__errno_location@plt>
  40e896:	8b 38                	mov    edi,DWORD PTR [rax]
  40e898:	e8 e3 29 ff ff       	call   401280 <strerror@plt>
  40e89d:	48 8d 35 66 37 00 00 	lea    rsi,[rip+0x3766]        # 41200a <_IO_stdin_used+0xa>
  40e8a4:	bf 01 00 00 00       	mov    edi,0x1
  40e8a9:	48 89 c2             	mov    rdx,rax
  40e8ac:	31 c0                	xor    eax,eax
  40e8ae:	e8 7d 29 ff ff       	call   401230 <__printf_chk@plt>
  40e8b3:	e8 28 29 ff ff       	call   4011e0 <geteuid@plt>
  40e8b8:	85 c0                	test   eax,eax
  40e8ba:	0f 84 19 2d ff ff    	je     4015d9 <win+0x63>
  40e8c0:	e9 fc 2c ff ff       	jmp    4015c1 <win+0x4b>
  40e8c5:	ba 00 01 00 00       	mov    edx,0x100
  40e8ca:	48 89 ee             	mov    rsi,rbp
  40e8cd:	e8 2e 29 ff ff       	call   401200 <read@plt>
  40e8d2:	85 c0                	test   eax,eax
  40e8d4:	7f 2a                	jg     40e900 <win+0xd38a>
  40e8d6:	e8 a5 28 ff ff       	call   401180 <__errno_location@plt>
  40e8db:	8b 38                	mov    edi,DWORD PTR [rax]
  40e8dd:	e8 9e 29 ff ff       	call   401280 <strerror@plt>
  40e8e2:	bf 01 00 00 00       	mov    edi,0x1
  40e8e7:	48 8d 35 bb 37 00 00 	lea    rsi,[rip+0x37bb]        # 4120a9 <_IO_stdin_used+0xa9>
  40e8ee:	48 89 c2             	mov    rdx,rax
  40e8f1:	31 c0                	xor    eax,eax
  40e8f3:	e8 38 29 ff ff       	call   401230 <__printf_chk@plt>
  40e8f8:	83 cf ff             	or     edi,0xffffffff
  40e8fb:	e8 60 29 ff ff       	call   401260 <exit@plt>
  40e900:	48 63 d0             	movsxd rdx,eax
  40e903:	48 89 ee             	mov    rsi,rbp
  40e906:	bf 01 00 00 00       	mov    edi,0x1
  40e90b:	e8 90 28 ff ff       	call   4011a0 <write@plt>
  40e910:	48 8d 3d 3d 38 00 00 	lea    rdi,[rip+0x383d]        # 412154 <_IO_stdin_used+0x154>
  40e917:	e8 74 28 ff ff       	call   401190 <puts@plt>
  40e91c:	48 8d 3d e1 36 00 00 	lea    rdi,[rip+0x36e1]        # 412004 <_IO_stdin_used+0x4>
  40e923:	31 f6                	xor    esi,esi
  40e925:	31 c0                	xor    eax,eax
  40e927:	e8 24 29 ff ff       	call   401250 <open@plt>
  40e92c:	89 c7                	mov    edi,eax
  40e92e:	85 c0                	test   eax,eax
  40e930:	79 34                	jns    40e966 <win+0xd3f0>
  40e932:	e8 49 28 ff ff       	call   401180 <__errno_location@plt>
  40e937:	8b 38                	mov    edi,DWORD PTR [rax]
  40e939:	e8 42 29 ff ff       	call   401280 <strerror@plt>
  40e93e:	48 8d 35 c5 36 00 00 	lea    rsi,[rip+0x36c5]        # 41200a <_IO_stdin_used+0xa>
  40e945:	bf 01 00 00 00       	mov    edi,0x1
  40e94a:	48 89 c2             	mov    rdx,rax
  40e94d:	31 c0                	xor    eax,eax
  40e94f:	e8 dc 28 ff ff       	call   401230 <__printf_chk@plt>
  40e954:	e8 87 28 ff ff       	call   4011e0 <geteuid@plt>
  40e959:	85 c0                	test   eax,eax
  40e95b:	0f 84 78 2c ff ff    	je     4015d9 <win+0x63>
  40e961:	e9 5b 2c ff ff       	jmp    4015c1 <win+0x4b>
  40e966:	ba 00 01 00 00       	mov    edx,0x100
  40e96b:	48 89 ee             	mov    rsi,rbp
  40e96e:	e8 8d 28 ff ff       	call   401200 <read@plt>
  40e973:	85 c0                	test   eax,eax
  40e975:	7f 2a                	jg     40e9a1 <win+0xd42b>
  40e977:	e8 04 28 ff ff       	call   401180 <__errno_location@plt>
  40e97c:	8b 38                	mov    edi,DWORD PTR [rax]
  40e97e:	e8 fd 28 ff ff       	call   401280 <strerror@plt>
  40e983:	bf 01 00 00 00       	mov    edi,0x1
  40e988:	48 8d 35 1a 37 00 00 	lea    rsi,[rip+0x371a]        # 4120a9 <_IO_stdin_used+0xa9>
  40e98f:	48 89 c2             	mov    rdx,rax
  40e992:	31 c0                	xor    eax,eax
  40e994:	e8 97 28 ff ff       	call   401230 <__printf_chk@plt>
  40e999:	83 cf ff             	or     edi,0xffffffff
  40e99c:	e8 bf 28 ff ff       	call   401260 <exit@plt>
  40e9a1:	48 63 d0             	movsxd rdx,eax
  40e9a4:	48 89 ee             	mov    rsi,rbp
  40e9a7:	bf 01 00 00 00       	mov    edi,0x1
  40e9ac:	e8 ef 27 ff ff       	call   4011a0 <write@plt>
  40e9b1:	48 8d 3d 9c 37 00 00 	lea    rdi,[rip+0x379c]        # 412154 <_IO_stdin_used+0x154>
  40e9b8:	e8 d3 27 ff ff       	call   401190 <puts@plt>
  40e9bd:	48 8d 3d 40 36 00 00 	lea    rdi,[rip+0x3640]        # 412004 <_IO_stdin_used+0x4>
  40e9c4:	31 f6                	xor    esi,esi
  40e9c6:	31 c0                	xor    eax,eax
  40e9c8:	e8 83 28 ff ff       	call   401250 <open@plt>
  40e9cd:	89 c7                	mov    edi,eax
  40e9cf:	85 c0                	test   eax,eax
  40e9d1:	79 34                	jns    40ea07 <win+0xd491>
  40e9d3:	e8 a8 27 ff ff       	call   401180 <__errno_location@plt>
  40e9d8:	8b 38                	mov    edi,DWORD PTR [rax]
  40e9da:	e8 a1 28 ff ff       	call   401280 <strerror@plt>
  40e9df:	48 8d 35 24 36 00 00 	lea    rsi,[rip+0x3624]        # 41200a <_IO_stdin_used+0xa>
  40e9e6:	bf 01 00 00 00       	mov    edi,0x1
  40e9eb:	48 89 c2             	mov    rdx,rax
  40e9ee:	31 c0                	xor    eax,eax
  40e9f0:	e8 3b 28 ff ff       	call   401230 <__printf_chk@plt>
  40e9f5:	e8 e6 27 ff ff       	call   4011e0 <geteuid@plt>
  40e9fa:	85 c0                	test   eax,eax
  40e9fc:	0f 84 d7 2b ff ff    	je     4015d9 <win+0x63>
  40ea02:	e9 ba 2b ff ff       	jmp    4015c1 <win+0x4b>
  40ea07:	ba 00 01 00 00       	mov    edx,0x100
  40ea0c:	48 89 ee             	mov    rsi,rbp
  40ea0f:	e8 ec 27 ff ff       	call   401200 <read@plt>
  40ea14:	85 c0                	test   eax,eax
  40ea16:	7f 2a                	jg     40ea42 <win+0xd4cc>
  40ea18:	e8 63 27 ff ff       	call   401180 <__errno_location@plt>
  40ea1d:	8b 38                	mov    edi,DWORD PTR [rax]
  40ea1f:	e8 5c 28 ff ff       	call   401280 <strerror@plt>
  40ea24:	bf 01 00 00 00       	mov    edi,0x1
  40ea29:	48 8d 35 79 36 00 00 	lea    rsi,[rip+0x3679]        # 4120a9 <_IO_stdin_used+0xa9>
  40ea30:	48 89 c2             	mov    rdx,rax
  40ea33:	31 c0                	xor    eax,eax
  40ea35:	e8 f6 27 ff ff       	call   401230 <__printf_chk@plt>
  40ea3a:	83 cf ff             	or     edi,0xffffffff
  40ea3d:	e8 1e 28 ff ff       	call   401260 <exit@plt>
  40ea42:	48 63 d0             	movsxd rdx,eax
  40ea45:	48 89 ee             	mov    rsi,rbp
  40ea48:	bf 01 00 00 00       	mov    edi,0x1
  40ea4d:	e8 4e 27 ff ff       	call   4011a0 <write@plt>
  40ea52:	48 8d 3d fb 36 00 00 	lea    rdi,[rip+0x36fb]        # 412154 <_IO_stdin_used+0x154>
  40ea59:	e8 32 27 ff ff       	call   401190 <puts@plt>
  40ea5e:	48 8d 3d 9f 35 00 00 	lea    rdi,[rip+0x359f]        # 412004 <_IO_stdin_used+0x4>
  40ea65:	31 f6                	xor    esi,esi
  40ea67:	31 c0                	xor    eax,eax
  40ea69:	e8 e2 27 ff ff       	call   401250 <open@plt>
  40ea6e:	89 c7                	mov    edi,eax
  40ea70:	85 c0                	test   eax,eax
  40ea72:	79 34                	jns    40eaa8 <win+0xd532>
  40ea74:	e8 07 27 ff ff       	call   401180 <__errno_location@plt>
  40ea79:	8b 38                	mov    edi,DWORD PTR [rax]
  40ea7b:	e8 00 28 ff ff       	call   401280 <strerror@plt>
  40ea80:	48 8d 35 83 35 00 00 	lea    rsi,[rip+0x3583]        # 41200a <_IO_stdin_used+0xa>
  40ea87:	bf 01 00 00 00       	mov    edi,0x1
  40ea8c:	48 89 c2             	mov    rdx,rax
  40ea8f:	31 c0                	xor    eax,eax
  40ea91:	e8 9a 27 ff ff       	call   401230 <__printf_chk@plt>
  40ea96:	e8 45 27 ff ff       	call   4011e0 <geteuid@plt>
  40ea9b:	85 c0                	test   eax,eax
  40ea9d:	0f 84 36 2b ff ff    	je     4015d9 <win+0x63>
  40eaa3:	e9 19 2b ff ff       	jmp    4015c1 <win+0x4b>
  40eaa8:	ba 00 01 00 00       	mov    edx,0x100
  40eaad:	48 89 ee             	mov    rsi,rbp
  40eab0:	e8 4b 27 ff ff       	call   401200 <read@plt>
  40eab5:	85 c0                	test   eax,eax
  40eab7:	7f 2a                	jg     40eae3 <win+0xd56d>
  40eab9:	e8 c2 26 ff ff       	call   401180 <__errno_location@plt>
  40eabe:	8b 38                	mov    edi,DWORD PTR [rax]
  40eac0:	e8 bb 27 ff ff       	call   401280 <strerror@plt>
  40eac5:	bf 01 00 00 00       	mov    edi,0x1
  40eaca:	48 8d 35 d8 35 00 00 	lea    rsi,[rip+0x35d8]        # 4120a9 <_IO_stdin_used+0xa9>
  40ead1:	48 89 c2             	mov    rdx,rax
  40ead4:	31 c0                	xor    eax,eax
  40ead6:	e8 55 27 ff ff       	call   401230 <__printf_chk@plt>
  40eadb:	83 cf ff             	or     edi,0xffffffff
  40eade:	e8 7d 27 ff ff       	call   401260 <exit@plt>
  40eae3:	48 63 d0             	movsxd rdx,eax
  40eae6:	48 89 ee             	mov    rsi,rbp
  40eae9:	bf 01 00 00 00       	mov    edi,0x1
  40eaee:	e8 ad 26 ff ff       	call   4011a0 <write@plt>
  40eaf3:	48 8d 3d 5a 36 00 00 	lea    rdi,[rip+0x365a]        # 412154 <_IO_stdin_used+0x154>
  40eafa:	e8 91 26 ff ff       	call   401190 <puts@plt>
  40eaff:	48 8d 3d fe 34 00 00 	lea    rdi,[rip+0x34fe]        # 412004 <_IO_stdin_used+0x4>
  40eb06:	31 f6                	xor    esi,esi
  40eb08:	31 c0                	xor    eax,eax
  40eb0a:	e8 41 27 ff ff       	call   401250 <open@plt>
  40eb0f:	89 c7                	mov    edi,eax
  40eb11:	85 c0                	test   eax,eax
  40eb13:	79 34                	jns    40eb49 <win+0xd5d3>
  40eb15:	e8 66 26 ff ff       	call   401180 <__errno_location@plt>
  40eb1a:	8b 38                	mov    edi,DWORD PTR [rax]
  40eb1c:	e8 5f 27 ff ff       	call   401280 <strerror@plt>
  40eb21:	48 8d 35 e2 34 00 00 	lea    rsi,[rip+0x34e2]        # 41200a <_IO_stdin_used+0xa>
  40eb28:	bf 01 00 00 00       	mov    edi,0x1
  40eb2d:	48 89 c2             	mov    rdx,rax
  40eb30:	31 c0                	xor    eax,eax
  40eb32:	e8 f9 26 ff ff       	call   401230 <__printf_chk@plt>
  40eb37:	e8 a4 26 ff ff       	call   4011e0 <geteuid@plt>
  40eb3c:	85 c0                	test   eax,eax
  40eb3e:	0f 84 95 2a ff ff    	je     4015d9 <win+0x63>
  40eb44:	e9 78 2a ff ff       	jmp    4015c1 <win+0x4b>
  40eb49:	ba 00 01 00 00       	mov    edx,0x100
  40eb4e:	48 89 ee             	mov    rsi,rbp
  40eb51:	e8 aa 26 ff ff       	call   401200 <read@plt>
  40eb56:	85 c0                	test   eax,eax
  40eb58:	7f 2a                	jg     40eb84 <win+0xd60e>
  40eb5a:	e8 21 26 ff ff       	call   401180 <__errno_location@plt>
  40eb5f:	8b 38                	mov    edi,DWORD PTR [rax]
  40eb61:	e8 1a 27 ff ff       	call   401280 <strerror@plt>
  40eb66:	bf 01 00 00 00       	mov    edi,0x1
  40eb6b:	48 8d 35 37 35 00 00 	lea    rsi,[rip+0x3537]        # 4120a9 <_IO_stdin_used+0xa9>
  40eb72:	48 89 c2             	mov    rdx,rax
  40eb75:	31 c0                	xor    eax,eax
  40eb77:	e8 b4 26 ff ff       	call   401230 <__printf_chk@plt>
  40eb7c:	83 cf ff             	or     edi,0xffffffff
  40eb7f:	e8 dc 26 ff ff       	call   401260 <exit@plt>
  40eb84:	48 89 e5             	mov    rbp,rsp
  40eb87:	48 63 d0             	movsxd rdx,eax
  40eb8a:	bf 01 00 00 00       	mov    edi,0x1
  40eb8f:	48 89 ee             	mov    rsi,rbp
  40eb92:	e8 09 26 ff ff       	call   4011a0 <write@plt>
  40eb97:	48 8d 3d b6 35 00 00 	lea    rdi,[rip+0x35b6]        # 412154 <_IO_stdin_used+0x154>
  40eb9e:	e8 ed 25 ff ff       	call   401190 <puts@plt>
  40eba3:	48 8d 3d 5a 34 00 00 	lea    rdi,[rip+0x345a]        # 412004 <_IO_stdin_used+0x4>
  40ebaa:	31 f6                	xor    esi,esi
  40ebac:	31 c0                	xor    eax,eax
  40ebae:	e8 9d 26 ff ff       	call   401250 <open@plt>
  40ebb3:	89 c7                	mov    edi,eax
  40ebb5:	85 c0                	test   eax,eax
  40ebb7:	79 34                	jns    40ebed <win+0xd677>
  40ebb9:	e8 c2 25 ff ff       	call   401180 <__errno_location@plt>
  40ebbe:	8b 38                	mov    edi,DWORD PTR [rax]
  40ebc0:	e8 bb 26 ff ff       	call   401280 <strerror@plt>
  40ebc5:	48 8d 35 3e 34 00 00 	lea    rsi,[rip+0x343e]        # 41200a <_IO_stdin_used+0xa>
  40ebcc:	bf 01 00 00 00       	mov    edi,0x1
  40ebd1:	48 89 c2             	mov    rdx,rax
  40ebd4:	31 c0                	xor    eax,eax
  40ebd6:	e8 55 26 ff ff       	call   401230 <__printf_chk@plt>
  40ebdb:	e8 00 26 ff ff       	call   4011e0 <geteuid@plt>
  40ebe0:	85 c0                	test   eax,eax
  40ebe2:	0f 84 f1 29 ff ff    	je     4015d9 <win+0x63>
  40ebe8:	e9 d4 29 ff ff       	jmp    4015c1 <win+0x4b>
  40ebed:	ba 00 01 00 00       	mov    edx,0x100
  40ebf2:	48 89 ee             	mov    rsi,rbp
  40ebf5:	e8 06 26 ff ff       	call   401200 <read@plt>
  40ebfa:	85 c0                	test   eax,eax
  40ebfc:	7f 2a                	jg     40ec28 <win+0xd6b2>
  40ebfe:	e8 7d 25 ff ff       	call   401180 <__errno_location@plt>
  40ec03:	8b 38                	mov    edi,DWORD PTR [rax]
  40ec05:	e8 76 26 ff ff       	call   401280 <strerror@plt>
  40ec0a:	bf 01 00 00 00       	mov    edi,0x1
  40ec0f:	48 8d 35 93 34 00 00 	lea    rsi,[rip+0x3493]        # 4120a9 <_IO_stdin_used+0xa9>
  40ec16:	48 89 c2             	mov    rdx,rax
  40ec19:	31 c0                	xor    eax,eax
  40ec1b:	e8 10 26 ff ff       	call   401230 <__printf_chk@plt>
  40ec20:	83 cf ff             	or     edi,0xffffffff
  40ec23:	e8 38 26 ff ff       	call   401260 <exit@plt>
  40ec28:	48 63 d0             	movsxd rdx,eax
  40ec2b:	48 89 ee             	mov    rsi,rbp
  40ec2e:	bf 01 00 00 00       	mov    edi,0x1
  40ec33:	e8 68 25 ff ff       	call   4011a0 <write@plt>
  40ec38:	48 8d 3d 15 35 00 00 	lea    rdi,[rip+0x3515]        # 412154 <_IO_stdin_used+0x154>
  40ec3f:	e8 4c 25 ff ff       	call   401190 <puts@plt>
  40ec44:	48 8d 3d b9 33 00 00 	lea    rdi,[rip+0x33b9]        # 412004 <_IO_stdin_used+0x4>
  40ec4b:	31 f6                	xor    esi,esi
  40ec4d:	31 c0                	xor    eax,eax
  40ec4f:	e8 fc 25 ff ff       	call   401250 <open@plt>
  40ec54:	89 c7                	mov    edi,eax
  40ec56:	85 c0                	test   eax,eax
  40ec58:	79 34                	jns    40ec8e <win+0xd718>
  40ec5a:	e8 21 25 ff ff       	call   401180 <__errno_location@plt>
  40ec5f:	8b 38                	mov    edi,DWORD PTR [rax]
  40ec61:	e8 1a 26 ff ff       	call   401280 <strerror@plt>
  40ec66:	48 8d 35 9d 33 00 00 	lea    rsi,[rip+0x339d]        # 41200a <_IO_stdin_used+0xa>
  40ec6d:	bf 01 00 00 00       	mov    edi,0x1
  40ec72:	48 89 c2             	mov    rdx,rax
  40ec75:	31 c0                	xor    eax,eax
  40ec77:	e8 b4 25 ff ff       	call   401230 <__printf_chk@plt>
  40ec7c:	e8 5f 25 ff ff       	call   4011e0 <geteuid@plt>
  40ec81:	85 c0                	test   eax,eax
  40ec83:	0f 84 50 29 ff ff    	je     4015d9 <win+0x63>
  40ec89:	e9 33 29 ff ff       	jmp    4015c1 <win+0x4b>
  40ec8e:	ba 00 01 00 00       	mov    edx,0x100
  40ec93:	48 89 ee             	mov    rsi,rbp
  40ec96:	e8 65 25 ff ff       	call   401200 <read@plt>
  40ec9b:	85 c0                	test   eax,eax
  40ec9d:	7f 2a                	jg     40ecc9 <win+0xd753>
  40ec9f:	e8 dc 24 ff ff       	call   401180 <__errno_location@plt>
  40eca4:	8b 38                	mov    edi,DWORD PTR [rax]
  40eca6:	e8 d5 25 ff ff       	call   401280 <strerror@plt>
  40ecab:	bf 01 00 00 00       	mov    edi,0x1
  40ecb0:	48 8d 35 f2 33 00 00 	lea    rsi,[rip+0x33f2]        # 4120a9 <_IO_stdin_used+0xa9>
  40ecb7:	48 89 c2             	mov    rdx,rax
  40ecba:	31 c0                	xor    eax,eax
  40ecbc:	e8 6f 25 ff ff       	call   401230 <__printf_chk@plt>
  40ecc1:	83 cf ff             	or     edi,0xffffffff
  40ecc4:	e8 97 25 ff ff       	call   401260 <exit@plt>
  40ecc9:	48 63 d0             	movsxd rdx,eax
  40eccc:	48 89 ee             	mov    rsi,rbp
  40eccf:	bf 01 00 00 00       	mov    edi,0x1
  40ecd4:	e8 c7 24 ff ff       	call   4011a0 <write@plt>
  40ecd9:	48 8d 3d 74 34 00 00 	lea    rdi,[rip+0x3474]        # 412154 <_IO_stdin_used+0x154>
  40ece0:	e8 ab 24 ff ff       	call   401190 <puts@plt>
  40ece5:	48 8d 3d 18 33 00 00 	lea    rdi,[rip+0x3318]        # 412004 <_IO_stdin_used+0x4>
  40ecec:	31 f6                	xor    esi,esi
  40ecee:	31 c0                	xor    eax,eax
  40ecf0:	e8 5b 25 ff ff       	call   401250 <open@plt>
  40ecf5:	89 c7                	mov    edi,eax
  40ecf7:	85 c0                	test   eax,eax
  40ecf9:	79 34                	jns    40ed2f <win+0xd7b9>
  40ecfb:	e8 80 24 ff ff       	call   401180 <__errno_location@plt>
  40ed00:	8b 38                	mov    edi,DWORD PTR [rax]
  40ed02:	e8 79 25 ff ff       	call   401280 <strerror@plt>
  40ed07:	48 8d 35 fc 32 00 00 	lea    rsi,[rip+0x32fc]        # 41200a <_IO_stdin_used+0xa>
  40ed0e:	bf 01 00 00 00       	mov    edi,0x1
  40ed13:	48 89 c2             	mov    rdx,rax
  40ed16:	31 c0                	xor    eax,eax
  40ed18:	e8 13 25 ff ff       	call   401230 <__printf_chk@plt>
  40ed1d:	e8 be 24 ff ff       	call   4011e0 <geteuid@plt>
  40ed22:	85 c0                	test   eax,eax
  40ed24:	0f 84 af 28 ff ff    	je     4015d9 <win+0x63>
  40ed2a:	e9 92 28 ff ff       	jmp    4015c1 <win+0x4b>
  40ed2f:	ba 00 01 00 00       	mov    edx,0x100
  40ed34:	48 89 ee             	mov    rsi,rbp
  40ed37:	e8 c4 24 ff ff       	call   401200 <read@plt>
  40ed3c:	85 c0                	test   eax,eax
  40ed3e:	7f 2a                	jg     40ed6a <win+0xd7f4>
  40ed40:	e8 3b 24 ff ff       	call   401180 <__errno_location@plt>
  40ed45:	8b 38                	mov    edi,DWORD PTR [rax]
  40ed47:	e8 34 25 ff ff       	call   401280 <strerror@plt>
  40ed4c:	bf 01 00 00 00       	mov    edi,0x1
  40ed51:	48 8d 35 51 33 00 00 	lea    rsi,[rip+0x3351]        # 4120a9 <_IO_stdin_used+0xa9>
  40ed58:	48 89 c2             	mov    rdx,rax
  40ed5b:	31 c0                	xor    eax,eax
  40ed5d:	e8 ce 24 ff ff       	call   401230 <__printf_chk@plt>
  40ed62:	83 cf ff             	or     edi,0xffffffff
  40ed65:	e8 f6 24 ff ff       	call   401260 <exit@plt>
  40ed6a:	48 63 d0             	movsxd rdx,eax
  40ed6d:	48 89 ee             	mov    rsi,rbp
  40ed70:	bf 01 00 00 00       	mov    edi,0x1
  40ed75:	e8 26 24 ff ff       	call   4011a0 <write@plt>
  40ed7a:	48 8d 3d d3 33 00 00 	lea    rdi,[rip+0x33d3]        # 412154 <_IO_stdin_used+0x154>
  40ed81:	e8 0a 24 ff ff       	call   401190 <puts@plt>
  40ed86:	48 8d 3d 77 32 00 00 	lea    rdi,[rip+0x3277]        # 412004 <_IO_stdin_used+0x4>
  40ed8d:	31 f6                	xor    esi,esi
  40ed8f:	31 c0                	xor    eax,eax
  40ed91:	e8 ba 24 ff ff       	call   401250 <open@plt>
  40ed96:	89 c7                	mov    edi,eax
  40ed98:	85 c0                	test   eax,eax
  40ed9a:	79 34                	jns    40edd0 <win+0xd85a>
  40ed9c:	e8 df 23 ff ff       	call   401180 <__errno_location@plt>
  40eda1:	8b 38                	mov    edi,DWORD PTR [rax]
  40eda3:	e8 d8 24 ff ff       	call   401280 <strerror@plt>
  40eda8:	48 8d 35 5b 32 00 00 	lea    rsi,[rip+0x325b]        # 41200a <_IO_stdin_used+0xa>
  40edaf:	bf 01 00 00 00       	mov    edi,0x1
  40edb4:	48 89 c2             	mov    rdx,rax
  40edb7:	31 c0                	xor    eax,eax
  40edb9:	e8 72 24 ff ff       	call   401230 <__printf_chk@plt>
  40edbe:	e8 1d 24 ff ff       	call   4011e0 <geteuid@plt>
  40edc3:	85 c0                	test   eax,eax
  40edc5:	0f 84 0e 28 ff ff    	je     4015d9 <win+0x63>
  40edcb:	e9 f1 27 ff ff       	jmp    4015c1 <win+0x4b>
  40edd0:	ba 00 01 00 00       	mov    edx,0x100
  40edd5:	48 89 ee             	mov    rsi,rbp
  40edd8:	e8 23 24 ff ff       	call   401200 <read@plt>
  40eddd:	85 c0                	test   eax,eax
  40eddf:	7f 2a                	jg     40ee0b <win+0xd895>
  40ede1:	e8 9a 23 ff ff       	call   401180 <__errno_location@plt>
  40ede6:	8b 38                	mov    edi,DWORD PTR [rax]
  40ede8:	e8 93 24 ff ff       	call   401280 <strerror@plt>
  40eded:	bf 01 00 00 00       	mov    edi,0x1
  40edf2:	48 8d 35 b0 32 00 00 	lea    rsi,[rip+0x32b0]        # 4120a9 <_IO_stdin_used+0xa9>
  40edf9:	48 89 c2             	mov    rdx,rax
  40edfc:	31 c0                	xor    eax,eax
  40edfe:	e8 2d 24 ff ff       	call   401230 <__printf_chk@plt>
  40ee03:	83 cf ff             	or     edi,0xffffffff
  40ee06:	e8 55 24 ff ff       	call   401260 <exit@plt>
  40ee0b:	48 63 d0             	movsxd rdx,eax
  40ee0e:	48 89 ee             	mov    rsi,rbp
  40ee11:	bf 01 00 00 00       	mov    edi,0x1
  40ee16:	e8 85 23 ff ff       	call   4011a0 <write@plt>
  40ee1b:	48 8d 3d 32 33 00 00 	lea    rdi,[rip+0x3332]        # 412154 <_IO_stdin_used+0x154>
  40ee22:	e8 69 23 ff ff       	call   401190 <puts@plt>
  40ee27:	48 8d 3d d6 31 00 00 	lea    rdi,[rip+0x31d6]        # 412004 <_IO_stdin_used+0x4>
  40ee2e:	31 f6                	xor    esi,esi
  40ee30:	31 c0                	xor    eax,eax
  40ee32:	e8 19 24 ff ff       	call   401250 <open@plt>
  40ee37:	89 c7                	mov    edi,eax
  40ee39:	85 c0                	test   eax,eax
  40ee3b:	79 34                	jns    40ee71 <win+0xd8fb>
  40ee3d:	e8 3e 23 ff ff       	call   401180 <__errno_location@plt>
  40ee42:	8b 38                	mov    edi,DWORD PTR [rax]
  40ee44:	e8 37 24 ff ff       	call   401280 <strerror@plt>
  40ee49:	48 8d 35 ba 31 00 00 	lea    rsi,[rip+0x31ba]        # 41200a <_IO_stdin_used+0xa>
  40ee50:	bf 01 00 00 00       	mov    edi,0x1
  40ee55:	48 89 c2             	mov    rdx,rax
  40ee58:	31 c0                	xor    eax,eax
  40ee5a:	e8 d1 23 ff ff       	call   401230 <__printf_chk@plt>
  40ee5f:	e8 7c 23 ff ff       	call   4011e0 <geteuid@plt>
  40ee64:	85 c0                	test   eax,eax
  40ee66:	0f 84 6d 27 ff ff    	je     4015d9 <win+0x63>
  40ee6c:	e9 50 27 ff ff       	jmp    4015c1 <win+0x4b>
  40ee71:	ba 00 01 00 00       	mov    edx,0x100
  40ee76:	48 89 ee             	mov    rsi,rbp
  40ee79:	e8 82 23 ff ff       	call   401200 <read@plt>
  40ee7e:	85 c0                	test   eax,eax
  40ee80:	7f 2a                	jg     40eeac <win+0xd936>
  40ee82:	e8 f9 22 ff ff       	call   401180 <__errno_location@plt>
  40ee87:	8b 38                	mov    edi,DWORD PTR [rax]
  40ee89:	e8 f2 23 ff ff       	call   401280 <strerror@plt>
  40ee8e:	bf 01 00 00 00       	mov    edi,0x1
  40ee93:	48 8d 35 0f 32 00 00 	lea    rsi,[rip+0x320f]        # 4120a9 <_IO_stdin_used+0xa9>
  40ee9a:	48 89 c2             	mov    rdx,rax
  40ee9d:	31 c0                	xor    eax,eax
  40ee9f:	e8 8c 23 ff ff       	call   401230 <__printf_chk@plt>
  40eea4:	83 cf ff             	or     edi,0xffffffff
  40eea7:	e8 b4 23 ff ff       	call   401260 <exit@plt>
  40eeac:	48 63 d0             	movsxd rdx,eax
  40eeaf:	48 89 ee             	mov    rsi,rbp
  40eeb2:	bf 01 00 00 00       	mov    edi,0x1
  40eeb7:	e8 e4 22 ff ff       	call   4011a0 <write@plt>
  40eebc:	48 8d 3d 91 32 00 00 	lea    rdi,[rip+0x3291]        # 412154 <_IO_stdin_used+0x154>
  40eec3:	e8 c8 22 ff ff       	call   401190 <puts@plt>
  40eec8:	48 8d 3d 35 31 00 00 	lea    rdi,[rip+0x3135]        # 412004 <_IO_stdin_used+0x4>
  40eecf:	31 f6                	xor    esi,esi
  40eed1:	31 c0                	xor    eax,eax
  40eed3:	e8 78 23 ff ff       	call   401250 <open@plt>
  40eed8:	89 c7                	mov    edi,eax
  40eeda:	85 c0                	test   eax,eax
  40eedc:	79 34                	jns    40ef12 <win+0xd99c>
  40eede:	e8 9d 22 ff ff       	call   401180 <__errno_location@plt>
  40eee3:	8b 38                	mov    edi,DWORD PTR [rax]
  40eee5:	e8 96 23 ff ff       	call   401280 <strerror@plt>
  40eeea:	48 8d 35 19 31 00 00 	lea    rsi,[rip+0x3119]        # 41200a <_IO_stdin_used+0xa>
  40eef1:	bf 01 00 00 00       	mov    edi,0x1
  40eef6:	48 89 c2             	mov    rdx,rax
  40eef9:	31 c0                	xor    eax,eax
  40eefb:	e8 30 23 ff ff       	call   401230 <__printf_chk@plt>
  40ef00:	e8 db 22 ff ff       	call   4011e0 <geteuid@plt>
  40ef05:	85 c0                	test   eax,eax
  40ef07:	0f 84 cc 26 ff ff    	je     4015d9 <win+0x63>
  40ef0d:	e9 af 26 ff ff       	jmp    4015c1 <win+0x4b>
  40ef12:	ba 00 01 00 00       	mov    edx,0x100
  40ef17:	48 89 ee             	mov    rsi,rbp
  40ef1a:	e8 e1 22 ff ff       	call   401200 <read@plt>
  40ef1f:	85 c0                	test   eax,eax
  40ef21:	7f 2a                	jg     40ef4d <win+0xd9d7>
  40ef23:	e8 58 22 ff ff       	call   401180 <__errno_location@plt>
  40ef28:	8b 38                	mov    edi,DWORD PTR [rax]
  40ef2a:	e8 51 23 ff ff       	call   401280 <strerror@plt>
  40ef2f:	bf 01 00 00 00       	mov    edi,0x1
  40ef34:	48 8d 35 6e 31 00 00 	lea    rsi,[rip+0x316e]        # 4120a9 <_IO_stdin_used+0xa9>
  40ef3b:	48 89 c2             	mov    rdx,rax
  40ef3e:	31 c0                	xor    eax,eax
  40ef40:	e8 eb 22 ff ff       	call   401230 <__printf_chk@plt>
  40ef45:	83 cf ff             	or     edi,0xffffffff
  40ef48:	e8 13 23 ff ff       	call   401260 <exit@plt>
  40ef4d:	48 63 d0             	movsxd rdx,eax
  40ef50:	48 89 ee             	mov    rsi,rbp
  40ef53:	bf 01 00 00 00       	mov    edi,0x1
  40ef58:	e8 43 22 ff ff       	call   4011a0 <write@plt>
  40ef5d:	48 8d 3d f0 31 00 00 	lea    rdi,[rip+0x31f0]        # 412154 <_IO_stdin_used+0x154>
  40ef64:	e8 27 22 ff ff       	call   401190 <puts@plt>
  40ef69:	48 8d 3d 94 30 00 00 	lea    rdi,[rip+0x3094]        # 412004 <_IO_stdin_used+0x4>
  40ef70:	31 f6                	xor    esi,esi
  40ef72:	31 c0                	xor    eax,eax
  40ef74:	e8 d7 22 ff ff       	call   401250 <open@plt>
  40ef79:	89 c7                	mov    edi,eax
  40ef7b:	85 c0                	test   eax,eax
  40ef7d:	79 34                	jns    40efb3 <win+0xda3d>
  40ef7f:	e8 fc 21 ff ff       	call   401180 <__errno_location@plt>
  40ef84:	8b 38                	mov    edi,DWORD PTR [rax]
  40ef86:	e8 f5 22 ff ff       	call   401280 <strerror@plt>
  40ef8b:	48 8d 35 78 30 00 00 	lea    rsi,[rip+0x3078]        # 41200a <_IO_stdin_used+0xa>
  40ef92:	bf 01 00 00 00       	mov    edi,0x1
  40ef97:	48 89 c2             	mov    rdx,rax
  40ef9a:	31 c0                	xor    eax,eax
  40ef9c:	e8 8f 22 ff ff       	call   401230 <__printf_chk@plt>
  40efa1:	e8 3a 22 ff ff       	call   4011e0 <geteuid@plt>
  40efa6:	85 c0                	test   eax,eax
  40efa8:	0f 84 2b 26 ff ff    	je     4015d9 <win+0x63>
  40efae:	e9 0e 26 ff ff       	jmp    4015c1 <win+0x4b>
  40efb3:	ba 00 01 00 00       	mov    edx,0x100
  40efb8:	48 89 ee             	mov    rsi,rbp
  40efbb:	e8 40 22 ff ff       	call   401200 <read@plt>
  40efc0:	85 c0                	test   eax,eax
  40efc2:	7f 2a                	jg     40efee <win+0xda78>
  40efc4:	e8 b7 21 ff ff       	call   401180 <__errno_location@plt>
  40efc9:	8b 38                	mov    edi,DWORD PTR [rax]
  40efcb:	e8 b0 22 ff ff       	call   401280 <strerror@plt>
  40efd0:	bf 01 00 00 00       	mov    edi,0x1
  40efd5:	48 8d 35 cd 30 00 00 	lea    rsi,[rip+0x30cd]        # 4120a9 <_IO_stdin_used+0xa9>
  40efdc:	48 89 c2             	mov    rdx,rax
  40efdf:	31 c0                	xor    eax,eax
  40efe1:	e8 4a 22 ff ff       	call   401230 <__printf_chk@plt>
  40efe6:	83 cf ff             	or     edi,0xffffffff
  40efe9:	e8 72 22 ff ff       	call   401260 <exit@plt>
  40efee:	48 63 d0             	movsxd rdx,eax
  40eff1:	48 89 ee             	mov    rsi,rbp
  40eff4:	bf 01 00 00 00       	mov    edi,0x1
  40eff9:	e8 a2 21 ff ff       	call   4011a0 <write@plt>
  40effe:	48 8d 3d 4f 31 00 00 	lea    rdi,[rip+0x314f]        # 412154 <_IO_stdin_used+0x154>
  40f005:	e8 86 21 ff ff       	call   401190 <puts@plt>
  40f00a:	48 8d 3d f3 2f 00 00 	lea    rdi,[rip+0x2ff3]        # 412004 <_IO_stdin_used+0x4>
  40f011:	31 f6                	xor    esi,esi
  40f013:	31 c0                	xor    eax,eax
  40f015:	e8 36 22 ff ff       	call   401250 <open@plt>
  40f01a:	89 c7                	mov    edi,eax
  40f01c:	85 c0                	test   eax,eax
  40f01e:	79 34                	jns    40f054 <win+0xdade>
  40f020:	e8 5b 21 ff ff       	call   401180 <__errno_location@plt>
  40f025:	8b 38                	mov    edi,DWORD PTR [rax]
  40f027:	e8 54 22 ff ff       	call   401280 <strerror@plt>
  40f02c:	48 8d 35 d7 2f 00 00 	lea    rsi,[rip+0x2fd7]        # 41200a <_IO_stdin_used+0xa>
  40f033:	bf 01 00 00 00       	mov    edi,0x1
  40f038:	48 89 c2             	mov    rdx,rax
  40f03b:	31 c0                	xor    eax,eax
  40f03d:	e8 ee 21 ff ff       	call   401230 <__printf_chk@plt>
  40f042:	e8 99 21 ff ff       	call   4011e0 <geteuid@plt>
  40f047:	85 c0                	test   eax,eax
  40f049:	0f 84 8a 25 ff ff    	je     4015d9 <win+0x63>
  40f04f:	e9 6d 25 ff ff       	jmp    4015c1 <win+0x4b>
  40f054:	ba 00 01 00 00       	mov    edx,0x100
  40f059:	48 89 ee             	mov    rsi,rbp
  40f05c:	e8 9f 21 ff ff       	call   401200 <read@plt>
  40f061:	85 c0                	test   eax,eax
  40f063:	7f 2a                	jg     40f08f <win+0xdb19>
  40f065:	e8 16 21 ff ff       	call   401180 <__errno_location@plt>
  40f06a:	8b 38                	mov    edi,DWORD PTR [rax]
  40f06c:	e8 0f 22 ff ff       	call   401280 <strerror@plt>
  40f071:	bf 01 00 00 00       	mov    edi,0x1
  40f076:	48 8d 35 2c 30 00 00 	lea    rsi,[rip+0x302c]        # 4120a9 <_IO_stdin_used+0xa9>
  40f07d:	48 89 c2             	mov    rdx,rax
  40f080:	31 c0                	xor    eax,eax
  40f082:	e8 a9 21 ff ff       	call   401230 <__printf_chk@plt>
  40f087:	83 cf ff             	or     edi,0xffffffff
  40f08a:	e8 d1 21 ff ff       	call   401260 <exit@plt>
  40f08f:	48 63 d0             	movsxd rdx,eax
  40f092:	48 89 ee             	mov    rsi,rbp
  40f095:	bf 01 00 00 00       	mov    edi,0x1
  40f09a:	e8 01 21 ff ff       	call   4011a0 <write@plt>
  40f09f:	48 8d 3d ae 30 00 00 	lea    rdi,[rip+0x30ae]        # 412154 <_IO_stdin_used+0x154>
  40f0a6:	e8 e5 20 ff ff       	call   401190 <puts@plt>
  40f0ab:	48 8d 3d 52 2f 00 00 	lea    rdi,[rip+0x2f52]        # 412004 <_IO_stdin_used+0x4>
  40f0b2:	31 f6                	xor    esi,esi
  40f0b4:	31 c0                	xor    eax,eax
  40f0b6:	e8 95 21 ff ff       	call   401250 <open@plt>
  40f0bb:	89 c7                	mov    edi,eax
  40f0bd:	85 c0                	test   eax,eax
  40f0bf:	79 34                	jns    40f0f5 <win+0xdb7f>
  40f0c1:	e8 ba 20 ff ff       	call   401180 <__errno_location@plt>
  40f0c6:	8b 38                	mov    edi,DWORD PTR [rax]
  40f0c8:	e8 b3 21 ff ff       	call   401280 <strerror@plt>
  40f0cd:	48 8d 35 36 2f 00 00 	lea    rsi,[rip+0x2f36]        # 41200a <_IO_stdin_used+0xa>
  40f0d4:	bf 01 00 00 00       	mov    edi,0x1
  40f0d9:	48 89 c2             	mov    rdx,rax
  40f0dc:	31 c0                	xor    eax,eax
  40f0de:	e8 4d 21 ff ff       	call   401230 <__printf_chk@plt>
  40f0e3:	e8 f8 20 ff ff       	call   4011e0 <geteuid@plt>
  40f0e8:	85 c0                	test   eax,eax
  40f0ea:	0f 84 e9 24 ff ff    	je     4015d9 <win+0x63>
  40f0f0:	e9 cc 24 ff ff       	jmp    4015c1 <win+0x4b>
  40f0f5:	ba 00 01 00 00       	mov    edx,0x100
  40f0fa:	48 89 ee             	mov    rsi,rbp
  40f0fd:	e8 fe 20 ff ff       	call   401200 <read@plt>
  40f102:	85 c0                	test   eax,eax
  40f104:	7f 2a                	jg     40f130 <win+0xdbba>
  40f106:	e8 75 20 ff ff       	call   401180 <__errno_location@plt>
  40f10b:	8b 38                	mov    edi,DWORD PTR [rax]
  40f10d:	e8 6e 21 ff ff       	call   401280 <strerror@plt>
  40f112:	bf 01 00 00 00       	mov    edi,0x1
  40f117:	48 8d 35 8b 2f 00 00 	lea    rsi,[rip+0x2f8b]        # 4120a9 <_IO_stdin_used+0xa9>
  40f11e:	48 89 c2             	mov    rdx,rax
  40f121:	31 c0                	xor    eax,eax
  40f123:	e8 08 21 ff ff       	call   401230 <__printf_chk@plt>
  40f128:	83 cf ff             	or     edi,0xffffffff
  40f12b:	e8 30 21 ff ff       	call   401260 <exit@plt>
  40f130:	48 63 d0             	movsxd rdx,eax
  40f133:	48 89 ee             	mov    rsi,rbp
  40f136:	bf 01 00 00 00       	mov    edi,0x1
  40f13b:	e8 60 20 ff ff       	call   4011a0 <write@plt>
  40f140:	48 8d 3d 0d 30 00 00 	lea    rdi,[rip+0x300d]        # 412154 <_IO_stdin_used+0x154>
  40f147:	e8 44 20 ff ff       	call   401190 <puts@plt>
  40f14c:	48 8d 3d b1 2e 00 00 	lea    rdi,[rip+0x2eb1]        # 412004 <_IO_stdin_used+0x4>
  40f153:	31 f6                	xor    esi,esi
  40f155:	31 c0                	xor    eax,eax
  40f157:	e8 f4 20 ff ff       	call   401250 <open@plt>
  40f15c:	89 c7                	mov    edi,eax
  40f15e:	85 c0                	test   eax,eax
  40f160:	79 34                	jns    40f196 <win+0xdc20>
  40f162:	e8 19 20 ff ff       	call   401180 <__errno_location@plt>
  40f167:	8b 38                	mov    edi,DWORD PTR [rax]
  40f169:	e8 12 21 ff ff       	call   401280 <strerror@plt>
  40f16e:	48 8d 35 95 2e 00 00 	lea    rsi,[rip+0x2e95]        # 41200a <_IO_stdin_used+0xa>
  40f175:	bf 01 00 00 00       	mov    edi,0x1
  40f17a:	48 89 c2             	mov    rdx,rax
  40f17d:	31 c0                	xor    eax,eax
  40f17f:	e8 ac 20 ff ff       	call   401230 <__printf_chk@plt>
  40f184:	e8 57 20 ff ff       	call   4011e0 <geteuid@plt>
  40f189:	85 c0                	test   eax,eax
  40f18b:	0f 84 48 24 ff ff    	je     4015d9 <win+0x63>
  40f191:	e9 2b 24 ff ff       	jmp    4015c1 <win+0x4b>
  40f196:	ba 00 01 00 00       	mov    edx,0x100
  40f19b:	48 89 ee             	mov    rsi,rbp
  40f19e:	e8 5d 20 ff ff       	call   401200 <read@plt>
  40f1a3:	85 c0                	test   eax,eax
  40f1a5:	7f 2a                	jg     40f1d1 <win+0xdc5b>
  40f1a7:	e8 d4 1f ff ff       	call   401180 <__errno_location@plt>
  40f1ac:	8b 38                	mov    edi,DWORD PTR [rax]
  40f1ae:	e8 cd 20 ff ff       	call   401280 <strerror@plt>
  40f1b3:	bf 01 00 00 00       	mov    edi,0x1
  40f1b8:	48 8d 35 ea 2e 00 00 	lea    rsi,[rip+0x2eea]        # 4120a9 <_IO_stdin_used+0xa9>
  40f1bf:	48 89 c2             	mov    rdx,rax
  40f1c2:	31 c0                	xor    eax,eax
  40f1c4:	e8 67 20 ff ff       	call   401230 <__printf_chk@plt>
  40f1c9:	83 cf ff             	or     edi,0xffffffff
  40f1cc:	e8 8f 20 ff ff       	call   401260 <exit@plt>
  40f1d1:	48 63 d0             	movsxd rdx,eax
  40f1d4:	48 89 ee             	mov    rsi,rbp
  40f1d7:	bf 01 00 00 00       	mov    edi,0x1
  40f1dc:	e8 bf 1f ff ff       	call   4011a0 <write@plt>
  40f1e1:	48 8d 3d 6c 2f 00 00 	lea    rdi,[rip+0x2f6c]        # 412154 <_IO_stdin_used+0x154>
  40f1e8:	e8 a3 1f ff ff       	call   401190 <puts@plt>
  40f1ed:	48 8d 3d 10 2e 00 00 	lea    rdi,[rip+0x2e10]        # 412004 <_IO_stdin_used+0x4>
  40f1f4:	31 f6                	xor    esi,esi
  40f1f6:	31 c0                	xor    eax,eax
  40f1f8:	e8 53 20 ff ff       	call   401250 <open@plt>
  40f1fd:	89 c7                	mov    edi,eax
  40f1ff:	85 c0                	test   eax,eax
  40f201:	79 34                	jns    40f237 <win+0xdcc1>
  40f203:	e8 78 1f ff ff       	call   401180 <__errno_location@plt>
  40f208:	8b 38                	mov    edi,DWORD PTR [rax]
  40f20a:	e8 71 20 ff ff       	call   401280 <strerror@plt>
  40f20f:	48 8d 35 f4 2d 00 00 	lea    rsi,[rip+0x2df4]        # 41200a <_IO_stdin_used+0xa>
  40f216:	bf 01 00 00 00       	mov    edi,0x1
  40f21b:	48 89 c2             	mov    rdx,rax
  40f21e:	31 c0                	xor    eax,eax
  40f220:	e8 0b 20 ff ff       	call   401230 <__printf_chk@plt>
  40f225:	e8 b6 1f ff ff       	call   4011e0 <geteuid@plt>
  40f22a:	85 c0                	test   eax,eax
  40f22c:	0f 84 a7 23 ff ff    	je     4015d9 <win+0x63>
  40f232:	e9 8a 23 ff ff       	jmp    4015c1 <win+0x4b>
  40f237:	ba 00 01 00 00       	mov    edx,0x100
  40f23c:	48 89 ee             	mov    rsi,rbp
  40f23f:	e8 bc 1f ff ff       	call   401200 <read@plt>
  40f244:	85 c0                	test   eax,eax
  40f246:	7f 2a                	jg     40f272 <win+0xdcfc>
  40f248:	e8 33 1f ff ff       	call   401180 <__errno_location@plt>
  40f24d:	8b 38                	mov    edi,DWORD PTR [rax]
  40f24f:	e8 2c 20 ff ff       	call   401280 <strerror@plt>
  40f254:	bf 01 00 00 00       	mov    edi,0x1
  40f259:	48 8d 35 49 2e 00 00 	lea    rsi,[rip+0x2e49]        # 4120a9 <_IO_stdin_used+0xa9>
  40f260:	48 89 c2             	mov    rdx,rax
  40f263:	31 c0                	xor    eax,eax
  40f265:	e8 c6 1f ff ff       	call   401230 <__printf_chk@plt>
  40f26a:	83 cf ff             	or     edi,0xffffffff
  40f26d:	e8 ee 1f ff ff       	call   401260 <exit@plt>
  40f272:	48 63 d0             	movsxd rdx,eax
  40f275:	48 89 ee             	mov    rsi,rbp
  40f278:	bf 01 00 00 00       	mov    edi,0x1
  40f27d:	e8 1e 1f ff ff       	call   4011a0 <write@plt>
  40f282:	48 8d 3d cb 2e 00 00 	lea    rdi,[rip+0x2ecb]        # 412154 <_IO_stdin_used+0x154>
  40f289:	e8 02 1f ff ff       	call   401190 <puts@plt>
  40f28e:	48 8d 3d 6f 2d 00 00 	lea    rdi,[rip+0x2d6f]        # 412004 <_IO_stdin_used+0x4>
  40f295:	31 f6                	xor    esi,esi
  40f297:	31 c0                	xor    eax,eax
  40f299:	e8 b2 1f ff ff       	call   401250 <open@plt>
  40f29e:	89 c7                	mov    edi,eax
  40f2a0:	85 c0                	test   eax,eax
  40f2a2:	79 34                	jns    40f2d8 <win+0xdd62>
  40f2a4:	e8 d7 1e ff ff       	call   401180 <__errno_location@plt>
  40f2a9:	8b 38                	mov    edi,DWORD PTR [rax]
  40f2ab:	e8 d0 1f ff ff       	call   401280 <strerror@plt>
  40f2b0:	48 8d 35 53 2d 00 00 	lea    rsi,[rip+0x2d53]        # 41200a <_IO_stdin_used+0xa>
  40f2b7:	bf 01 00 00 00       	mov    edi,0x1
  40f2bc:	48 89 c2             	mov    rdx,rax
  40f2bf:	31 c0                	xor    eax,eax
  40f2c1:	e8 6a 1f ff ff       	call   401230 <__printf_chk@plt>
  40f2c6:	e8 15 1f ff ff       	call   4011e0 <geteuid@plt>
  40f2cb:	85 c0                	test   eax,eax
  40f2cd:	0f 84 06 23 ff ff    	je     4015d9 <win+0x63>
  40f2d3:	e9 e9 22 ff ff       	jmp    4015c1 <win+0x4b>
  40f2d8:	ba 00 01 00 00       	mov    edx,0x100
  40f2dd:	48 89 ee             	mov    rsi,rbp
  40f2e0:	e8 1b 1f ff ff       	call   401200 <read@plt>
  40f2e5:	85 c0                	test   eax,eax
  40f2e7:	7f 2a                	jg     40f313 <win+0xdd9d>
  40f2e9:	e8 92 1e ff ff       	call   401180 <__errno_location@plt>
  40f2ee:	8b 38                	mov    edi,DWORD PTR [rax]
  40f2f0:	e8 8b 1f ff ff       	call   401280 <strerror@plt>
  40f2f5:	bf 01 00 00 00       	mov    edi,0x1
  40f2fa:	48 8d 35 a8 2d 00 00 	lea    rsi,[rip+0x2da8]        # 4120a9 <_IO_stdin_used+0xa9>
  40f301:	48 89 c2             	mov    rdx,rax
  40f304:	31 c0                	xor    eax,eax
  40f306:	e8 25 1f ff ff       	call   401230 <__printf_chk@plt>
  40f30b:	83 cf ff             	or     edi,0xffffffff
  40f30e:	e8 4d 1f ff ff       	call   401260 <exit@plt>
  40f313:	48 63 d0             	movsxd rdx,eax
  40f316:	48 89 ee             	mov    rsi,rbp
  40f319:	bf 01 00 00 00       	mov    edi,0x1
  40f31e:	e8 7d 1e ff ff       	call   4011a0 <write@plt>
  40f323:	48 8d 3d 2a 2e 00 00 	lea    rdi,[rip+0x2e2a]        # 412154 <_IO_stdin_used+0x154>
  40f32a:	e8 61 1e ff ff       	call   401190 <puts@plt>
  40f32f:	48 8d 3d ce 2c 00 00 	lea    rdi,[rip+0x2cce]        # 412004 <_IO_stdin_used+0x4>
  40f336:	31 f6                	xor    esi,esi
  40f338:	31 c0                	xor    eax,eax
  40f33a:	e8 11 1f ff ff       	call   401250 <open@plt>
  40f33f:	89 c7                	mov    edi,eax
  40f341:	85 c0                	test   eax,eax
  40f343:	79 34                	jns    40f379 <win+0xde03>
  40f345:	e8 36 1e ff ff       	call   401180 <__errno_location@plt>
  40f34a:	8b 38                	mov    edi,DWORD PTR [rax]
  40f34c:	e8 2f 1f ff ff       	call   401280 <strerror@plt>
  40f351:	48 8d 35 b2 2c 00 00 	lea    rsi,[rip+0x2cb2]        # 41200a <_IO_stdin_used+0xa>
  40f358:	bf 01 00 00 00       	mov    edi,0x1
  40f35d:	48 89 c2             	mov    rdx,rax
  40f360:	31 c0                	xor    eax,eax
  40f362:	e8 c9 1e ff ff       	call   401230 <__printf_chk@plt>
  40f367:	e8 74 1e ff ff       	call   4011e0 <geteuid@plt>
  40f36c:	85 c0                	test   eax,eax
  40f36e:	0f 84 65 22 ff ff    	je     4015d9 <win+0x63>
  40f374:	e9 48 22 ff ff       	jmp    4015c1 <win+0x4b>
  40f379:	ba 00 01 00 00       	mov    edx,0x100
  40f37e:	48 89 ee             	mov    rsi,rbp
  40f381:	e8 7a 1e ff ff       	call   401200 <read@plt>
  40f386:	85 c0                	test   eax,eax
  40f388:	7f 2a                	jg     40f3b4 <win+0xde3e>
  40f38a:	e8 f1 1d ff ff       	call   401180 <__errno_location@plt>
  40f38f:	8b 38                	mov    edi,DWORD PTR [rax]
  40f391:	e8 ea 1e ff ff       	call   401280 <strerror@plt>
  40f396:	bf 01 00 00 00       	mov    edi,0x1
  40f39b:	48 8d 35 07 2d 00 00 	lea    rsi,[rip+0x2d07]        # 4120a9 <_IO_stdin_used+0xa9>
  40f3a2:	48 89 c2             	mov    rdx,rax
  40f3a5:	31 c0                	xor    eax,eax
  40f3a7:	e8 84 1e ff ff       	call   401230 <__printf_chk@plt>
  40f3ac:	83 cf ff             	or     edi,0xffffffff
  40f3af:	e8 ac 1e ff ff       	call   401260 <exit@plt>
  40f3b4:	48 63 d0             	movsxd rdx,eax
  40f3b7:	48 89 ee             	mov    rsi,rbp
  40f3ba:	bf 01 00 00 00       	mov    edi,0x1
  40f3bf:	e8 dc 1d ff ff       	call   4011a0 <write@plt>
  40f3c4:	48 8d 3d 89 2d 00 00 	lea    rdi,[rip+0x2d89]        # 412154 <_IO_stdin_used+0x154>
  40f3cb:	e8 c0 1d ff ff       	call   401190 <puts@plt>
  40f3d0:	48 8d 3d 2d 2c 00 00 	lea    rdi,[rip+0x2c2d]        # 412004 <_IO_stdin_used+0x4>
  40f3d7:	31 f6                	xor    esi,esi
  40f3d9:	31 c0                	xor    eax,eax
  40f3db:	e8 70 1e ff ff       	call   401250 <open@plt>
  40f3e0:	89 c7                	mov    edi,eax
  40f3e2:	85 c0                	test   eax,eax
  40f3e4:	79 34                	jns    40f41a <win+0xdea4>
  40f3e6:	e8 95 1d ff ff       	call   401180 <__errno_location@plt>
  40f3eb:	8b 38                	mov    edi,DWORD PTR [rax]
  40f3ed:	e8 8e 1e ff ff       	call   401280 <strerror@plt>
  40f3f2:	48 8d 35 11 2c 00 00 	lea    rsi,[rip+0x2c11]        # 41200a <_IO_stdin_used+0xa>
  40f3f9:	bf 01 00 00 00       	mov    edi,0x1
  40f3fe:	48 89 c2             	mov    rdx,rax
  40f401:	31 c0                	xor    eax,eax
  40f403:	e8 28 1e ff ff       	call   401230 <__printf_chk@plt>
  40f408:	e8 d3 1d ff ff       	call   4011e0 <geteuid@plt>
  40f40d:	85 c0                	test   eax,eax
  40f40f:	0f 84 c4 21 ff ff    	je     4015d9 <win+0x63>
  40f415:	e9 a7 21 ff ff       	jmp    4015c1 <win+0x4b>
  40f41a:	ba 00 01 00 00       	mov    edx,0x100
  40f41f:	48 89 ee             	mov    rsi,rbp
  40f422:	e8 d9 1d ff ff       	call   401200 <read@plt>
  40f427:	85 c0                	test   eax,eax
  40f429:	7f 2a                	jg     40f455 <win+0xdedf>
  40f42b:	e8 50 1d ff ff       	call   401180 <__errno_location@plt>
  40f430:	8b 38                	mov    edi,DWORD PTR [rax]
  40f432:	e8 49 1e ff ff       	call   401280 <strerror@plt>
  40f437:	bf 01 00 00 00       	mov    edi,0x1
  40f43c:	48 8d 35 66 2c 00 00 	lea    rsi,[rip+0x2c66]        # 4120a9 <_IO_stdin_used+0xa9>
  40f443:	48 89 c2             	mov    rdx,rax
  40f446:	31 c0                	xor    eax,eax
  40f448:	e8 e3 1d ff ff       	call   401230 <__printf_chk@plt>
  40f44d:	83 cf ff             	or     edi,0xffffffff
  40f450:	e8 0b 1e ff ff       	call   401260 <exit@plt>
  40f455:	48 63 d0             	movsxd rdx,eax
  40f458:	48 89 ee             	mov    rsi,rbp
  40f45b:	bf 01 00 00 00       	mov    edi,0x1
  40f460:	e8 3b 1d ff ff       	call   4011a0 <write@plt>
  40f465:	48 8d 3d e8 2c 00 00 	lea    rdi,[rip+0x2ce8]        # 412154 <_IO_stdin_used+0x154>
  40f46c:	e8 1f 1d ff ff       	call   401190 <puts@plt>
  40f471:	48 8d 3d 8c 2b 00 00 	lea    rdi,[rip+0x2b8c]        # 412004 <_IO_stdin_used+0x4>
  40f478:	31 f6                	xor    esi,esi
  40f47a:	31 c0                	xor    eax,eax
  40f47c:	e8 cf 1d ff ff       	call   401250 <open@plt>
  40f481:	89 c7                	mov    edi,eax
  40f483:	85 c0                	test   eax,eax
  40f485:	79 34                	jns    40f4bb <win+0xdf45>
  40f487:	e8 f4 1c ff ff       	call   401180 <__errno_location@plt>
  40f48c:	8b 38                	mov    edi,DWORD PTR [rax]
  40f48e:	e8 ed 1d ff ff       	call   401280 <strerror@plt>
  40f493:	48 8d 35 70 2b 00 00 	lea    rsi,[rip+0x2b70]        # 41200a <_IO_stdin_used+0xa>
  40f49a:	bf 01 00 00 00       	mov    edi,0x1
  40f49f:	48 89 c2             	mov    rdx,rax
  40f4a2:	31 c0                	xor    eax,eax
  40f4a4:	e8 87 1d ff ff       	call   401230 <__printf_chk@plt>
  40f4a9:	e8 32 1d ff ff       	call   4011e0 <geteuid@plt>
  40f4ae:	85 c0                	test   eax,eax
  40f4b0:	0f 84 23 21 ff ff    	je     4015d9 <win+0x63>
  40f4b6:	e9 06 21 ff ff       	jmp    4015c1 <win+0x4b>
  40f4bb:	ba 00 01 00 00       	mov    edx,0x100
  40f4c0:	48 89 ee             	mov    rsi,rbp
  40f4c3:	e8 38 1d ff ff       	call   401200 <read@plt>
  40f4c8:	85 c0                	test   eax,eax
  40f4ca:	7f 2a                	jg     40f4f6 <win+0xdf80>
  40f4cc:	e8 af 1c ff ff       	call   401180 <__errno_location@plt>
  40f4d1:	8b 38                	mov    edi,DWORD PTR [rax]
  40f4d3:	e8 a8 1d ff ff       	call   401280 <strerror@plt>
  40f4d8:	bf 01 00 00 00       	mov    edi,0x1
  40f4dd:	48 8d 35 c5 2b 00 00 	lea    rsi,[rip+0x2bc5]        # 4120a9 <_IO_stdin_used+0xa9>
  40f4e4:	48 89 c2             	mov    rdx,rax
  40f4e7:	31 c0                	xor    eax,eax
  40f4e9:	e8 42 1d ff ff       	call   401230 <__printf_chk@plt>
  40f4ee:	83 cf ff             	or     edi,0xffffffff
  40f4f1:	e8 6a 1d ff ff       	call   401260 <exit@plt>
  40f4f6:	48 63 d0             	movsxd rdx,eax
  40f4f9:	48 89 ee             	mov    rsi,rbp
  40f4fc:	bf 01 00 00 00       	mov    edi,0x1
  40f501:	e8 9a 1c ff ff       	call   4011a0 <write@plt>
  40f506:	48 8d 3d 47 2c 00 00 	lea    rdi,[rip+0x2c47]        # 412154 <_IO_stdin_used+0x154>
  40f50d:	e8 7e 1c ff ff       	call   401190 <puts@plt>
  40f512:	48 8d 3d eb 2a 00 00 	lea    rdi,[rip+0x2aeb]        # 412004 <_IO_stdin_used+0x4>
  40f519:	31 f6                	xor    esi,esi
  40f51b:	31 c0                	xor    eax,eax
  40f51d:	e8 2e 1d ff ff       	call   401250 <open@plt>
  40f522:	89 c7                	mov    edi,eax
  40f524:	85 c0                	test   eax,eax
  40f526:	79 34                	jns    40f55c <win+0xdfe6>
  40f528:	e8 53 1c ff ff       	call   401180 <__errno_location@plt>
  40f52d:	8b 38                	mov    edi,DWORD PTR [rax]
  40f52f:	e8 4c 1d ff ff       	call   401280 <strerror@plt>
  40f534:	48 8d 35 cf 2a 00 00 	lea    rsi,[rip+0x2acf]        # 41200a <_IO_stdin_used+0xa>
  40f53b:	bf 01 00 00 00       	mov    edi,0x1
  40f540:	48 89 c2             	mov    rdx,rax
  40f543:	31 c0                	xor    eax,eax
  40f545:	e8 e6 1c ff ff       	call   401230 <__printf_chk@plt>
  40f54a:	e8 91 1c ff ff       	call   4011e0 <geteuid@plt>
  40f54f:	85 c0                	test   eax,eax
  40f551:	0f 84 82 20 ff ff    	je     4015d9 <win+0x63>
  40f557:	e9 65 20 ff ff       	jmp    4015c1 <win+0x4b>
  40f55c:	ba 00 01 00 00       	mov    edx,0x100
  40f561:	48 89 ee             	mov    rsi,rbp
  40f564:	e8 97 1c ff ff       	call   401200 <read@plt>
  40f569:	85 c0                	test   eax,eax
  40f56b:	7f 2a                	jg     40f597 <win+0xe021>
  40f56d:	e8 0e 1c ff ff       	call   401180 <__errno_location@plt>
  40f572:	8b 38                	mov    edi,DWORD PTR [rax]
  40f574:	e8 07 1d ff ff       	call   401280 <strerror@plt>
  40f579:	bf 01 00 00 00       	mov    edi,0x1
  40f57e:	48 8d 35 24 2b 00 00 	lea    rsi,[rip+0x2b24]        # 4120a9 <_IO_stdin_used+0xa9>
  40f585:	48 89 c2             	mov    rdx,rax
  40f588:	31 c0                	xor    eax,eax
  40f58a:	e8 a1 1c ff ff       	call   401230 <__printf_chk@plt>
  40f58f:	83 cf ff             	or     edi,0xffffffff
  40f592:	e8 c9 1c ff ff       	call   401260 <exit@plt>
  40f597:	48 63 d0             	movsxd rdx,eax
  40f59a:	48 89 ee             	mov    rsi,rbp
  40f59d:	bf 01 00 00 00       	mov    edi,0x1
  40f5a2:	e8 f9 1b ff ff       	call   4011a0 <write@plt>
  40f5a7:	48 8d 3d a6 2b 00 00 	lea    rdi,[rip+0x2ba6]        # 412154 <_IO_stdin_used+0x154>
  40f5ae:	e8 dd 1b ff ff       	call   401190 <puts@plt>
  40f5b3:	48 8d 3d 4a 2a 00 00 	lea    rdi,[rip+0x2a4a]        # 412004 <_IO_stdin_used+0x4>
  40f5ba:	31 f6                	xor    esi,esi
  40f5bc:	31 c0                	xor    eax,eax
  40f5be:	e8 8d 1c ff ff       	call   401250 <open@plt>
  40f5c3:	89 c7                	mov    edi,eax
  40f5c5:	85 c0                	test   eax,eax
  40f5c7:	79 34                	jns    40f5fd <win+0xe087>
  40f5c9:	e8 b2 1b ff ff       	call   401180 <__errno_location@plt>
  40f5ce:	8b 38                	mov    edi,DWORD PTR [rax]
  40f5d0:	e8 ab 1c ff ff       	call   401280 <strerror@plt>
  40f5d5:	48 8d 35 2e 2a 00 00 	lea    rsi,[rip+0x2a2e]        # 41200a <_IO_stdin_used+0xa>
  40f5dc:	bf 01 00 00 00       	mov    edi,0x1
  40f5e1:	48 89 c2             	mov    rdx,rax
  40f5e4:	31 c0                	xor    eax,eax
  40f5e6:	e8 45 1c ff ff       	call   401230 <__printf_chk@plt>
  40f5eb:	e8 f0 1b ff ff       	call   4011e0 <geteuid@plt>
  40f5f0:	85 c0                	test   eax,eax
  40f5f2:	0f 84 e1 1f ff ff    	je     4015d9 <win+0x63>
  40f5f8:	e9 c4 1f ff ff       	jmp    4015c1 <win+0x4b>
  40f5fd:	ba 00 01 00 00       	mov    edx,0x100
  40f602:	48 89 ee             	mov    rsi,rbp
  40f605:	e8 f6 1b ff ff       	call   401200 <read@plt>
  40f60a:	85 c0                	test   eax,eax
  40f60c:	7f 2a                	jg     40f638 <win+0xe0c2>
  40f60e:	e8 6d 1b ff ff       	call   401180 <__errno_location@plt>
  40f613:	8b 38                	mov    edi,DWORD PTR [rax]
  40f615:	e8 66 1c ff ff       	call   401280 <strerror@plt>
  40f61a:	bf 01 00 00 00       	mov    edi,0x1
  40f61f:	48 8d 35 83 2a 00 00 	lea    rsi,[rip+0x2a83]        # 4120a9 <_IO_stdin_used+0xa9>
  40f626:	48 89 c2             	mov    rdx,rax
  40f629:	31 c0                	xor    eax,eax
  40f62b:	e8 00 1c ff ff       	call   401230 <__printf_chk@plt>
  40f630:	83 cf ff             	or     edi,0xffffffff
  40f633:	e8 28 1c ff ff       	call   401260 <exit@plt>
  40f638:	48 63 d0             	movsxd rdx,eax
  40f63b:	48 89 ee             	mov    rsi,rbp
  40f63e:	bf 01 00 00 00       	mov    edi,0x1
  40f643:	e8 58 1b ff ff       	call   4011a0 <write@plt>
  40f648:	48 8d 3d 05 2b 00 00 	lea    rdi,[rip+0x2b05]        # 412154 <_IO_stdin_used+0x154>
  40f64f:	e8 3c 1b ff ff       	call   401190 <puts@plt>
  40f654:	48 8d 3d a9 29 00 00 	lea    rdi,[rip+0x29a9]        # 412004 <_IO_stdin_used+0x4>
  40f65b:	31 f6                	xor    esi,esi
  40f65d:	31 c0                	xor    eax,eax
  40f65f:	e8 ec 1b ff ff       	call   401250 <open@plt>
  40f664:	89 c7                	mov    edi,eax
  40f666:	85 c0                	test   eax,eax
  40f668:	79 34                	jns    40f69e <win+0xe128>
  40f66a:	e8 11 1b ff ff       	call   401180 <__errno_location@plt>
  40f66f:	8b 38                	mov    edi,DWORD PTR [rax]
  40f671:	e8 0a 1c ff ff       	call   401280 <strerror@plt>
  40f676:	48 8d 35 8d 29 00 00 	lea    rsi,[rip+0x298d]        # 41200a <_IO_stdin_used+0xa>
  40f67d:	bf 01 00 00 00       	mov    edi,0x1
  40f682:	48 89 c2             	mov    rdx,rax
  40f685:	31 c0                	xor    eax,eax
  40f687:	e8 a4 1b ff ff       	call   401230 <__printf_chk@plt>
  40f68c:	e8 4f 1b ff ff       	call   4011e0 <geteuid@plt>
  40f691:	85 c0                	test   eax,eax
  40f693:	0f 84 40 1f ff ff    	je     4015d9 <win+0x63>
  40f699:	e9 23 1f ff ff       	jmp    4015c1 <win+0x4b>
  40f69e:	ba 00 01 00 00       	mov    edx,0x100
  40f6a3:	48 89 ee             	mov    rsi,rbp
  40f6a6:	e8 55 1b ff ff       	call   401200 <read@plt>
  40f6ab:	85 c0                	test   eax,eax
  40f6ad:	7f 2a                	jg     40f6d9 <win+0xe163>
  40f6af:	e8 cc 1a ff ff       	call   401180 <__errno_location@plt>
  40f6b4:	8b 38                	mov    edi,DWORD PTR [rax]
  40f6b6:	e8 c5 1b ff ff       	call   401280 <strerror@plt>
  40f6bb:	bf 01 00 00 00       	mov    edi,0x1
  40f6c0:	48 8d 35 e2 29 00 00 	lea    rsi,[rip+0x29e2]        # 4120a9 <_IO_stdin_used+0xa9>
  40f6c7:	48 89 c2             	mov    rdx,rax
  40f6ca:	31 c0                	xor    eax,eax
  40f6cc:	e8 5f 1b ff ff       	call   401230 <__printf_chk@plt>
  40f6d1:	83 cf ff             	or     edi,0xffffffff
  40f6d4:	e8 87 1b ff ff       	call   401260 <exit@plt>
  40f6d9:	48 63 d0             	movsxd rdx,eax
  40f6dc:	48 89 ee             	mov    rsi,rbp
  40f6df:	bf 01 00 00 00       	mov    edi,0x1
  40f6e4:	e8 b7 1a ff ff       	call   4011a0 <write@plt>
  40f6e9:	48 8d 3d 64 2a 00 00 	lea    rdi,[rip+0x2a64]        # 412154 <_IO_stdin_used+0x154>
  40f6f0:	e8 9b 1a ff ff       	call   401190 <puts@plt>
  40f6f5:	48 8d 3d 08 29 00 00 	lea    rdi,[rip+0x2908]        # 412004 <_IO_stdin_used+0x4>
  40f6fc:	31 f6                	xor    esi,esi
  40f6fe:	31 c0                	xor    eax,eax
  40f700:	e8 4b 1b ff ff       	call   401250 <open@plt>
  40f705:	89 c7                	mov    edi,eax
  40f707:	85 c0                	test   eax,eax
  40f709:	79 34                	jns    40f73f <win+0xe1c9>
  40f70b:	e8 70 1a ff ff       	call   401180 <__errno_location@plt>
  40f710:	8b 38                	mov    edi,DWORD PTR [rax]
  40f712:	e8 69 1b ff ff       	call   401280 <strerror@plt>
  40f717:	48 8d 35 ec 28 00 00 	lea    rsi,[rip+0x28ec]        # 41200a <_IO_stdin_used+0xa>
  40f71e:	bf 01 00 00 00       	mov    edi,0x1
  40f723:	48 89 c2             	mov    rdx,rax
  40f726:	31 c0                	xor    eax,eax
  40f728:	e8 03 1b ff ff       	call   401230 <__printf_chk@plt>
  40f72d:	e8 ae 1a ff ff       	call   4011e0 <geteuid@plt>
  40f732:	85 c0                	test   eax,eax
  40f734:	0f 84 9f 1e ff ff    	je     4015d9 <win+0x63>
  40f73a:	e9 82 1e ff ff       	jmp    4015c1 <win+0x4b>
  40f73f:	ba 00 01 00 00       	mov    edx,0x100
  40f744:	48 89 ee             	mov    rsi,rbp
  40f747:	e8 b4 1a ff ff       	call   401200 <read@plt>
  40f74c:	85 c0                	test   eax,eax
  40f74e:	7f 2a                	jg     40f77a <win+0xe204>
  40f750:	e8 2b 1a ff ff       	call   401180 <__errno_location@plt>
  40f755:	8b 38                	mov    edi,DWORD PTR [rax]
  40f757:	e8 24 1b ff ff       	call   401280 <strerror@plt>
  40f75c:	bf 01 00 00 00       	mov    edi,0x1
  40f761:	48 8d 35 41 29 00 00 	lea    rsi,[rip+0x2941]        # 4120a9 <_IO_stdin_used+0xa9>
  40f768:	48 89 c2             	mov    rdx,rax
  40f76b:	31 c0                	xor    eax,eax
  40f76d:	e8 be 1a ff ff       	call   401230 <__printf_chk@plt>
  40f772:	83 cf ff             	or     edi,0xffffffff
  40f775:	e8 e6 1a ff ff       	call   401260 <exit@plt>
  40f77a:	48 63 d0             	movsxd rdx,eax
  40f77d:	48 89 ee             	mov    rsi,rbp
  40f780:	bf 01 00 00 00       	mov    edi,0x1
  40f785:	e8 16 1a ff ff       	call   4011a0 <write@plt>
  40f78a:	48 8d 3d c3 29 00 00 	lea    rdi,[rip+0x29c3]        # 412154 <_IO_stdin_used+0x154>
  40f791:	e8 fa 19 ff ff       	call   401190 <puts@plt>
  40f796:	48 8d 3d 67 28 00 00 	lea    rdi,[rip+0x2867]        # 412004 <_IO_stdin_used+0x4>
  40f79d:	31 f6                	xor    esi,esi
  40f79f:	31 c0                	xor    eax,eax
  40f7a1:	e8 aa 1a ff ff       	call   401250 <open@plt>
  40f7a6:	89 c7                	mov    edi,eax
  40f7a8:	85 c0                	test   eax,eax
  40f7aa:	79 34                	jns    40f7e0 <win+0xe26a>
  40f7ac:	e8 cf 19 ff ff       	call   401180 <__errno_location@plt>
  40f7b1:	8b 38                	mov    edi,DWORD PTR [rax]
  40f7b3:	e8 c8 1a ff ff       	call   401280 <strerror@plt>
  40f7b8:	48 8d 35 4b 28 00 00 	lea    rsi,[rip+0x284b]        # 41200a <_IO_stdin_used+0xa>
  40f7bf:	bf 01 00 00 00       	mov    edi,0x1
  40f7c4:	48 89 c2             	mov    rdx,rax
  40f7c7:	31 c0                	xor    eax,eax
  40f7c9:	e8 62 1a ff ff       	call   401230 <__printf_chk@plt>
  40f7ce:	e8 0d 1a ff ff       	call   4011e0 <geteuid@plt>
  40f7d3:	85 c0                	test   eax,eax
  40f7d5:	0f 84 fe 1d ff ff    	je     4015d9 <win+0x63>
  40f7db:	e9 e1 1d ff ff       	jmp    4015c1 <win+0x4b>
  40f7e0:	ba 00 01 00 00       	mov    edx,0x100
  40f7e5:	48 89 ee             	mov    rsi,rbp
  40f7e8:	e8 13 1a ff ff       	call   401200 <read@plt>
  40f7ed:	85 c0                	test   eax,eax
  40f7ef:	7f 2a                	jg     40f81b <win+0xe2a5>
  40f7f1:	e8 8a 19 ff ff       	call   401180 <__errno_location@plt>
  40f7f6:	8b 38                	mov    edi,DWORD PTR [rax]
  40f7f8:	e8 83 1a ff ff       	call   401280 <strerror@plt>
  40f7fd:	bf 01 00 00 00       	mov    edi,0x1
  40f802:	48 8d 35 a0 28 00 00 	lea    rsi,[rip+0x28a0]        # 4120a9 <_IO_stdin_used+0xa9>
  40f809:	48 89 c2             	mov    rdx,rax
  40f80c:	31 c0                	xor    eax,eax
  40f80e:	e8 1d 1a ff ff       	call   401230 <__printf_chk@plt>
  40f813:	83 cf ff             	or     edi,0xffffffff
  40f816:	e8 45 1a ff ff       	call   401260 <exit@plt>
  40f81b:	48 89 e5             	mov    rbp,rsp
  40f81e:	48 63 d0             	movsxd rdx,eax
  40f821:	bf 01 00 00 00       	mov    edi,0x1
  40f826:	48 89 ee             	mov    rsi,rbp
  40f829:	e8 72 19 ff ff       	call   4011a0 <write@plt>
  40f82e:	48 8d 3d 1f 29 00 00 	lea    rdi,[rip+0x291f]        # 412154 <_IO_stdin_used+0x154>
  40f835:	e8 56 19 ff ff       	call   401190 <puts@plt>
  40f83a:	48 8d 3d c3 27 00 00 	lea    rdi,[rip+0x27c3]        # 412004 <_IO_stdin_used+0x4>
  40f841:	31 f6                	xor    esi,esi
  40f843:	31 c0                	xor    eax,eax
  40f845:	e8 06 1a ff ff       	call   401250 <open@plt>
  40f84a:	89 c7                	mov    edi,eax
  40f84c:	85 c0                	test   eax,eax
  40f84e:	79 34                	jns    40f884 <win+0xe30e>
  40f850:	e8 2b 19 ff ff       	call   401180 <__errno_location@plt>
  40f855:	8b 38                	mov    edi,DWORD PTR [rax]
  40f857:	e8 24 1a ff ff       	call   401280 <strerror@plt>
  40f85c:	48 8d 35 a7 27 00 00 	lea    rsi,[rip+0x27a7]        # 41200a <_IO_stdin_used+0xa>
  40f863:	bf 01 00 00 00       	mov    edi,0x1
  40f868:	48 89 c2             	mov    rdx,rax
  40f86b:	31 c0                	xor    eax,eax
  40f86d:	e8 be 19 ff ff       	call   401230 <__printf_chk@plt>
  40f872:	e8 69 19 ff ff       	call   4011e0 <geteuid@plt>
  40f877:	85 c0                	test   eax,eax
  40f879:	0f 84 5a 1d ff ff    	je     4015d9 <win+0x63>
  40f87f:	e9 3d 1d ff ff       	jmp    4015c1 <win+0x4b>
  40f884:	ba 00 01 00 00       	mov    edx,0x100
  40f889:	48 89 ee             	mov    rsi,rbp
  40f88c:	e8 6f 19 ff ff       	call   401200 <read@plt>
  40f891:	85 c0                	test   eax,eax
  40f893:	7f 2a                	jg     40f8bf <win+0xe349>
  40f895:	e8 e6 18 ff ff       	call   401180 <__errno_location@plt>
  40f89a:	8b 38                	mov    edi,DWORD PTR [rax]
  40f89c:	e8 df 19 ff ff       	call   401280 <strerror@plt>
  40f8a1:	bf 01 00 00 00       	mov    edi,0x1
  40f8a6:	48 8d 35 fc 27 00 00 	lea    rsi,[rip+0x27fc]        # 4120a9 <_IO_stdin_used+0xa9>
  40f8ad:	48 89 c2             	mov    rdx,rax
  40f8b0:	31 c0                	xor    eax,eax
  40f8b2:	e8 79 19 ff ff       	call   401230 <__printf_chk@plt>
  40f8b7:	83 cf ff             	or     edi,0xffffffff
  40f8ba:	e8 a1 19 ff ff       	call   401260 <exit@plt>
  40f8bf:	48 63 d0             	movsxd rdx,eax
  40f8c2:	48 89 ee             	mov    rsi,rbp
  40f8c5:	bf 01 00 00 00       	mov    edi,0x1
  40f8ca:	e8 d1 18 ff ff       	call   4011a0 <write@plt>
  40f8cf:	48 8d 3d 7e 28 00 00 	lea    rdi,[rip+0x287e]        # 412154 <_IO_stdin_used+0x154>
  40f8d6:	e8 b5 18 ff ff       	call   401190 <puts@plt>
  40f8db:	48 8d 3d 22 27 00 00 	lea    rdi,[rip+0x2722]        # 412004 <_IO_stdin_used+0x4>
  40f8e2:	31 f6                	xor    esi,esi
  40f8e4:	31 c0                	xor    eax,eax
  40f8e6:	e8 65 19 ff ff       	call   401250 <open@plt>
  40f8eb:	89 c7                	mov    edi,eax
  40f8ed:	85 c0                	test   eax,eax
  40f8ef:	79 34                	jns    40f925 <win+0xe3af>
  40f8f1:	e8 8a 18 ff ff       	call   401180 <__errno_location@plt>
  40f8f6:	8b 38                	mov    edi,DWORD PTR [rax]
  40f8f8:	e8 83 19 ff ff       	call   401280 <strerror@plt>
  40f8fd:	48 8d 35 06 27 00 00 	lea    rsi,[rip+0x2706]        # 41200a <_IO_stdin_used+0xa>
  40f904:	bf 01 00 00 00       	mov    edi,0x1
  40f909:	48 89 c2             	mov    rdx,rax
  40f90c:	31 c0                	xor    eax,eax
  40f90e:	e8 1d 19 ff ff       	call   401230 <__printf_chk@plt>
  40f913:	e8 c8 18 ff ff       	call   4011e0 <geteuid@plt>
  40f918:	85 c0                	test   eax,eax
  40f91a:	0f 84 b9 1c ff ff    	je     4015d9 <win+0x63>
  40f920:	e9 9c 1c ff ff       	jmp    4015c1 <win+0x4b>
  40f925:	ba 00 01 00 00       	mov    edx,0x100
  40f92a:	48 89 ee             	mov    rsi,rbp
  40f92d:	e8 ce 18 ff ff       	call   401200 <read@plt>
  40f932:	85 c0                	test   eax,eax
  40f934:	7f 2a                	jg     40f960 <win+0xe3ea>
  40f936:	e8 45 18 ff ff       	call   401180 <__errno_location@plt>
  40f93b:	8b 38                	mov    edi,DWORD PTR [rax]
  40f93d:	e8 3e 19 ff ff       	call   401280 <strerror@plt>
  40f942:	bf 01 00 00 00       	mov    edi,0x1
  40f947:	48 8d 35 5b 27 00 00 	lea    rsi,[rip+0x275b]        # 4120a9 <_IO_stdin_used+0xa9>
  40f94e:	48 89 c2             	mov    rdx,rax
  40f951:	31 c0                	xor    eax,eax
  40f953:	e8 d8 18 ff ff       	call   401230 <__printf_chk@plt>
  40f958:	83 cf ff             	or     edi,0xffffffff
  40f95b:	e8 00 19 ff ff       	call   401260 <exit@plt>
  40f960:	48 63 d0             	movsxd rdx,eax
  40f963:	48 89 ee             	mov    rsi,rbp
  40f966:	bf 01 00 00 00       	mov    edi,0x1
  40f96b:	e8 30 18 ff ff       	call   4011a0 <write@plt>
  40f970:	48 8d 3d dd 27 00 00 	lea    rdi,[rip+0x27dd]        # 412154 <_IO_stdin_used+0x154>
  40f977:	e8 14 18 ff ff       	call   401190 <puts@plt>
  40f97c:	48 8d 3d 81 26 00 00 	lea    rdi,[rip+0x2681]        # 412004 <_IO_stdin_used+0x4>
  40f983:	31 f6                	xor    esi,esi
  40f985:	31 c0                	xor    eax,eax
  40f987:	e8 c4 18 ff ff       	call   401250 <open@plt>
  40f98c:	89 c7                	mov    edi,eax
  40f98e:	85 c0                	test   eax,eax
  40f990:	79 34                	jns    40f9c6 <win+0xe450>
  40f992:	e8 e9 17 ff ff       	call   401180 <__errno_location@plt>
  40f997:	8b 38                	mov    edi,DWORD PTR [rax]
  40f999:	e8 e2 18 ff ff       	call   401280 <strerror@plt>
  40f99e:	48 8d 35 65 26 00 00 	lea    rsi,[rip+0x2665]        # 41200a <_IO_stdin_used+0xa>
  40f9a5:	bf 01 00 00 00       	mov    edi,0x1
  40f9aa:	48 89 c2             	mov    rdx,rax
  40f9ad:	31 c0                	xor    eax,eax
  40f9af:	e8 7c 18 ff ff       	call   401230 <__printf_chk@plt>
  40f9b4:	e8 27 18 ff ff       	call   4011e0 <geteuid@plt>
  40f9b9:	85 c0                	test   eax,eax
  40f9bb:	0f 84 18 1c ff ff    	je     4015d9 <win+0x63>
  40f9c1:	e9 fb 1b ff ff       	jmp    4015c1 <win+0x4b>
  40f9c6:	ba 00 01 00 00       	mov    edx,0x100
  40f9cb:	48 89 ee             	mov    rsi,rbp
  40f9ce:	e8 2d 18 ff ff       	call   401200 <read@plt>
  40f9d3:	85 c0                	test   eax,eax
  40f9d5:	7f 2a                	jg     40fa01 <win+0xe48b>
  40f9d7:	e8 a4 17 ff ff       	call   401180 <__errno_location@plt>
  40f9dc:	8b 38                	mov    edi,DWORD PTR [rax]
  40f9de:	e8 9d 18 ff ff       	call   401280 <strerror@plt>
  40f9e3:	bf 01 00 00 00       	mov    edi,0x1
  40f9e8:	48 8d 35 ba 26 00 00 	lea    rsi,[rip+0x26ba]        # 4120a9 <_IO_stdin_used+0xa9>
  40f9ef:	48 89 c2             	mov    rdx,rax
  40f9f2:	31 c0                	xor    eax,eax
  40f9f4:	e8 37 18 ff ff       	call   401230 <__printf_chk@plt>
  40f9f9:	83 cf ff             	or     edi,0xffffffff
  40f9fc:	e8 5f 18 ff ff       	call   401260 <exit@plt>
  40fa01:	48 63 d0             	movsxd rdx,eax
  40fa04:	48 89 ee             	mov    rsi,rbp
  40fa07:	bf 01 00 00 00       	mov    edi,0x1
  40fa0c:	e8 8f 17 ff ff       	call   4011a0 <write@plt>
  40fa11:	48 8d 3d 3c 27 00 00 	lea    rdi,[rip+0x273c]        # 412154 <_IO_stdin_used+0x154>
  40fa18:	e8 73 17 ff ff       	call   401190 <puts@plt>
  40fa1d:	48 8d 3d e0 25 00 00 	lea    rdi,[rip+0x25e0]        # 412004 <_IO_stdin_used+0x4>
  40fa24:	31 f6                	xor    esi,esi
  40fa26:	31 c0                	xor    eax,eax
  40fa28:	e8 23 18 ff ff       	call   401250 <open@plt>
  40fa2d:	89 c7                	mov    edi,eax
  40fa2f:	85 c0                	test   eax,eax
  40fa31:	79 34                	jns    40fa67 <win+0xe4f1>
  40fa33:	e8 48 17 ff ff       	call   401180 <__errno_location@plt>
  40fa38:	8b 38                	mov    edi,DWORD PTR [rax]
  40fa3a:	e8 41 18 ff ff       	call   401280 <strerror@plt>
  40fa3f:	48 8d 35 c4 25 00 00 	lea    rsi,[rip+0x25c4]        # 41200a <_IO_stdin_used+0xa>
  40fa46:	bf 01 00 00 00       	mov    edi,0x1
  40fa4b:	48 89 c2             	mov    rdx,rax
  40fa4e:	31 c0                	xor    eax,eax
  40fa50:	e8 db 17 ff ff       	call   401230 <__printf_chk@plt>
  40fa55:	e8 86 17 ff ff       	call   4011e0 <geteuid@plt>
  40fa5a:	85 c0                	test   eax,eax
  40fa5c:	0f 84 77 1b ff ff    	je     4015d9 <win+0x63>
  40fa62:	e9 5a 1b ff ff       	jmp    4015c1 <win+0x4b>
  40fa67:	ba 00 01 00 00       	mov    edx,0x100
  40fa6c:	48 89 ee             	mov    rsi,rbp
  40fa6f:	e8 8c 17 ff ff       	call   401200 <read@plt>
  40fa74:	85 c0                	test   eax,eax
  40fa76:	7f 2a                	jg     40faa2 <win+0xe52c>
  40fa78:	e8 03 17 ff ff       	call   401180 <__errno_location@plt>
  40fa7d:	8b 38                	mov    edi,DWORD PTR [rax]
  40fa7f:	e8 fc 17 ff ff       	call   401280 <strerror@plt>
  40fa84:	bf 01 00 00 00       	mov    edi,0x1
  40fa89:	48 8d 35 19 26 00 00 	lea    rsi,[rip+0x2619]        # 4120a9 <_IO_stdin_used+0xa9>
  40fa90:	48 89 c2             	mov    rdx,rax
  40fa93:	31 c0                	xor    eax,eax
  40fa95:	e8 96 17 ff ff       	call   401230 <__printf_chk@plt>
  40fa9a:	83 cf ff             	or     edi,0xffffffff
  40fa9d:	e8 be 17 ff ff       	call   401260 <exit@plt>
  40faa2:	48 63 d0             	movsxd rdx,eax
  40faa5:	48 89 ee             	mov    rsi,rbp
  40faa8:	bf 01 00 00 00       	mov    edi,0x1
  40faad:	e8 ee 16 ff ff       	call   4011a0 <write@plt>
  40fab2:	48 8d 3d 9b 26 00 00 	lea    rdi,[rip+0x269b]        # 412154 <_IO_stdin_used+0x154>
  40fab9:	e8 d2 16 ff ff       	call   401190 <puts@plt>
  40fabe:	48 8d 3d 3f 25 00 00 	lea    rdi,[rip+0x253f]        # 412004 <_IO_stdin_used+0x4>
  40fac5:	31 f6                	xor    esi,esi
  40fac7:	31 c0                	xor    eax,eax
  40fac9:	e8 82 17 ff ff       	call   401250 <open@plt>
  40face:	89 c7                	mov    edi,eax
  40fad0:	85 c0                	test   eax,eax
  40fad2:	79 34                	jns    40fb08 <win+0xe592>
  40fad4:	e8 a7 16 ff ff       	call   401180 <__errno_location@plt>
  40fad9:	8b 38                	mov    edi,DWORD PTR [rax]
  40fadb:	e8 a0 17 ff ff       	call   401280 <strerror@plt>
  40fae0:	48 8d 35 23 25 00 00 	lea    rsi,[rip+0x2523]        # 41200a <_IO_stdin_used+0xa>
  40fae7:	bf 01 00 00 00       	mov    edi,0x1
  40faec:	48 89 c2             	mov    rdx,rax
  40faef:	31 c0                	xor    eax,eax
  40faf1:	e8 3a 17 ff ff       	call   401230 <__printf_chk@plt>
  40faf6:	e8 e5 16 ff ff       	call   4011e0 <geteuid@plt>
  40fafb:	85 c0                	test   eax,eax
  40fafd:	0f 84 d6 1a ff ff    	je     4015d9 <win+0x63>
  40fb03:	e9 b9 1a ff ff       	jmp    4015c1 <win+0x4b>
  40fb08:	ba 00 01 00 00       	mov    edx,0x100
  40fb0d:	48 89 ee             	mov    rsi,rbp
  40fb10:	e8 eb 16 ff ff       	call   401200 <read@plt>
  40fb15:	85 c0                	test   eax,eax
  40fb17:	7f 2a                	jg     40fb43 <win+0xe5cd>
  40fb19:	e8 62 16 ff ff       	call   401180 <__errno_location@plt>
  40fb1e:	8b 38                	mov    edi,DWORD PTR [rax]
  40fb20:	e8 5b 17 ff ff       	call   401280 <strerror@plt>
  40fb25:	bf 01 00 00 00       	mov    edi,0x1
  40fb2a:	48 8d 35 78 25 00 00 	lea    rsi,[rip+0x2578]        # 4120a9 <_IO_stdin_used+0xa9>
  40fb31:	48 89 c2             	mov    rdx,rax
  40fb34:	31 c0                	xor    eax,eax
  40fb36:	e8 f5 16 ff ff       	call   401230 <__printf_chk@plt>
  40fb3b:	83 cf ff             	or     edi,0xffffffff
  40fb3e:	e8 1d 17 ff ff       	call   401260 <exit@plt>
  40fb43:	48 63 d0             	movsxd rdx,eax
  40fb46:	48 89 ee             	mov    rsi,rbp
  40fb49:	bf 01 00 00 00       	mov    edi,0x1
  40fb4e:	e8 4d 16 ff ff       	call   4011a0 <write@plt>
  40fb53:	48 8d 3d fa 25 00 00 	lea    rdi,[rip+0x25fa]        # 412154 <_IO_stdin_used+0x154>
  40fb5a:	e8 31 16 ff ff       	call   401190 <puts@plt>
  40fb5f:	48 8d 3d 9e 24 00 00 	lea    rdi,[rip+0x249e]        # 412004 <_IO_stdin_used+0x4>
  40fb66:	31 f6                	xor    esi,esi
  40fb68:	31 c0                	xor    eax,eax
  40fb6a:	e8 e1 16 ff ff       	call   401250 <open@plt>
  40fb6f:	89 c7                	mov    edi,eax
  40fb71:	85 c0                	test   eax,eax
  40fb73:	79 34                	jns    40fba9 <win+0xe633>
  40fb75:	e8 06 16 ff ff       	call   401180 <__errno_location@plt>
  40fb7a:	8b 38                	mov    edi,DWORD PTR [rax]
  40fb7c:	e8 ff 16 ff ff       	call   401280 <strerror@plt>
  40fb81:	48 8d 35 82 24 00 00 	lea    rsi,[rip+0x2482]        # 41200a <_IO_stdin_used+0xa>
  40fb88:	bf 01 00 00 00       	mov    edi,0x1
  40fb8d:	48 89 c2             	mov    rdx,rax
  40fb90:	31 c0                	xor    eax,eax
  40fb92:	e8 99 16 ff ff       	call   401230 <__printf_chk@plt>
  40fb97:	e8 44 16 ff ff       	call   4011e0 <geteuid@plt>
  40fb9c:	85 c0                	test   eax,eax
  40fb9e:	0f 84 35 1a ff ff    	je     4015d9 <win+0x63>
  40fba4:	e9 18 1a ff ff       	jmp    4015c1 <win+0x4b>
  40fba9:	ba 00 01 00 00       	mov    edx,0x100
  40fbae:	48 89 ee             	mov    rsi,rbp
  40fbb1:	e8 4a 16 ff ff       	call   401200 <read@plt>
  40fbb6:	85 c0                	test   eax,eax
  40fbb8:	7f 2a                	jg     40fbe4 <win+0xe66e>
  40fbba:	e8 c1 15 ff ff       	call   401180 <__errno_location@plt>
  40fbbf:	8b 38                	mov    edi,DWORD PTR [rax]
  40fbc1:	e8 ba 16 ff ff       	call   401280 <strerror@plt>
  40fbc6:	bf 01 00 00 00       	mov    edi,0x1
  40fbcb:	48 8d 35 d7 24 00 00 	lea    rsi,[rip+0x24d7]        # 4120a9 <_IO_stdin_used+0xa9>
  40fbd2:	48 89 c2             	mov    rdx,rax
  40fbd5:	31 c0                	xor    eax,eax
  40fbd7:	e8 54 16 ff ff       	call   401230 <__printf_chk@plt>
  40fbdc:	83 cf ff             	or     edi,0xffffffff
  40fbdf:	e8 7c 16 ff ff       	call   401260 <exit@plt>
  40fbe4:	48 63 d0             	movsxd rdx,eax
  40fbe7:	48 89 ee             	mov    rsi,rbp
  40fbea:	bf 01 00 00 00       	mov    edi,0x1
  40fbef:	e8 ac 15 ff ff       	call   4011a0 <write@plt>
  40fbf4:	48 8d 3d 59 25 00 00 	lea    rdi,[rip+0x2559]        # 412154 <_IO_stdin_used+0x154>
  40fbfb:	e8 90 15 ff ff       	call   401190 <puts@plt>
  40fc00:	48 8d 3d fd 23 00 00 	lea    rdi,[rip+0x23fd]        # 412004 <_IO_stdin_used+0x4>
  40fc07:	31 f6                	xor    esi,esi
  40fc09:	31 c0                	xor    eax,eax
  40fc0b:	e8 40 16 ff ff       	call   401250 <open@plt>
  40fc10:	89 c7                	mov    edi,eax
  40fc12:	85 c0                	test   eax,eax
  40fc14:	79 34                	jns    40fc4a <win+0xe6d4>
  40fc16:	e8 65 15 ff ff       	call   401180 <__errno_location@plt>
  40fc1b:	8b 38                	mov    edi,DWORD PTR [rax]
  40fc1d:	e8 5e 16 ff ff       	call   401280 <strerror@plt>
  40fc22:	48 8d 35 e1 23 00 00 	lea    rsi,[rip+0x23e1]        # 41200a <_IO_stdin_used+0xa>
  40fc29:	bf 01 00 00 00       	mov    edi,0x1
  40fc2e:	48 89 c2             	mov    rdx,rax
  40fc31:	31 c0                	xor    eax,eax
  40fc33:	e8 f8 15 ff ff       	call   401230 <__printf_chk@plt>
  40fc38:	e8 a3 15 ff ff       	call   4011e0 <geteuid@plt>
  40fc3d:	85 c0                	test   eax,eax
  40fc3f:	0f 84 94 19 ff ff    	je     4015d9 <win+0x63>
  40fc45:	e9 77 19 ff ff       	jmp    4015c1 <win+0x4b>
  40fc4a:	ba 00 01 00 00       	mov    edx,0x100
  40fc4f:	48 89 ee             	mov    rsi,rbp
  40fc52:	e8 a9 15 ff ff       	call   401200 <read@plt>
  40fc57:	85 c0                	test   eax,eax
  40fc59:	7f 2a                	jg     40fc85 <win+0xe70f>
  40fc5b:	e8 20 15 ff ff       	call   401180 <__errno_location@plt>
  40fc60:	8b 38                	mov    edi,DWORD PTR [rax]
  40fc62:	e8 19 16 ff ff       	call   401280 <strerror@plt>
  40fc67:	bf 01 00 00 00       	mov    edi,0x1
  40fc6c:	48 8d 35 36 24 00 00 	lea    rsi,[rip+0x2436]        # 4120a9 <_IO_stdin_used+0xa9>
  40fc73:	48 89 c2             	mov    rdx,rax
  40fc76:	31 c0                	xor    eax,eax
  40fc78:	e8 b3 15 ff ff       	call   401230 <__printf_chk@plt>
  40fc7d:	83 cf ff             	or     edi,0xffffffff
  40fc80:	e8 db 15 ff ff       	call   401260 <exit@plt>
  40fc85:	48 63 d0             	movsxd rdx,eax
  40fc88:	48 89 ee             	mov    rsi,rbp
  40fc8b:	bf 01 00 00 00       	mov    edi,0x1
  40fc90:	e8 0b 15 ff ff       	call   4011a0 <write@plt>
  40fc95:	48 8d 3d b8 24 00 00 	lea    rdi,[rip+0x24b8]        # 412154 <_IO_stdin_used+0x154>
  40fc9c:	e8 ef 14 ff ff       	call   401190 <puts@plt>
  40fca1:	48 8d 3d 5c 23 00 00 	lea    rdi,[rip+0x235c]        # 412004 <_IO_stdin_used+0x4>
  40fca8:	31 f6                	xor    esi,esi
  40fcaa:	31 c0                	xor    eax,eax
  40fcac:	e8 9f 15 ff ff       	call   401250 <open@plt>
  40fcb1:	89 c7                	mov    edi,eax
  40fcb3:	85 c0                	test   eax,eax
  40fcb5:	79 34                	jns    40fceb <win+0xe775>
  40fcb7:	e8 c4 14 ff ff       	call   401180 <__errno_location@plt>
  40fcbc:	8b 38                	mov    edi,DWORD PTR [rax]
  40fcbe:	e8 bd 15 ff ff       	call   401280 <strerror@plt>
  40fcc3:	48 8d 35 40 23 00 00 	lea    rsi,[rip+0x2340]        # 41200a <_IO_stdin_used+0xa>
  40fcca:	bf 01 00 00 00       	mov    edi,0x1
  40fccf:	48 89 c2             	mov    rdx,rax
  40fcd2:	31 c0                	xor    eax,eax
  40fcd4:	e8 57 15 ff ff       	call   401230 <__printf_chk@plt>
  40fcd9:	e8 02 15 ff ff       	call   4011e0 <geteuid@plt>
  40fcde:	85 c0                	test   eax,eax
  40fce0:	0f 84 f3 18 ff ff    	je     4015d9 <win+0x63>
  40fce6:	e9 d6 18 ff ff       	jmp    4015c1 <win+0x4b>
  40fceb:	ba 00 01 00 00       	mov    edx,0x100
  40fcf0:	48 89 ee             	mov    rsi,rbp
  40fcf3:	e8 08 15 ff ff       	call   401200 <read@plt>
  40fcf8:	85 c0                	test   eax,eax
  40fcfa:	7f 2a                	jg     40fd26 <win+0xe7b0>
  40fcfc:	e8 7f 14 ff ff       	call   401180 <__errno_location@plt>
  40fd01:	8b 38                	mov    edi,DWORD PTR [rax]
  40fd03:	e8 78 15 ff ff       	call   401280 <strerror@plt>
  40fd08:	bf 01 00 00 00       	mov    edi,0x1
  40fd0d:	48 8d 35 95 23 00 00 	lea    rsi,[rip+0x2395]        # 4120a9 <_IO_stdin_used+0xa9>
  40fd14:	48 89 c2             	mov    rdx,rax
  40fd17:	31 c0                	xor    eax,eax
  40fd19:	e8 12 15 ff ff       	call   401230 <__printf_chk@plt>
  40fd1e:	83 cf ff             	or     edi,0xffffffff
  40fd21:	e8 3a 15 ff ff       	call   401260 <exit@plt>
  40fd26:	48 63 d0             	movsxd rdx,eax
  40fd29:	48 89 ee             	mov    rsi,rbp
  40fd2c:	bf 01 00 00 00       	mov    edi,0x1
  40fd31:	e8 6a 14 ff ff       	call   4011a0 <write@plt>
  40fd36:	48 8d 3d 17 24 00 00 	lea    rdi,[rip+0x2417]        # 412154 <_IO_stdin_used+0x154>
  40fd3d:	e8 4e 14 ff ff       	call   401190 <puts@plt>
  40fd42:	48 8d 3d bb 22 00 00 	lea    rdi,[rip+0x22bb]        # 412004 <_IO_stdin_used+0x4>
  40fd49:	31 f6                	xor    esi,esi
  40fd4b:	31 c0                	xor    eax,eax
  40fd4d:	e8 fe 14 ff ff       	call   401250 <open@plt>
  40fd52:	89 c7                	mov    edi,eax
  40fd54:	85 c0                	test   eax,eax
  40fd56:	79 34                	jns    40fd8c <win+0xe816>
  40fd58:	e8 23 14 ff ff       	call   401180 <__errno_location@plt>
  40fd5d:	8b 38                	mov    edi,DWORD PTR [rax]
  40fd5f:	e8 1c 15 ff ff       	call   401280 <strerror@plt>
  40fd64:	48 8d 35 9f 22 00 00 	lea    rsi,[rip+0x229f]        # 41200a <_IO_stdin_used+0xa>
  40fd6b:	bf 01 00 00 00       	mov    edi,0x1
  40fd70:	48 89 c2             	mov    rdx,rax
  40fd73:	31 c0                	xor    eax,eax
  40fd75:	e8 b6 14 ff ff       	call   401230 <__printf_chk@plt>
  40fd7a:	e8 61 14 ff ff       	call   4011e0 <geteuid@plt>
  40fd7f:	85 c0                	test   eax,eax
  40fd81:	0f 84 52 18 ff ff    	je     4015d9 <win+0x63>
  40fd87:	e9 35 18 ff ff       	jmp    4015c1 <win+0x4b>
  40fd8c:	ba 00 01 00 00       	mov    edx,0x100
  40fd91:	48 89 ee             	mov    rsi,rbp
  40fd94:	e8 67 14 ff ff       	call   401200 <read@plt>
  40fd99:	85 c0                	test   eax,eax
  40fd9b:	7f 2a                	jg     40fdc7 <win+0xe851>
  40fd9d:	e8 de 13 ff ff       	call   401180 <__errno_location@plt>
  40fda2:	8b 38                	mov    edi,DWORD PTR [rax]
  40fda4:	e8 d7 14 ff ff       	call   401280 <strerror@plt>
  40fda9:	bf 01 00 00 00       	mov    edi,0x1
  40fdae:	48 8d 35 f4 22 00 00 	lea    rsi,[rip+0x22f4]        # 4120a9 <_IO_stdin_used+0xa9>
  40fdb5:	48 89 c2             	mov    rdx,rax
  40fdb8:	31 c0                	xor    eax,eax
  40fdba:	e8 71 14 ff ff       	call   401230 <__printf_chk@plt>
  40fdbf:	83 cf ff             	or     edi,0xffffffff
  40fdc2:	e8 99 14 ff ff       	call   401260 <exit@plt>
  40fdc7:	48 63 d0             	movsxd rdx,eax
  40fdca:	48 89 ee             	mov    rsi,rbp
  40fdcd:	bf 01 00 00 00       	mov    edi,0x1
  40fdd2:	e8 c9 13 ff ff       	call   4011a0 <write@plt>
  40fdd7:	48 8d 3d 76 23 00 00 	lea    rdi,[rip+0x2376]        # 412154 <_IO_stdin_used+0x154>
  40fdde:	e8 ad 13 ff ff       	call   401190 <puts@plt>
  40fde3:	48 8d 3d 1a 22 00 00 	lea    rdi,[rip+0x221a]        # 412004 <_IO_stdin_used+0x4>
  40fdea:	31 f6                	xor    esi,esi
  40fdec:	31 c0                	xor    eax,eax
  40fdee:	e8 5d 14 ff ff       	call   401250 <open@plt>
  40fdf3:	89 c7                	mov    edi,eax
  40fdf5:	85 c0                	test   eax,eax
  40fdf7:	79 34                	jns    40fe2d <win+0xe8b7>
  40fdf9:	e8 82 13 ff ff       	call   401180 <__errno_location@plt>
  40fdfe:	8b 38                	mov    edi,DWORD PTR [rax]
  40fe00:	e8 7b 14 ff ff       	call   401280 <strerror@plt>
  40fe05:	48 8d 35 fe 21 00 00 	lea    rsi,[rip+0x21fe]        # 41200a <_IO_stdin_used+0xa>
  40fe0c:	bf 01 00 00 00       	mov    edi,0x1
  40fe11:	48 89 c2             	mov    rdx,rax
  40fe14:	31 c0                	xor    eax,eax
  40fe16:	e8 15 14 ff ff       	call   401230 <__printf_chk@plt>
  40fe1b:	e8 c0 13 ff ff       	call   4011e0 <geteuid@plt>
  40fe20:	85 c0                	test   eax,eax
  40fe22:	0f 84 b1 17 ff ff    	je     4015d9 <win+0x63>
  40fe28:	e9 94 17 ff ff       	jmp    4015c1 <win+0x4b>
  40fe2d:	ba 00 01 00 00       	mov    edx,0x100
  40fe32:	48 89 ee             	mov    rsi,rbp
  40fe35:	e8 c6 13 ff ff       	call   401200 <read@plt>
  40fe3a:	85 c0                	test   eax,eax
  40fe3c:	7f 2a                	jg     40fe68 <win+0xe8f2>
  40fe3e:	e8 3d 13 ff ff       	call   401180 <__errno_location@plt>
  40fe43:	8b 38                	mov    edi,DWORD PTR [rax]
  40fe45:	e8 36 14 ff ff       	call   401280 <strerror@plt>
  40fe4a:	bf 01 00 00 00       	mov    edi,0x1
  40fe4f:	48 8d 35 53 22 00 00 	lea    rsi,[rip+0x2253]        # 4120a9 <_IO_stdin_used+0xa9>
  40fe56:	48 89 c2             	mov    rdx,rax
  40fe59:	31 c0                	xor    eax,eax
  40fe5b:	e8 d0 13 ff ff       	call   401230 <__printf_chk@plt>
  40fe60:	83 cf ff             	or     edi,0xffffffff
  40fe63:	e8 f8 13 ff ff       	call   401260 <exit@plt>
  40fe68:	48 63 d0             	movsxd rdx,eax
  40fe6b:	48 89 ee             	mov    rsi,rbp
  40fe6e:	bf 01 00 00 00       	mov    edi,0x1
  40fe73:	e8 28 13 ff ff       	call   4011a0 <write@plt>
  40fe78:	48 8d 3d d5 22 00 00 	lea    rdi,[rip+0x22d5]        # 412154 <_IO_stdin_used+0x154>
  40fe7f:	e8 0c 13 ff ff       	call   401190 <puts@plt>
  40fe84:	48 8d 3d 79 21 00 00 	lea    rdi,[rip+0x2179]        # 412004 <_IO_stdin_used+0x4>
  40fe8b:	31 f6                	xor    esi,esi
  40fe8d:	31 c0                	xor    eax,eax
  40fe8f:	e8 bc 13 ff ff       	call   401250 <open@plt>
  40fe94:	89 c7                	mov    edi,eax
  40fe96:	85 c0                	test   eax,eax
  40fe98:	79 34                	jns    40fece <win+0xe958>
  40fe9a:	e8 e1 12 ff ff       	call   401180 <__errno_location@plt>
  40fe9f:	8b 38                	mov    edi,DWORD PTR [rax]
  40fea1:	e8 da 13 ff ff       	call   401280 <strerror@plt>
  40fea6:	48 8d 35 5d 21 00 00 	lea    rsi,[rip+0x215d]        # 41200a <_IO_stdin_used+0xa>
  40fead:	bf 01 00 00 00       	mov    edi,0x1
  40feb2:	48 89 c2             	mov    rdx,rax
  40feb5:	31 c0                	xor    eax,eax
  40feb7:	e8 74 13 ff ff       	call   401230 <__printf_chk@plt>
  40febc:	e8 1f 13 ff ff       	call   4011e0 <geteuid@plt>
  40fec1:	85 c0                	test   eax,eax
  40fec3:	0f 84 10 17 ff ff    	je     4015d9 <win+0x63>
  40fec9:	e9 f3 16 ff ff       	jmp    4015c1 <win+0x4b>
  40fece:	ba 00 01 00 00       	mov    edx,0x100
  40fed3:	48 89 ee             	mov    rsi,rbp
  40fed6:	e8 25 13 ff ff       	call   401200 <read@plt>
  40fedb:	85 c0                	test   eax,eax
  40fedd:	7f 2a                	jg     40ff09 <win+0xe993>
  40fedf:	e8 9c 12 ff ff       	call   401180 <__errno_location@plt>
  40fee4:	8b 38                	mov    edi,DWORD PTR [rax]
  40fee6:	e8 95 13 ff ff       	call   401280 <strerror@plt>
  40feeb:	bf 01 00 00 00       	mov    edi,0x1
  40fef0:	48 8d 35 b2 21 00 00 	lea    rsi,[rip+0x21b2]        # 4120a9 <_IO_stdin_used+0xa9>
  40fef7:	48 89 c2             	mov    rdx,rax
  40fefa:	31 c0                	xor    eax,eax
  40fefc:	e8 2f 13 ff ff       	call   401230 <__printf_chk@plt>
  40ff01:	83 cf ff             	or     edi,0xffffffff
  40ff04:	e8 57 13 ff ff       	call   401260 <exit@plt>
  40ff09:	48 63 d0             	movsxd rdx,eax
  40ff0c:	48 89 ee             	mov    rsi,rbp
  40ff0f:	bf 01 00 00 00       	mov    edi,0x1
  40ff14:	e8 87 12 ff ff       	call   4011a0 <write@plt>
  40ff19:	48 8d 3d 34 22 00 00 	lea    rdi,[rip+0x2234]        # 412154 <_IO_stdin_used+0x154>
  40ff20:	e8 6b 12 ff ff       	call   401190 <puts@plt>
  40ff25:	48 8d 3d d8 20 00 00 	lea    rdi,[rip+0x20d8]        # 412004 <_IO_stdin_used+0x4>
  40ff2c:	31 f6                	xor    esi,esi
  40ff2e:	31 c0                	xor    eax,eax
  40ff30:	e8 1b 13 ff ff       	call   401250 <open@plt>
  40ff35:	89 c7                	mov    edi,eax
  40ff37:	85 c0                	test   eax,eax
  40ff39:	79 34                	jns    40ff6f <win+0xe9f9>
  40ff3b:	e8 40 12 ff ff       	call   401180 <__errno_location@plt>
  40ff40:	8b 38                	mov    edi,DWORD PTR [rax]
  40ff42:	e8 39 13 ff ff       	call   401280 <strerror@plt>
  40ff47:	48 8d 35 bc 20 00 00 	lea    rsi,[rip+0x20bc]        # 41200a <_IO_stdin_used+0xa>
  40ff4e:	bf 01 00 00 00       	mov    edi,0x1
  40ff53:	48 89 c2             	mov    rdx,rax
  40ff56:	31 c0                	xor    eax,eax
  40ff58:	e8 d3 12 ff ff       	call   401230 <__printf_chk@plt>
  40ff5d:	e8 7e 12 ff ff       	call   4011e0 <geteuid@plt>
  40ff62:	85 c0                	test   eax,eax
  40ff64:	0f 84 6f 16 ff ff    	je     4015d9 <win+0x63>
  40ff6a:	e9 52 16 ff ff       	jmp    4015c1 <win+0x4b>
  40ff6f:	ba 00 01 00 00       	mov    edx,0x100
  40ff74:	48 89 ee             	mov    rsi,rbp
  40ff77:	e8 84 12 ff ff       	call   401200 <read@plt>
  40ff7c:	85 c0                	test   eax,eax
  40ff7e:	7f 2a                	jg     40ffaa <win+0xea34>
  40ff80:	e8 fb 11 ff ff       	call   401180 <__errno_location@plt>
  40ff85:	8b 38                	mov    edi,DWORD PTR [rax]
  40ff87:	e8 f4 12 ff ff       	call   401280 <strerror@plt>
  40ff8c:	bf 01 00 00 00       	mov    edi,0x1
  40ff91:	48 8d 35 11 21 00 00 	lea    rsi,[rip+0x2111]        # 4120a9 <_IO_stdin_used+0xa9>
  40ff98:	48 89 c2             	mov    rdx,rax
  40ff9b:	31 c0                	xor    eax,eax
  40ff9d:	e8 8e 12 ff ff       	call   401230 <__printf_chk@plt>
  40ffa2:	83 cf ff             	or     edi,0xffffffff
  40ffa5:	e8 b6 12 ff ff       	call   401260 <exit@plt>
  40ffaa:	48 63 d0             	movsxd rdx,eax
  40ffad:	48 89 ee             	mov    rsi,rbp
  40ffb0:	bf 01 00 00 00       	mov    edi,0x1
  40ffb5:	e8 e6 11 ff ff       	call   4011a0 <write@plt>
  40ffba:	48 8d 3d 93 21 00 00 	lea    rdi,[rip+0x2193]        # 412154 <_IO_stdin_used+0x154>
  40ffc1:	e8 ca 11 ff ff       	call   401190 <puts@plt>
  40ffc6:	48 8d 3d 37 20 00 00 	lea    rdi,[rip+0x2037]        # 412004 <_IO_stdin_used+0x4>
  40ffcd:	31 f6                	xor    esi,esi
  40ffcf:	31 c0                	xor    eax,eax
  40ffd1:	e8 7a 12 ff ff       	call   401250 <open@plt>
  40ffd6:	89 c7                	mov    edi,eax
  40ffd8:	85 c0                	test   eax,eax
  40ffda:	79 34                	jns    410010 <win+0xea9a>
  40ffdc:	e8 9f 11 ff ff       	call   401180 <__errno_location@plt>
  40ffe1:	8b 38                	mov    edi,DWORD PTR [rax]
  40ffe3:	e8 98 12 ff ff       	call   401280 <strerror@plt>
  40ffe8:	48 8d 35 1b 20 00 00 	lea    rsi,[rip+0x201b]        # 41200a <_IO_stdin_used+0xa>
  40ffef:	bf 01 00 00 00       	mov    edi,0x1
  40fff4:	48 89 c2             	mov    rdx,rax
  40fff7:	31 c0                	xor    eax,eax
  40fff9:	e8 32 12 ff ff       	call   401230 <__printf_chk@plt>
  40fffe:	e8 dd 11 ff ff       	call   4011e0 <geteuid@plt>
  410003:	85 c0                	test   eax,eax
  410005:	0f 84 ce 15 ff ff    	je     4015d9 <win+0x63>
  41000b:	e9 b1 15 ff ff       	jmp    4015c1 <win+0x4b>
  410010:	ba 00 01 00 00       	mov    edx,0x100
  410015:	48 89 ee             	mov    rsi,rbp
  410018:	e8 e3 11 ff ff       	call   401200 <read@plt>
  41001d:	85 c0                	test   eax,eax
  41001f:	7f 2a                	jg     41004b <win+0xead5>
  410021:	e8 5a 11 ff ff       	call   401180 <__errno_location@plt>
  410026:	8b 38                	mov    edi,DWORD PTR [rax]
  410028:	e8 53 12 ff ff       	call   401280 <strerror@plt>
  41002d:	bf 01 00 00 00       	mov    edi,0x1
  410032:	48 8d 35 70 20 00 00 	lea    rsi,[rip+0x2070]        # 4120a9 <_IO_stdin_used+0xa9>
  410039:	48 89 c2             	mov    rdx,rax
  41003c:	31 c0                	xor    eax,eax
  41003e:	e8 ed 11 ff ff       	call   401230 <__printf_chk@plt>
  410043:	83 cf ff             	or     edi,0xffffffff
  410046:	e8 15 12 ff ff       	call   401260 <exit@plt>
  41004b:	48 63 d0             	movsxd rdx,eax
  41004e:	48 89 ee             	mov    rsi,rbp
  410051:	bf 01 00 00 00       	mov    edi,0x1
  410056:	e8 45 11 ff ff       	call   4011a0 <write@plt>
  41005b:	48 8d 3d f2 20 00 00 	lea    rdi,[rip+0x20f2]        # 412154 <_IO_stdin_used+0x154>
  410062:	e8 29 11 ff ff       	call   401190 <puts@plt>
  410067:	48 8d 3d 96 1f 00 00 	lea    rdi,[rip+0x1f96]        # 412004 <_IO_stdin_used+0x4>
  41006e:	31 f6                	xor    esi,esi
  410070:	31 c0                	xor    eax,eax
  410072:	e8 d9 11 ff ff       	call   401250 <open@plt>
  410077:	89 c7                	mov    edi,eax
  410079:	85 c0                	test   eax,eax
  41007b:	79 34                	jns    4100b1 <win+0xeb3b>
  41007d:	e8 fe 10 ff ff       	call   401180 <__errno_location@plt>
  410082:	8b 38                	mov    edi,DWORD PTR [rax]
  410084:	e8 f7 11 ff ff       	call   401280 <strerror@plt>
  410089:	48 8d 35 7a 1f 00 00 	lea    rsi,[rip+0x1f7a]        # 41200a <_IO_stdin_used+0xa>
  410090:	bf 01 00 00 00       	mov    edi,0x1
  410095:	48 89 c2             	mov    rdx,rax
  410098:	31 c0                	xor    eax,eax
  41009a:	e8 91 11 ff ff       	call   401230 <__printf_chk@plt>
  41009f:	e8 3c 11 ff ff       	call   4011e0 <geteuid@plt>
  4100a4:	85 c0                	test   eax,eax
  4100a6:	0f 84 2d 15 ff ff    	je     4015d9 <win+0x63>
  4100ac:	e9 10 15 ff ff       	jmp    4015c1 <win+0x4b>
  4100b1:	ba 00 01 00 00       	mov    edx,0x100
  4100b6:	48 89 ee             	mov    rsi,rbp
  4100b9:	e8 42 11 ff ff       	call   401200 <read@plt>
  4100be:	85 c0                	test   eax,eax
  4100c0:	7f 2a                	jg     4100ec <win+0xeb76>
  4100c2:	e8 b9 10 ff ff       	call   401180 <__errno_location@plt>
  4100c7:	8b 38                	mov    edi,DWORD PTR [rax]
  4100c9:	e8 b2 11 ff ff       	call   401280 <strerror@plt>
  4100ce:	bf 01 00 00 00       	mov    edi,0x1
  4100d3:	48 8d 35 cf 1f 00 00 	lea    rsi,[rip+0x1fcf]        # 4120a9 <_IO_stdin_used+0xa9>
  4100da:	48 89 c2             	mov    rdx,rax
  4100dd:	31 c0                	xor    eax,eax
  4100df:	e8 4c 11 ff ff       	call   401230 <__printf_chk@plt>
  4100e4:	83 cf ff             	or     edi,0xffffffff
  4100e7:	e8 74 11 ff ff       	call   401260 <exit@plt>
  4100ec:	48 63 d0             	movsxd rdx,eax
  4100ef:	48 89 ee             	mov    rsi,rbp
  4100f2:	bf 01 00 00 00       	mov    edi,0x1
  4100f7:	e8 a4 10 ff ff       	call   4011a0 <write@plt>
  4100fc:	48 8d 3d 51 20 00 00 	lea    rdi,[rip+0x2051]        # 412154 <_IO_stdin_used+0x154>
  410103:	e8 88 10 ff ff       	call   401190 <puts@plt>
  410108:	48 8d 3d f5 1e 00 00 	lea    rdi,[rip+0x1ef5]        # 412004 <_IO_stdin_used+0x4>
  41010f:	31 f6                	xor    esi,esi
  410111:	31 c0                	xor    eax,eax
  410113:	e8 38 11 ff ff       	call   401250 <open@plt>
  410118:	89 c7                	mov    edi,eax
  41011a:	85 c0                	test   eax,eax
  41011c:	79 34                	jns    410152 <win+0xebdc>
  41011e:	e8 5d 10 ff ff       	call   401180 <__errno_location@plt>
  410123:	8b 38                	mov    edi,DWORD PTR [rax]
  410125:	e8 56 11 ff ff       	call   401280 <strerror@plt>
  41012a:	48 8d 35 d9 1e 00 00 	lea    rsi,[rip+0x1ed9]        # 41200a <_IO_stdin_used+0xa>
  410131:	bf 01 00 00 00       	mov    edi,0x1
  410136:	48 89 c2             	mov    rdx,rax
  410139:	31 c0                	xor    eax,eax
  41013b:	e8 f0 10 ff ff       	call   401230 <__printf_chk@plt>
  410140:	e8 9b 10 ff ff       	call   4011e0 <geteuid@plt>
  410145:	85 c0                	test   eax,eax
  410147:	0f 84 8c 14 ff ff    	je     4015d9 <win+0x63>
  41014d:	e9 6f 14 ff ff       	jmp    4015c1 <win+0x4b>
  410152:	ba 00 01 00 00       	mov    edx,0x100
  410157:	48 89 ee             	mov    rsi,rbp
  41015a:	e8 a1 10 ff ff       	call   401200 <read@plt>
  41015f:	85 c0                	test   eax,eax
  410161:	7f 2a                	jg     41018d <win+0xec17>
  410163:	e8 18 10 ff ff       	call   401180 <__errno_location@plt>
  410168:	8b 38                	mov    edi,DWORD PTR [rax]
  41016a:	e8 11 11 ff ff       	call   401280 <strerror@plt>
  41016f:	bf 01 00 00 00       	mov    edi,0x1
  410174:	48 8d 35 2e 1f 00 00 	lea    rsi,[rip+0x1f2e]        # 4120a9 <_IO_stdin_used+0xa9>
  41017b:	48 89 c2             	mov    rdx,rax
  41017e:	31 c0                	xor    eax,eax
  410180:	e8 ab 10 ff ff       	call   401230 <__printf_chk@plt>
  410185:	83 cf ff             	or     edi,0xffffffff
  410188:	e8 d3 10 ff ff       	call   401260 <exit@plt>
  41018d:	48 63 d0             	movsxd rdx,eax
  410190:	48 89 ee             	mov    rsi,rbp
  410193:	bf 01 00 00 00       	mov    edi,0x1
  410198:	e8 03 10 ff ff       	call   4011a0 <write@plt>
  41019d:	48 8d 3d b0 1f 00 00 	lea    rdi,[rip+0x1fb0]        # 412154 <_IO_stdin_used+0x154>
  4101a4:	e8 e7 0f ff ff       	call   401190 <puts@plt>
  4101a9:	48 8d 3d 54 1e 00 00 	lea    rdi,[rip+0x1e54]        # 412004 <_IO_stdin_used+0x4>
  4101b0:	31 f6                	xor    esi,esi
  4101b2:	31 c0                	xor    eax,eax
  4101b4:	e8 97 10 ff ff       	call   401250 <open@plt>
  4101b9:	89 c7                	mov    edi,eax
  4101bb:	85 c0                	test   eax,eax
  4101bd:	79 34                	jns    4101f3 <win+0xec7d>
  4101bf:	e8 bc 0f ff ff       	call   401180 <__errno_location@plt>
  4101c4:	8b 38                	mov    edi,DWORD PTR [rax]
  4101c6:	e8 b5 10 ff ff       	call   401280 <strerror@plt>
  4101cb:	48 8d 35 38 1e 00 00 	lea    rsi,[rip+0x1e38]        # 41200a <_IO_stdin_used+0xa>
  4101d2:	bf 01 00 00 00       	mov    edi,0x1
  4101d7:	48 89 c2             	mov    rdx,rax
  4101da:	31 c0                	xor    eax,eax
  4101dc:	e8 4f 10 ff ff       	call   401230 <__printf_chk@plt>
  4101e1:	e8 fa 0f ff ff       	call   4011e0 <geteuid@plt>
  4101e6:	85 c0                	test   eax,eax
  4101e8:	0f 84 eb 13 ff ff    	je     4015d9 <win+0x63>
  4101ee:	e9 ce 13 ff ff       	jmp    4015c1 <win+0x4b>
  4101f3:	ba 00 01 00 00       	mov    edx,0x100
  4101f8:	48 89 ee             	mov    rsi,rbp
  4101fb:	e8 00 10 ff ff       	call   401200 <read@plt>
  410200:	85 c0                	test   eax,eax
  410202:	7f 2a                	jg     41022e <win+0xecb8>
  410204:	e8 77 0f ff ff       	call   401180 <__errno_location@plt>
  410209:	8b 38                	mov    edi,DWORD PTR [rax]
  41020b:	e8 70 10 ff ff       	call   401280 <strerror@plt>
  410210:	bf 01 00 00 00       	mov    edi,0x1
  410215:	48 8d 35 8d 1e 00 00 	lea    rsi,[rip+0x1e8d]        # 4120a9 <_IO_stdin_used+0xa9>
  41021c:	48 89 c2             	mov    rdx,rax
  41021f:	31 c0                	xor    eax,eax
  410221:	e8 0a 10 ff ff       	call   401230 <__printf_chk@plt>
  410226:	83 cf ff             	or     edi,0xffffffff
  410229:	e8 32 10 ff ff       	call   401260 <exit@plt>
  41022e:	48 63 d0             	movsxd rdx,eax
  410231:	48 89 ee             	mov    rsi,rbp
  410234:	bf 01 00 00 00       	mov    edi,0x1
  410239:	e8 62 0f ff ff       	call   4011a0 <write@plt>
  41023e:	48 8d 3d 0f 1f 00 00 	lea    rdi,[rip+0x1f0f]        # 412154 <_IO_stdin_used+0x154>
  410245:	e8 46 0f ff ff       	call   401190 <puts@plt>
  41024a:	48 8d 3d b3 1d 00 00 	lea    rdi,[rip+0x1db3]        # 412004 <_IO_stdin_used+0x4>
  410251:	31 f6                	xor    esi,esi
  410253:	31 c0                	xor    eax,eax
  410255:	e8 f6 0f ff ff       	call   401250 <open@plt>
  41025a:	89 c7                	mov    edi,eax
  41025c:	85 c0                	test   eax,eax
  41025e:	79 34                	jns    410294 <win+0xed1e>
  410260:	e8 1b 0f ff ff       	call   401180 <__errno_location@plt>
  410265:	8b 38                	mov    edi,DWORD PTR [rax]
  410267:	e8 14 10 ff ff       	call   401280 <strerror@plt>
  41026c:	48 8d 35 97 1d 00 00 	lea    rsi,[rip+0x1d97]        # 41200a <_IO_stdin_used+0xa>
  410273:	bf 01 00 00 00       	mov    edi,0x1
  410278:	48 89 c2             	mov    rdx,rax
  41027b:	31 c0                	xor    eax,eax
  41027d:	e8 ae 0f ff ff       	call   401230 <__printf_chk@plt>
  410282:	e8 59 0f ff ff       	call   4011e0 <geteuid@plt>
  410287:	85 c0                	test   eax,eax
  410289:	0f 84 4a 13 ff ff    	je     4015d9 <win+0x63>
  41028f:	e9 2d 13 ff ff       	jmp    4015c1 <win+0x4b>
  410294:	ba 00 01 00 00       	mov    edx,0x100
  410299:	48 89 ee             	mov    rsi,rbp
  41029c:	e8 5f 0f ff ff       	call   401200 <read@plt>
  4102a1:	85 c0                	test   eax,eax
  4102a3:	7f 2a                	jg     4102cf <win+0xed59>
  4102a5:	e8 d6 0e ff ff       	call   401180 <__errno_location@plt>
  4102aa:	8b 38                	mov    edi,DWORD PTR [rax]
  4102ac:	e8 cf 0f ff ff       	call   401280 <strerror@plt>
  4102b1:	bf 01 00 00 00       	mov    edi,0x1
  4102b6:	48 8d 35 ec 1d 00 00 	lea    rsi,[rip+0x1dec]        # 4120a9 <_IO_stdin_used+0xa9>
  4102bd:	48 89 c2             	mov    rdx,rax
  4102c0:	31 c0                	xor    eax,eax
  4102c2:	e8 69 0f ff ff       	call   401230 <__printf_chk@plt>
  4102c7:	83 cf ff             	or     edi,0xffffffff
  4102ca:	e8 91 0f ff ff       	call   401260 <exit@plt>
  4102cf:	48 63 d0             	movsxd rdx,eax
  4102d2:	48 89 ee             	mov    rsi,rbp
  4102d5:	bf 01 00 00 00       	mov    edi,0x1
  4102da:	e8 c1 0e ff ff       	call   4011a0 <write@plt>
  4102df:	48 8d 3d 6e 1e 00 00 	lea    rdi,[rip+0x1e6e]        # 412154 <_IO_stdin_used+0x154>
  4102e6:	e8 a5 0e ff ff       	call   401190 <puts@plt>
  4102eb:	48 8d 3d 12 1d 00 00 	lea    rdi,[rip+0x1d12]        # 412004 <_IO_stdin_used+0x4>
  4102f2:	31 f6                	xor    esi,esi
  4102f4:	31 c0                	xor    eax,eax
  4102f6:	e8 55 0f ff ff       	call   401250 <open@plt>
  4102fb:	89 c7                	mov    edi,eax
  4102fd:	85 c0                	test   eax,eax
  4102ff:	79 34                	jns    410335 <win+0xedbf>
  410301:	e8 7a 0e ff ff       	call   401180 <__errno_location@plt>
  410306:	8b 38                	mov    edi,DWORD PTR [rax]
  410308:	e8 73 0f ff ff       	call   401280 <strerror@plt>
  41030d:	48 8d 35 f6 1c 00 00 	lea    rsi,[rip+0x1cf6]        # 41200a <_IO_stdin_used+0xa>
  410314:	bf 01 00 00 00       	mov    edi,0x1
  410319:	48 89 c2             	mov    rdx,rax
  41031c:	31 c0                	xor    eax,eax
  41031e:	e8 0d 0f ff ff       	call   401230 <__printf_chk@plt>
  410323:	e8 b8 0e ff ff       	call   4011e0 <geteuid@plt>
  410328:	85 c0                	test   eax,eax
  41032a:	0f 84 a9 12 ff ff    	je     4015d9 <win+0x63>
  410330:	e9 8c 12 ff ff       	jmp    4015c1 <win+0x4b>
  410335:	ba 00 01 00 00       	mov    edx,0x100
  41033a:	48 89 ee             	mov    rsi,rbp
  41033d:	e8 be 0e ff ff       	call   401200 <read@plt>
  410342:	85 c0                	test   eax,eax
  410344:	7f 2a                	jg     410370 <win+0xedfa>
  410346:	e8 35 0e ff ff       	call   401180 <__errno_location@plt>
  41034b:	8b 38                	mov    edi,DWORD PTR [rax]
  41034d:	e8 2e 0f ff ff       	call   401280 <strerror@plt>
  410352:	bf 01 00 00 00       	mov    edi,0x1
  410357:	48 8d 35 4b 1d 00 00 	lea    rsi,[rip+0x1d4b]        # 4120a9 <_IO_stdin_used+0xa9>
  41035e:	48 89 c2             	mov    rdx,rax
  410361:	31 c0                	xor    eax,eax
  410363:	e8 c8 0e ff ff       	call   401230 <__printf_chk@plt>
  410368:	83 cf ff             	or     edi,0xffffffff
  41036b:	e8 f0 0e ff ff       	call   401260 <exit@plt>
  410370:	48 63 d0             	movsxd rdx,eax
  410373:	48 89 ee             	mov    rsi,rbp
  410376:	bf 01 00 00 00       	mov    edi,0x1
  41037b:	e8 20 0e ff ff       	call   4011a0 <write@plt>
  410380:	48 8d 3d cd 1d 00 00 	lea    rdi,[rip+0x1dcd]        # 412154 <_IO_stdin_used+0x154>
  410387:	e8 04 0e ff ff       	call   401190 <puts@plt>
  41038c:	48 8d 3d 71 1c 00 00 	lea    rdi,[rip+0x1c71]        # 412004 <_IO_stdin_used+0x4>
  410393:	31 f6                	xor    esi,esi
  410395:	31 c0                	xor    eax,eax
  410397:	e8 b4 0e ff ff       	call   401250 <open@plt>
  41039c:	89 c7                	mov    edi,eax
  41039e:	85 c0                	test   eax,eax
  4103a0:	79 34                	jns    4103d6 <win+0xee60>
  4103a2:	e8 d9 0d ff ff       	call   401180 <__errno_location@plt>
  4103a7:	8b 38                	mov    edi,DWORD PTR [rax]
  4103a9:	e8 d2 0e ff ff       	call   401280 <strerror@plt>
  4103ae:	48 8d 35 55 1c 00 00 	lea    rsi,[rip+0x1c55]        # 41200a <_IO_stdin_used+0xa>
  4103b5:	bf 01 00 00 00       	mov    edi,0x1
  4103ba:	48 89 c2             	mov    rdx,rax
  4103bd:	31 c0                	xor    eax,eax
  4103bf:	e8 6c 0e ff ff       	call   401230 <__printf_chk@plt>
  4103c4:	e8 17 0e ff ff       	call   4011e0 <geteuid@plt>
  4103c9:	85 c0                	test   eax,eax
  4103cb:	0f 84 08 12 ff ff    	je     4015d9 <win+0x63>
  4103d1:	e9 eb 11 ff ff       	jmp    4015c1 <win+0x4b>
  4103d6:	ba 00 01 00 00       	mov    edx,0x100
  4103db:	48 89 ee             	mov    rsi,rbp
  4103de:	e8 1d 0e ff ff       	call   401200 <read@plt>
  4103e3:	85 c0                	test   eax,eax
  4103e5:	7f 2a                	jg     410411 <win+0xee9b>
  4103e7:	e8 94 0d ff ff       	call   401180 <__errno_location@plt>
  4103ec:	8b 38                	mov    edi,DWORD PTR [rax]
  4103ee:	e8 8d 0e ff ff       	call   401280 <strerror@plt>
  4103f3:	bf 01 00 00 00       	mov    edi,0x1
  4103f8:	48 8d 35 aa 1c 00 00 	lea    rsi,[rip+0x1caa]        # 4120a9 <_IO_stdin_used+0xa9>
  4103ff:	48 89 c2             	mov    rdx,rax
  410402:	31 c0                	xor    eax,eax
  410404:	e8 27 0e ff ff       	call   401230 <__printf_chk@plt>
  410409:	83 cf ff             	or     edi,0xffffffff
  41040c:	e8 4f 0e ff ff       	call   401260 <exit@plt>
  410411:	48 63 d0             	movsxd rdx,eax
  410414:	48 89 ee             	mov    rsi,rbp
  410417:	bf 01 00 00 00       	mov    edi,0x1
  41041c:	e8 7f 0d ff ff       	call   4011a0 <write@plt>
  410421:	48 8d 3d 2c 1d 00 00 	lea    rdi,[rip+0x1d2c]        # 412154 <_IO_stdin_used+0x154>
  410428:	e8 63 0d ff ff       	call   401190 <puts@plt>
  41042d:	48 8d 3d d0 1b 00 00 	lea    rdi,[rip+0x1bd0]        # 412004 <_IO_stdin_used+0x4>
  410434:	31 f6                	xor    esi,esi
  410436:	31 c0                	xor    eax,eax
  410438:	e8 13 0e ff ff       	call   401250 <open@plt>
  41043d:	89 c7                	mov    edi,eax
  41043f:	85 c0                	test   eax,eax
  410441:	79 34                	jns    410477 <win+0xef01>
  410443:	e8 38 0d ff ff       	call   401180 <__errno_location@plt>
  410448:	8b 38                	mov    edi,DWORD PTR [rax]
  41044a:	e8 31 0e ff ff       	call   401280 <strerror@plt>
  41044f:	48 8d 35 b4 1b 00 00 	lea    rsi,[rip+0x1bb4]        # 41200a <_IO_stdin_used+0xa>
  410456:	bf 01 00 00 00       	mov    edi,0x1
  41045b:	48 89 c2             	mov    rdx,rax
  41045e:	31 c0                	xor    eax,eax
  410460:	e8 cb 0d ff ff       	call   401230 <__printf_chk@plt>
  410465:	e8 76 0d ff ff       	call   4011e0 <geteuid@plt>
  41046a:	85 c0                	test   eax,eax
  41046c:	0f 84 67 11 ff ff    	je     4015d9 <win+0x63>
  410472:	e9 4a 11 ff ff       	jmp    4015c1 <win+0x4b>
  410477:	ba 00 01 00 00       	mov    edx,0x100
  41047c:	48 89 ee             	mov    rsi,rbp
  41047f:	e8 7c 0d ff ff       	call   401200 <read@plt>
  410484:	85 c0                	test   eax,eax
  410486:	7f 2a                	jg     4104b2 <win+0xef3c>
  410488:	e8 f3 0c ff ff       	call   401180 <__errno_location@plt>
  41048d:	8b 38                	mov    edi,DWORD PTR [rax]
  41048f:	e8 ec 0d ff ff       	call   401280 <strerror@plt>
  410494:	bf 01 00 00 00       	mov    edi,0x1
  410499:	48 8d 35 09 1c 00 00 	lea    rsi,[rip+0x1c09]        # 4120a9 <_IO_stdin_used+0xa9>
  4104a0:	48 89 c2             	mov    rdx,rax
  4104a3:	31 c0                	xor    eax,eax
  4104a5:	e8 86 0d ff ff       	call   401230 <__printf_chk@plt>
  4104aa:	83 cf ff             	or     edi,0xffffffff
  4104ad:	e8 ae 0d ff ff       	call   401260 <exit@plt>
  4104b2:	48 89 e5             	mov    rbp,rsp
  4104b5:	48 63 d0             	movsxd rdx,eax
  4104b8:	bf 01 00 00 00       	mov    edi,0x1
  4104bd:	48 89 ee             	mov    rsi,rbp
  4104c0:	e8 db 0c ff ff       	call   4011a0 <write@plt>
  4104c5:	48 8d 3d 88 1c 00 00 	lea    rdi,[rip+0x1c88]        # 412154 <_IO_stdin_used+0x154>
  4104cc:	e8 bf 0c ff ff       	call   401190 <puts@plt>
  4104d1:	48 8d 3d 2c 1b 00 00 	lea    rdi,[rip+0x1b2c]        # 412004 <_IO_stdin_used+0x4>
  4104d8:	31 f6                	xor    esi,esi
  4104da:	31 c0                	xor    eax,eax
  4104dc:	e8 6f 0d ff ff       	call   401250 <open@plt>
  4104e1:	89 c7                	mov    edi,eax
  4104e3:	85 c0                	test   eax,eax
  4104e5:	79 34                	jns    41051b <win+0xefa5>
  4104e7:	e8 94 0c ff ff       	call   401180 <__errno_location@plt>
  4104ec:	8b 38                	mov    edi,DWORD PTR [rax]
  4104ee:	e8 8d 0d ff ff       	call   401280 <strerror@plt>
  4104f3:	48 8d 35 10 1b 00 00 	lea    rsi,[rip+0x1b10]        # 41200a <_IO_stdin_used+0xa>
  4104fa:	bf 01 00 00 00       	mov    edi,0x1
  4104ff:	48 89 c2             	mov    rdx,rax
  410502:	31 c0                	xor    eax,eax
  410504:	e8 27 0d ff ff       	call   401230 <__printf_chk@plt>
  410509:	e8 d2 0c ff ff       	call   4011e0 <geteuid@plt>
  41050e:	85 c0                	test   eax,eax
  410510:	0f 84 c3 10 ff ff    	je     4015d9 <win+0x63>
  410516:	e9 a6 10 ff ff       	jmp    4015c1 <win+0x4b>
  41051b:	ba 00 01 00 00       	mov    edx,0x100
  410520:	48 89 ee             	mov    rsi,rbp
  410523:	e8 d8 0c ff ff       	call   401200 <read@plt>
  410528:	85 c0                	test   eax,eax
  41052a:	7f 2a                	jg     410556 <win+0xefe0>
  41052c:	e8 4f 0c ff ff       	call   401180 <__errno_location@plt>
  410531:	8b 38                	mov    edi,DWORD PTR [rax]
  410533:	e8 48 0d ff ff       	call   401280 <strerror@plt>
  410538:	bf 01 00 00 00       	mov    edi,0x1
  41053d:	48 8d 35 65 1b 00 00 	lea    rsi,[rip+0x1b65]        # 4120a9 <_IO_stdin_used+0xa9>
  410544:	48 89 c2             	mov    rdx,rax
  410547:	31 c0                	xor    eax,eax
  410549:	e8 e2 0c ff ff       	call   401230 <__printf_chk@plt>
  41054e:	83 cf ff             	or     edi,0xffffffff
  410551:	e8 0a 0d ff ff       	call   401260 <exit@plt>
  410556:	48 63 d0             	movsxd rdx,eax
  410559:	48 89 ee             	mov    rsi,rbp
  41055c:	bf 01 00 00 00       	mov    edi,0x1
  410561:	e8 3a 0c ff ff       	call   4011a0 <write@plt>
  410566:	48 8d 3d e7 1b 00 00 	lea    rdi,[rip+0x1be7]        # 412154 <_IO_stdin_used+0x154>
  41056d:	e8 1e 0c ff ff       	call   401190 <puts@plt>
  410572:	48 8d 3d 8b 1a 00 00 	lea    rdi,[rip+0x1a8b]        # 412004 <_IO_stdin_used+0x4>
  410579:	31 f6                	xor    esi,esi
  41057b:	31 c0                	xor    eax,eax
  41057d:	e8 ce 0c ff ff       	call   401250 <open@plt>
  410582:	89 c7                	mov    edi,eax
  410584:	85 c0                	test   eax,eax
  410586:	79 34                	jns    4105bc <win+0xf046>
  410588:	e8 f3 0b ff ff       	call   401180 <__errno_location@plt>
  41058d:	8b 38                	mov    edi,DWORD PTR [rax]
  41058f:	e8 ec 0c ff ff       	call   401280 <strerror@plt>
  410594:	48 8d 35 6f 1a 00 00 	lea    rsi,[rip+0x1a6f]        # 41200a <_IO_stdin_used+0xa>
  41059b:	bf 01 00 00 00       	mov    edi,0x1
  4105a0:	48 89 c2             	mov    rdx,rax
  4105a3:	31 c0                	xor    eax,eax
  4105a5:	e8 86 0c ff ff       	call   401230 <__printf_chk@plt>
  4105aa:	e8 31 0c ff ff       	call   4011e0 <geteuid@plt>
  4105af:	85 c0                	test   eax,eax
  4105b1:	0f 84 22 10 ff ff    	je     4015d9 <win+0x63>
  4105b7:	e9 05 10 ff ff       	jmp    4015c1 <win+0x4b>
  4105bc:	ba 00 01 00 00       	mov    edx,0x100
  4105c1:	48 89 ee             	mov    rsi,rbp
  4105c4:	e8 37 0c ff ff       	call   401200 <read@plt>
  4105c9:	85 c0                	test   eax,eax
  4105cb:	7f 2a                	jg     4105f7 <win+0xf081>
  4105cd:	e8 ae 0b ff ff       	call   401180 <__errno_location@plt>
  4105d2:	8b 38                	mov    edi,DWORD PTR [rax]
  4105d4:	e8 a7 0c ff ff       	call   401280 <strerror@plt>
  4105d9:	bf 01 00 00 00       	mov    edi,0x1
  4105de:	48 8d 35 c4 1a 00 00 	lea    rsi,[rip+0x1ac4]        # 4120a9 <_IO_stdin_used+0xa9>
  4105e5:	48 89 c2             	mov    rdx,rax
  4105e8:	31 c0                	xor    eax,eax
  4105ea:	e8 41 0c ff ff       	call   401230 <__printf_chk@plt>
  4105ef:	83 cf ff             	or     edi,0xffffffff
  4105f2:	e8 69 0c ff ff       	call   401260 <exit@plt>
  4105f7:	48 63 d0             	movsxd rdx,eax
  4105fa:	48 89 ee             	mov    rsi,rbp
  4105fd:	bf 01 00 00 00       	mov    edi,0x1
  410602:	e8 99 0b ff ff       	call   4011a0 <write@plt>
  410607:	48 8d 3d 46 1b 00 00 	lea    rdi,[rip+0x1b46]        # 412154 <_IO_stdin_used+0x154>
  41060e:	e8 7d 0b ff ff       	call   401190 <puts@plt>
  410613:	48 8d 3d ea 19 00 00 	lea    rdi,[rip+0x19ea]        # 412004 <_IO_stdin_used+0x4>
  41061a:	31 f6                	xor    esi,esi
  41061c:	31 c0                	xor    eax,eax
  41061e:	e8 2d 0c ff ff       	call   401250 <open@plt>
  410623:	89 c7                	mov    edi,eax
  410625:	85 c0                	test   eax,eax
  410627:	79 34                	jns    41065d <win+0xf0e7>
  410629:	e8 52 0b ff ff       	call   401180 <__errno_location@plt>
  41062e:	8b 38                	mov    edi,DWORD PTR [rax]
  410630:	e8 4b 0c ff ff       	call   401280 <strerror@plt>
  410635:	48 8d 35 ce 19 00 00 	lea    rsi,[rip+0x19ce]        # 41200a <_IO_stdin_used+0xa>
  41063c:	bf 01 00 00 00       	mov    edi,0x1
  410641:	48 89 c2             	mov    rdx,rax
  410644:	31 c0                	xor    eax,eax
  410646:	e8 e5 0b ff ff       	call   401230 <__printf_chk@plt>
  41064b:	e8 90 0b ff ff       	call   4011e0 <geteuid@plt>
  410650:	85 c0                	test   eax,eax
  410652:	0f 84 81 0f ff ff    	je     4015d9 <win+0x63>
  410658:	e9 64 0f ff ff       	jmp    4015c1 <win+0x4b>
  41065d:	ba 00 01 00 00       	mov    edx,0x100
  410662:	48 89 ee             	mov    rsi,rbp
  410665:	e8 96 0b ff ff       	call   401200 <read@plt>
  41066a:	85 c0                	test   eax,eax
  41066c:	7f 2a                	jg     410698 <win+0xf122>
  41066e:	e8 0d 0b ff ff       	call   401180 <__errno_location@plt>
  410673:	8b 38                	mov    edi,DWORD PTR [rax]
  410675:	e8 06 0c ff ff       	call   401280 <strerror@plt>
  41067a:	bf 01 00 00 00       	mov    edi,0x1
  41067f:	48 8d 35 23 1a 00 00 	lea    rsi,[rip+0x1a23]        # 4120a9 <_IO_stdin_used+0xa9>
  410686:	48 89 c2             	mov    rdx,rax
  410689:	31 c0                	xor    eax,eax
  41068b:	e8 a0 0b ff ff       	call   401230 <__printf_chk@plt>
  410690:	83 cf ff             	or     edi,0xffffffff
  410693:	e8 c8 0b ff ff       	call   401260 <exit@plt>
  410698:	48 63 d0             	movsxd rdx,eax
  41069b:	48 89 ee             	mov    rsi,rbp
  41069e:	bf 01 00 00 00       	mov    edi,0x1
  4106a3:	e8 f8 0a ff ff       	call   4011a0 <write@plt>
  4106a8:	48 8d 3d a5 1a 00 00 	lea    rdi,[rip+0x1aa5]        # 412154 <_IO_stdin_used+0x154>
  4106af:	e8 dc 0a ff ff       	call   401190 <puts@plt>
  4106b4:	48 8d 3d 49 19 00 00 	lea    rdi,[rip+0x1949]        # 412004 <_IO_stdin_used+0x4>
  4106bb:	31 f6                	xor    esi,esi
  4106bd:	31 c0                	xor    eax,eax
  4106bf:	e8 8c 0b ff ff       	call   401250 <open@plt>
  4106c4:	89 c7                	mov    edi,eax
  4106c6:	85 c0                	test   eax,eax
  4106c8:	79 34                	jns    4106fe <win+0xf188>
  4106ca:	e8 b1 0a ff ff       	call   401180 <__errno_location@plt>
  4106cf:	8b 38                	mov    edi,DWORD PTR [rax]
  4106d1:	e8 aa 0b ff ff       	call   401280 <strerror@plt>
  4106d6:	48 8d 35 2d 19 00 00 	lea    rsi,[rip+0x192d]        # 41200a <_IO_stdin_used+0xa>
  4106dd:	bf 01 00 00 00       	mov    edi,0x1
  4106e2:	48 89 c2             	mov    rdx,rax
  4106e5:	31 c0                	xor    eax,eax
  4106e7:	e8 44 0b ff ff       	call   401230 <__printf_chk@plt>
  4106ec:	e8 ef 0a ff ff       	call   4011e0 <geteuid@plt>
  4106f1:	85 c0                	test   eax,eax
  4106f3:	0f 84 e0 0e ff ff    	je     4015d9 <win+0x63>
  4106f9:	e9 c3 0e ff ff       	jmp    4015c1 <win+0x4b>
  4106fe:	ba 00 01 00 00       	mov    edx,0x100
  410703:	48 89 ee             	mov    rsi,rbp
  410706:	e8 f5 0a ff ff       	call   401200 <read@plt>
  41070b:	85 c0                	test   eax,eax
  41070d:	7f 2a                	jg     410739 <win+0xf1c3>
  41070f:	e8 6c 0a ff ff       	call   401180 <__errno_location@plt>
  410714:	8b 38                	mov    edi,DWORD PTR [rax]
  410716:	e8 65 0b ff ff       	call   401280 <strerror@plt>
  41071b:	bf 01 00 00 00       	mov    edi,0x1
  410720:	48 8d 35 82 19 00 00 	lea    rsi,[rip+0x1982]        # 4120a9 <_IO_stdin_used+0xa9>
  410727:	48 89 c2             	mov    rdx,rax
  41072a:	31 c0                	xor    eax,eax
  41072c:	e8 ff 0a ff ff       	call   401230 <__printf_chk@plt>
  410731:	83 cf ff             	or     edi,0xffffffff
  410734:	e8 27 0b ff ff       	call   401260 <exit@plt>
  410739:	48 63 d0             	movsxd rdx,eax
  41073c:	48 89 ee             	mov    rsi,rbp
  41073f:	bf 01 00 00 00       	mov    edi,0x1
  410744:	e8 57 0a ff ff       	call   4011a0 <write@plt>
  410749:	48 8d 3d 04 1a 00 00 	lea    rdi,[rip+0x1a04]        # 412154 <_IO_stdin_used+0x154>
  410750:	e8 3b 0a ff ff       	call   401190 <puts@plt>
  410755:	48 8d 3d a8 18 00 00 	lea    rdi,[rip+0x18a8]        # 412004 <_IO_stdin_used+0x4>
  41075c:	31 f6                	xor    esi,esi
  41075e:	31 c0                	xor    eax,eax
  410760:	e8 eb 0a ff ff       	call   401250 <open@plt>
  410765:	89 c7                	mov    edi,eax
  410767:	85 c0                	test   eax,eax
  410769:	79 34                	jns    41079f <win+0xf229>
  41076b:	e8 10 0a ff ff       	call   401180 <__errno_location@plt>
  410770:	8b 38                	mov    edi,DWORD PTR [rax]
  410772:	e8 09 0b ff ff       	call   401280 <strerror@plt>
  410777:	48 8d 35 8c 18 00 00 	lea    rsi,[rip+0x188c]        # 41200a <_IO_stdin_used+0xa>
  41077e:	bf 01 00 00 00       	mov    edi,0x1
  410783:	48 89 c2             	mov    rdx,rax
  410786:	31 c0                	xor    eax,eax
  410788:	e8 a3 0a ff ff       	call   401230 <__printf_chk@plt>
  41078d:	e8 4e 0a ff ff       	call   4011e0 <geteuid@plt>
  410792:	85 c0                	test   eax,eax
  410794:	0f 84 3f 0e ff ff    	je     4015d9 <win+0x63>
  41079a:	e9 22 0e ff ff       	jmp    4015c1 <win+0x4b>
  41079f:	ba 00 01 00 00       	mov    edx,0x100
  4107a4:	48 89 ee             	mov    rsi,rbp
  4107a7:	e8 54 0a ff ff       	call   401200 <read@plt>
  4107ac:	85 c0                	test   eax,eax
  4107ae:	7f 2a                	jg     4107da <win+0xf264>
  4107b0:	e8 cb 09 ff ff       	call   401180 <__errno_location@plt>
  4107b5:	8b 38                	mov    edi,DWORD PTR [rax]
  4107b7:	e8 c4 0a ff ff       	call   401280 <strerror@plt>
  4107bc:	bf 01 00 00 00       	mov    edi,0x1
  4107c1:	48 8d 35 e1 18 00 00 	lea    rsi,[rip+0x18e1]        # 4120a9 <_IO_stdin_used+0xa9>
  4107c8:	48 89 c2             	mov    rdx,rax
  4107cb:	31 c0                	xor    eax,eax
  4107cd:	e8 5e 0a ff ff       	call   401230 <__printf_chk@plt>
  4107d2:	83 cf ff             	or     edi,0xffffffff
  4107d5:	e8 86 0a ff ff       	call   401260 <exit@plt>
  4107da:	48 63 d0             	movsxd rdx,eax
  4107dd:	48 89 ee             	mov    rsi,rbp
  4107e0:	bf 01 00 00 00       	mov    edi,0x1
  4107e5:	e8 b6 09 ff ff       	call   4011a0 <write@plt>
  4107ea:	48 8d 3d 63 19 00 00 	lea    rdi,[rip+0x1963]        # 412154 <_IO_stdin_used+0x154>
  4107f1:	e8 9a 09 ff ff       	call   401190 <puts@plt>
  4107f6:	48 8d 3d 07 18 00 00 	lea    rdi,[rip+0x1807]        # 412004 <_IO_stdin_used+0x4>
  4107fd:	31 f6                	xor    esi,esi
  4107ff:	31 c0                	xor    eax,eax
  410801:	e8 4a 0a ff ff       	call   401250 <open@plt>
  410806:	89 c7                	mov    edi,eax
  410808:	85 c0                	test   eax,eax
  41080a:	79 34                	jns    410840 <win+0xf2ca>
  41080c:	e8 6f 09 ff ff       	call   401180 <__errno_location@plt>
  410811:	8b 38                	mov    edi,DWORD PTR [rax]
  410813:	e8 68 0a ff ff       	call   401280 <strerror@plt>
  410818:	48 8d 35 eb 17 00 00 	lea    rsi,[rip+0x17eb]        # 41200a <_IO_stdin_used+0xa>
  41081f:	bf 01 00 00 00       	mov    edi,0x1
  410824:	48 89 c2             	mov    rdx,rax
  410827:	31 c0                	xor    eax,eax
  410829:	e8 02 0a ff ff       	call   401230 <__printf_chk@plt>
  41082e:	e8 ad 09 ff ff       	call   4011e0 <geteuid@plt>
  410833:	85 c0                	test   eax,eax
  410835:	0f 84 9e 0d ff ff    	je     4015d9 <win+0x63>
  41083b:	e9 81 0d ff ff       	jmp    4015c1 <win+0x4b>
  410840:	ba 00 01 00 00       	mov    edx,0x100
  410845:	48 89 ee             	mov    rsi,rbp
  410848:	e8 b3 09 ff ff       	call   401200 <read@plt>
  41084d:	85 c0                	test   eax,eax
  41084f:	7f 2a                	jg     41087b <win+0xf305>
  410851:	e8 2a 09 ff ff       	call   401180 <__errno_location@plt>
  410856:	8b 38                	mov    edi,DWORD PTR [rax]
  410858:	e8 23 0a ff ff       	call   401280 <strerror@plt>
  41085d:	bf 01 00 00 00       	mov    edi,0x1
  410862:	48 8d 35 40 18 00 00 	lea    rsi,[rip+0x1840]        # 4120a9 <_IO_stdin_used+0xa9>
  410869:	48 89 c2             	mov    rdx,rax
  41086c:	31 c0                	xor    eax,eax
  41086e:	e8 bd 09 ff ff       	call   401230 <__printf_chk@plt>
  410873:	83 cf ff             	or     edi,0xffffffff
  410876:	e8 e5 09 ff ff       	call   401260 <exit@plt>
  41087b:	48 63 d0             	movsxd rdx,eax
  41087e:	48 89 ee             	mov    rsi,rbp
  410881:	bf 01 00 00 00       	mov    edi,0x1
  410886:	e8 15 09 ff ff       	call   4011a0 <write@plt>
  41088b:	48 8d 3d c2 18 00 00 	lea    rdi,[rip+0x18c2]        # 412154 <_IO_stdin_used+0x154>
  410892:	e8 f9 08 ff ff       	call   401190 <puts@plt>
  410897:	48 8d 3d 66 17 00 00 	lea    rdi,[rip+0x1766]        # 412004 <_IO_stdin_used+0x4>
  41089e:	31 f6                	xor    esi,esi
  4108a0:	31 c0                	xor    eax,eax
  4108a2:	e8 a9 09 ff ff       	call   401250 <open@plt>
  4108a7:	89 c7                	mov    edi,eax
  4108a9:	85 c0                	test   eax,eax
  4108ab:	79 34                	jns    4108e1 <win+0xf36b>
  4108ad:	e8 ce 08 ff ff       	call   401180 <__errno_location@plt>
  4108b2:	8b 38                	mov    edi,DWORD PTR [rax]
  4108b4:	e8 c7 09 ff ff       	call   401280 <strerror@plt>
  4108b9:	48 8d 35 4a 17 00 00 	lea    rsi,[rip+0x174a]        # 41200a <_IO_stdin_used+0xa>
  4108c0:	bf 01 00 00 00       	mov    edi,0x1
  4108c5:	48 89 c2             	mov    rdx,rax
  4108c8:	31 c0                	xor    eax,eax
  4108ca:	e8 61 09 ff ff       	call   401230 <__printf_chk@plt>
  4108cf:	e8 0c 09 ff ff       	call   4011e0 <geteuid@plt>
  4108d4:	85 c0                	test   eax,eax
  4108d6:	0f 84 fd 0c ff ff    	je     4015d9 <win+0x63>
  4108dc:	e9 e0 0c ff ff       	jmp    4015c1 <win+0x4b>
  4108e1:	ba 00 01 00 00       	mov    edx,0x100
  4108e6:	48 89 ee             	mov    rsi,rbp
  4108e9:	e8 12 09 ff ff       	call   401200 <read@plt>
  4108ee:	85 c0                	test   eax,eax
  4108f0:	7f 2a                	jg     41091c <win+0xf3a6>
  4108f2:	e8 89 08 ff ff       	call   401180 <__errno_location@plt>
  4108f7:	8b 38                	mov    edi,DWORD PTR [rax]
  4108f9:	e8 82 09 ff ff       	call   401280 <strerror@plt>
  4108fe:	bf 01 00 00 00       	mov    edi,0x1
  410903:	48 8d 35 9f 17 00 00 	lea    rsi,[rip+0x179f]        # 4120a9 <_IO_stdin_used+0xa9>
  41090a:	48 89 c2             	mov    rdx,rax
  41090d:	31 c0                	xor    eax,eax
  41090f:	e8 1c 09 ff ff       	call   401230 <__printf_chk@plt>
  410914:	83 cf ff             	or     edi,0xffffffff
  410917:	e8 44 09 ff ff       	call   401260 <exit@plt>
  41091c:	48 63 d0             	movsxd rdx,eax
  41091f:	48 89 ee             	mov    rsi,rbp
  410922:	bf 01 00 00 00       	mov    edi,0x1
  410927:	e8 74 08 ff ff       	call   4011a0 <write@plt>
  41092c:	48 8d 3d 21 18 00 00 	lea    rdi,[rip+0x1821]        # 412154 <_IO_stdin_used+0x154>
  410933:	e8 58 08 ff ff       	call   401190 <puts@plt>
  410938:	48 8d 3d c5 16 00 00 	lea    rdi,[rip+0x16c5]        # 412004 <_IO_stdin_used+0x4>
  41093f:	31 f6                	xor    esi,esi
  410941:	31 c0                	xor    eax,eax
  410943:	e8 08 09 ff ff       	call   401250 <open@plt>
  410948:	89 c7                	mov    edi,eax
  41094a:	85 c0                	test   eax,eax
  41094c:	79 34                	jns    410982 <win+0xf40c>
  41094e:	e8 2d 08 ff ff       	call   401180 <__errno_location@plt>
  410953:	8b 38                	mov    edi,DWORD PTR [rax]
  410955:	e8 26 09 ff ff       	call   401280 <strerror@plt>
  41095a:	48 8d 35 a9 16 00 00 	lea    rsi,[rip+0x16a9]        # 41200a <_IO_stdin_used+0xa>
  410961:	bf 01 00 00 00       	mov    edi,0x1
  410966:	48 89 c2             	mov    rdx,rax
  410969:	31 c0                	xor    eax,eax
  41096b:	e8 c0 08 ff ff       	call   401230 <__printf_chk@plt>
  410970:	e8 6b 08 ff ff       	call   4011e0 <geteuid@plt>
  410975:	85 c0                	test   eax,eax
  410977:	0f 84 5c 0c ff ff    	je     4015d9 <win+0x63>
  41097d:	e9 3f 0c ff ff       	jmp    4015c1 <win+0x4b>
  410982:	ba 00 01 00 00       	mov    edx,0x100
  410987:	48 89 ee             	mov    rsi,rbp
  41098a:	e8 71 08 ff ff       	call   401200 <read@plt>
  41098f:	85 c0                	test   eax,eax
  410991:	7f 2a                	jg     4109bd <win+0xf447>
  410993:	e8 e8 07 ff ff       	call   401180 <__errno_location@plt>
  410998:	8b 38                	mov    edi,DWORD PTR [rax]
  41099a:	e8 e1 08 ff ff       	call   401280 <strerror@plt>
  41099f:	bf 01 00 00 00       	mov    edi,0x1
  4109a4:	48 8d 35 fe 16 00 00 	lea    rsi,[rip+0x16fe]        # 4120a9 <_IO_stdin_used+0xa9>
  4109ab:	48 89 c2             	mov    rdx,rax
  4109ae:	31 c0                	xor    eax,eax
  4109b0:	e8 7b 08 ff ff       	call   401230 <__printf_chk@plt>
  4109b5:	83 cf ff             	or     edi,0xffffffff
  4109b8:	e8 a3 08 ff ff       	call   401260 <exit@plt>
  4109bd:	48 63 d0             	movsxd rdx,eax
  4109c0:	48 89 ee             	mov    rsi,rbp
  4109c3:	bf 01 00 00 00       	mov    edi,0x1
  4109c8:	e8 d3 07 ff ff       	call   4011a0 <write@plt>
  4109cd:	48 8d 3d 80 17 00 00 	lea    rdi,[rip+0x1780]        # 412154 <_IO_stdin_used+0x154>
  4109d4:	e8 b7 07 ff ff       	call   401190 <puts@plt>
  4109d9:	48 8d 3d 24 16 00 00 	lea    rdi,[rip+0x1624]        # 412004 <_IO_stdin_used+0x4>
  4109e0:	31 f6                	xor    esi,esi
  4109e2:	31 c0                	xor    eax,eax
  4109e4:	e8 67 08 ff ff       	call   401250 <open@plt>
  4109e9:	89 c7                	mov    edi,eax
  4109eb:	85 c0                	test   eax,eax
  4109ed:	79 34                	jns    410a23 <win+0xf4ad>
  4109ef:	e8 8c 07 ff ff       	call   401180 <__errno_location@plt>
  4109f4:	8b 38                	mov    edi,DWORD PTR [rax]
  4109f6:	e8 85 08 ff ff       	call   401280 <strerror@plt>
  4109fb:	48 8d 35 08 16 00 00 	lea    rsi,[rip+0x1608]        # 41200a <_IO_stdin_used+0xa>
  410a02:	bf 01 00 00 00       	mov    edi,0x1
  410a07:	48 89 c2             	mov    rdx,rax
  410a0a:	31 c0                	xor    eax,eax
  410a0c:	e8 1f 08 ff ff       	call   401230 <__printf_chk@plt>
  410a11:	e8 ca 07 ff ff       	call   4011e0 <geteuid@plt>
  410a16:	85 c0                	test   eax,eax
  410a18:	0f 84 bb 0b ff ff    	je     4015d9 <win+0x63>
  410a1e:	e9 9e 0b ff ff       	jmp    4015c1 <win+0x4b>
  410a23:	ba 00 01 00 00       	mov    edx,0x100
  410a28:	48 89 ee             	mov    rsi,rbp
  410a2b:	e8 d0 07 ff ff       	call   401200 <read@plt>
  410a30:	85 c0                	test   eax,eax
  410a32:	7f 2a                	jg     410a5e <win+0xf4e8>
  410a34:	e8 47 07 ff ff       	call   401180 <__errno_location@plt>
  410a39:	8b 38                	mov    edi,DWORD PTR [rax]
  410a3b:	e8 40 08 ff ff       	call   401280 <strerror@plt>
  410a40:	bf 01 00 00 00       	mov    edi,0x1
  410a45:	48 8d 35 5d 16 00 00 	lea    rsi,[rip+0x165d]        # 4120a9 <_IO_stdin_used+0xa9>
  410a4c:	48 89 c2             	mov    rdx,rax
  410a4f:	31 c0                	xor    eax,eax
  410a51:	e8 da 07 ff ff       	call   401230 <__printf_chk@plt>
  410a56:	83 cf ff             	or     edi,0xffffffff
  410a59:	e8 02 08 ff ff       	call   401260 <exit@plt>
  410a5e:	48 63 d0             	movsxd rdx,eax
  410a61:	48 89 ee             	mov    rsi,rbp
  410a64:	bf 01 00 00 00       	mov    edi,0x1
  410a69:	e8 32 07 ff ff       	call   4011a0 <write@plt>
  410a6e:	48 8d 3d df 16 00 00 	lea    rdi,[rip+0x16df]        # 412154 <_IO_stdin_used+0x154>
  410a75:	e8 16 07 ff ff       	call   401190 <puts@plt>
  410a7a:	48 8d 3d 83 15 00 00 	lea    rdi,[rip+0x1583]        # 412004 <_IO_stdin_used+0x4>
  410a81:	31 f6                	xor    esi,esi
  410a83:	31 c0                	xor    eax,eax
  410a85:	e8 c6 07 ff ff       	call   401250 <open@plt>
  410a8a:	89 c7                	mov    edi,eax
  410a8c:	85 c0                	test   eax,eax
  410a8e:	79 34                	jns    410ac4 <win+0xf54e>
  410a90:	e8 eb 06 ff ff       	call   401180 <__errno_location@plt>
  410a95:	8b 38                	mov    edi,DWORD PTR [rax]
  410a97:	e8 e4 07 ff ff       	call   401280 <strerror@plt>
  410a9c:	48 8d 35 67 15 00 00 	lea    rsi,[rip+0x1567]        # 41200a <_IO_stdin_used+0xa>
  410aa3:	bf 01 00 00 00       	mov    edi,0x1
  410aa8:	48 89 c2             	mov    rdx,rax
  410aab:	31 c0                	xor    eax,eax
  410aad:	e8 7e 07 ff ff       	call   401230 <__printf_chk@plt>
  410ab2:	e8 29 07 ff ff       	call   4011e0 <geteuid@plt>
  410ab7:	85 c0                	test   eax,eax
  410ab9:	0f 84 1a 0b ff ff    	je     4015d9 <win+0x63>
  410abf:	e9 fd 0a ff ff       	jmp    4015c1 <win+0x4b>
  410ac4:	ba 00 01 00 00       	mov    edx,0x100
  410ac9:	48 89 ee             	mov    rsi,rbp
  410acc:	e8 2f 07 ff ff       	call   401200 <read@plt>
  410ad1:	85 c0                	test   eax,eax
  410ad3:	7f 2a                	jg     410aff <win+0xf589>
  410ad5:	e8 a6 06 ff ff       	call   401180 <__errno_location@plt>
  410ada:	8b 38                	mov    edi,DWORD PTR [rax]
  410adc:	e8 9f 07 ff ff       	call   401280 <strerror@plt>
  410ae1:	bf 01 00 00 00       	mov    edi,0x1
  410ae6:	48 8d 35 bc 15 00 00 	lea    rsi,[rip+0x15bc]        # 4120a9 <_IO_stdin_used+0xa9>
  410aed:	48 89 c2             	mov    rdx,rax
  410af0:	31 c0                	xor    eax,eax
  410af2:	e8 39 07 ff ff       	call   401230 <__printf_chk@plt>
  410af7:	83 cf ff             	or     edi,0xffffffff
  410afa:	e8 61 07 ff ff       	call   401260 <exit@plt>
  410aff:	48 63 d0             	movsxd rdx,eax
  410b02:	48 89 ee             	mov    rsi,rbp
  410b05:	bf 01 00 00 00       	mov    edi,0x1
  410b0a:	e8 91 06 ff ff       	call   4011a0 <write@plt>
  410b0f:	48 8d 3d 3e 16 00 00 	lea    rdi,[rip+0x163e]        # 412154 <_IO_stdin_used+0x154>
  410b16:	e8 75 06 ff ff       	call   401190 <puts@plt>
  410b1b:	48 8d 3d e2 14 00 00 	lea    rdi,[rip+0x14e2]        # 412004 <_IO_stdin_used+0x4>
  410b22:	31 f6                	xor    esi,esi
  410b24:	31 c0                	xor    eax,eax
  410b26:	e8 25 07 ff ff       	call   401250 <open@plt>
  410b2b:	89 c7                	mov    edi,eax
  410b2d:	85 c0                	test   eax,eax
  410b2f:	79 34                	jns    410b65 <win+0xf5ef>
  410b31:	e8 4a 06 ff ff       	call   401180 <__errno_location@plt>
  410b36:	8b 38                	mov    edi,DWORD PTR [rax]
  410b38:	e8 43 07 ff ff       	call   401280 <strerror@plt>
  410b3d:	48 8d 35 c6 14 00 00 	lea    rsi,[rip+0x14c6]        # 41200a <_IO_stdin_used+0xa>
  410b44:	bf 01 00 00 00       	mov    edi,0x1
  410b49:	48 89 c2             	mov    rdx,rax
  410b4c:	31 c0                	xor    eax,eax
  410b4e:	e8 dd 06 ff ff       	call   401230 <__printf_chk@plt>
  410b53:	e8 88 06 ff ff       	call   4011e0 <geteuid@plt>
  410b58:	85 c0                	test   eax,eax
  410b5a:	0f 84 79 0a ff ff    	je     4015d9 <win+0x63>
  410b60:	e9 5c 0a ff ff       	jmp    4015c1 <win+0x4b>
  410b65:	ba 00 01 00 00       	mov    edx,0x100
  410b6a:	48 89 ee             	mov    rsi,rbp
  410b6d:	e8 8e 06 ff ff       	call   401200 <read@plt>
  410b72:	85 c0                	test   eax,eax
  410b74:	7f 2a                	jg     410ba0 <win+0xf62a>
  410b76:	e8 05 06 ff ff       	call   401180 <__errno_location@plt>
  410b7b:	8b 38                	mov    edi,DWORD PTR [rax]
  410b7d:	e8 fe 06 ff ff       	call   401280 <strerror@plt>
  410b82:	bf 01 00 00 00       	mov    edi,0x1
  410b87:	48 8d 35 1b 15 00 00 	lea    rsi,[rip+0x151b]        # 4120a9 <_IO_stdin_used+0xa9>
  410b8e:	48 89 c2             	mov    rdx,rax
  410b91:	31 c0                	xor    eax,eax
  410b93:	e8 98 06 ff ff       	call   401230 <__printf_chk@plt>
  410b98:	83 cf ff             	or     edi,0xffffffff
  410b9b:	e8 c0 06 ff ff       	call   401260 <exit@plt>
  410ba0:	48 63 d0             	movsxd rdx,eax
  410ba3:	48 89 ee             	mov    rsi,rbp
  410ba6:	bf 01 00 00 00       	mov    edi,0x1
  410bab:	e8 f0 05 ff ff       	call   4011a0 <write@plt>
  410bb0:	48 8d 3d 9d 15 00 00 	lea    rdi,[rip+0x159d]        # 412154 <_IO_stdin_used+0x154>
  410bb7:	e8 d4 05 ff ff       	call   401190 <puts@plt>
  410bbc:	48 8d 3d 41 14 00 00 	lea    rdi,[rip+0x1441]        # 412004 <_IO_stdin_used+0x4>
  410bc3:	31 f6                	xor    esi,esi
  410bc5:	31 c0                	xor    eax,eax
  410bc7:	e8 84 06 ff ff       	call   401250 <open@plt>
  410bcc:	89 c7                	mov    edi,eax
  410bce:	85 c0                	test   eax,eax
  410bd0:	79 34                	jns    410c06 <win+0xf690>
  410bd2:	e8 a9 05 ff ff       	call   401180 <__errno_location@plt>
  410bd7:	8b 38                	mov    edi,DWORD PTR [rax]
  410bd9:	e8 a2 06 ff ff       	call   401280 <strerror@plt>
  410bde:	48 8d 35 25 14 00 00 	lea    rsi,[rip+0x1425]        # 41200a <_IO_stdin_used+0xa>
  410be5:	bf 01 00 00 00       	mov    edi,0x1
  410bea:	48 89 c2             	mov    rdx,rax
  410bed:	31 c0                	xor    eax,eax
  410bef:	e8 3c 06 ff ff       	call   401230 <__printf_chk@plt>
  410bf4:	e8 e7 05 ff ff       	call   4011e0 <geteuid@plt>
  410bf9:	85 c0                	test   eax,eax
  410bfb:	0f 84 d8 09 ff ff    	je     4015d9 <win+0x63>
  410c01:	e9 bb 09 ff ff       	jmp    4015c1 <win+0x4b>
  410c06:	ba 00 01 00 00       	mov    edx,0x100
  410c0b:	48 89 ee             	mov    rsi,rbp
  410c0e:	e8 ed 05 ff ff       	call   401200 <read@plt>
  410c13:	85 c0                	test   eax,eax
  410c15:	7f 2a                	jg     410c41 <win+0xf6cb>
  410c17:	e8 64 05 ff ff       	call   401180 <__errno_location@plt>
  410c1c:	8b 38                	mov    edi,DWORD PTR [rax]
  410c1e:	e8 5d 06 ff ff       	call   401280 <strerror@plt>
  410c23:	bf 01 00 00 00       	mov    edi,0x1
  410c28:	48 8d 35 7a 14 00 00 	lea    rsi,[rip+0x147a]        # 4120a9 <_IO_stdin_used+0xa9>
  410c2f:	48 89 c2             	mov    rdx,rax
  410c32:	31 c0                	xor    eax,eax
  410c34:	e8 f7 05 ff ff       	call   401230 <__printf_chk@plt>
  410c39:	83 cf ff             	or     edi,0xffffffff
  410c3c:	e8 1f 06 ff ff       	call   401260 <exit@plt>
  410c41:	48 63 d0             	movsxd rdx,eax
  410c44:	48 89 ee             	mov    rsi,rbp
  410c47:	bf 01 00 00 00       	mov    edi,0x1
  410c4c:	e8 4f 05 ff ff       	call   4011a0 <write@plt>
  410c51:	48 8d 3d fc 14 00 00 	lea    rdi,[rip+0x14fc]        # 412154 <_IO_stdin_used+0x154>
  410c58:	e8 33 05 ff ff       	call   401190 <puts@plt>
  410c5d:	48 8d 3d a0 13 00 00 	lea    rdi,[rip+0x13a0]        # 412004 <_IO_stdin_used+0x4>
  410c64:	31 f6                	xor    esi,esi
  410c66:	31 c0                	xor    eax,eax
  410c68:	e8 e3 05 ff ff       	call   401250 <open@plt>
  410c6d:	89 c7                	mov    edi,eax
  410c6f:	85 c0                	test   eax,eax
  410c71:	79 34                	jns    410ca7 <win+0xf731>
  410c73:	e8 08 05 ff ff       	call   401180 <__errno_location@plt>
  410c78:	8b 38                	mov    edi,DWORD PTR [rax]
  410c7a:	e8 01 06 ff ff       	call   401280 <strerror@plt>
  410c7f:	48 8d 35 84 13 00 00 	lea    rsi,[rip+0x1384]        # 41200a <_IO_stdin_used+0xa>
  410c86:	bf 01 00 00 00       	mov    edi,0x1
  410c8b:	48 89 c2             	mov    rdx,rax
  410c8e:	31 c0                	xor    eax,eax
  410c90:	e8 9b 05 ff ff       	call   401230 <__printf_chk@plt>
  410c95:	e8 46 05 ff ff       	call   4011e0 <geteuid@plt>
  410c9a:	85 c0                	test   eax,eax
  410c9c:	0f 84 37 09 ff ff    	je     4015d9 <win+0x63>
  410ca2:	e9 1a 09 ff ff       	jmp    4015c1 <win+0x4b>
  410ca7:	ba 00 01 00 00       	mov    edx,0x100
  410cac:	48 89 ee             	mov    rsi,rbp
  410caf:	e8 4c 05 ff ff       	call   401200 <read@plt>
  410cb4:	85 c0                	test   eax,eax
  410cb6:	7f 2a                	jg     410ce2 <win+0xf76c>
  410cb8:	e8 c3 04 ff ff       	call   401180 <__errno_location@plt>
  410cbd:	8b 38                	mov    edi,DWORD PTR [rax]
  410cbf:	e8 bc 05 ff ff       	call   401280 <strerror@plt>
  410cc4:	bf 01 00 00 00       	mov    edi,0x1
  410cc9:	48 8d 35 d9 13 00 00 	lea    rsi,[rip+0x13d9]        # 4120a9 <_IO_stdin_used+0xa9>
  410cd0:	48 89 c2             	mov    rdx,rax
  410cd3:	31 c0                	xor    eax,eax
  410cd5:	e8 56 05 ff ff       	call   401230 <__printf_chk@plt>
  410cda:	83 cf ff             	or     edi,0xffffffff
  410cdd:	e8 7e 05 ff ff       	call   401260 <exit@plt>
  410ce2:	48 63 d0             	movsxd rdx,eax
  410ce5:	48 89 ee             	mov    rsi,rbp
  410ce8:	bf 01 00 00 00       	mov    edi,0x1
  410ced:	e8 ae 04 ff ff       	call   4011a0 <write@plt>
  410cf2:	48 8d 3d 5b 14 00 00 	lea    rdi,[rip+0x145b]        # 412154 <_IO_stdin_used+0x154>
  410cf9:	e8 92 04 ff ff       	call   401190 <puts@plt>
  410cfe:	48 8d 3d ff 12 00 00 	lea    rdi,[rip+0x12ff]        # 412004 <_IO_stdin_used+0x4>
  410d05:	31 f6                	xor    esi,esi
  410d07:	31 c0                	xor    eax,eax
  410d09:	e8 42 05 ff ff       	call   401250 <open@plt>
  410d0e:	89 c7                	mov    edi,eax
  410d10:	85 c0                	test   eax,eax
  410d12:	79 34                	jns    410d48 <win+0xf7d2>
  410d14:	e8 67 04 ff ff       	call   401180 <__errno_location@plt>
  410d19:	8b 38                	mov    edi,DWORD PTR [rax]
  410d1b:	e8 60 05 ff ff       	call   401280 <strerror@plt>
  410d20:	48 8d 35 e3 12 00 00 	lea    rsi,[rip+0x12e3]        # 41200a <_IO_stdin_used+0xa>
  410d27:	bf 01 00 00 00       	mov    edi,0x1
  410d2c:	48 89 c2             	mov    rdx,rax
  410d2f:	31 c0                	xor    eax,eax
  410d31:	e8 fa 04 ff ff       	call   401230 <__printf_chk@plt>
  410d36:	e8 a5 04 ff ff       	call   4011e0 <geteuid@plt>
  410d3b:	85 c0                	test   eax,eax
  410d3d:	0f 84 96 08 ff ff    	je     4015d9 <win+0x63>
  410d43:	e9 79 08 ff ff       	jmp    4015c1 <win+0x4b>
  410d48:	ba 00 01 00 00       	mov    edx,0x100
  410d4d:	48 89 ee             	mov    rsi,rbp
  410d50:	e8 ab 04 ff ff       	call   401200 <read@plt>
  410d55:	85 c0                	test   eax,eax
  410d57:	7f 2a                	jg     410d83 <win+0xf80d>
  410d59:	e8 22 04 ff ff       	call   401180 <__errno_location@plt>
  410d5e:	8b 38                	mov    edi,DWORD PTR [rax]
  410d60:	e8 1b 05 ff ff       	call   401280 <strerror@plt>
  410d65:	bf 01 00 00 00       	mov    edi,0x1
  410d6a:	48 8d 35 38 13 00 00 	lea    rsi,[rip+0x1338]        # 4120a9 <_IO_stdin_used+0xa9>
  410d71:	48 89 c2             	mov    rdx,rax
  410d74:	31 c0                	xor    eax,eax
  410d76:	e8 b5 04 ff ff       	call   401230 <__printf_chk@plt>
  410d7b:	83 cf ff             	or     edi,0xffffffff
  410d7e:	e8 dd 04 ff ff       	call   401260 <exit@plt>
  410d83:	48 63 d0             	movsxd rdx,eax
  410d86:	48 89 ee             	mov    rsi,rbp
  410d89:	bf 01 00 00 00       	mov    edi,0x1
  410d8e:	e8 0d 04 ff ff       	call   4011a0 <write@plt>
  410d93:	48 8d 3d ba 13 00 00 	lea    rdi,[rip+0x13ba]        # 412154 <_IO_stdin_used+0x154>
  410d9a:	e8 f1 03 ff ff       	call   401190 <puts@plt>
  410d9f:	48 8d 3d 5e 12 00 00 	lea    rdi,[rip+0x125e]        # 412004 <_IO_stdin_used+0x4>
  410da6:	31 f6                	xor    esi,esi
  410da8:	31 c0                	xor    eax,eax
  410daa:	e8 a1 04 ff ff       	call   401250 <open@plt>
  410daf:	89 c7                	mov    edi,eax
  410db1:	85 c0                	test   eax,eax
  410db3:	79 34                	jns    410de9 <win+0xf873>
  410db5:	e8 c6 03 ff ff       	call   401180 <__errno_location@plt>
  410dba:	8b 38                	mov    edi,DWORD PTR [rax]
  410dbc:	e8 bf 04 ff ff       	call   401280 <strerror@plt>
  410dc1:	48 8d 35 42 12 00 00 	lea    rsi,[rip+0x1242]        # 41200a <_IO_stdin_used+0xa>
  410dc8:	bf 01 00 00 00       	mov    edi,0x1
  410dcd:	48 89 c2             	mov    rdx,rax
  410dd0:	31 c0                	xor    eax,eax
  410dd2:	e8 59 04 ff ff       	call   401230 <__printf_chk@plt>
  410dd7:	e8 04 04 ff ff       	call   4011e0 <geteuid@plt>
  410ddc:	85 c0                	test   eax,eax
  410dde:	0f 84 f5 07 ff ff    	je     4015d9 <win+0x63>
  410de4:	e9 d8 07 ff ff       	jmp    4015c1 <win+0x4b>
  410de9:	ba 00 01 00 00       	mov    edx,0x100
  410dee:	48 89 ee             	mov    rsi,rbp
  410df1:	e8 0a 04 ff ff       	call   401200 <read@plt>
  410df6:	85 c0                	test   eax,eax
  410df8:	7f 2a                	jg     410e24 <win+0xf8ae>
  410dfa:	e8 81 03 ff ff       	call   401180 <__errno_location@plt>
  410dff:	8b 38                	mov    edi,DWORD PTR [rax]
  410e01:	e8 7a 04 ff ff       	call   401280 <strerror@plt>
  410e06:	bf 01 00 00 00       	mov    edi,0x1
  410e0b:	48 8d 35 97 12 00 00 	lea    rsi,[rip+0x1297]        # 4120a9 <_IO_stdin_used+0xa9>
  410e12:	48 89 c2             	mov    rdx,rax
  410e15:	31 c0                	xor    eax,eax
  410e17:	e8 14 04 ff ff       	call   401230 <__printf_chk@plt>
  410e1c:	83 cf ff             	or     edi,0xffffffff
  410e1f:	e8 3c 04 ff ff       	call   401260 <exit@plt>
  410e24:	48 63 d0             	movsxd rdx,eax
  410e27:	48 89 ee             	mov    rsi,rbp
  410e2a:	bf 01 00 00 00       	mov    edi,0x1
  410e2f:	e8 6c 03 ff ff       	call   4011a0 <write@plt>
  410e34:	48 8d 3d 19 13 00 00 	lea    rdi,[rip+0x1319]        # 412154 <_IO_stdin_used+0x154>
  410e3b:	e8 50 03 ff ff       	call   401190 <puts@plt>
  410e40:	48 8d 3d bd 11 00 00 	lea    rdi,[rip+0x11bd]        # 412004 <_IO_stdin_used+0x4>
  410e47:	31 f6                	xor    esi,esi
  410e49:	31 c0                	xor    eax,eax
  410e4b:	e8 00 04 ff ff       	call   401250 <open@plt>
  410e50:	89 c7                	mov    edi,eax
  410e52:	85 c0                	test   eax,eax
  410e54:	79 34                	jns    410e8a <win+0xf914>
  410e56:	e8 25 03 ff ff       	call   401180 <__errno_location@plt>
  410e5b:	8b 38                	mov    edi,DWORD PTR [rax]
  410e5d:	e8 1e 04 ff ff       	call   401280 <strerror@plt>
  410e62:	48 8d 35 a1 11 00 00 	lea    rsi,[rip+0x11a1]        # 41200a <_IO_stdin_used+0xa>
  410e69:	bf 01 00 00 00       	mov    edi,0x1
  410e6e:	48 89 c2             	mov    rdx,rax
  410e71:	31 c0                	xor    eax,eax
  410e73:	e8 b8 03 ff ff       	call   401230 <__printf_chk@plt>
  410e78:	e8 63 03 ff ff       	call   4011e0 <geteuid@plt>
  410e7d:	85 c0                	test   eax,eax
  410e7f:	0f 84 54 07 ff ff    	je     4015d9 <win+0x63>
  410e85:	e9 37 07 ff ff       	jmp    4015c1 <win+0x4b>
  410e8a:	ba 00 01 00 00       	mov    edx,0x100
  410e8f:	48 89 ee             	mov    rsi,rbp
  410e92:	e8 69 03 ff ff       	call   401200 <read@plt>
  410e97:	85 c0                	test   eax,eax
  410e99:	7f 2a                	jg     410ec5 <win+0xf94f>
  410e9b:	e8 e0 02 ff ff       	call   401180 <__errno_location@plt>
  410ea0:	8b 38                	mov    edi,DWORD PTR [rax]
  410ea2:	e8 d9 03 ff ff       	call   401280 <strerror@plt>
  410ea7:	bf 01 00 00 00       	mov    edi,0x1
  410eac:	48 8d 35 f6 11 00 00 	lea    rsi,[rip+0x11f6]        # 4120a9 <_IO_stdin_used+0xa9>
  410eb3:	48 89 c2             	mov    rdx,rax
  410eb6:	31 c0                	xor    eax,eax
  410eb8:	e8 73 03 ff ff       	call   401230 <__printf_chk@plt>
  410ebd:	83 cf ff             	or     edi,0xffffffff
  410ec0:	e8 9b 03 ff ff       	call   401260 <exit@plt>
  410ec5:	48 63 d0             	movsxd rdx,eax
  410ec8:	48 89 ee             	mov    rsi,rbp
  410ecb:	bf 01 00 00 00       	mov    edi,0x1
  410ed0:	e8 cb 02 ff ff       	call   4011a0 <write@plt>
  410ed5:	48 8d 3d 78 12 00 00 	lea    rdi,[rip+0x1278]        # 412154 <_IO_stdin_used+0x154>
  410edc:	e8 af 02 ff ff       	call   401190 <puts@plt>
  410ee1:	48 8d 3d 1c 11 00 00 	lea    rdi,[rip+0x111c]        # 412004 <_IO_stdin_used+0x4>
  410ee8:	31 f6                	xor    esi,esi
  410eea:	31 c0                	xor    eax,eax
  410eec:	e8 5f 03 ff ff       	call   401250 <open@plt>
  410ef1:	89 c7                	mov    edi,eax
  410ef3:	85 c0                	test   eax,eax
  410ef5:	79 34                	jns    410f2b <win+0xf9b5>
  410ef7:	e8 84 02 ff ff       	call   401180 <__errno_location@plt>
  410efc:	8b 38                	mov    edi,DWORD PTR [rax]
  410efe:	e8 7d 03 ff ff       	call   401280 <strerror@plt>
  410f03:	48 8d 35 00 11 00 00 	lea    rsi,[rip+0x1100]        # 41200a <_IO_stdin_used+0xa>
  410f0a:	bf 01 00 00 00       	mov    edi,0x1
  410f0f:	48 89 c2             	mov    rdx,rax
  410f12:	31 c0                	xor    eax,eax
  410f14:	e8 17 03 ff ff       	call   401230 <__printf_chk@plt>
  410f19:	e8 c2 02 ff ff       	call   4011e0 <geteuid@plt>
  410f1e:	85 c0                	test   eax,eax
  410f20:	0f 84 b3 06 ff ff    	je     4015d9 <win+0x63>
  410f26:	e9 96 06 ff ff       	jmp    4015c1 <win+0x4b>
  410f2b:	ba 00 01 00 00       	mov    edx,0x100
  410f30:	48 89 ee             	mov    rsi,rbp
  410f33:	e8 c8 02 ff ff       	call   401200 <read@plt>
  410f38:	85 c0                	test   eax,eax
  410f3a:	7f 2a                	jg     410f66 <win+0xf9f0>
  410f3c:	e8 3f 02 ff ff       	call   401180 <__errno_location@plt>
  410f41:	8b 38                	mov    edi,DWORD PTR [rax]
  410f43:	e8 38 03 ff ff       	call   401280 <strerror@plt>
  410f48:	bf 01 00 00 00       	mov    edi,0x1
  410f4d:	48 8d 35 55 11 00 00 	lea    rsi,[rip+0x1155]        # 4120a9 <_IO_stdin_used+0xa9>
  410f54:	48 89 c2             	mov    rdx,rax
  410f57:	31 c0                	xor    eax,eax
  410f59:	e8 d2 02 ff ff       	call   401230 <__printf_chk@plt>
  410f5e:	83 cf ff             	or     edi,0xffffffff
  410f61:	e8 fa 02 ff ff       	call   401260 <exit@plt>
  410f66:	48 63 d0             	movsxd rdx,eax
  410f69:	48 89 ee             	mov    rsi,rbp
  410f6c:	bf 01 00 00 00       	mov    edi,0x1
  410f71:	e8 2a 02 ff ff       	call   4011a0 <write@plt>
  410f76:	48 8d 3d d7 11 00 00 	lea    rdi,[rip+0x11d7]        # 412154 <_IO_stdin_used+0x154>
  410f7d:	e8 0e 02 ff ff       	call   401190 <puts@plt>
  410f82:	48 8d 3d 7b 10 00 00 	lea    rdi,[rip+0x107b]        # 412004 <_IO_stdin_used+0x4>
  410f89:	31 f6                	xor    esi,esi
  410f8b:	31 c0                	xor    eax,eax
  410f8d:	e8 be 02 ff ff       	call   401250 <open@plt>
  410f92:	89 c7                	mov    edi,eax
  410f94:	85 c0                	test   eax,eax
  410f96:	79 34                	jns    410fcc <win+0xfa56>
  410f98:	e8 e3 01 ff ff       	call   401180 <__errno_location@plt>
  410f9d:	8b 38                	mov    edi,DWORD PTR [rax]
  410f9f:	e8 dc 02 ff ff       	call   401280 <strerror@plt>
  410fa4:	48 8d 35 5f 10 00 00 	lea    rsi,[rip+0x105f]        # 41200a <_IO_stdin_used+0xa>
  410fab:	bf 01 00 00 00       	mov    edi,0x1
  410fb0:	48 89 c2             	mov    rdx,rax
  410fb3:	31 c0                	xor    eax,eax
  410fb5:	e8 76 02 ff ff       	call   401230 <__printf_chk@plt>
  410fba:	e8 21 02 ff ff       	call   4011e0 <geteuid@plt>
  410fbf:	85 c0                	test   eax,eax
  410fc1:	0f 84 12 06 ff ff    	je     4015d9 <win+0x63>
  410fc7:	e9 f5 05 ff ff       	jmp    4015c1 <win+0x4b>
  410fcc:	ba 00 01 00 00       	mov    edx,0x100
  410fd1:	48 89 ee             	mov    rsi,rbp
  410fd4:	e8 27 02 ff ff       	call   401200 <read@plt>
  410fd9:	85 c0                	test   eax,eax
  410fdb:	7f 2a                	jg     411007 <win+0xfa91>
  410fdd:	e8 9e 01 ff ff       	call   401180 <__errno_location@plt>
  410fe2:	8b 38                	mov    edi,DWORD PTR [rax]
  410fe4:	e8 97 02 ff ff       	call   401280 <strerror@plt>
  410fe9:	bf 01 00 00 00       	mov    edi,0x1
  410fee:	48 8d 35 b4 10 00 00 	lea    rsi,[rip+0x10b4]        # 4120a9 <_IO_stdin_used+0xa9>
  410ff5:	48 89 c2             	mov    rdx,rax
  410ff8:	31 c0                	xor    eax,eax
  410ffa:	e8 31 02 ff ff       	call   401230 <__printf_chk@plt>
  410fff:	83 cf ff             	or     edi,0xffffffff
  411002:	e8 59 02 ff ff       	call   401260 <exit@plt>
  411007:	48 63 d0             	movsxd rdx,eax
  41100a:	48 89 ee             	mov    rsi,rbp
  41100d:	bf 01 00 00 00       	mov    edi,0x1
  411012:	e8 89 01 ff ff       	call   4011a0 <write@plt>
  411017:	48 8d 3d 36 11 00 00 	lea    rdi,[rip+0x1136]        # 412154 <_IO_stdin_used+0x154>
  41101e:	e8 6d 01 ff ff       	call   401190 <puts@plt>
  411023:	48 8d 3d da 0f 00 00 	lea    rdi,[rip+0xfda]        # 412004 <_IO_stdin_used+0x4>
  41102a:	31 f6                	xor    esi,esi
  41102c:	31 c0                	xor    eax,eax
  41102e:	e8 1d 02 ff ff       	call   401250 <open@plt>
  411033:	89 c7                	mov    edi,eax
  411035:	85 c0                	test   eax,eax
  411037:	79 34                	jns    41106d <win+0xfaf7>
  411039:	e8 42 01 ff ff       	call   401180 <__errno_location@plt>
  41103e:	8b 38                	mov    edi,DWORD PTR [rax]
  411040:	e8 3b 02 ff ff       	call   401280 <strerror@plt>
  411045:	48 8d 35 be 0f 00 00 	lea    rsi,[rip+0xfbe]        # 41200a <_IO_stdin_used+0xa>
  41104c:	bf 01 00 00 00       	mov    edi,0x1
  411051:	48 89 c2             	mov    rdx,rax
  411054:	31 c0                	xor    eax,eax
  411056:	e8 d5 01 ff ff       	call   401230 <__printf_chk@plt>
  41105b:	e8 80 01 ff ff       	call   4011e0 <geteuid@plt>
  411060:	85 c0                	test   eax,eax
  411062:	0f 84 71 05 ff ff    	je     4015d9 <win+0x63>
  411068:	e9 54 05 ff ff       	jmp    4015c1 <win+0x4b>
  41106d:	ba 00 01 00 00       	mov    edx,0x100
  411072:	48 89 ee             	mov    rsi,rbp
  411075:	e8 86 01 ff ff       	call   401200 <read@plt>
  41107a:	85 c0                	test   eax,eax
  41107c:	7f 2a                	jg     4110a8 <win+0xfb32>
  41107e:	e8 fd 00 ff ff       	call   401180 <__errno_location@plt>
  411083:	8b 38                	mov    edi,DWORD PTR [rax]
  411085:	e8 f6 01 ff ff       	call   401280 <strerror@plt>
  41108a:	bf 01 00 00 00       	mov    edi,0x1
  41108f:	48 8d 35 13 10 00 00 	lea    rsi,[rip+0x1013]        # 4120a9 <_IO_stdin_used+0xa9>
  411096:	48 89 c2             	mov    rdx,rax
  411099:	31 c0                	xor    eax,eax
  41109b:	e8 90 01 ff ff       	call   401230 <__printf_chk@plt>
  4110a0:	83 cf ff             	or     edi,0xffffffff
  4110a3:	e8 b8 01 ff ff       	call   401260 <exit@plt>
  4110a8:	48 63 d0             	movsxd rdx,eax
  4110ab:	48 89 ee             	mov    rsi,rbp
  4110ae:	bf 01 00 00 00       	mov    edi,0x1
  4110b3:	e8 e8 00 ff ff       	call   4011a0 <write@plt>
  4110b8:	48 8d 3d 95 10 00 00 	lea    rdi,[rip+0x1095]        # 412154 <_IO_stdin_used+0x154>
  4110bf:	e8 cc 00 ff ff       	call   401190 <puts@plt>
  4110c4:	48 8d 3d 39 0f 00 00 	lea    rdi,[rip+0xf39]        # 412004 <_IO_stdin_used+0x4>
  4110cb:	31 f6                	xor    esi,esi
  4110cd:	31 c0                	xor    eax,eax
  4110cf:	e8 7c 01 ff ff       	call   401250 <open@plt>
  4110d4:	89 c7                	mov    edi,eax
  4110d6:	85 c0                	test   eax,eax
  4110d8:	79 34                	jns    41110e <win+0xfb98>
  4110da:	e8 a1 00 ff ff       	call   401180 <__errno_location@plt>
  4110df:	8b 38                	mov    edi,DWORD PTR [rax]
  4110e1:	e8 9a 01 ff ff       	call   401280 <strerror@plt>
  4110e6:	48 8d 35 1d 0f 00 00 	lea    rsi,[rip+0xf1d]        # 41200a <_IO_stdin_used+0xa>
  4110ed:	bf 01 00 00 00       	mov    edi,0x1
  4110f2:	48 89 c2             	mov    rdx,rax
  4110f5:	31 c0                	xor    eax,eax
  4110f7:	e8 34 01 ff ff       	call   401230 <__printf_chk@plt>
  4110fc:	e8 df 00 ff ff       	call   4011e0 <geteuid@plt>
  411101:	85 c0                	test   eax,eax
  411103:	0f 84 d0 04 ff ff    	je     4015d9 <win+0x63>
  411109:	e9 b3 04 ff ff       	jmp    4015c1 <win+0x4b>
  41110e:	ba 00 01 00 00       	mov    edx,0x100
  411113:	48 89 ee             	mov    rsi,rbp
  411116:	e8 e5 00 ff ff       	call   401200 <read@plt>
  41111b:	85 c0                	test   eax,eax
  41111d:	7f 2a                	jg     411149 <win+0xfbd3>
  41111f:	e8 5c 00 ff ff       	call   401180 <__errno_location@plt>
  411124:	8b 38                	mov    edi,DWORD PTR [rax]
  411126:	e8 55 01 ff ff       	call   401280 <strerror@plt>
  41112b:	bf 01 00 00 00       	mov    edi,0x1
  411130:	48 8d 35 72 0f 00 00 	lea    rsi,[rip+0xf72]        # 4120a9 <_IO_stdin_used+0xa9>
  411137:	48 89 c2             	mov    rdx,rax
  41113a:	31 c0                	xor    eax,eax
  41113c:	e8 ef 00 ff ff       	call   401230 <__printf_chk@plt>
  411141:	83 cf ff             	or     edi,0xffffffff
  411144:	e8 17 01 ff ff       	call   401260 <exit@plt>
  411149:	48 89 e6             	mov    rsi,rsp
  41114c:	48 63 d0             	movsxd rdx,eax
  41114f:	bf 01 00 00 00       	mov    edi,0x1
  411154:	e8 47 00 ff ff       	call   4011a0 <write@plt>
  411159:	48 8d 3d f4 0f 00 00 	lea    rdi,[rip+0xff4]        # 412154 <_IO_stdin_used+0x154>
  411160:	e8 2b 00 ff ff       	call   401190 <puts@plt>
  411165:	48 81 c4 00 01 00 00 	add    rsp,0x100
  41116c:	5d                   	pop    rbp
  41116d:	c3                   	ret

000000000041116e <read_exact>:
  41116e:	f3 0f 1e fa          	endbr64
  411172:	41 54                	push   r12
  411174:	48 63 d2             	movsxd rdx,edx
  411177:	49 89 cc             	mov    r12,rcx
  41117a:	55                   	push   rbp
  41117b:	44 89 c5             	mov    ebp,r8d
  41117e:	53                   	push   rbx
  41117f:	48 89 d3             	mov    rbx,rdx
  411182:	e8 79 00 ff ff       	call   401200 <read@plt>
  411187:	39 c3                	cmp    ebx,eax
  411189:	74 2e                	je     4111b9 <read_exact+0x4b>
  41118b:	48 8b 3d ae 2e 00 00 	mov    rdi,QWORD PTR [rip+0x2eae]        # 414040 <stderr@GLIBC_2.2.5>
  411192:	4c 89 e2             	mov    rdx,r12
  411195:	be 01 00 00 00       	mov    esi,0x1
  41119a:	31 c0                	xor    eax,eax
  41119c:	e8 cf 00 ff ff       	call   401270 <__fprintf_chk@plt>
  4111a1:	48 8b 35 98 2e 00 00 	mov    rsi,QWORD PTR [rip+0x2e98]        # 414040 <stderr@GLIBC_2.2.5>
  4111a8:	bf 0a 00 00 00       	mov    edi,0xa
  4111ad:	e8 3e 00 ff ff       	call   4011f0 <fputc@plt>
  4111b2:	89 ef                	mov    edi,ebp
  4111b4:	e8 a7 00 ff ff       	call   401260 <exit@plt>
  4111b9:	5b                   	pop    rbx
  4111ba:	5d                   	pop    rbp
  4111bb:	41 5c                	pop    r12
  4111bd:	c3                   	ret

00000000004111be <handle_1>:
  4111be:	f3 0f 1e fa          	endbr64
  4111c2:	41 57                	push   r15
  4111c4:	41 56                	push   r14
  4111c6:	41 55                	push   r13
  4111c8:	41 54                	push   r12
  4111ca:	55                   	push   rbp
  4111cb:	53                   	push   rbx
  4111cc:	48 89 fb             	mov    rbx,rdi
  4111cf:	48 83 ec 38          	sub    rsp,0x38
  4111d3:	0f b6 6f 06          	movzx  ebp,BYTE PTR [rdi+0x6]
  4111d7:	0f b6 57 07          	movzx  edx,BYTE PTR [rdi+0x7]
  4111db:	0f af ea             	imul   ebp,edx
  4111de:	48 63 ed             	movsxd rbp,ebp
  4111e1:	48 c1 e5 02          	shl    rbp,0x2
  4111e5:	48 89 ef             	mov    rdi,rbp
  4111e8:	e8 33 00 ff ff       	call   401220 <malloc@plt>
  4111ed:	48 85 c0             	test   rax,rax
  4111f0:	75 0e                	jne    411200 <handle_1+0x42>
  4111f2:	48 8d 3d da 0e 00 00 	lea    rdi,[rip+0xeda]        # 4120d3 <_IO_stdin_used+0xd3>
  4111f9:	e8 92 ff fe ff       	call   401190 <puts@plt>
  4111fe:	eb 57                	jmp    411257 <handle_1+0x99>
  411200:	89 ea                	mov    edx,ebp
  411202:	48 89 c6             	mov    rsi,rax
  411205:	41 83 c8 ff          	or     r8d,0xffffffff
  411209:	31 ff                	xor    edi,edi
  41120b:	48 8d 0d f6 0e 00 00 	lea    rcx,[rip+0xef6]        # 412108 <_IO_stdin_used+0x108>
  411212:	49 89 c4             	mov    r12,rax
  411215:	e8 54 ff ff ff       	call   41116e <read_exact>
  41121a:	0f b6 43 07          	movzx  eax,BYTE PTR [rbx+0x7]
  41121e:	0f b6 53 06          	movzx  edx,BYTE PTR [rbx+0x6]
  411222:	0f af d0             	imul   edx,eax
  411225:	31 c0                	xor    eax,eax
  411227:	39 c2                	cmp    edx,eax
  411229:	7e 34                	jle    41125f <handle_1+0xa1>
  41122b:	41 0f b6 4c 84 03    	movzx  ecx,BYTE PTR [r12+rax*4+0x3]
  411231:	48 ff c0             	inc    rax
  411234:	8d 71 e0             	lea    esi,[rcx-0x20]
  411237:	40 80 fe 5e          	cmp    sil,0x5e
  41123b:	76 ea                	jbe    411227 <handle_1+0x69>
  41123d:	48 8b 3d fc 2d 00 00 	mov    rdi,QWORD PTR [rip+0x2dfc]        # 414040 <stderr@GLIBC_2.2.5>
  411244:	48 8d 15 d9 0e 00 00 	lea    rdx,[rip+0xed9]        # 412124 <_IO_stdin_used+0x124>
  41124b:	be 01 00 00 00       	mov    esi,0x1
  411250:	31 c0                	xor    eax,eax
  411252:	e8 19 00 ff ff       	call   401270 <__fprintf_chk@plt>
  411257:	83 cf ff             	or     edi,0xffffffff
  41125a:	e8 01 00 ff ff       	call   401260 <exit@plt>
  41125f:	45 31 ed             	xor    r13d,r13d
  411262:	4c 8d 74 24 17       	lea    r14,[rsp+0x17]
  411267:	0f b6 43 07          	movzx  eax,BYTE PTR [rbx+0x7]
  41126b:	44 39 e8             	cmp    eax,r13d
  41126e:	0f 8e 98 00 00 00    	jle    41130c <handle_1+0x14e>
  411274:	31 ed                	xor    ebp,ebp
  411276:	44 0f b6 7b 06       	movzx  r15d,BYTE PTR [rbx+0x6]
  41127b:	41 39 ef             	cmp    r15d,ebp
  41127e:	0f 8e 80 00 00 00    	jle    411304 <handle_1+0x146>
  411284:	45 89 fa             	mov    r10d,r15d
  411287:	b9 19 00 00 00       	mov    ecx,0x19
  41128c:	be 19 00 00 00       	mov    esi,0x19
  411291:	4c 89 f7             	mov    rdi,r14
  411294:	45 0f af d5          	imul   r10d,r13d
  411298:	4c 8d 05 b7 0e 00 00 	lea    r8,[rip+0xeb7]        # 412156 <_IO_stdin_used+0x156>
  41129f:	41 8d 04 2a          	lea    eax,[r10+rbp*1]
  4112a3:	44 89 54 24 0c       	mov    DWORD PTR [rsp+0xc],r10d
  4112a8:	48 98                	cdqe
  4112aa:	52                   	push   rdx
  4112ab:	49 8d 04 84          	lea    rax,[r12+rax*4]
  4112af:	0f b6 50 03          	movzx  edx,BYTE PTR [rax+0x3]
  4112b3:	52                   	push   rdx
  4112b4:	0f b6 50 02          	movzx  edx,BYTE PTR [rax+0x2]
  4112b8:	52                   	push   rdx
  4112b9:	0f b6 50 01          	movzx  edx,BYTE PTR [rax+0x1]
  4112bd:	52                   	push   rdx
  4112be:	44 0f b6 08          	movzx  r9d,BYTE PTR [rax]
  4112c2:	ba 01 00 00 00       	mov    edx,0x1
  4112c7:	31 c0                	xor    eax,eax
  4112c9:	e8 92 fe fe ff       	call   401160 <__snprintf_chk@plt>
  4112ce:	89 e8                	mov    eax,ebp
  4112d0:	44 8b 54 24 2c       	mov    r10d,DWORD PTR [rsp+0x2c]
  4112d5:	41 0f 10 06          	movups xmm0,XMMWORD PTR [r14]
  4112d9:	99                   	cdq
  4112da:	48 83 c4 20          	add    rsp,0x20
  4112de:	ff c5                	inc    ebp
  4112e0:	41 f7 ff             	idiv   r15d
  4112e3:	42 8d 04 12          	lea    eax,[rdx+r10*1]
  4112e7:	31 d2                	xor    edx,edx
  4112e9:	f7 73 0c             	div    DWORD PTR [rbx+0xc]
  4112ec:	48 6b d2 18          	imul   rdx,rdx,0x18
  4112f0:	48 03 53 10          	add    rdx,QWORD PTR [rbx+0x10]
  4112f4:	0f 11 02             	movups XMMWORD PTR [rdx],xmm0
  4112f7:	49 8b 46 10          	mov    rax,QWORD PTR [r14+0x10]
  4112fb:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
  4112ff:	e9 72 ff ff ff       	jmp    411276 <handle_1+0xb8>
  411304:	41 ff c5             	inc    r13d
  411307:	e9 5b ff ff ff       	jmp    411267 <handle_1+0xa9>
  41130c:	48 83 c4 38          	add    rsp,0x38
  411310:	5b                   	pop    rbx
  411311:	5d                   	pop    rbp
  411312:	41 5c                	pop    r12
  411314:	41 5d                	pop    r13
  411316:	41 5e                	pop    r14
  411318:	41 5f                	pop    r15
  41131a:	c3                   	ret

000000000041131b <handle_2>:
  41131b:	f3 0f 1e fa          	endbr64
  41131f:	41 57                	push   r15
  411321:	41 83 c8 ff          	or     r8d,0xffffffff
  411325:	ba 01 00 00 00       	mov    edx,0x1
  41132a:	48 8d 0d 42 0e 00 00 	lea    rcx,[rip+0xe42]        # 412173 <_IO_stdin_used+0x173>
  411331:	41 56                	push   r14
  411333:	41 55                	push   r13
  411335:	41 54                	push   r12
  411337:	49 89 fc             	mov    r12,rdi
  41133a:	31 ff                	xor    edi,edi
  41133c:	55                   	push   rbp
  41133d:	53                   	push   rbx
  41133e:	48 83 ec 28          	sub    rsp,0x28
  411342:	48 8d 74 24 05       	lea    rsi,[rsp+0x5]
  411347:	e8 22 fe ff ff       	call   41116e <read_exact>
  41134c:	41 83 c8 ff          	or     r8d,0xffffffff
  411350:	31 ff                	xor    edi,edi
  411352:	48 8d 74 24 06       	lea    rsi,[rsp+0x6]
  411357:	48 8d 0d 34 0e 00 00 	lea    rcx,[rip+0xe34]        # 412192 <_IO_stdin_used+0x192>
  41135e:	ba 01 00 00 00       	mov    edx,0x1
  411363:	e8 06 fe ff ff       	call   41116e <read_exact>
  411368:	41 83 c8 ff          	or     r8d,0xffffffff
  41136c:	31 ff                	xor    edi,edi
  41136e:	48 8d 74 24 03       	lea    rsi,[rsp+0x3]
  411373:	48 8d 0d 37 0e 00 00 	lea    rcx,[rip+0xe37]        # 4121b1 <_IO_stdin_used+0x1b1>
  41137a:	ba 01 00 00 00       	mov    edx,0x1
  41137f:	e8 ea fd ff ff       	call   41116e <read_exact>
  411384:	31 ff                	xor    edi,edi
  411386:	41 83 c8 ff          	or     r8d,0xffffffff
  41138a:	ba 01 00 00 00       	mov    edx,0x1
  41138f:	48 8d 74 24 04       	lea    rsi,[rsp+0x4]
  411394:	48 8d 0d 34 0e 00 00 	lea    rcx,[rip+0xe34]        # 4121cf <_IO_stdin_used+0x1cf>
  41139b:	e8 ce fd ff ff       	call   41116e <read_exact>
  4113a0:	0f b6 5c 24 03       	movzx  ebx,BYTE PTR [rsp+0x3]
  4113a5:	0f b6 54 24 04       	movzx  edx,BYTE PTR [rsp+0x4]
  4113aa:	0f af da             	imul   ebx,edx
  4113ad:	48 63 db             	movsxd rbx,ebx
  4113b0:	48 c1 e3 02          	shl    rbx,0x2
  4113b4:	48 89 df             	mov    rdi,rbx
  4113b7:	e8 64 fe fe ff       	call   401220 <malloc@plt>
  4113bc:	48 85 c0             	test   rax,rax
  4113bf:	75 0e                	jne    4113cf <handle_2+0xb4>
  4113c1:	48 8d 3d 0b 0d 00 00 	lea    rdi,[rip+0xd0b]        # 4120d3 <_IO_stdin_used+0xd3>
  4113c8:	e8 c3 fd fe ff       	call   401190 <puts@plt>
  4113cd:	eb 58                	jmp    411427 <handle_2+0x10c>
  4113cf:	89 da                	mov    edx,ebx
  4113d1:	48 89 c6             	mov    rsi,rax
  4113d4:	41 83 c8 ff          	or     r8d,0xffffffff
  4113d8:	31 ff                	xor    edi,edi
  4113da:	48 8d 0d 27 0d 00 00 	lea    rcx,[rip+0xd27]        # 412108 <_IO_stdin_used+0x108>
  4113e1:	48 89 c5             	mov    rbp,rax
  4113e4:	e8 85 fd ff ff       	call   41116e <read_exact>
  4113e9:	0f b6 44 24 04       	movzx  eax,BYTE PTR [rsp+0x4]
  4113ee:	0f b6 54 24 03       	movzx  edx,BYTE PTR [rsp+0x3]
  4113f3:	0f af d0             	imul   edx,eax
  4113f6:	31 c0                	xor    eax,eax
  4113f8:	39 c2                	cmp    edx,eax
  4113fa:	7e 33                	jle    41142f <handle_2+0x114>
  4113fc:	0f b6 4c 85 03       	movzx  ecx,BYTE PTR [rbp+rax*4+0x3]
  411401:	48 ff c0             	inc    rax
  411404:	8d 71 e0             	lea    esi,[rcx-0x20]
  411407:	40 80 fe 5e          	cmp    sil,0x5e
  41140b:	76 eb                	jbe    4113f8 <handle_2+0xdd>
  41140d:	48 8b 3d 2c 2c 00 00 	mov    rdi,QWORD PTR [rip+0x2c2c]        # 414040 <stderr@GLIBC_2.2.5>
  411414:	48 8d 15 09 0d 00 00 	lea    rdx,[rip+0xd09]        # 412124 <_IO_stdin_used+0x124>
  41141b:	be 01 00 00 00       	mov    esi,0x1
  411420:	31 c0                	xor    eax,eax
  411422:	e8 49 fe fe ff       	call   401270 <__fprintf_chk@plt>
  411427:	83 cf ff             	or     edi,0xffffffff
  41142a:	e8 31 fe fe ff       	call   401260 <exit@plt>
  41142f:	45 31 ed             	xor    r13d,r13d
  411432:	4c 8d 7c 24 07       	lea    r15,[rsp+0x7]
  411437:	0f b6 44 24 04       	movzx  eax,BYTE PTR [rsp+0x4]
  41143c:	44 39 e8             	cmp    eax,r13d
  41143f:	0f 8e a7 00 00 00    	jle    4114ec <handle_2+0x1d1>
  411445:	45 31 f6             	xor    r14d,r14d
  411448:	0f b6 4c 24 03       	movzx  ecx,BYTE PTR [rsp+0x3]
  41144d:	44 39 f1             	cmp    ecx,r14d
  411450:	0f 8e 8e 00 00 00    	jle    4114e4 <handle_2+0x1c9>
  411456:	0f b6 44 24 05       	movzx  eax,BYTE PTR [rsp+0x5]
  41145b:	0f b6 5c 24 06       	movzx  ebx,BYTE PTR [rsp+0x6]
  411460:	41 0f af cd          	imul   ecx,r13d
  411464:	4c 89 ff             	mov    rdi,r15
  411467:	41 0f b6 74 24 06    	movzx  esi,BYTE PTR [r12+0x6]
  41146d:	4c 8d 05 e2 0c 00 00 	lea    r8,[rip+0xce2]        # 412156 <_IO_stdin_used+0x156>
  411474:	44 01 f0             	add    eax,r14d
  411477:	44 01 eb             	add    ebx,r13d
  41147a:	99                   	cdq
  41147b:	0f af de             	imul   ebx,esi
  41147e:	44 01 f1             	add    ecx,r14d
  411481:	41 ff c6             	inc    r14d
  411484:	f7 fe                	idiv   esi
  411486:	48 63 c9             	movsxd rcx,ecx
  411489:	be 19 00 00 00       	mov    esi,0x19
  41148e:	48 8d 44 8d 00       	lea    rax,[rbp+rcx*4+0x0]
  411493:	b9 19 00 00 00       	mov    ecx,0x19
  411498:	01 d3                	add    ebx,edx
  41149a:	52                   	push   rdx
  41149b:	0f b6 50 03          	movzx  edx,BYTE PTR [rax+0x3]
  41149f:	52                   	push   rdx
  4114a0:	0f b6 50 02          	movzx  edx,BYTE PTR [rax+0x2]
  4114a4:	52                   	push   rdx
  4114a5:	0f b6 50 01          	movzx  edx,BYTE PTR [rax+0x1]
  4114a9:	52                   	push   rdx
  4114aa:	44 0f b6 08          	movzx  r9d,BYTE PTR [rax]
  4114ae:	ba 01 00 00 00       	mov    edx,0x1
  4114b3:	31 c0                	xor    eax,eax
  4114b5:	e8 a6 fc fe ff       	call   401160 <__snprintf_chk@plt>
  4114ba:	89 d8                	mov    eax,ebx
  4114bc:	31 d2                	xor    edx,edx
  4114be:	41 0f 10 07          	movups xmm0,XMMWORD PTR [r15]
  4114c2:	41 f7 74 24 0c       	div    DWORD PTR [r12+0xc]
  4114c7:	48 83 c4 20          	add    rsp,0x20
  4114cb:	48 6b d2 18          	imul   rdx,rdx,0x18
  4114cf:	49 03 54 24 10       	add    rdx,QWORD PTR [r12+0x10]
  4114d4:	0f 11 02             	movups XMMWORD PTR [rdx],xmm0
  4114d7:	49 8b 47 10          	mov    rax,QWORD PTR [r15+0x10]
  4114db:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
  4114df:	e9 64 ff ff ff       	jmp    411448 <handle_2+0x12d>
  4114e4:	41 ff c5             	inc    r13d
  4114e7:	e9 4b ff ff ff       	jmp    411437 <handle_2+0x11c>
  4114ec:	48 83 c4 28          	add    rsp,0x28
  4114f0:	5b                   	pop    rbx
  4114f1:	5d                   	pop    rbp
  4114f2:	41 5c                	pop    r12
  4114f4:	41 5d                	pop    r13
  4114f6:	41 5e                	pop    r14
  4114f8:	41 5f                	pop    r15
  4114fa:	c3                   	ret

00000000004114fb <handle_3>:
  4114fb:	f3 0f 1e fa          	endbr64
  4114ff:	41 54                	push   r12
  411501:	41 83 c8 ff          	or     r8d,0xffffffff
  411505:	ba 01 00 00 00       	mov    edx,0x1
  41150a:	48 8d 0d dd 0c 00 00 	lea    rcx,[rip+0xcdd]        # 4121ee <_IO_stdin_used+0x1ee>
  411511:	55                   	push   rbp
  411512:	48 89 fd             	mov    rbp,rdi
  411515:	31 ff                	xor    edi,edi
  411517:	53                   	push   rbx
  411518:	48 83 ec 10          	sub    rsp,0x10
  41151c:	48 8d 74 24 0d       	lea    rsi,[rsp+0xd]
  411521:	e8 48 fc ff ff       	call   41116e <read_exact>
  411526:	48 8d 74 24 0e       	lea    rsi,[rsp+0xe]
  41152b:	41 83 c8 ff          	or     r8d,0xffffffff
  41152f:	31 ff                	xor    edi,edi
  411531:	48 8d 0d 79 0c 00 00 	lea    rcx,[rip+0xc79]        # 4121b1 <_IO_stdin_used+0x1b1>
  411538:	ba 01 00 00 00       	mov    edx,0x1
  41153d:	e8 2c fc ff ff       	call   41116e <read_exact>
  411542:	ba 01 00 00 00       	mov    edx,0x1
  411547:	31 ff                	xor    edi,edi
  411549:	41 83 c8 ff          	or     r8d,0xffffffff
  41154d:	48 8d 74 24 0f       	lea    rsi,[rsp+0xf]
  411552:	48 8d 0d 76 0c 00 00 	lea    rcx,[rip+0xc76]        # 4121cf <_IO_stdin_used+0x1cf>
  411559:	e8 10 fc ff ff       	call   41116e <read_exact>
  41155e:	0f b6 44 24 0d       	movzx  eax,BYTE PTR [rsp+0xd]
  411563:	8a 54 24 0e          	mov    dl,BYTE PTR [rsp+0xe]
  411567:	48 c1 e0 04          	shl    rax,0x4
  41156b:	48 01 e8             	add    rax,rbp
  41156e:	88 50 19             	mov    BYTE PTR [rax+0x19],dl
  411571:	48 8b 78 20          	mov    rdi,QWORD PTR [rax+0x20]
  411575:	8a 54 24 0f          	mov    dl,BYTE PTR [rsp+0xf]
  411579:	88 50 18             	mov    BYTE PTR [rax+0x18],dl
  41157c:	48 85 ff             	test   rdi,rdi
  41157f:	74 05                	je     411586 <handle_3+0x8b>
  411581:	e8 ea fb fe ff       	call   401170 <free@plt>
  411586:	44 0f b6 64 24 0e    	movzx  r12d,BYTE PTR [rsp+0xe]
  41158c:	0f b6 54 24 0f       	movzx  edx,BYTE PTR [rsp+0xf]
  411591:	44 0f af e2          	imul   r12d,edx
  411595:	49 63 fc             	movsxd rdi,r12d
  411598:	e8 83 fc fe ff       	call   401220 <malloc@plt>
  41159d:	48 89 c3             	mov    rbx,rax
  4115a0:	48 85 c0             	test   rax,rax
  4115a3:	75 0e                	jne    4115b3 <handle_3+0xb8>
  4115a5:	48 8d 3d 27 0b 00 00 	lea    rdi,[rip+0xb27]        # 4120d3 <_IO_stdin_used+0xd3>
  4115ac:	e8 df fb fe ff       	call   401190 <puts@plt>
  4115b1:	eb 55                	jmp    411608 <handle_3+0x10d>
  4115b3:	44 89 e2             	mov    edx,r12d
  4115b6:	48 89 c6             	mov    rsi,rax
  4115b9:	41 83 c8 ff          	or     r8d,0xffffffff
  4115bd:	31 ff                	xor    edi,edi
  4115bf:	48 8d 0d 42 0b 00 00 	lea    rcx,[rip+0xb42]        # 412108 <_IO_stdin_used+0x108>
  4115c6:	e8 a3 fb ff ff       	call   41116e <read_exact>
  4115cb:	0f b6 44 24 0f       	movzx  eax,BYTE PTR [rsp+0xf]
  4115d0:	0f b6 54 24 0e       	movzx  edx,BYTE PTR [rsp+0xe]
  4115d5:	0f af d0             	imul   edx,eax
  4115d8:	31 c0                	xor    eax,eax
  4115da:	39 c2                	cmp    edx,eax
  4115dc:	7e 32                	jle    411610 <handle_3+0x115>
  4115de:	0f b6 0c 03          	movzx  ecx,BYTE PTR [rbx+rax*1]
  4115e2:	48 ff c0             	inc    rax
  4115e5:	8d 71 e0             	lea    esi,[rcx-0x20]
  4115e8:	40 80 fe 5e          	cmp    sil,0x5e
  4115ec:	76 ec                	jbe    4115da <handle_3+0xdf>
  4115ee:	48 8b 3d 4b 2a 00 00 	mov    rdi,QWORD PTR [rip+0x2a4b]        # 414040 <stderr@GLIBC_2.2.5>
  4115f5:	48 8d 15 28 0b 00 00 	lea    rdx,[rip+0xb28]        # 412124 <_IO_stdin_used+0x124>
  4115fc:	be 01 00 00 00       	mov    esi,0x1
  411601:	31 c0                	xor    eax,eax
  411603:	e8 68 fc fe ff       	call   401270 <__fprintf_chk@plt>
  411608:	83 cf ff             	or     edi,0xffffffff
  41160b:	e8 50 fc fe ff       	call   401260 <exit@plt>
  411610:	0f b6 44 24 0d       	movzx  eax,BYTE PTR [rsp+0xd]
  411615:	48 c1 e0 04          	shl    rax,0x4
  411619:	48 89 5c 28 20       	mov    QWORD PTR [rax+rbp*1+0x20],rbx
  41161e:	48 83 c4 10          	add    rsp,0x10
  411622:	5b                   	pop    rbx
  411623:	5d                   	pop    rbp
  411624:	41 5c                	pop    r12
  411626:	c3                   	ret

0000000000411627 <handle_4>:
  411627:	f3 0f 1e fa          	endbr64
  41162b:	41 57                	push   r15
  41162d:	41 56                	push   r14
  41162f:	41 55                	push   r13
  411631:	41 54                	push   r12
  411633:	55                   	push   rbp
  411634:	53                   	push   rbx
  411635:	4c 8d 9c 24 00 00 fc 	lea    r11,[rsp-0x40000]
  41163c:	ff 
  41163d:	48 81 ec 00 10 00 00 	sub    rsp,0x1000
  411644:	83 0c 24 00          	or     DWORD PTR [rsp],0x0
  411648:	4c 39 dc             	cmp    rsp,r11
  41164b:	75 f0                	jne    41163d <handle_4+0x16>
  41164d:	48 83 ec 48          	sub    rsp,0x48
  411651:	48 8d 0d b8 0b 00 00 	lea    rcx,[rip+0xbb8]        # 412210 <_IO_stdin_used+0x210>
  411658:	ba 09 00 00 00       	mov    edx,0x9
  41165d:	41 83 c8 ff          	or     r8d,0xffffffff
  411661:	48 89 fb             	mov    rbx,rdi
  411664:	48 8d 74 24 1e       	lea    rsi,[rsp+0x1e]
  411669:	31 ff                	xor    edi,edi
  41166b:	e8 fe fa ff ff       	call   41116e <read_exact>
  411670:	48 8d 7c 24 40       	lea    rdi,[rsp+0x40]
  411675:	b9 00 00 01 00       	mov    ecx,0x10000
  41167a:	31 c0                	xor    eax,eax
  41167c:	0f b6 54 24 1e       	movzx  edx,BYTE PTR [rsp+0x1e]
  411681:	44 8a 54 24 1f       	mov    r10b,BYTE PTR [rsp+0x1f]
  411686:	48 8d 74 24 40       	lea    rsi,[rsp+0x40]
  41168b:	f3 ab                	rep stos DWORD PTR es:[rdi],eax
  41168d:	44 8a 5c 24 20       	mov    r11b,BYTE PTR [rsp+0x20]
  411692:	40 8a 6c 24 21       	mov    bpl,BYTE PTR [rsp+0x21]
  411697:	48 c1 e2 04          	shl    rdx,0x4
  41169b:	48 01 da             	add    rdx,rbx
  41169e:	44 0f b6 62 18       	movzx  r12d,BYTE PTR [rdx+0x18]
  4116a3:	41 39 cc             	cmp    r12d,ecx
  4116a6:	7e 58                	jle    411700 <handle_4+0xd9>
  4116a8:	44 0f b6 42 19       	movzx  r8d,BYTE PTR [rdx+0x19]
  4116ad:	31 ff                	xor    edi,edi
  4116af:	44 89 c0             	mov    eax,r8d
  4116b2:	0f af c1             	imul   eax,ecx
  4116b5:	41 39 f8             	cmp    r8d,edi
  4116b8:	7e 42                	jle    4116fc <handle_4+0xd5>
  4116ba:	4c 8b 4a 20          	mov    r9,QWORD PTR [rdx+0x20]
  4116be:	44 88 14 86          	mov    BYTE PTR [rsi+rax*4],r10b
  4116c2:	44 88 5c 86 01       	mov    BYTE PTR [rsi+rax*4+0x1],r11b
  4116c7:	40 88 6c 86 02       	mov    BYTE PTR [rsi+rax*4+0x2],bpl
  4116cc:	4d 85 c9             	test   r9,r9
  4116cf:	75 1b                	jne    4116ec <handle_4+0xc5>
  4116d1:	48 8b 35 68 29 00 00 	mov    rsi,QWORD PTR [rip+0x2968]        # 414040 <stderr@GLIBC_2.2.5>
  4116d8:	48 8d 3d 5e 0b 00 00 	lea    rdi,[rip+0xb5e]        # 41223d <_IO_stdin_used+0x23d>
  4116df:	e8 ec fa fe ff       	call   4011d0 <fputs@plt>
  4116e4:	83 cf ff             	or     edi,0xffffffff
  4116e7:	e8 74 fb fe ff       	call   401260 <exit@plt>
  4116ec:	45 8a 0c 01          	mov    r9b,BYTE PTR [r9+rax*1]
  4116f0:	ff c7                	inc    edi
  4116f2:	44 88 4c 86 03       	mov    BYTE PTR [rsi+rax*4+0x3],r9b
  4116f7:	48 ff c0             	inc    rax
  4116fa:	eb b9                	jmp    4116b5 <handle_4+0x8e>
  4116fc:	ff c1                	inc    ecx
  4116fe:	eb a3                	jmp    4116a3 <handle_4+0x7c>
  411700:	45 31 ff             	xor    r15d,r15d
  411703:	48 8d 7c 24 27       	lea    rdi,[rsp+0x27]
  411708:	0f b6 44 24 25       	movzx  eax,BYTE PTR [rsp+0x25]
  41170d:	44 39 f8             	cmp    eax,r15d
  411710:	0f 8e 2c 01 00 00    	jle    411842 <handle_4+0x21b>
  411716:	45 31 d2             	xor    r10d,r10d
  411719:	0f b6 44 24 24       	movzx  eax,BYTE PTR [rsp+0x24]
  41171e:	44 39 d0             	cmp    eax,r10d
  411721:	0f 8e 13 01 00 00    	jle    41183a <handle_4+0x213>
  411727:	0f b6 54 24 1e       	movzx  edx,BYTE PTR [rsp+0x1e]
  41172c:	45 31 db             	xor    r11d,r11d
  41172f:	48 c1 e2 04          	shl    rdx,0x4
  411733:	48 01 da             	add    rdx,rbx
  411736:	8a 42 19             	mov    al,BYTE PTR [rdx+0x19]
  411739:	41 0f af c2          	imul   eax,r10d
  41173d:	02 44 24 22          	add    al,BYTE PTR [rsp+0x22]
  411741:	44 0f b6 e0          	movzx  r12d,al
  411745:	8a 42 18             	mov    al,BYTE PTR [rdx+0x18]
  411748:	41 0f af c7          	imul   eax,r15d
  41174c:	02 44 24 23          	add    al,BYTE PTR [rsp+0x23]
  411750:	0f b6 e8             	movzx  ebp,al
  411753:	0f b6 44 24 1e       	movzx  eax,BYTE PTR [rsp+0x1e]
  411758:	48 c1 e0 04          	shl    rax,0x4
  41175c:	0f b6 44 18 18       	movzx  eax,BYTE PTR [rax+rbx*1+0x18]
  411761:	44 39 d8             	cmp    eax,r11d
  411764:	0f 8e c8 00 00 00    	jle    411832 <handle_4+0x20b>
  41176a:	45 31 ed             	xor    r13d,r13d
  41176d:	0f b6 44 24 1e       	movzx  eax,BYTE PTR [rsp+0x1e]
  411772:	48 c1 e0 04          	shl    rax,0x4
  411776:	0f b6 44 18 19       	movzx  eax,BYTE PTR [rax+rbx*1+0x19]
  41177b:	44 39 e8             	cmp    eax,r13d
  41177e:	0f 8e a4 00 00 00    	jle    411828 <handle_4+0x201>
  411784:	41 0f af c3          	imul   eax,r11d
  411788:	44 01 e8             	add    eax,r13d
  41178b:	48 98                	cdqe
  41178d:	0f b6 54 84 43       	movzx  edx,BYTE PTR [rsp+rax*4+0x43]
  411792:	3a 54 24 26          	cmp    dl,BYTE PTR [rsp+0x26]
  411796:	0f 84 84 00 00 00    	je     411820 <handle_4+0x1f9>
  41179c:	44 89 5c 24 0c       	mov    DWORD PTR [rsp+0xc],r11d
  4117a1:	be 19 00 00 00       	mov    esi,0x19
  4117a6:	44 0f b6 73 06       	movzx  r14d,BYTE PTR [rbx+0x6]
  4117ab:	4c 8d 05 a4 09 00 00 	lea    r8,[rip+0x9a4]        # 412156 <_IO_stdin_used+0x156>
  4117b2:	44 89 54 24 08       	mov    DWORD PTR [rsp+0x8],r10d
  4117b7:	51                   	push   rcx
  4117b8:	b9 19 00 00 00       	mov    ecx,0x19
  4117bd:	52                   	push   rdx
  4117be:	0f b6 54 84 52       	movzx  edx,BYTE PTR [rsp+rax*4+0x52]
  4117c3:	52                   	push   rdx
  4117c4:	0f b6 54 84 59       	movzx  edx,BYTE PTR [rsp+rax*4+0x59]
  4117c9:	52                   	push   rdx
  4117ca:	44 0f b6 4c 84 60    	movzx  r9d,BYTE PTR [rsp+rax*4+0x60]
  4117d0:	ba 01 00 00 00       	mov    edx,0x1
  4117d5:	31 c0                	xor    eax,eax
  4117d7:	48 89 7c 24 20       	mov    QWORD PTR [rsp+0x20],rdi
  4117dc:	e8 7f f9 fe ff       	call   401160 <__snprintf_chk@plt>
  4117e1:	43 8d 44 25 00       	lea    eax,[r13+r12*1+0x0]
  4117e6:	48 8b 7c 24 20       	mov    rdi,QWORD PTR [rsp+0x20]
  4117eb:	44 8b 5c 24 2c       	mov    r11d,DWORD PTR [rsp+0x2c]
  4117f0:	99                   	cdq
  4117f1:	44 8b 54 24 28       	mov    r10d,DWORD PTR [rsp+0x28]
  4117f6:	48 83 c4 20          	add    rsp,0x20
  4117fa:	41 f7 fe             	idiv   r14d
  4117fd:	0f 10 07             	movups xmm0,XMMWORD PTR [rdi]
  411800:	44 0f af f5          	imul   r14d,ebp
  411804:	42 8d 04 32          	lea    eax,[rdx+r14*1]
  411808:	31 d2                	xor    edx,edx
  41180a:	f7 73 0c             	div    DWORD PTR [rbx+0xc]
  41180d:	48 6b d2 18          	imul   rdx,rdx,0x18
  411811:	48 03 53 10          	add    rdx,QWORD PTR [rbx+0x10]
  411815:	0f 11 02             	movups XMMWORD PTR [rdx],xmm0
  411818:	48 8b 47 10          	mov    rax,QWORD PTR [rdi+0x10]
  41181c:	48 89 42 10          	mov    QWORD PTR [rdx+0x10],rax
  411820:	41 ff c5             	inc    r13d
  411823:	e9 45 ff ff ff       	jmp    41176d <handle_4+0x146>
  411828:	41 ff c3             	inc    r11d
  41182b:	ff c5                	inc    ebp
  41182d:	e9 21 ff ff ff       	jmp    411753 <handle_4+0x12c>
  411832:	41 ff c2             	inc    r10d
  411835:	e9 df fe ff ff       	jmp    411719 <handle_4+0xf2>
  41183a:	41 ff c7             	inc    r15d
  41183d:	e9 c6 fe ff ff       	jmp    411708 <handle_4+0xe1>
  411842:	48 81 c4 48 00 04 00 	add    rsp,0x40048
  411849:	5b                   	pop    rbx
  41184a:	5d                   	pop    rbp
  41184b:	41 5c                	pop    r12
  41184d:	41 5d                	pop    r13
  41184f:	41 5e                	pop    r14
  411851:	41 5f                	pop    r15
  411853:	c3                   	ret

0000000000411854 <handle_1337>:
  411854:	f3 0f 1e fa          	endbr64
  411858:	41 55                	push   r13
  41185a:	41 83 c8 ff          	or     r8d,0xffffffff
  41185e:	ba 05 00 00 00       	mov    edx,0x5
  411863:	48 8d 0d 05 0a 00 00 	lea    rcx,[rip+0xa05]        # 41226f <_IO_stdin_used+0x26f>
  41186a:	41 54                	push   r12
  41186c:	55                   	push   rbp
  41186d:	53                   	push   rbx
  41186e:	48 89 fb             	mov    rbx,rdi
  411871:	31 ff                	xor    edi,edi
  411873:	48 81 ec 98 00 00 00 	sub    rsp,0x98
  41187a:	48 8d 74 24 0b       	lea    rsi,[rsp+0xb]
  41187f:	e8 ea f8 ff ff       	call   41116e <read_exact>
  411884:	44 0f b6 64 24 0e    	movzx  r12d,BYTE PTR [rsp+0xe]
  41188a:	48 8d 7c 24 10       	lea    rdi,[rsp+0x10]
  41188f:	31 f6                	xor    esi,esi
  411891:	44 0f b6 6c 24 0f    	movzx  r13d,BYTE PTR [rsp+0xf]
  411897:	44 0f b6 5c 24 0c    	movzx  r11d,BYTE PTR [rsp+0xc]
  41189d:	48 89 fd             	mov    rbp,rdi
  4118a0:	44 0f b6 54 24 0d    	movzx  r10d,BYTE PTR [rsp+0xd]
  4118a6:	4d 89 e0             	mov    r8,r12
  4118a9:	41 39 f5             	cmp    r13d,esi
  4118ac:	7e 37                	jle    4118e5 <handle_1337+0x91>
  4118ae:	45 8d 0c 32          	lea    r9d,[r10+rsi*1]
  4118b2:	31 c9                	xor    ecx,ecx
  4118b4:	41 39 cc             	cmp    r12d,ecx
  4118b7:	7e 25                	jle    4118de <handle_1337+0x8a>
  4118b9:	0f b6 43 06          	movzx  eax,BYTE PTR [rbx+0x6]
  4118bd:	31 d2                	xor    edx,edx
  4118bf:	41 0f af c1          	imul   eax,r9d
  4118c3:	44 01 d8             	add    eax,r11d
  4118c6:	01 c8                	add    eax,ecx
  4118c8:	f7 73 0c             	div    DWORD PTR [rbx+0xc]
  4118cb:	48 6b c2 18          	imul   rax,rdx,0x18
  4118cf:	48 03 43 10          	add    rax,QWORD PTR [rbx+0x10]
  4118d3:	8a 40 13             	mov    al,BYTE PTR [rax+0x13]
  4118d6:	88 04 0f             	mov    BYTE PTR [rdi+rcx*1],al
  4118d9:	48 ff c1             	inc    rcx
  4118dc:	eb d6                	jmp    4118b4 <handle_1337+0x60>
  4118de:	ff c6                	inc    esi
  4118e0:	4c 01 c7             	add    rdi,r8
  4118e3:	eb c4                	jmp    4118a9 <handle_1337+0x55>
  4118e5:	0f b6 44 24 0b       	movzx  eax,BYTE PTR [rsp+0xb]
  4118ea:	48 c1 e0 04          	shl    rax,0x4
  4118ee:	48 8b 7c 18 20       	mov    rdi,QWORD PTR [rax+rbx*1+0x20]
  4118f3:	48 85 ff             	test   rdi,rdi
  4118f6:	74 05                	je     4118fd <handle_1337+0xa9>
  4118f8:	e8 73 f8 fe ff       	call   401170 <free@plt>
  4118fd:	66 8b 44 24 0e       	mov    ax,WORD PTR [rsp+0xe]
  411902:	0f b6 7c 24 0b       	movzx  edi,BYTE PTR [rsp+0xb]
  411907:	86 e0                	xchg   al,ah
  411909:	48 c1 e7 04          	shl    rdi,0x4
  41190d:	48 01 fb             	add    rbx,rdi
  411910:	48 89 6b 20          	mov    QWORD PTR [rbx+0x20],rbp
  411914:	66 89 43 18          	mov    WORD PTR [rbx+0x18],ax
  411918:	48 81 c4 98 00 00 00 	add    rsp,0x98
  41191f:	5b                   	pop    rbx
  411920:	5d                   	pop    rbp
  411921:	41 5c                	pop    r12
  411923:	41 5d                	pop    r13
  411925:	c3                   	ret

0000000000411926 <handle_7>:
  411926:	f3 0f 1e fa          	endbr64
  41192a:	48 83 ec 28          	sub    rsp,0x28
  41192e:	41 83 c8 ff          	or     r8d,0xffffffff
  411932:	ba 04 00 00 00       	mov    edx,0x4
  411937:	31 ff                	xor    edi,edi
  411939:	48 8d 74 24 0c       	lea    rsi,[rsp+0xc]
  41193e:	48 8d 0d 5b 09 00 00 	lea    rcx,[rip+0x95b]        # 4122a0 <_IO_stdin_used+0x2a0>
  411945:	e8 24 f8 ff ff       	call   41116e <read_exact>
  41194a:	8b 44 24 0c          	mov    eax,DWORD PTR [rsp+0xc]
  41194e:	b9 e8 03 00 00       	mov    ecx,0x3e8
  411953:	31 d2                	xor    edx,edx
  411955:	48 8d 7c 24 10       	lea    rdi,[rsp+0x10]
  41195a:	31 f6                	xor    esi,esi
  41195c:	f7 f1                	div    ecx
  41195e:	89 c0                	mov    eax,eax
  411960:	48 89 44 24 10       	mov    QWORD PTR [rsp+0x10],rax
  411965:	69 c2 40 42 0f 00    	imul   eax,edx,0xf4240
  41196b:	48 89 44 24 18       	mov    QWORD PTR [rsp+0x18],rax
  411970:	e8 4b f8 fe ff       	call   4011c0 <nanosleep@plt>
  411975:	48 83 c4 28          	add    rsp,0x28
  411979:	c3                   	ret

000000000041197a <display>:
  41197a:	f3 0f 1e fa          	endbr64
  41197e:	41 54                	push   r12
  411980:	45 31 e4             	xor    r12d,r12d
  411983:	55                   	push   rbp
  411984:	48 89 fd             	mov    rbp,rdi
  411987:	53                   	push   rbx
  411988:	48 8d 1d 36 09 00 00 	lea    rbx,[rip+0x936]        # 4122c5 <_IO_stdin_used+0x2c5>
  41198f:	0f b6 45 07          	movzx  eax,BYTE PTR [rbp+0x7]
  411993:	44 39 e0             	cmp    eax,r12d
  411996:	7e 3e                	jle    4119d6 <display+0x5c>
  411998:	0f b6 55 06          	movzx  edx,BYTE PTR [rbp+0x6]
  41199c:	bf 01 00 00 00       	mov    edi,0x1
  4119a1:	48 89 d0             	mov    rax,rdx
  4119a4:	48 6b d2 18          	imul   rdx,rdx,0x18
  4119a8:	0f b6 f0             	movzx  esi,al
  4119ab:	41 0f af f4          	imul   esi,r12d
  4119af:	41 ff c4             	inc    r12d
  4119b2:	48 63 f6             	movsxd rsi,esi
  4119b5:	48 6b f6 18          	imul   rsi,rsi,0x18
  4119b9:	48 03 75 10          	add    rsi,QWORD PTR [rbp+0x10]
  4119bd:	e8 de f7 fe ff       	call   4011a0 <write@plt>
  4119c2:	ba 18 00 00 00       	mov    edx,0x18
  4119c7:	48 89 de             	mov    rsi,rbx
  4119ca:	bf 01 00 00 00       	mov    edi,0x1
  4119cf:	e8 cc f7 fe ff       	call   4011a0 <write@plt>
  4119d4:	eb b9                	jmp    41198f <display+0x15>
  4119d6:	5b                   	pop    rbx
  4119d7:	5d                   	pop    rbp
  4119d8:	41 5c                	pop    r12
  4119da:	c3                   	ret

00000000004119db <handle_6>:
  4119db:	f3 0f 1e fa          	endbr64
  4119df:	55                   	push   rbp
  4119e0:	41 83 c8 ff          	or     r8d,0xffffffff
  4119e4:	48 89 fd             	mov    rbp,rdi
  4119e7:	ba 01 00 00 00       	mov    edx,0x1
  4119ec:	31 ff                	xor    edi,edi
  4119ee:	48 8d 0d e9 08 00 00 	lea    rcx,[rip+0x8e9]        # 4122de <_IO_stdin_used+0x2de>
  4119f5:	48 83 ec 10          	sub    rsp,0x10
  4119f9:	48 8d 74 24 0f       	lea    rsi,[rsp+0xf]
  4119fe:	e8 6b f7 ff ff       	call   41116e <read_exact>
  411a03:	80 7c 24 0f 00       	cmp    BYTE PTR [rsp+0xf],0x0
  411a08:	74 13                	je     411a1d <handle_6+0x42>
  411a0a:	48 8d 35 eb 08 00 00 	lea    rsi,[rip+0x8eb]        # 4122fc <_IO_stdin_used+0x2fc>
  411a11:	bf 01 00 00 00       	mov    edi,0x1
  411a16:	31 c0                	xor    eax,eax
  411a18:	e8 13 f8 fe ff       	call   401230 <__printf_chk@plt>
  411a1d:	48 89 ef             	mov    rdi,rbp
  411a20:	31 f6                	xor    esi,esi
  411a22:	31 c0                	xor    eax,eax
  411a24:	e8 51 ff ff ff       	call   41197a <display>
  411a29:	48 83 c4 10          	add    rsp,0x10
  411a2d:	5d                   	pop    rbp
  411a2e:	c3                   	ret

0000000000411a2f <initialize_framebuffer>:
  411a2f:	f3 0f 1e fa          	endbr64
  411a33:	41 54                	push   r12
  411a35:	49 89 fc             	mov    r12,rdi
  411a38:	55                   	push   rbp
  411a39:	53                   	push   rbx
  411a3a:	48 83 ec 20          	sub    rsp,0x20
  411a3e:	0f b6 7f 06          	movzx  edi,BYTE PTR [rdi+0x6]
  411a42:	41 0f b6 44 24 07    	movzx  eax,BYTE PTR [r12+0x7]
  411a48:	0f af f8             	imul   edi,eax
  411a4b:	41 89 7c 24 0c       	mov    DWORD PTR [r12+0xc],edi
  411a50:	48 63 ff             	movsxd rdi,edi
  411a53:	48 6b ff 18          	imul   rdi,rdi,0x18
  411a57:	48 ff c7             	inc    rdi
  411a5a:	e8 c1 f7 fe ff       	call   401220 <malloc@plt>
  411a5f:	49 89 44 24 10       	mov    QWORD PTR [r12+0x10],rax
  411a64:	48 85 c0             	test   rax,rax
  411a67:	75 14                	jne    411a7d <initialize_framebuffer+0x4e>
  411a69:	48 8d 3d 94 08 00 00 	lea    rdi,[rip+0x894]        # 412304 <_IO_stdin_used+0x304>
  411a70:	e8 1b f7 fe ff       	call   401190 <puts@plt>
  411a75:	83 cf ff             	or     edi,0xffffffff
  411a78:	e8 e3 f7 fe ff       	call   401260 <exit@plt>
  411a7d:	31 db                	xor    ebx,ebx
  411a7f:	48 8d 6c 24 07       	lea    rbp,[rsp+0x7]
  411a84:	41 39 5c 24 0c       	cmp    DWORD PTR [r12+0xc],ebx
  411a89:	76 54                	jbe    411adf <initialize_framebuffer+0xb0>
  411a8b:	50                   	push   rax
  411a8c:	ba 01 00 00 00       	mov    edx,0x1
  411a91:	41 b9 ff 00 00 00    	mov    r9d,0xff
  411a97:	48 89 ef             	mov    rdi,rbp
  411a9a:	6a 20                	push   0x20
  411a9c:	4c 8d 05 b3 06 00 00 	lea    r8,[rip+0x6b3]        # 412156 <_IO_stdin_used+0x156>
  411aa3:	b9 19 00 00 00       	mov    ecx,0x19
  411aa8:	31 c0                	xor    eax,eax
  411aaa:	68 ff 00 00 00       	push   0xff
  411aaf:	be 19 00 00 00       	mov    esi,0x19
  411ab4:	68 ff 00 00 00       	push   0xff
  411ab9:	e8 a2 f6 fe ff       	call   401160 <__snprintf_chk@plt>
  411abe:	0f 10 45 00          	movups xmm0,XMMWORD PTR [rbp+0x0]
  411ac2:	48 6b c3 18          	imul   rax,rbx,0x18
  411ac6:	48 ff c3             	inc    rbx
  411ac9:	49 03 44 24 10       	add    rax,QWORD PTR [r12+0x10]
  411ace:	48 83 c4 20          	add    rsp,0x20
  411ad2:	0f 11 00             	movups XMMWORD PTR [rax],xmm0
  411ad5:	48 8b 55 10          	mov    rdx,QWORD PTR [rbp+0x10]
  411ad9:	48 89 50 10          	mov    QWORD PTR [rax+0x10],rdx
  411add:	eb a5                	jmp    411a84 <initialize_framebuffer+0x55>
  411adf:	48 83 c4 20          	add    rsp,0x20
  411ae3:	4c 89 e0             	mov    rax,r12
  411ae6:	5b                   	pop    rbx
  411ae7:	5d                   	pop    rbp
  411ae8:	41 5c                	pop    r12
  411aea:	c3                   	ret
  411aeb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000411af0 <__libc_csu_init>:
  411af0:	f3 0f 1e fa          	endbr64
  411af4:	41 57                	push   r15
  411af6:	4c 8d 3d 3b 22 00 00 	lea    r15,[rip+0x223b]        # 413d38 <__frame_dummy_init_array_entry>
  411afd:	41 56                	push   r14
  411aff:	49 89 d6             	mov    r14,rdx
  411b02:	41 55                	push   r13
  411b04:	49 89 f5             	mov    r13,rsi
  411b07:	41 54                	push   r12
  411b09:	41 89 fc             	mov    r12d,edi
  411b0c:	55                   	push   rbp
  411b0d:	48 8d 2d 34 22 00 00 	lea    rbp,[rip+0x2234]        # 413d48 <__do_global_dtors_aux_fini_array_entry>
  411b14:	53                   	push   rbx
  411b15:	4c 29 fd             	sub    rbp,r15
  411b18:	48 83 ec 08          	sub    rsp,0x8
  411b1c:	e8 df f4 fe ff       	call   401000 <_init>
  411b21:	48 c1 fd 03          	sar    rbp,0x3
  411b25:	74 1f                	je     411b46 <__libc_csu_init+0x56>
  411b27:	31 db                	xor    ebx,ebx
  411b29:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
  411b30:	4c 89 f2             	mov    rdx,r14
  411b33:	4c 89 ee             	mov    rsi,r13
  411b36:	44 89 e7             	mov    edi,r12d
  411b39:	41 ff 14 df          	call   QWORD PTR [r15+rbx*8]
  411b3d:	48 83 c3 01          	add    rbx,0x1
  411b41:	48 39 dd             	cmp    rbp,rbx
  411b44:	75 ea                	jne    411b30 <__libc_csu_init+0x40>
  411b46:	48 83 c4 08          	add    rsp,0x8
  411b4a:	5b                   	pop    rbx
  411b4b:	5d                   	pop    rbp
  411b4c:	41 5c                	pop    r12
  411b4e:	41 5d                	pop    r13
  411b50:	41 5e                	pop    r14
  411b52:	41 5f                	pop    r15
  411b54:	c3                   	ret
  411b55:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  411b5c:	00 00 00 00 

0000000000411b60 <__libc_csu_fini>:
  411b60:	f3 0f 1e fa          	endbr64
  411b64:	c3                   	ret

Disassembly of section .fini:

0000000000411b68 <_fini>:
  411b68:	f3 0f 1e fa          	endbr64
  411b6c:	48 83 ec 08          	sub    rsp,0x8
  411b70:	48 83 c4 08          	add    rsp,0x8
  411b74:	c3                   	ret
