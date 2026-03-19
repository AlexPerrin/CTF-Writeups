#!/usr/bin/env python3
import socket

def recv_until(s, marker):
    data = b''
    while not data.endswith(marker):
        chunk = s.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode()

def decode_message(msg_int):
    try:
        b = msg_int.to_bytes((msg_int.bit_length() + 7) // 8, 'big')
        return b.decode('utf-8', errors='replace')
    except Exception as e:
        return f"(decode error: {e})"

def get_messages(k_fn):
    s = socket.socket()
    s.connect(('challenge.utctf.live', 8379))
    s.settimeout(5)

    data = recv_until(s, b'Please pick a value k.\n')

    N = int(data.split('N = ')[1].split('\n')[0])
    e = int(data.split('e = ')[1].split('\n')[0])
    x0 = int(data.split('x0: ')[1].split('\n')[0])
    x1 = int(data.split('x1: ')[1].split('\n')[0])

    print(f"N  = {N}")
    print(f"x0 = {x0}")
    print(f"x1 = {x1}")

    k = k_fn(e, x0, x1, N)
    print(f"Sending k = {k}")
    s.sendall((str(k) + '\n').encode())

    out = b''
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
    except socket.timeout:
        pass
    s.close()
    out = out.decode()

    m1 = int(out.split('Message 1:')[1].split('\n')[0].strip())
    m2 = int(out.split('Message 2:')[1].strip())
    return m1, m2

print("=== Getting m0 (send k=e so k XOR e=0, k0=0) ===")
m1, m2 = get_messages(lambda e, x0, x1, N: e)
print(f"Message 1: {decode_message(m1)}")
print(f"Message 2: {decode_message(m2)}")

print()
print("=== Getting m1 (send k = e XOR ((x1-x0) % N) so k1=0) ===")
m1, m2 = get_messages(lambda e, x0, x1, N: e ^ ((x1 - x0) % N))
print(f"Message 1: {decode_message(m1)}")
print(f"Message 2: {decode_message(m2)}")
