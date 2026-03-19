# WatCTF Fall 2025 design-portfolio Writeup

A slick “design portfolio” site with curated color palettes… but something feels off.

`network_capture.pcap`

![alt text](<Screenshot 2025-09-09 185739.png>)

There are 16 HTTP 200 that return HTML, each containing 10 hex codes. Each page is a numbered *Featured Palette*, with the numbering out of order in the pcap.

Let's extract and order the hex codes as bytes to see what we can see.

```python
#!/usr/bin/env python3
import subprocess
import re

# Extract HTTP response data
result = subprocess.run(['tshark', '-r', 'network_capture.pcap', '-Y', 'http.response', '-T', 'fields', '-e', 'http.file_data'], 
                       capture_output=True, text=True)

# Convert hex to HTML
html_data = bytes.fromhex(result.stdout.replace('\n', '')).decode('utf-8', errors='ignore')

# Find collections and their hex codes
collections = {}
collection_sections = re.split(r'Professional Color Palettes - Collection (\d+)', html_data)[1:]

for i in range(0, len(collection_sections), 2):
    if i+1 < len(collection_sections):
        collection_num = int(collection_sections[i])
        section_content = collection_sections[i+1]
        
        # Extract hex codes from this section
        hex_codes = re.findall(r'<div class="color-info">(#[0-9A-Fa-f]{6})</div>', section_content)
        collections[collection_num] = hex_codes

# Get all hex codes in order 1-16
all_hex_codes = []
for i in range(1, 17):
    if i in collections:
        all_hex_codes.extend([code[1:] for code in collections[i]])  # Remove #

# Convert to bytes
result_bytes = b''
for hex_code in all_hex_codes:
    result_bytes += bytes.fromhex(hex_code)

# Save as human readable hex
with open('extracted_bytes.txt', 'w') as f:
    f.write(result_bytes.hex())

# Save as ASCII (printable characters only, replace non-printable with .)
with open('extracted_bytes_ascii.txt', 'w') as f:
    ascii_text = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in result_bytes)
    f.write(ascii_text)

# Save bytes to file
with open('extracted_bytes.bin', 'wb') as f:
    f.write(result_bytes)
```

`extracted_bytes_ascii.txt` shows the bytes seem to be a png image.

```
.PNG........IHDR...,...d......c......IDATx....j.@.@.....y.......;.s.b.......1..t....O'B...b"...!&B...b"...!&B...b"...!&B...b"...!&B...b"...!&B...b"...!&B...b"...!&B...b"...!&B...b"...!&B...b"...!&B...b"...!&B.}.7..}..........yg>5.u[...paG<G9c.^.YT..|.....r:.^.v...#.....r....<,X...f.l.v..}x@...?f./...f..J...s.b"...!&B...b"...!&B...b"...!&B...b"...!&B...b"...!&B...b"...!&B...b"...!&B...b"...!&B...b"...!&B...b"...!&B...b"...!&B...b"....M?..w......IEND.B`.......... .e\.;p.W.L....
```

Let's open the bin as a png

```bash
$ mv extracted_bytes.bin extracted_bytes.png
```

![alt text](extracted_image.png)

Thought I was on to something...

![alt text](<Screenshot 2025-09-09 191133.png>)

Theres an extra `X-Flag-Total`, and `X-Flag-Chunk ` header on the HTTP response. `89504E` is the hex for the `PNG` ASCII.

Let's concat all the X-Flag-Chunks as bytes and write to a png

```python
#!/usr/bin/env python3
import subprocess
import re

# Use strings command to extract X-Flag-Chunk headers without truncation
result = subprocess.run(['strings', 'network_capture.pcap'], capture_output=True, text=True)

flag_chunks = {}
for line in result.stdout.split('\n'):
    if line.startswith('X-Flag-Chunk-'):
        # Extract chunk number and hex data
        match = re.search(r'X-Flag-Chunk-(\d{4}):\s*([0-9A-Fa-f]+)', line)
        if match:
            chunk_num = int(match.group(1))
            hex_data = match.group(2)
            flag_chunks[chunk_num] = hex_data
            print(f"Found chunk {chunk_num}")

print(f"Extracted {len(flag_chunks)} X-Flag-Chunk headers")

# Get all chunks in order
all_hex_data = []
for i in sorted(flag_chunks.keys()):
    all_hex_data.append(flag_chunks[i])
    print(f"X-Flag-Chunk-{i:04d}: {flag_chunks[i]}")

# Concatenate all hex data
combined_hex = ''.join(all_hex_data)

# Convert to bytes
result_bytes = bytes.fromhex(combined_hex)

# Save as PNG (since the bytes start with PNG header)
with open('flag_image.png', 'wb') as f:
    f.write(result_bytes)
```

![alt text](flag_image.png)