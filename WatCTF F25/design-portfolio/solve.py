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