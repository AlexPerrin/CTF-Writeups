#!/usr/bin/env python3
import socket
import ecdsa
from Crypto.Util.number import bytes_to_long
import re

# Target connection details
HOST = "challs.watctf.org"
PORT = 3788

# Curve parameters (same as target)
curve = ecdsa.curves.BRAINPOOLP512r1
gen = curve.generator
n = curve.order

class RemoteECDSAExploit:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None
        self.challenge = None
        
    def connect(self):
        """Establish connection to the remote target"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        print(f"[+] Connected to {self.host}:{self.port}")
        
        # Read initial output and extract challenge
        initial_data = self.recv_until(b"Choose an option: ")
        challenge_match = re.search(rb'Challenge hex: ([a-f0-9]+)', initial_data)
        if challenge_match:
            self.challenge = bytes.fromhex(challenge_match.group(1).decode())
            print(f"[+] Extracted challenge: {self.challenge.hex()}")
        else:
            raise Exception("Could not extract challenge from initial output")
    
    def recv_until(self, delimiter):
        """Receive data until delimiter is found"""
        data = b""
        while delimiter not in data:
            chunk = self.sock.recv(1024)
            if not chunk:
                break
            data += chunk
        return data
    
    def send_line(self, data):
        """Send a line of data"""
        self.sock.send(data + b'\n')
    
    def sign_message(self, message_hex):
        """Sign a message using the remote service"""
        print(f"[*] Signing message: {message_hex}")
        
        # Choose option 1 (Sign)
        self.send_line(b'1')
        
        # Wait for prompt and send message
        self.recv_until(b"Input hex of message to sign: ")
        self.send_line(message_hex.encode())
        
        # Receive signature
        response = self.recv_until(b"Choose an option: ")
        
        # Extract signature using regex
        sig_match = re.search(rb'Your signature is: (\d+) (\d+)', response)
        if sig_match:
            r = int(sig_match.group(1))
            s = int(sig_match.group(2))
            print(f"[+] Received signature: r={r}, s={s}")
            return (r, s)
        else:
            raise Exception(f"Could not extract signature from response: {response}")
    
    def verify_signature(self, message_hex, r, s):
        """Verify a signature using the remote service"""
        print(f"[*] Verifying signature for message: {message_hex}")
        
        # Choose option 2 (Verify)
        self.send_line(b'2')
        
        # Send message hex
        self.recv_until(b"Input hex of message to verify: ")
        self.send_line(message_hex.encode())
        
        # Send signature
        self.recv_until(b"Input the two integers of the signature seperated by a space: ")
        self.send_line(f"{r} {s}".encode())
        
        # Receive response
        response = self.recv_until(b"Choose an option: ")
        return response
    
    def exploit_nonce_reuse(self, msg1, sig1, msg2, sig2, challenge):
        """Exploit ECDSA nonce reuse to recover private key and forge signature"""
        r1, s1 = sig1
        r2, s2 = sig2
        
        # Convert messages to integers
        z1 = bytes_to_long(msg1)
        z2 = bytes_to_long(msg2)
        z_challenge = bytes_to_long(challenge)
        
        print(f"[*] Message 1 hash: {z1}")
        print(f"[*] Message 2 hash: {z2}")
        print(f"[*] Challenge hash: {z_challenge}")
        
        # Check if nonce was reused (same r value)
        if r1 != r2:
            raise ValueError("Different r values - nonce reuse exploit won't work")
        
        r = r1
        print(f"[+] Nonce reuse detected! Same r value: {r}")
        
        # Calculate k using: k = (z1 - z2) * (s1 - s2)^(-1) mod n
        numerator = (z1 - z2) % n
        denominator = (s1 - s2) % n
        
        if denominator == 0:
            raise ValueError("Cannot exploit - identical signatures")
        
        k = (numerator * pow(denominator, -1, n)) % n
        print(f"[+] Recovered nonce k: {k}")
        
        # Calculate private key using: priv = (s1 * k - z1) * r^(-1) mod n
        priv_numerator = (s1 * k - z1) % n
        priv = (priv_numerator * pow(r, -1, n)) % n
        print(f"[+] Recovered private key: {priv}")
        
        # Forge signature for the challenge
        r_forge = r  # Same r since we're using the same k
        s_forge = (pow(k, -1, n) * (z_challenge + r_forge * priv)) % n
        
        return (int(r_forge), int(s_forge))
    
    def run_exploit(self):
        """Run the complete exploit"""
        try:
            # Step 1: Connect and get challenge
            self.connect()
            
            # Step 2: Sign two different messages
            print("\n[*] Step 1: Signing first message...")
            msg1 = b'hello'
            sig1 = self.sign_message(msg1.hex())
            
            print("\n[*] Step 2: Signing second message...")
            msg2 = b'world'
            sig2 = self.sign_message(msg2.hex())
            
            # Step 3: Exploit nonce reuse
            print("\n[*] Step 3: Exploiting nonce reuse...")
            forged_sig = self.exploit_nonce_reuse(msg1, sig1, msg2, sig2, self.challenge)
            
            # Step 4: Submit forged signature
            print(f"\n[*] Step 4: Submitting forged signature...")
            print(f"[+] Forged signature: r={forged_sig[0]}, s={forged_sig[1]}")
            
            response = self.verify_signature(self.challenge.hex(), forged_sig[0], forged_sig[1])
            
            # Check if we got the flag
            if b'Your reward:' in response or b'flag' in response.lower():
                print("\n[+] SUCCESS! Got the flag:")
                print(response.decode('utf-8', errors='ignore'))
            else:
                print(f"\n[-] Verification response: {response}")
                
        except Exception as e:
            print(f"\n[-] Error: {e}")
        finally:
            if self.sock:
                self.sock.close()
                print("[*] Connection closed")

def main():
    print("ECDSA Nonce Reuse Remote Exploit")
    print("=" * 40)
    print(f"Target: {HOST}:{PORT}")
    print()
    
    exploit = RemoteECDSAExploit(HOST, PORT)
    exploit.run_exploit()

if __name__ == "__main__":
    main()