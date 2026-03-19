import math
from Crypto.Util.number import isPrime, long_to_bytes

def nextPrime(k):
    while not isPrime(k):
        k += 1
    return k

def isqrt(n):
    """Integer square root using Newton's method"""
    if n < 0:
        return None
    if n == 0:
        return 0
    
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x

# Given values
N = 331952857868366988663932945877951080549278582595446041827767968625349664658283914707688360079014486835580798093875473318398665440196327017511963073666394378115620522693620625071360763670651867749935306771611365203669632958229266010553458203000895499490278056591308718235818336550276558946434347335414409026661
e = 65537
ct = 27392982072168505918328498224512439143304951239197916179225339049412270594576024668071218892690652612353376666973045187430259051892719839059780552668922042760370020764362839523844795479477997719361780814250593853162333527993824104731684172908271583213365558182307524519318252505075812038979585427505321346605

print("RSA Attack - Integer arithmetic approach")
print("="*50)

def fermat_factorization(N):
    """Fermat's factorization method using integer arithmetic"""
    print("Using Fermat's factorization...")
    
    # Start with a = ceil(sqrt(N))
    a = isqrt(N)
    if a * a < N:
        a += 1
    
    for i in range(10000000):  # Large range for safety
        b_squared = a * a - N
        
        if b_squared >= 0:
            b = isqrt(b_squared)
            if b * b == b_squared:  # Perfect square
                p = a - b
                q = a + b
                if p > 1 and q > 1 and p * q == N:
                    return min(p, q), max(p, q)
        
        a += 1
        
        # Progress indicator
        if i % 1000000 == 0 and i > 0:
            print(f"  Tried {i} iterations...")
    
    return None, None

def trial_division_around_estimate(N):
    """Try factoring around the estimated value of p"""
    print("Trying trial division around estimated p...")
    
    # Estimate p ≈ sqrt(N/2)
    p_est = isqrt(N // 2)
    print(f"Estimated p: {p_est}")
    
    # Try values around the estimate
    search_ranges = [1000000, 10000000, 100000000]
    
    for search_range in search_ranges:
        print(f"  Searching in range ±{search_range}")
        
        # Check divisibility for values around p_est
        for offset in range(0, search_range, 1000):  # Use step size for efficiency
            for p_candidate in [p_est - offset, p_est + offset]:
                if p_candidate > 1 and N % p_candidate == 0:
                    q_candidate = N // p_candidate
                    if q_candidate > p_candidate:  # Ensure p < q
                        p, q = p_candidate, q_candidate
                    else:
                        p, q = q_candidate, p_candidate
                    
                    print(f"  Found factors: p={p}, q={q}")
                    
                    # Verify they are prime
                    if isPrime(p) and isPrime(q):
                        # Check the relationship q = nextPrime(2*p)
                        expected_q = nextPrime(2 * p)
                        if q == expected_q:
                            return p, q
                        else:
                            print(f"  Factors don't match expected relationship")
                    else:
                        print(f"  Found factors are not both prime")
            
            if offset > 0 and offset % 10000000 == 0:
                print(f"    Checked up to offset {offset}")
    
    return None, None

def continued_fraction_factor(N):
    """Use continued fraction method"""
    print("Trying continued fraction factorization...")
    
    # This is a simplified version - for very large numbers we'd need more sophisticated implementation
    sqrt_n = isqrt(N)
    
    if sqrt_n * sqrt_n == N:
        return sqrt_n, sqrt_n
    
    # Try a few iterations of continued fraction
    convergents = []
    a0 = sqrt_n
    m, d, a = 0, 1, a0
    
    for i in range(100):  # Limited iterations
        m = d * a - m
        d = (N - m * m) // d
        if d == 0:
            break
        a = (a0 + m) // d
        
        # Update convergents and check for factors
        if len(convergents) > 0:
            h_prev, k_prev = convergents[-1] if convergents else (1, 0)
            if i == 0:
                h, k = a0, 1
            else:
                h = a * h_prev + (convergents[-2][0] if len(convergents) > 1 else 1)
                k = a * k_prev + (convergents[-2][1] if len(convergents) > 1 else 0)
            
            convergents.append((h, k))
            
            # Check if we found a factor
            factor = math.gcd(h, N) if h < N else None
            if factor and factor > 1 and factor < N:
                return factor, N // factor
    
    return None, None

# Try different methods
print(f"N = {N}")
print(f"Bit length of N: {N.bit_length()}")

methods = [fermat_factorization, trial_division_around_estimate, continued_fraction_factor]

p, q = None, None
for method in methods:
    print(f"\nTrying {method.__name__}...")
    try:
        p, q = method(N)
        if p and q and p * q == N:
            print(f"SUCCESS! Found factors with {method.__name__}")
            break
        else:
            print(f"{method.__name__} did not find valid factors")
    except Exception as e:
        print(f"{method.__name__} failed with error: {e}")

if not p or not q:
    print("\nAll methods failed. Let's try a more direct approach...")
    # One more attempt with very targeted search
    p_target = isqrt(N // 2)
    print(f"Doing final targeted search around {p_target}")
    
    for i in range(1000000000):  # Very large range
        p_candidate = p_target - 500000000 + i
        if p_candidate > 0 and N % p_candidate == 0:
            q_candidate = N // p_candidate
            if isPrime(p_candidate) and isPrime(q_candidate):
                if nextPrime(2 * p_candidate) == q_candidate:
                    p, q = p_candidate, q_candidate
                    print(f"Found in final search: p={p}, q={q}")
                    break
        
        if i % 10000000 == 0:
            print(f"  Checked {i} candidates...")

if not p or not q or p * q != N:
    print("Failed to factor N")
    exit(1)

print(f"\n" + "="*50)
print("FACTORIZATION SUCCESSFUL!")
print(f"p = {p}")
print(f"q = {q}")
print(f"p * q = N: {p * q == N}")
print(f"p is prime: {isPrime(p)}")
print(f"q is prime: {isPrime(q)}")

# Verify the relationship
expected_q = nextPrime(2 * p)
print(f"\nRelationship verification:")
print(f"2*p = {2*p}")
print(f"nextPrime(2*p) = {expected_q}")
print(f"q = {q}")
print(f"q == nextPrime(2*p): {q == expected_q}")

# Calculate private key and decrypt
phi_n = (p - 1) * (q - 1)

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(e, phi):
    gcd, x, y = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return (x % phi + phi) % phi

print(f"\nCalculating private key...")
d = mod_inverse(e, phi_n)

print(f"Decrypting message...")
pt = pow(ct, d, N)

print(f"\nPlaintext (integer): {pt}")

try:
    flag_bytes = long_to_bytes(pt)
    flag_text = flag_bytes.decode('utf-8', errors='replace')
    print(f"Flag: {flag_text}")
except Exception as ex:
    print(f"Error decoding: {ex}")
    flag_bytes = long_to_bytes(pt)
    print(f"Raw bytes: {flag_bytes}")

print("\n" + "="*60)
print("RSA CRACKED!")
print("="*60)