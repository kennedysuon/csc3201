import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import number
import secrets

# --- Reuse RSA implementation from Task 3 Part 1 ---
def extended_gcd(a, b):
    if b == 0:
        return (a, 1, 0)
    gcd, x1, y1 = extended_gcd(b, a % b)
    return (gcd, y1, x1 - (a // b) * y1)

def mod_inverse(e, phi):
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise Exception("e and phi are not coprime")
    return x % phi

def generate_keypair(bits=1024):
    e = 65537
    while True:
        p = number.getPrime(bits)
        q = number.getPrime(bits)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if number.GCD(e, phi) == 1:
            break
    n = p * q
    d = mod_inverse(e, phi)
    return (n, e), (n, d)

def rsa_encrypt(m, public_key):
    n, e = public_key
    return pow(m, e, n)

def rsa_decrypt(c, private_key):
    n, d = private_key
    return pow(c, d, n)

def derive_key(s):
    s_bytes = s.to_bytes(max((s.bit_length() + 7) // 8, 1), byteorder='big')
    return hashlib.sha256(s_bytes).digest()[:16]

iv = b'\x00' * 16

def encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext.encode(), AES.block_size))

def decrypt(key, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

# ================= Protocol 2: RSA Key Exchange =================

print("Alice generates her RSA keypair...")
public_key, private_key = generate_keypair(bits=1024)
n, e = public_key

# --- Bob's real message (irrelevant to the attack, but shown for completeness) ---
x = secrets.randbelow(n - 1) + 1
c = rsa_encrypt(x, public_key)
print(f"Bob picks secret x = {x}")
print(f"Bob sends real ciphertext c = x^e mod n")

# ================= Mallory's attack =================
# Mallory intercepts c, but doesn't even need to touch it.
# She picks her own value r and encrypts it herself using Alice's PUBLIC key.
r = 1234
c_prime = rsa_encrypt(r, public_key)
print(f"\nMallory picks her own value r = {r}")
print("Mallory computes c' = r^e mod n and sends c' to Alice instead of c")

# --- Alice decrypts what she thinks is Bob's message ---
s_alice = rsa_decrypt(c_prime, private_key)
print(f"\nAlice decrypts s = (c')^d mod n = {s_alice}")
assert s_alice == r, "Attack setup broken -- s should equal Mallory's r"

k_alice = derive_key(s_alice)
print(f"Alice derives AES key: {k_alice.hex()}")

# Alice encrypts her message using this key
message = "Hi Bob!"
c0 = encrypt(k_alice, message)
print(f"Alice sends c0 = AES-CBC_k('{message}')")

# --- Mallory already knows s = r, no private key needed ---
k_mallory = derive_key(r)
print(f"\nMallory derives the same key using only her own r: {k_mallory.hex()}")
assert k_mallory == k_alice

recovered = decrypt(k_mallory, c0)
print(f"Mallory decrypts c0: '{recovered}'")
assert recovered == message

print("\nAttack succeeded! Mallory recovered Alice's message without knowing d.")

def rsa_sign(m, private_key):
    n, d = private_key
    return pow(m, d, n)

def rsa_verify(m, signature, public_key):
    n, e = public_key
    return pow(signature, e, n) == m

# --- Mallory has observed two valid signatures ---
m1 = 42
m2 = 17
s1 = rsa_sign(m1, private_key)
s2 = rsa_sign(m2, private_key)

print(f"Signature on m1={m1}: {s1}")
print(f"Signature on m2={m2}: {s2}")

# --- Mallory forges a signature on m3 = m1 * m2, without knowing d ---
n, e = public_key
m3 = (m1 * m2) % n
s3_forged = (s1 * s2) % n

print(f"\nMallory forges signature for m3 = m1*m2 = {m3}")
print(f"Forged signature: {s3_forged}")

# --- Verify the forged signature is actually valid ---
is_valid = rsa_verify(m3, s3_forged, public_key)
print(f"Forged signature verifies correctly: {is_valid}")
assert is_valid