import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import secrets

# --- Toy parameters from the assignment ---
q = 37
alpha = 5

# --- Alice's side ---
x_A = secrets.randbelow(q - 1) + 1      # random element in Z_q (nonzero)
Y_A = pow(alpha, x_A, q)

# --- Bob's side ---
x_B = secrets.randbelow(q - 1) + 1
Y_B = pow(alpha, x_B, q)

print(f"Alice picks x_A = {x_A}, sends Y_A = {Y_A}")
print(f"Bob picks   x_B = {x_B}, sends Y_B = {Y_B}")

# --- Each side computes the shared secret ---
s_alice = pow(Y_B, x_A, q)
s_bob   = pow(Y_A, x_B, q)

print(f"Alice computes s = {s_alice}")
print(f"Bob computes   s = {s_bob}")
assert s_alice == s_bob, "Shared secrets don't match!"

# --- Derive symmetric key k = SHA256(s), truncated to 16 bytes ---
def derive_key(s):
    s_bytes = str(s).encode()
    return hashlib.sha256(s_bytes).digest()[:16]

k_alice = derive_key(s_alice)
k_bob = derive_key(s_bob)
assert k_alice == k_bob
print(f"Shared AES key (hex): {k_alice.hex()}")

# --- Encrypt/decrypt messages with AES-CBC ---
iv = b'\x00' * 16

def encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext.encode(), AES.block_size))

def decrypt(key, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

c0 = encrypt(k_alice, "Hi Bob!")
c1 = encrypt(k_bob, "Hi Alice!")

print(f"c0 (Alice->Bob), hex: {c0.hex()}")
print(f"c1 (Bob->Alice), hex: {c1.hex()}")

print(f"Bob decrypts c0: {decrypt(k_bob, c0)}")
print(f"Alice decrypts c1: {decrypt(k_alice, c1)}")