import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import secrets

q = int(
    "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B61"
    "6073E28675A23D189838EF1E2EE652C013ECB4AEA9061123024975C3CD49B83B"
    "FACCBDD7D90C4BD709896488E9C219A72724EFFD6FAE5644738FAA31A4FF55BC"
    "C0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A43"
    "71", 16
)
alpha = int(
    "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D3"
    "1266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749"
    "F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A2"
    "8AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5",
    16
)

# Alice and Bob generate their real values, unaware of Mallory
x_A = secrets.randbelow(q - 2) + 1
Y_A = pow(alpha, x_A, q)

x_B = secrets.randbelow(q - 2) + 1
Y_B = pow(alpha, x_B, q)

print(f"Real Y_A = {Y_A}")
print(f"Real Y_B = {Y_B}")

# --- Mallory intercepts and replaces both Y_A and Y_B with q ---
tampered_value = q  # Mallory sends q instead of the real Y values

# Alice thinks she received Y_B, but really got q from Mallory
s_alice = pow(tampered_value, x_A, q)

# Bob thinks he received Y_A, but really got q from Mallory
s_bob = pow(tampered_value, x_B, q)

print(f"Alice computes s = {s_alice}")
print(f"Bob computes   s = {s_bob}")

# --- Mallory doesn't even need x_A or x_B — she knows s must be 0 ---
s_mallory = 0
print(f"Mallory deduces s = {s_mallory} (trivially, since q mod q = 0)")

assert s_alice == s_bob == s_mallory

# --- Derive the key and show Mallory can decrypt everything ---
def derive_key(s):
    s_bytes = s.to_bytes(max((s.bit_length() + 7) // 8, 1), byteorder='big')
    return hashlib.sha256(s_bytes).digest()[:16]

k = derive_key(s_alice)
k_mallory = derive_key(s_mallory)
assert k == k_mallory
print(f"Alice/Bob's key: {k.hex()}")
print(f"Mallory's derived key: {k_mallory.hex()} (matches!)")

iv = b'\x00' * 16

def encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext.encode(), AES.block_size))

def decrypt(key, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

c0 = encrypt(k, "Hi Bob!")
c1 = encrypt(k, "Hi Alice!")

print(f"\nMallory intercepts c0 and decrypts: {decrypt(k_mallory, c0)}")
print(f"Mallory intercepts c1 and decrypts: {decrypt(k_mallory, c1)}")