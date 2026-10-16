import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import secrets

# --- IETF 1024-bit MODP Group parameters (RFC 2409, Group 2) ---
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

# --- Alice's side ---
x_A = secrets.randbelow(q - 2) + 1
Y_A = pow(alpha, x_A, q)

# --- Bob's side ---
x_B = secrets.randbelow(q - 2) + 1
Y_B = pow(alpha, x_B, q)

print(f"Y_A = {Y_A}")
print(f"Y_B = {Y_B}")

# --- Shared secret ---
s_alice = pow(Y_B, x_A, q)
s_bob   = pow(Y_A, x_B, q)
assert s_alice == s_bob
print(f"Shared secret s matches: {s_alice == s_bob}")

# --- Derive AES key ---
def derive_key(s):
    s_bytes = s.to_bytes((s.bit_length() + 7) // 8, byteorder='big')
    return hashlib.sha256(s_bytes).digest()[:16]

k = derive_key(s_alice)
print(f"AES key (hex): {k.hex()}")

# --- Encrypt/decrypt ---
iv = b'\x00' * 16

def encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext.encode(), AES.block_size))

def decrypt(key, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

c0 = encrypt(k, "Hi Bob!")
c1 = encrypt(k, "Hi Alice!")

print(f"c0 hex: {c0.hex()}")
print(f"c1 hex: {c1.hex()}")
print(f"Bob decrypts c0: {decrypt(k, c0)}")
print(f"Alice decrypts c1: {decrypt(k, c1)}")