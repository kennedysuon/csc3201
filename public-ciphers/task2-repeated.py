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

def run_attack(alpha_tampered, label):
    print(f"\n--- Mallory sets alpha = {label} ---")

    x_A = secrets.randbelow(q - 2) + 1
    x_B = secrets.randbelow(q - 2) + 1

    # Alice and Bob compute Y values using the TAMPERED alpha
    Y_A = pow(alpha_tampered, x_A, q)
    Y_B = pow(alpha_tampered, x_B, q)

    s_alice = pow(Y_B, x_A, q)
    s_bob = pow(Y_A, x_B, q)
    assert s_alice == s_bob
    print(f"Actual shared secret s = {s_alice}")

    k = derive_key(s_alice)
    c0 = encrypt(k, "Hi Bob!")
    c1 = encrypt(k, "Hi Alice!")

    # Mallory's candidate values for s, depending on which alpha was used
    if alpha_tampered == 1:
        candidates = [1]
    elif alpha_tampered == q:
        candidates = [0]
    elif alpha_tampered == q - 1:
        candidates = [1, q - 1]  # Mallory tries both possibilities
    else:
        candidates = []

    for guess in candidates:
        try:
            k_guess = derive_key(guess)
            msg0 = decrypt(k_guess, c0)
            msg1 = decrypt(k_guess, c1)
            print(f"Mallory tries s={guess}: SUCCESS -> '{msg0}', '{msg1}'")
        except Exception:
            print(f"Mallory tries s={guess}: failed (padding error, wrong guess)")

run_attack(1, "1")
run_attack(q, "q")
run_attack(q - 1, "q-1")