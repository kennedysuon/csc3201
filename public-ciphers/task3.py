from Crypto.Util import number
import secrets

def extended_gcd(a, b):
    """Returns (gcd, x, y) such that a*x + b*y = gcd"""
    if b == 0:
        return (a, 1, 0)
    gcd, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return (gcd, x, y)

def mod_inverse(e, phi):
    """Computes the multiplicative inverse of e mod phi"""
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise Exception("e and phi are not coprime; no inverse exists")
    return x % phi

def generate_keypair(bits=1024):
    """Generates an RSA keypair with primes of the given bit length"""
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

    return (n, e), (n, d)  # (public key), (private key)

def rsa_encrypt(m, public_key):
    n, e = public_key
    return pow(m, e, n)

def rsa_decrypt(c, private_key):
    n, d = private_key
    return pow(c, d, n)

def string_to_int(s):
    return int(s.encode().hex(), 16)

def int_to_string(i):
    hex_str = hex(i)[2:]
    if len(hex_str) % 2 != 0:
        hex_str = "0" + hex_str
    return bytes.fromhex(hex_str).decode()

if __name__ == "__main__":
    print("Generating RSA keypair (1024-bit primes)...")
    public_key, private_key = generate_keypair(bits=1024)
    n, e = public_key
    _, d = private_key

    print(f"n = {n}")
    print(f"e = {e}")
    print(f"d = {d}")

    message = "Hello RSA!"
    m_int = string_to_int(message)
    print(f"\nMessage: {message}")
    print(f"As integer: {m_int}")
    assert m_int < n, "Message too large for this key size"

    c = rsa_encrypt(m_int, public_key)
    print(f"Encrypted: {c}")

    decrypted_int = rsa_decrypt(c, private_key)
    decrypted_message = int_to_string(decrypted_int)
    print(f"Decrypted integer: {decrypted_int}")
    print(f"Decrypted message: {decrypted_message}")

    assert decrypted_message == message
    print("\nSuccess! Encryption/decryption round-trip works.")