"""CBC bit flipping against the assignment's submit and verify functions."""

from pathlib import Path
from crypto_modes import (
    aes_cbc_encrypt, aes_cbc_decrypt, generate_aes_key, generate_iv,
    pkcs7_pad, pkcs7_unpad,
)

PREFIX = b"userid=456;userdata="
SUFFIX = b";session-id=31337"
ADMIN = b";admin=true;"
# Both functions use one random key and IV for this program execution.
KEY, IV = generate_aes_key(), generate_iv()


def submit(user_data):
    safe = user_data.replace(";", "%3B").replace("=", "%3D")
    plaintext = PREFIX + safe.encode("utf-8") + SUFFIX
    return aes_cbc_encrypt(pkcs7_pad(plaintext), KEY, IV)


def decrypt(ciphertext):
    return pkcs7_unpad(aes_cbc_decrypt(ciphertext, KEY, IV))


def verify(ciphertext):
    try:
        return ADMIN in decrypt(ciphertext)
    except ValueError:
        return False


def forge(ciphertext):
    # Twelve A characters after the prefix place the marker at byte 32.
    # Change the previous ciphertext block without using the key or IV.
    marker = b":admin<true:"
    modified = bytearray(ciphertext)
    for offset, (old, new) in enumerate(zip(marker, ADMIN)):
        modified[16 + offset] ^= old ^ new
    return bytes(modified)


def run_demo():
    direct = submit(";admin=true;")
    original = submit("A" * 12 + ":admin<true:")
    modified = forge(original)
    changed = [i for i in range(len(original))
               if original[i] != modified[i]]
    lines = [
        f"Direct injection accepted: {verify(direct)}",
        f"Unmodified placeholder accepted: {verify(original)}",
        f"Modified ciphertext accepted: {verify(modified)}",
        f"Changed ciphertext byte indexes: {changed}",
    ]
    # Actual decrypted bytes show the effect after the attack is complete.
    before, after = decrypt(original), decrypt(modified)
    for i in range(0, len(before), 16):
        lines.append(f"P{i // 16} before: {before[i:i + 16]!r}")
        lines.append(f"P{i // 16} after:  {after[i:i + 16]!r}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    result = run_demo()
    print(result, end="")
    folder = Path("outputs/task2")
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "bit_flipping_results.txt").write_text(result, encoding="utf-8")
