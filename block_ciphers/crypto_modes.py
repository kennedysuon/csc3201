"""AES 128 modes and PKCS#7 padding for Tasks 1 and 2."""

import secrets
from Crypto.Cipher import AES

BLOCK_SIZE = 16


def generate_aes_key():
    return secrets.token_bytes(BLOCK_SIZE)


def generate_iv():
    return secrets.token_bytes(BLOCK_SIZE)


def xor_bytes(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


def pkcs7_pad(data):
    count = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([count]) * count


def pkcs7_unpad(data):
    if not data or len(data) % BLOCK_SIZE:
        raise ValueError("Invalid padded data length")
    count = data[-1]
    if not 1 <= count <= BLOCK_SIZE:
        raise ValueError("Invalid padding length")
    if data[-count:] != bytes([count]) * count:
        raise ValueError("Invalid padding bytes")
    return data[:-count]


def check_input(data, key):
    if len(key) != BLOCK_SIZE or len(data) % BLOCK_SIZE:
        raise ValueError("Use a 16 byte key and complete 16 byte blocks")


def aes_ecb_encrypt(data, key):
    check_input(data, key)
    aes = AES.new(key, AES.MODE_ECB)
    blocks = []
    for i in range(0, len(data), BLOCK_SIZE):
        blocks.append(aes.encrypt(data[i:i + BLOCK_SIZE]))
    return b"".join(blocks)


def aes_ecb_decrypt(data, key):
    check_input(data, key)
    aes = AES.new(key, AES.MODE_ECB)
    blocks = []
    for i in range(0, len(data), BLOCK_SIZE):
        blocks.append(aes.decrypt(data[i:i + BLOCK_SIZE]))
    return b"".join(blocks)


def aes_cbc_encrypt(data, key, iv):
    check_input(data, key)
    if len(iv) != BLOCK_SIZE:
        raise ValueError("The IV must have 16 bytes")
    aes = AES.new(key, AES.MODE_ECB)
    previous = iv
    blocks = []
    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i + BLOCK_SIZE]
        encrypted = aes.encrypt(xor_bytes(block, previous))
        blocks.append(encrypted)
        previous = encrypted
    return b"".join(blocks)


def aes_cbc_decrypt(data, key, iv):
    check_input(data, key)
    if len(iv) != BLOCK_SIZE:
        raise ValueError("The IV must have 16 bytes")
    aes = AES.new(key, AES.MODE_ECB)
    previous = iv
    blocks = []
    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i + BLOCK_SIZE]
        blocks.append(xor_bytes(aes.decrypt(block), previous))
        previous = block
    return b"".join(blocks)
