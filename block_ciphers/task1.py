"""Encrypt files with ECB and CBC and compare BMP images."""

import argparse
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from PIL import Image
from crypto_modes import (
    aes_ecb_encrypt, aes_ecb_decrypt, aes_cbc_encrypt, aes_cbc_decrypt,
    generate_aes_key, generate_iv, pkcs7_pad, pkcs7_unpad,
)


def split_bmp(data):
    if len(data) < 14 or data[:2] != b"BM":
        raise ValueError("Expected a BMP file")
    offset = int.from_bytes(data[10:14], "little")
    if not 14 <= offset <= len(data):
        raise ValueError("Invalid BMP pixel offset")
    return data[:offset], data[offset:]


def save_comparison(source, ecb, cbc, destination):
    figure, axes = plt.subplots(1, 3, figsize=(12, 4))
    titles = ["Original", "AES 128 ECB", "AES 128 CBC"]
    for axis, path, title in zip(axes, [source, ecb, cbc], titles):
        with Image.open(path) as image:
            axis.imshow(image.convert("RGB"))
        axis.set_title(title)
        axis.axis("off")
    figure.tight_layout()
    figure.savefig(destination, dpi=160, bbox_inches="tight")
    plt.close(figure)


def encrypt_file(source, output_dir=Path("outputs/task1")):
    original = source.read_bytes()
    is_bmp = source.suffix.lower() == ".bmp"
    header, plaintext = split_bmp(original) if is_bmp else (b"", original)
    key, iv = generate_aes_key(), generate_iv()
    padded = pkcs7_pad(plaintext)
    encrypted = {
        "ecb": aes_ecb_encrypt(padded, key),
        "cbc": aes_cbc_encrypt(padded, key, iv),
    }
    recovered = {
        "ecb": pkcs7_unpad(aes_ecb_decrypt(encrypted["ecb"], key)),
        "cbc": pkcs7_unpad(aes_cbc_decrypt(encrypted["cbc"], key, iv)),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = source.stem if is_bmp else source.name
    extension = ".bmp" if is_bmp else ".bin"
    paths, matches = {}, {}
    for mode in ("ecb", "cbc"):
        paths[mode] = output_dir / f"{stem}_{mode}{extension}"
        restored = output_dir / f"{stem}_{mode}_decrypted{extension}"
        # Keep the BMP header unchanged and retain all padded ciphertext.
        paths[mode].write_bytes(header + encrypted[mode])
        restored.write_bytes(header + recovered[mode])
        matches[mode] = restored.read_bytes() == original
        print(source.name, mode.upper(), "matches original:", matches[mode])
    # Save the lab key and IV separately so they do not shift BMP pixels.
    (output_dir / f"{stem}_key_iv.txt").write_text(
        f"Key: {key.hex()}\nIV: {iv.hex()}\n", encoding="utf-8"
    )
    if is_bmp:
        save_comparison(source, paths["ecb"], paths["cbc"],
                        output_dir / f"{stem}_comparison.png")
    return matches


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", type=Path)
    args = parser.parse_args()
    for source in args.files:
        encrypt_file(source)
