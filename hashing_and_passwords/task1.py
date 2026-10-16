"""SHA256 examples, avalanche measurements and truncated collisions."""

import argparse
import csv
import hashlib
import json
import math
import platform
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "results"


def truncate(data, bits):
    # Keep the first n bits, including lengths that are not whole hex digits.
    return int.from_bytes(hashlib.sha256(data).digest()[:8], "big") >> (64 - bits)


def avalanche_examples():
    rows = []
    for original in [b"security", b"password", b"Cryptography"]:
        changed = bytes([original[0] ^ 1]) + original[1:]
        first = hashlib.sha256(original).digest()
        second = hashlib.sha256(changed).digest()
        row = {
            "input1": original.decode(), "input2": changed.decode(),
            "input_bits_different": sum((a ^ b).bit_count()
                                        for a, b in zip(original, changed)),
            "digest1": first.hex(), "digest2": second.hex(),
            "digest_bits_different": sum((a ^ b).bit_count()
                                         for a, b in zip(first, second)),
            "digest_bytes_different": sum(a != b for a, b in zip(first, second)),
        }
        assert row["input_bits_different"] == 1
        rows.append(row)
        print(json.dumps(row, indent=2), flush=True)
    return rows


def find_collision(bits, max_entries):
    start = time.perf_counter()
    attempts = 0
    batch = 0
    while True:
        seen = {}
        prefix = f"{bits}:{batch}:"
        for index in range(max_entries):
            message = f"{prefix}{index}"
            value = truncate(message.encode(), bits)
            attempts += 1
            if value in seen:
                first = f"{prefix}{seen[value]}"
                assert first != message
                return {
                    "bits": bits, "inputs": attempts,
                    "seconds": time.perf_counter() - start,
                    "input1": first, "input2": message,
                    "truncated_hex": f"{value:0{(bits + 3) // 4}x}",
                    "completed_batches": batch,
                }
            seen[value] = index
        # A new prefix keeps every input distinct after clearing the table.
        del seen
        batch += 1
        print(f"{bits} bits: {attempts:,} inputs checked", flush=True)


def save_results(data):
    OUT.mkdir(exist_ok=True)
    path = OUT / "task1_results.json"
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2) + "\n")
    temporary.replace(path)
    rows = data["collisions"]
    if not rows:
        return
    with (OUT / "collisions.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def plot_results(rows):
    bits = [r["bits"] for r in rows]
    for field, label, filename in [
        ("seconds", "Collision time in seconds", "collision_time.png"),
        ("inputs", "Number of inputs", "collision_inputs.png"),
    ]:
        fig, ax = plt.subplots(figsize=(7.2, 4.3))
        ax.plot(bits, [r[field] for r in rows], "o-", label="Measured")
        if field == "inputs":
            expected = [math.sqrt(math.pi / 2) * 2 ** (n / 2) for n in bits]
            ax.plot(bits, expected, ":", label="Birthday estimate without a memory limit")
            ax.legend(fontsize=8)
        ax.set(xlabel="Digest size in bits", ylabel=label, yscale="log")
        ax.set_xticks(bits[::2] + ([bits[-1]] if bits[-1] not in bits[::2] else []))
        ax.grid(alpha=0.25, which="both")
        fig.tight_layout()
        fig.savefig(OUT / filename, dpi=180)
        plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--message", help="Print the SHA256 digest of this text and exit")
    parser.add_argument("--max-bits", type=int, default=50)
    parser.add_argument("--max-entries", type=int, default=8_000_000)
    parser.add_argument("--fresh", action="store_true", help="Replace earlier Task 1 results")
    args = parser.parse_args()
    if args.message is not None:
        print(hashlib.sha256(args.message.encode()).hexdigest())
        return
    if args.max_bits not in range(8, 51, 2) or args.max_entries < 2:
        parser.error("Use an even bit length from 8 to 50 and at least 2 entries")

    examples = []
    for message in ["Hello, world!", "Python", "Cryptography"]:
        digest = hashlib.sha256(message.encode()).hexdigest()
        print(f"{message}: {digest}")
        examples.append({"input": message, "digest": digest})
    avalanche = avalanche_examples()
    metadata = {"platform": platform.platform(), "python": platform.python_version(),
                "max_entries": args.max_entries}
    path = OUT / "task1_results.json"
    data = {"environment": metadata, "examples": examples,
            "avalanche": avalanche, "collisions": []}
    if path.exists() and not args.fresh:
        data = json.loads(path.read_text())
        if data["environment"] != metadata:
            parser.error("The environment or memory limit changed. Run with --fresh")
    completed = {r["bits"] for r in data["collisions"]}
    for bits in range(8, args.max_bits + 1, 2):
        if bits in completed:
            continue
        row = find_collision(bits, args.max_entries)
        data["collisions"].append(row)
        save_results(data)
        print(f"{bits} bits: collision after {row['inputs']:,} inputs "
              f"in {row['seconds']:.6f} seconds", flush=True)
    plot_results(data["collisions"])
    print(f"Results saved in {OUT}")


if __name__ == "__main__":
    main()
