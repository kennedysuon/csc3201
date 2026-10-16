"""Measure AES and RSA with OpenSSL and save the two required graphs."""

import argparse
import csv
import math
import platform
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

AES_KEYS = (128, 192, 256)
BUFFER_SIZES = [2 ** n for n in range(4, 21)]
RSA_KEYS = (1024, 2048, 3072, 4096)


def find_openssl():
    for name in ("/opt/homebrew/opt/openssl@3/bin/openssl",
                 "/usr/local/opt/openssl@3/bin/openssl", "openssl"):
        path = shutil.which(name)
        if path:
            return str(Path(path).resolve())
    raise FileNotFoundError("OpenSSL 3 is required")


def run_command(command):
    result = subprocess.run(command, capture_output=True, text=True,
                            check=True, timeout=600)
    return result.stdout + result.stderr


def positive_rate(value):
    rate = float(value)
    if not math.isfinite(rate) or rate <= 0:
        raise ValueError("Invalid benchmark throughput")
    return rate


def parse_aes(output, size):
    lines = output.splitlines()
    if f"+H:{size}" not in lines:
        raise ValueError("Unexpected AES buffer size")
    for line in lines:
        if line.startswith("+F:"):
            return positive_rate(line.split(":")[3]) / 1_000_000
    raise ValueError("Missing AES result")


def parse_rsa(output):
    rows = []
    for line in output.splitlines():
        if line.startswith("+F2:"):
            fields = line.split(":")
            rows.append({
                "key_size_bits": int(fields[2]),
                "signing_operations_per_second": positive_rate(fields[3]),
                "verification_operations_per_second": positive_rate(fields[4]),
            })
    if [row["key_size_bits"] for row in rows] != list(RSA_KEYS):
        raise ValueError("Incomplete RSA results")
    return rows


def write_csv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def save_plots(aes_rows, rsa_rows, folder):
    figure, axis = plt.subplots(figsize=(10, 6))
    for bits in AES_KEYS:
        group = [row for row in aes_rows if row["key_size_bits"] == bits]
        axis.plot([row["block_size_mb"] for row in group],
                  [row["throughput_mb_per_second"] for row in group],
                  marker="o", label=f"AES {bits}")
    axis.set(xscale="log", yscale="log",
             xlabel="OpenSSL test buffer size in MB",
             ylabel="Throughput in MB per second",
             title="AES Performance: Buffer Size vs Throughput")
    axis.grid(True, which="both", alpha=0.25)
    axis.legend()
    figure.tight_layout()
    figure.savefig(folder / "aes_performance.png", dpi=180)
    plt.close(figure)

    figure, axis = plt.subplots(figsize=(10, 6))
    sizes = [row["key_size_bits"] for row in rsa_rows]
    axis.plot(sizes, [row["signing_operations_per_second"] for row in rsa_rows],
              marker="o", label="Signing")
    axis.plot(sizes, [row["verification_operations_per_second"] for row in rsa_rows],
              marker="o", label="Verification")
    axis.set(yscale="log", xticks=sizes, xlabel="RSA key size in bits",
             ylabel="Operations per second",
             title="RSA Performance: Key Size vs Throughput")
    axis.grid(True, which="both", alpha=0.25)
    axis.legend()
    figure.tight_layout()
    figure.savefig(folder / "rsa_performance.png", dpi=180)
    plt.close(figure)


def benchmark(seconds=1, folder=Path("outputs/task3")):
    openssl = find_openssl()
    version = run_command([openssl, "version"]).strip()
    if not version.startswith("OpenSSL 3."):
        raise RuntimeError("Use OpenSSL 3. On macOS: brew install openssl@3")
    folder.mkdir(parents=True, exist_ok=True)
    base = [openssl, "speed", "-mr", "-elapsed", "-seconds", str(seconds)]
    aes_rows = []
    for bits in AES_KEYS:
        logs = []
        for size in BUFFER_SIZES:
            command = base + ["-bytes", str(size), "-evp", f"aes-{bits}-ecb"]
            output = run_command(command)
            logs.append("$ " + " ".join(command) + "\n" + output)
            aes_rows.append({
                "key_size_bits": bits, "block_size_bytes": size,
                "block_size_mb": size / 1_000_000,
                "throughput_mb_per_second": parse_aes(output, size),
            })
        (folder / f"openssl_aes_{bits}_raw.txt").write_text("\n".join(logs))
        print(f"Completed AES {bits}", flush=True)
    command = base + [f"rsa{bits}" for bits in RSA_KEYS]
    output = run_command(command)
    (folder / "openssl_rsa_raw.txt").write_text(
        "$ " + " ".join(command) + "\n" + output
    )
    rsa_rows = parse_rsa(output)
    write_csv(folder / "aes_results.csv", aes_rows)
    write_csv(folder / "rsa_results.csv", rsa_rows)
    save_plots(aes_rows, rsa_rows, folder)
    (folder / "run_info.txt").write_text(
        f"Recorded: {datetime.now(timezone.utc).isoformat()}\n"
        f"System: {platform.system()} {platform.machine()}\n"
        f"OpenSSL: {version}\nExecutable: {openssl}\n"
        f"Seconds per measurement: {seconds}\n"
        "AES mode: ECB encryption through OpenSSL EVP\n"
        "Timing: one elapsed time trial per setting\n"
        "Units: 1 MB = 1000000 bytes; RSA uses operations per second\n"
    )
    print("Results and graphs:", folder)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=1)
    args = parser.parse_args()
    if args.seconds < 1:
        parser.error("Timing must be at least one second")
    benchmark(args.seconds)
