"""Search the supplied classroom bcrypt hashes with the NLTK words corpus."""

import argparse
import hashlib
import json
import multiprocessing as mp
import os
import platform
import re
import time
from collections import Counter
from pathlib import Path

import bcrypt

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "results"
CHUNK_SIZE = 32


def read_shadow(path):
    if path.suffix.lower() == ".pdf":
        from pypdf import PdfReader
        text = "\n".join(page.extract_text() or "" for page in PdfReader(path).pages)
    else:
        text = path.read_text()
    pattern = r"([\w.-]+)\s*:\s*(\$2[aby]\$\d{2}\$(?:[./A-Za-z0-9]\s*){53})"
    rows = []
    for name, value in re.findall(pattern, text):
        encoded = re.sub(r"\s+", "", value)
        if not 4 <= int(encoded[4:6]) <= 31:
            raise ValueError(f"Invalid bcrypt cost for {name}")
        if any(r["username"] == name for r in rows):
            raise ValueError(f"Duplicate username in the shadow file: {name}")
        rows.append({"username": name, "hash": encoded,
                     "algorithm": encoded.split("$")[1], "cost": int(encoded[4:6]),
                     "salt": encoded[7:29]})
    if not rows:
        raise ValueError("No complete username and bcrypt hash pairs were found")
    if len(re.findall(r"[\w.-]+\s*:\s*\$2", text)) != len(rows):
        raise ValueError("At least one bcrypt entry is incomplete or unsupported")
    return sorted(rows, key=lambda row: row["cost"])


def load_words():
    from nltk.corpus import brown, words
    eligible = list(dict.fromkeys(w for w in words.words()
                                   if 6 <= len(w) <= 10 and w.isascii() and w.isalpha()))
    frequency = Counter(w.lower() for w in brown.words())
    # Frequency only changes the search order. Password spelling stays unchanged.
    return sorted(eligible, key=lambda w: (-frequency[w.lower()], len(w), w))


def order_for_group(candidates, group):
    if group["cost"] < 12:
        return candidates
    from nltk.corpus import brown
    frequency = Counter(w.lower() for w in brown.words())
    # Keep saved work in place, then try longer words first within frequency ties.
    prefix = group.setdefault("original_order_prefix", group["next_index"])
    remaining = sorted(candidates[prefix:],
                       key=lambda w: (-frequency[w.lower()], -len(w), w))
    return candidates[:prefix] + remaining


def check_chunk(job):
    prefix, targets, candidates = job
    matches = {}
    for word in candidates:
        encoded = bcrypt.hashpw(word.encode(), prefix).decode()
        if encoded in targets:
            matches[encoded] = word
    return matches, len(candidates)


def save(data):
    OUT.mkdir(exist_ok=True)
    path = OUT / "task2_results.json"
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2) + "\n")
    temporary.replace(path)


def crack_group(group, candidates, workers, data):
    candidates = order_for_group(candidates, group)
    context = mp.get_context("spawn")
    rows = [r for r in data["users"] if r["hash"][:29] == group["prefix"]]
    targets = {r["hash"] for r in rows if r["status"] != "found"}
    width = workers * CHUNK_SIZE
    previous_seconds = group["seconds"]
    start = time.perf_counter()
    with context.Pool(workers) as pool:
        for offset in range(group["next_index"], len(candidates), width):
            end = min(offset + width, len(candidates))
            jobs = [(group["prefix"].encode(), targets,
                     candidates[i:min(i + CHUNK_SIZE, end)])
                    for i in range(offset, end, CHUNK_SIZE)]
            answers = pool.map(check_chunk, jobs)
            group["attempts"] += sum(count for _, count in answers)
            group["next_index"] = end
            group["seconds"] = previous_seconds + time.perf_counter() - start
            matches = {encoded: word for found, _ in answers for encoded, word in found.items()}
            for row in rows:
                if row["status"] == "found":
                    continue
                row["attempts"], row["seconds"] = group["attempts"], group["seconds"]
                row["status"] = "not found" if end == len(candidates) else "running"
                if row["hash"] in matches:
                    row["password"] = matches[row["hash"]]
                    assert bcrypt.checkpw(row["password"].encode(), row["hash"].encode())
                    row["status"] = "found"
                    targets.discard(row["hash"])
                    print(f"{row['username']}: {row['password']} in {row['seconds']:.2f} seconds",
                          flush=True)
            group["status"] = "found" if not targets else "running"
            if targets and end == len(candidates):
                group["status"] = "exhausted"
            save(data)
            print(f"Cost {group['cost']}: {group['attempts']:,} candidate hashes, "
                  f"{group['seconds']:.2f} seconds, {len(targets)} hashes remaining", flush=True)
            if not targets:
                break


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("shadow", type=Path, help="The classroom shadow PDF or text file")
    parser.add_argument("--workers", type=int, default=min(4, os.cpu_count() or 1))
    parser.add_argument("--fresh", action="store_true", help="Replace earlier Task 2 results")
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("Use at least one worker")
    try:
        targets = read_shadow(args.shadow)
        candidates = load_words()
    except LookupError:
        parser.error("Install the corpora with: python -m nltk.downloader words brown")
    except (OSError, ValueError) as error:
        parser.error(str(error))
    metadata = {
        "platform": platform.platform(), "python": platform.python_version(),
        "bcrypt": bcrypt.__version__, "workers": args.workers,
        "chunk_size": CHUNK_SIZE, "method": "shared salt groups",
        "dictionary_size": len(candidates),
        "dictionary_sha256": hashlib.sha256("\n".join(candidates).encode()).hexdigest(),
    }
    source_hash = hashlib.sha256(args.shadow.read_bytes()).hexdigest()
    data = {"environment": metadata, "source": args.shadow.name,
            "source_sha256": source_hash, "users": [], "groups": []}
    path = OUT / "task2_results.json"
    if path.exists() and not args.fresh:
        data = json.loads(path.read_text())
        if data["environment"] != metadata or data["source_sha256"] != source_hash:
            parser.error("The input or run settings changed. Run with --fresh")
    else:
        data["users"] = [{**target, "attempts": 0, "seconds": 0.0,
                          "password": None, "status": "pending"} for target in targets]
        for prefix in dict.fromkeys(r["hash"][:29] for r in targets):
            data["groups"].append({"prefix": prefix, "cost": int(prefix[4:6]),
                                   "next_index": 0, "attempts": 0, "seconds": 0.0,
                                   "status": "pending"})
    save(data)
    print(f"Dictionary: {len(candidates):,} unique words. Workers: {args.workers}", flush=True)
    try:
        for group in data["groups"]:
            if group["status"] in ["found", "exhausted"]:
                print(f"Saved cost {group['cost']}: {group['status']}", flush=True)
                continue
            crack_group(group, candidates, args.workers, data)
    except KeyboardInterrupt:
        print("Stopped. Run the same command to resume from the last saved batch.")
        return
    found_costs = {r["cost"] for r in data["users"] if r["status"] == "found"}
    missing = sorted(set(range(8, 14)) - found_costs)
    print(f"Results saved in {path}")
    remaining = [r["username"] for r in data["users"] if r["status"] != "found"]
    print(f"Verified passwords: {len(data['users']) - len(remaining)} of {len(data['users'])}")
    if remaining:
        print("Still missing: " + ", ".join(remaining))
    else:
        print("All supplied passwords were recovered.")
    if missing:
        print(f"Required costs still missing: {missing}")


if __name__ == "__main__":
    main()
