# CSC 3201 Block Ciphers

Carlos Lopez and Kennedy Suon  
Professor Eric Yocam  
Section S10, Fall 2026

Open this folder in VS Code. Use its terminal from this folder.

## Setup

Create and activate the Python environment, then install the packages.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

If the environment already exists, activate it with the second command.

## Task 1

```bash
python task1.py assets/mustang.bmp assets/cp-logo.bmp
```

The encrypted images, decrypted images, and comparison figures are saved in `outputs/task1`. Both recovery checks should print `True` for each image. The same script accepts a text file or another plaintext file. BMP headers are preserved so the encrypted images can be opened.

The key and IV are saved separately for this lab. Each new run generates new values, so the encrypted colors can change while the overall comparison stays the same.

## Task 2

```bash
python task2_bit_flipping.py
```

Direct injection and the original placeholder should print `False`. The modified ciphertext should print `True`. The actual decrypted blocks and the changed byte indexes are saved in `outputs/task2/bit_flipping_results.txt`.

## Task 3

```bash
python task3_benchmarks.py
```

This uses OpenSSL 3 and takes about a minute. The script first checks the usual Homebrew locations and then the system path. If OpenSSL 3 is missing and Homebrew is installed, use this command.

```bash
brew install openssl@3
```

The graphs, CSV measurements, raw OpenSSL output, and run information are saved in `outputs/task3`. The included measurements came from Carlos's Mac M3 on September 24, 2026. Running the benchmark again replaces these results with the new measurements. The PDF is a fixed report and does not update automatically.

## Files

`crypto_modes.py` contains the shared AES loops and padding. `task1.py` handles file encryption and image comparisons. `task2_bit_flipping.py` contains the two oracle functions and the attack. `task3_benchmarks.py` runs OpenSSL and plots its results.

`CSC3201_Report.pdf` is the Canvas submission. It contains the names, explanations, required figures, and all four source files. `SUBMISSION_REPORT.md` is an editable copy of the report.

Both team members must attend the instructor selected demonstration. Be ready to run the three commands and explain CBC chaining, the three changed ciphertext bytes, and the graph trends.
