# Module 4: Hashing and Passwords

Carlos Lopez and Kennedy Suon  
CSC 3201 Section S10 Professor Yocam

## Completed work

Task 1 includes SHA256 examples, three pairs of inputs that differ by one bit, and collisions for every even digest size from 8 through 50 bits. The results folder contains the measurements and both graphs.

Task 2 is complete. All 15 passwords and their recovery times are saved in results/task2_results.json. The PDF includes these results, both graphs, answers to all four questions, and both Python scripts.

Submit CSC3201_Module4_Report.pdf on Canvas. Keep this folder for the group demonstration.

## Setup on a Mac

Open this folder in VS Code. Choose Terminal, then New Terminal. Enter each command separately. Use Python 3.10 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m nltk.downloader words brown
```

When returning later, activate the environment again.

```bash
source .venv/bin/activate
```

## Short demonstration

Print the SHA256 digest of a message.

```bash
python task1.py --message "Computer security"
```

Show the three input pairs and count the digest differences.

```bash
python -c "from task1 import avalanche_examples; avalanche_examples()"
```

Open the two saved graphs.

```bash
open results/collision_time.png
open results/collision_inputs.png
```

Open results/task2_results.json in VS Code to show the recovered passwords and times. To check the saved passwords against their hashes, paste this complete block into the terminal.

```bash
python - <<'PY'
import json
import bcrypt

with open("results/task2_results.json") as file:
    data = json.load(file)
for user in data["users"]:
    valid = bcrypt.checkpw(user["password"].encode(), user["hash"].encode())
    print(user["username"], valid)
PY
```

This checks the 15 known answers without searching the dictionary again.

## Starting new measurements

The saved work is complete. These commands are only for a new experiment. Make a separate copy of the folder first because the fresh option replaces saved results.

```bash
python task1.py --fresh
python task2.py shadow.pdf --workers 4 --fresh
```

Task 2 can take hours. Keep the Mac connected to power and leave its lid open. You can add caffeinate before the command to prevent idle sleep.

```bash
caffeinate -i python task2.py shadow.pdf --workers 4 --fresh
```

Press Control and C to stop. To resume on the same setup, use the same command without the fresh option.

```bash
caffeinate -i python task2.py shadow.pdf --workers 4
```

The scripts check the saved run settings before resuming. If the setup has changed, use a separate folder for new measurements and keep the completed results.

## Code

task1.py uses hashlib for SHA256, a dictionary to find repeated truncated hashes, and matplotlib for the two graphs. It clears the dictionary at a memory limit so the largest searches can finish without using unlimited memory.

task2.py uses NLTK words with 6 through 10 letters and bcrypt to test them. Brown corpus frequencies change the order of guesses. Four worker processes search different parts of the dictionary. Users with the same salt and cost share the calculated hashes. Progress is saved after each batch so a stopped search can resume.

These are the same two lab scripts used for the recorded results. They follow the assignment and professor's hints. The folder contains the supplied shadow.pdf input and the packages needed by the scripts.
