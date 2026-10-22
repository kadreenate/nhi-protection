# nhi-protection

This lab is about protecting non-human identities. It has four parts: write the scanner, run it as a git pre-commit hook (local gate), run it again as a GitHub Actions stage (pipeline gate), and then test both with fake keys.

**Step 1: Setting up the repo**

Log in to your terminal on your device to clone a private repo using this command: 

_gh repo create nhi-secret-scanner --private --clone
cd nhi-secret-scanner
mkdir -p scanner .githooks .github/workflows test/fixtures_

After doing this, open the folder in VScode using this command: 
_cd ~/nhi-secret-scanner
code ._

Step 2: Create the scanner
The scanner itself is what decides whether the code contains a credential. It does three things:

a. Detects NHI credentials by their known formats. AWS access keys always start with AKIA or ASIA followed by 16 characters, and Stripe live keys start with sk_live_.
b. Reports each one as a CRITICAL log line with the file and line number, masking the key so the warning doesn’t leak it.
c. Blocks by exiting with code 1. Git and GitHub Actions both treat a non-zero exit as failure, so this single number is what stops the commit or halts the deploy. Without it, the scanner would only print warnings.

Do the following to create the scanner. 

I). In VS Code’s left panel (Explorer), right-click in the empty space > New File > type: _scanner/scan_nhis.py_ and press enter: 

<img width="2771" height="1212" alt="image" src="https://github.com/user-attachments/assets/f7ce1c44-6d6f-4d65-a375-1d4cbb1c8e43" />

VS Code will create the scanner folder if it doesn’t exist before. 

II). Copy and save the script below. 

The script works like a security checkpoint for your code. Before code is committed or deployed, it checks every file for passwords and keys that belong to machines rather than people, and it stops the process if it finds any. It does three things:

a). Searches: It reads your files line by line, looking for text shaped like a real credential, for example anything starting with AKIA (AWS keys) or sk_live_ (Stripe keys).
b). Warns: When it finds one, it prints a CRITICAL alert with the file name and line number, masking most of the key so the alert itself doesn’t expose it.
c). Blocks: It ends with a “fail” signal (exit code 1), which tells git to refuse the commit and tells GitHub Actions to stop the pipeline before deployment.

Summary of what the script does: 

<img width="1604" height="864" alt="image" src="https://github.com/user-attachments/assets/d6584670-2f3b-404f-95cf-64838d589e96" />

The script: 

#!/usr/bin/env python3
"""NHI secret scanner: blocks commits and builds that contain machine credentials."""
import argparse, logging, os, re, subprocess, sys

PATTERNS = {
    "Stripe live secret key": re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b"),
    "AWS access key ID":      re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "AWS secret access key":  re.compile(r"(?i)aws.{0,20}?(?:secret|private).{0,20}?['\"=:\s]([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])"),
    "GitHub token":           re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "Private key block":      re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}
MAX_BYTES = 1_000_000

logging.basicConfig(format="%(asctime)s [%(levelname)s] %(message)s", level=logging.INFO)
log = logging.getLogger("nhi-scanner")

def mask(secret):
    return secret[:8] + "*" * 8 if len(secret) > 8 else "****"

def staged_files():
    out = subprocess.run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
                         capture_output=True, text=True, check=True).stdout
    return [f for f in out.splitlines() if f]

def all_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            yield os.path.join(dirpath, name)

def scan_codebase_for_nhis(paths):
    findings = []
    for path in paths:
        try:
            if os.path.getsize(path) > MAX_BYTES:
                continue
            with open(path, "r", encoding="utf-8") as fh:
                lines = fh.readlines()
        except (UnicodeDecodeError, OSError):
            continue  # skip binary or unreadable files
        for lineno, line in enumerate(lines, 1):
            if "nhi-scan:allow" in line:
                continue  # explicit, reviewable allowlist marker
            for label, rx in PATTERNS.items():
                for m in rx.finditer(line):
                    secret = m.group(1) if m.groups() else m.group(0)
                    findings.append((path, lineno, label, mask(secret)))
    return findings

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["staged", "full"], default="full")
    ap.add_argument("--path", default=".")
    args = ap.parse_args()

    paths = staged_files() if args.mode == "staged" else list(all_files(args.path))
    log.info("Scanning %d file(s) in %s mode", len(paths), args.mode)
    findings = scan_codebase_for_nhis(paths)

    if findings:
        for path, lineno, label, masked in findings:
            log.critical("NHI SECRET DETECTED: %s in %s:%d (%s)", label, path, lineno, masked)
        log.critical("BLOCKED: %d secret(s) found. Remove them, rotate the credential, and retry.", len(findings))
        sys.exit(1)

    log.info("No NHI secrets found. Proceeding.")
    sys.exit(0)

if __name__ == "__main__":
    main()

The result in VS Code: 

<img width="3017" height="1905" alt="image" src="https://github.com/user-attachments/assets/c0d7f392-2030-44b0-95e5-c38e3bcec236" />

III). Test that the code is running
Open VS Code’s built-in terminal with Control + backtick (for Mac users). It opens inside your repo folder. Run this code: python3 scanner/scan_nhis.py --mode full. It'll open the terminal in your repo and show this result: 

<img width="3038" height="1663" alt="image" src="https://github.com/user-attachments/assets/dfe9ddf2-6265-42bc-b5e3-cfd424a5720a" />

I did a quick test to be sure the script is working as intended using this command: 

_echo "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" > test/fixtures/quick.env
python3 scanner/scan_nhis.py --mode full
echo $?_

The result (see image below) showed a CRITICAL line, and echo $? should print 1, confirming the blocking exit code: 

<img width="2001" height="271" alt="image" src="https://github.com/user-attachments/assets/6f89acbe-abc7-469e-80cd-18c786cb312b" />

Then I deleted the file with this: rm test/fixtures/quick.env

**Step 3: Connect the scanner to git**
Connecting the scanner to git makes the script run every time you commit instead of doing it manually. Git can run your own scripts at certain moments. A pre-commit hook runs right after you type git commit and before the commit is saved. If the hook exits with 1, Git cancels the commit, which is how the scanner’s “block” signal takes effect.

I). Create the hook file. In VS Code’s Explorer panel, right-click > New File > type: _.githooks/pre-commit_
The file name is exactly pre-commit, with no extension (no .sh or .txt). Git looks for that exact name. Then save it by following the steps below (all instructions tailored to Mac commands): 

a). In the dialog, press ⌘ + Shift + G to open a “Go to folder” box.
b). Type ~/nhi-secret-scanner and press Enter.
c). Press ⌘ + Shift + . (period) to show hidden folders. .githooks starts with a dot, so macOS hides it by default.
d). Double-click into .githooks. If it doesn’t exist, click New Folder and name it .githooks. macOS will warn that names starting with a dot are reserved for the system; click Use “.”.
e). In the Save As box, type exactly pre-commit, with no extension. If a file format option appears, leave it as is, and make sure the name doesn’t become pre-commit.txt or pre-commit.sh.
f). Click Save.

On the pre-commit terminal, paste this in and save: 

#!/bin/sh
python3 scanner/scan_nhis.py --mode staged

**_Note: The first line says the file is a shell script. The second line runs your scanner in staged mode, so it only checks files you’re about to commit._**

II). Make the hook and scanner executable

Open the VS Code terminal and run: _chmod +x .githooks/pre-commit scanner/scan_nhis.py_
Git silently skips hooks that aren’t executable, so leaving this out is the most common reason a hook “doesn’t work.”

III). Tell Git where the hooks are with this command: _git config core.hooksPath .githooks_
By default, git looks for hooks in .git/hooks. That folder is never committed, so a hook placed there exists only on your machine. Pointing git at .githooks keeps the hook in the repo, where it’s version-controlled and visible in your portfolio.

This setting applies to this clone only. Anyone else who clones the repo has to run that command too, which is one reason Step 4 adds CI as the enforced gate.

Check that it’s set: _git config core.hooksPath_

This should print _.githooks._ as shown below: 

<img width="896" height="262" alt="image" src="https://github.com/user-attachments/assets/0d409919-77ce-47c0-98c2-1434bc7afedf" />

IV). Check that the hook runs

Commit your files with this command: 

_bash
git add .
git commit -m "Add NHI scanner and pre-commit hook"_

You should see the scanner’s output before git confirms the commit:

<img width="1087" height="177" alt="image" src="https://github.com/user-attachments/assets/f63594a1-eeeb-4a2d-867c-eb8312828d31" />

Once the INFO lines appear, then push to Git with this command: _git push_ : 

<img width="945" height="124" alt="image" src="https://github.com/user-attachments/assets/f353ff6c-55c1-48d8-9bf6-0fdcbce7b138" />

I tested the scanner with this command: 

_echo "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" > test/fixtures/quick.env
git add test/fixtures/quick.env
git commit -m "test"_

And it gave me the CRITICAL alert and no commit (the correct response): 

<img width="1839" height="255" alt="image" src="https://github.com/user-attachments/assets/22172bf0-e664-4c9f-96f9-da48923fffbb" />

Then clean up the test file with this command: _git restore --staged test/fixtures/quick.env
rm test/fixtures/quick.env_

**Step 4: Deploy it as a CI/CD stage**

Currently, the pre-commit hook from Step 3 runs only on your device, and anyone can skip it with git commit --no-verify. That makes it a convenience for developers, not an enforced control. Step 4 runs the same scanner on GitHub’s servers, every time anyone pushes code. It’s the gate nobody can skip:

<img width="1484" height="450" alt="image" src="https://github.com/user-attachments/assets/b4dbb3bb-4abb-4f09-9eef-76c3c8b62335" />

The workflow has two jobs: nhi-scan and a simulated deploy. Deploy is set to run only if the scan passes. That’s how the lab’s requirement to “halt deployment” is met: if a secret is found, the deploy job never starts. Together with Step 3, this gives you defense in depth.

This is how I deployed the CI/CD. 

I). Create the workflow file with this bash command on the ~/nhi-secret-scanner terminal: 

mkdir -p .github/workflows
touch .github/workflows/nhi-scan.yml
code .github/workflows/nhi-scan.yml

Note the workflow file must be saved in the .github/workflows/ location. Use this command to confirm the location is current: _ls .github/workflows_

<img width="869" height="143" alt="image" src="https://github.com/user-attachments/assets/c38a24d2-6796-46c1-aa4f-3183cce19629" />

As shown in the image, the correct location is "nhi-scan.yml"

II). Copy and paste the script below in the nhi-scan-yml folder: 

name: NHI Secret Scan
on:
  push:
  pull_request:

jobs:
  nhi-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Scan for NHI secrets
        run: python3 scanner/scan_nhis.py --mode full

  deploy:
    needs: nhi-scan
    runs-on: ubuntu-latest
    steps:
      - run: echo "Deploying... (only reached if the NHI scan passed)"

III). Commit & push
Use this command to push the script live: 

_git add .github/workflows/nhi-scan.yml
git commit -m "Add NHI scan CI stage"
git push_

The hook should run first and should print [INFO] No NHI secrets found, as shown below: 

<img width="988" height="539" alt="image" src="https://github.com/user-attachments/assets/5058de1e-8a25-40c4-a38b-25c6c4b851c7" />

**IV). Watch it run on GitHub**
Open your repo on github.com and click the Actions tab. A run called “Add NHI scan CI stage” should appear. Click it, and you should see:

nhi-scan with a green ✅. Click it to see the same [INFO] log lines from the runner.
deploy with a green ✅, showing the “Deploying…” message.

<img width="2300" height="1062" alt="image" src="https://github.com/user-attachments/assets/fe5cf35a-f766-4cf5-8be5-9cb0daf93172" />

**Step 5: Save the mock config**
Paste this whole block into the terminal of the nhi-secret-scanner folder:

mkdir -p test/fixtures
cat > test/fixtures/mock_config.env <<'EOF'
# FAKE credentials for scanner testing only. None of these are real.
STRIPE_SECRET_KEY=sk_live_51FAKEt3stK3yN0tR3al0000000000
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
EOF

Use this command to check the file saved properly: _cat test/fixtures/mock_config.env_

If correct, it should print back the file like this: 
<img width="1197" height="225" alt="image" src="https://github.com/user-attachments/assets/493edb10-6118-4047-b4df-6d9da489edb5" />

**Step 6: Test the local gate**
Test the local gate with this command: 

_git add test/fixtures/mock_config.env
git commit -m "Add config"_

You'll see this result, which shows the device scanner is working: 

<img width="1800" height="320" alt="image" src="https://github.com/user-attachments/assets/01417f29-e9f1-41ec-a541-7e43fa025425" />

The run git log to confirm no new commit was created: 

<img width="1164" height="521" alt="image" src="https://github.com/user-attachments/assets/01a67131-f8c7-4eb6-abd8-1774b3441483" />

**Step 7: Test the pipeline gate (simulate a developer bypassing the hook)**
I). 1. Check the mock file is still staged. In Step 6, the hook blocked the commit, but the file stayed staged. Confirm with: git status. You should see test/fixtures/mock_config.env under “Changes to be committed”: 

<img width="865" height="224" alt="image" src="https://github.com/user-attachments/assets/4fbaf6d5-55f5-483f-a358-0bf97b2f06ab" />

If it’s listed as untracked or not staged instead, run: git add test/fixtures/mock_config.env

II). Then run the command: 

git checkout -b test/secret-leak
git commit --no-verify -m "Simulated bypass"
git push -u origin test/secret-leak

Note: 

a). The first line creates a separate test branch, so main stays clean.

b). The second line commits without running the hook, simulating a developer who bypasses it. You should see a [test/secret-leak …] line and no [INFO] or CRITICAL output.

c). The third line pushes the branch to GitHub, which triggers the workflow.

This is the result: 

<img width="1303" height="705" alt="image" src="https://github.com/user-attachments/assets/a0743cf0-c9b9-402a-865b-1890ce7571ea" />

III). Test the reuslt in your github repo. 
The terminal part ends at the push. To see the result, open your repo on github.com → Actions tab → click the “Simulated bypass” run. You should see:

a)> nhi-scan ❌ failed. Click it to see the CRITICAL log lines: 

<img width="2568" height="848" alt="image" src="https://github.com/user-attachments/assets/1afd0b95-cf68-4b69-a7b5-f50add1feb5d" />

b) deploy ⊘ skipped: 

<img width="2593" height="636" alt="image" src="https://github.com/user-attachments/assets/03493140-0356-47bb-bb71-c2b54ebfbd74" />

**Step 8: Make the gate mandatory**

Go to Repo > Settings > Branches > Add branch protection rule for main, enable Require status checks to pass > click on Add checks, and add nhi-scan. Without this rule, a failed check is only a warning and someone could still merge. With it, nothing that fails the scan can reach main: 

<img width="2487" height="1581" alt="image" src="https://github.com/user-attachments/assets/1c58b42e-4656-4f42-ad44-f814a7841964" />

