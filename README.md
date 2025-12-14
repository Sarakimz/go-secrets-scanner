# go-secrets-scanner

`go-secrets-scanner` is a simple **secret & hash scanner** written in Go.

It walks through files in a directory and tries to detect:

- hardcoded secrets (API keys, tokens, passwords)
- high-entropy strings that look like random tokens
- hashes (MD5 / SHA-1 / SHA-256 / SHA-512)  
  → with basic hints about how “crackable” they are in practice.

It can output a human-readable report or JSON, so you can plug it into other tools or CI pipelines.

---

## Features

- 🔍 **Secret detection (regex-based)**  
  Detects things like:
  - AWS Access Key IDs (`AKIA...`)
  - GitHub Personal Access Tokens (`ghp_...`)
  - generic `password=...`, `secret=...`, `token=...`, `apikey=...` patterns

- 📈 **High-entropy string detection**  
  - Uses Shannon entropy to flag suspicious random-looking strings
  - Useful for catching tokens, JWTs or unknown secrets that don’t match any regex
  - Entropy threshold is configurable

- 🔐 **Hash detection & classification**  
  - Looks for hex strings that match typical hash lengths:
    - 32 hex → `MD5/NTLM (32 hex)` (weak, fast to crack)
    - 40 hex → `SHA-1 (40 hex)` (weak, broken / collision-prone)
    - 64 hex → `SHA-256 (64 hex)` (stronger, but crackable offline if unsalted & weak password)
    - 128 hex → `SHA-512 (128 hex)` (stronger, depends on salt/KDF/password)
  - Each hash finding comes with:
    - `hash_algo` (best-effort classification)
    - `hash_crackability` (short text hint)

- 📂 **Repo / project scanning**  
  - Recursively scans a directory
  - Skips noisy directories:
    - `.git`
    - `node_modules`
    - `venv`, `.venv`
  - Ignores files larger than a configurable size (default: `1MB`)

- 📤 **Outputs**  
  - Text (human-readable): one line per finding
  - JSON (`--json`): can be consumed by other tools or CI

---

## Installation

Clone the repo and build the binary:

```bash
git clone https://github.com/TFLR/go-secrets-scanner.git
cd go-secrets-scanner

go build -o go-secrets-scanner
