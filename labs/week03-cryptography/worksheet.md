# Worksheet 3 — Cryptography Used Correctly (and Misused) (3 hrs)

> **Course:** Software Security (KOSEN69) · **Week 3**
> **Aligned to:** OWASP 2025 A04 Cryptographic Failures · CWE-327, CWE-916, CWE-330, CWE-798
> **Signature game:** "Capture the Hash" (recover plaintext from weak hashes)

> **Ethics note:** Crack only the hashes provided in `hashes.txt` on your own machine. Password-cracking against accounts or systems you don't own is illegal. Wordlists and recovered values stay inside the lab VM.

## Part 1 — Student Information
| Name | Student ID | Date | Group |
|---|---|---|---|
|Sai Seng  Main|6631503085|2026-08-26| |

## Part 2 — Lecture Questions
Answer in your own words (2–4 sentences each).
1. Distinguish hashing, encryption, and encoding — and give one job each is the wrong tool for.
   
   **Answer:** Hashing is a one-way transformation used to compare data, encryption is reversible with a key and is used to protect confidential data, and encoding changes data into a transport-friendly representation. Hashing is the wrong tool when the original data must be recovered, encryption is the wrong tool for storing passwords, and encoding is the wrong tool for keeping data secret.

2. Why is a fast hash like MD5/SHA-1 a bad choice for storing passwords, and what should be used instead?
   
   **Answer:** MD5 and SHA-1 are designed to be fast, so attackers can test huge numbers of password guesses using GPUs or specialized cracking hardware. Passwords should instead be stored with a slow, memory-hard password KDF such as Argon2id, with appropriate cost settings and a unique salt for every password.

3. What is a salt, what attack does it defeat, and why must it be unique per password?
   
   **Answer:** A salt is a random value stored with a password hash and combined with the password before hashing. It defeats precomputed rainbow-table attacks and prevents users with the same password from having the same stored hash. Each password needs a different salt so that one precomputation or comparison cannot be reused across accounts.

4. Why does AES-ECB leak structure, and what does an authenticated mode like AES-GCM add?
   
   **Answer:** AES-ECB encrypts each plaintext block independently, so equal plaintext blocks produce equal ciphertext blocks and reveal repeated structure and patterns. AES-GCM uses a nonce-based mode that hides this repetition and also provides an authentication tag, allowing the receiver to detect tampering or an incorrect key during decryption.

5. What's the difference between `random` and a CSPRNG (e.g. `secrets`), and where does it matter?
   
   **Answer:** Python's `random` module is intended for simulations and produces predictable pseudorandom output when its state can be inferred; it is not suitable for security decisions. A CSPRNG such as `secrets` gathers unpredictable operating-system entropy and should be used for reset tokens, session identifiers, password-reset links, keys, nonces, and other attacker-visible security values.

![Four paired rows showing that password storage, cipher mode, randomness and key source are four separate crypto decisions: MD5 (CWE-916/327) becomes argon2id, AES-ECB with a hardcoded key (CWE-327) becomes AES-GCM with a nonce and tag, a 6-digit random.choice token (CWE-330) becomes secrets.token_urlsafe, and HARDCODED_KEY (CWE-798) becomes a key injected from the environment — so naming AES answers none of the four questions.](img/crypto-misuse.svg)

## Part 3 — Hands-on Lab (180 min)
**Learning goals:** exploit four crypto misuses, then remediate them with a vetted KDF, authenticated encryption, and a CSPRNG.
**Prerequisites:** Docker (or local Python 3.12); `hashcat` or `john`; the `rockyou.txt` wordlist.

**Environment setup**
```bash
cd labs/week03-cryptography
docker compose up           # installs pycryptodome + argon2-cffi, runs both scripts
# or locally:
pip install pycryptodome argon2-cffi
python vulnerable_crypto.py # see the md5 hash, repeated ECB blocks, 6-digit token
```
Targets: `vulnerable_crypto.py` (the misuses), `hashes.txt` (four unsalted MD5s), and `solution_skeleton.py` (the fix).

**What to submit per task:** the command/payload run + a screenshot of the result + a 2–3 sentence mitigation.

**Task 0 — Onboarding (5 min)** · *Goal:* see the misuse output. *Steps:* run `python vulnerable_crypto.py`; note the md5 digest, the identical ECB ciphertext blocks, and the short token. *Deliverable:* screenshot of the program output.

**Answer & Execution Note:**
Ran `python3 vulnerable_crypto.py`. Output observed:
- `md5`: `482c811da5d5b4bc6d497ffa98491e38`
- `ecb`: `3bfd04cc0d7ed55358e2cbe19de213833bfd04cc0d7ed55358e2cbe19de21383377222e061a924c591cd9c27ea163ed4`
- `token`: `447934` (6-digit random string)

![Task 0 Output](Screenshot%201.png)

---

**Task 1 — Capture the Hash (30 min)** · *Goal:* recover the passwords. *Steps:* strip the comment lines from `hashes.txt`, then run `hashcat -m 0 hashes.txt rockyou.txt` (or the `john --format=raw-md5` equivalent); recover all four plaintexts. *Deliverable:* screenshot of the cracked results (mask any real-looking value). Note in one line why unsalted MD5 fell so fast (CWE-916/327).

**Answer & Results:**
Recovered plaintexts from `hashes.txt`:
- `482c811da5d5b4bc6d497ffa98491e38` -> `password123`
- `e10adc3949ba59abbe56e057f20f883e` -> `123456`
- `25f9e794323b453885f5181f1b624d0b` -> `123456789`
- `5f4dcc3b5aa765d61d8327deb882cf99` -> `password`

**Why unsalted MD5 fell so fast (CWE-916/CWE-327):** Unsalted MD5 has zero computational cost (>10 billion attempts/sec on GPUs) and lacks salts, allowing precomputed lookup tables and rainbow table attacks to instantly invert hashes without unique per-password computation.

![Task 1 Cracked Hashes Output](Screenshot%202.png)

---

```sim
aes-modes
```

**Task 2 — ECB structure leak (20 min)** · *Goal:* prove ECB leaks. *Steps:* call `encrypt_ecb(b"A"*16 + b"A"*16)` from `vulnerable_crypto.py` and show the two 16-byte ciphertext blocks are identical; explain how this leaks plaintext structure (CWE-327). *Deliverable:* hex output highlighting the repeated block.

**Answer & Demonstration:**
- Output hex of `encrypt_ecb(b"A"*16 + b"A"*16)`:
  `3bfd04cc0d7ed55358e2cbe19de21383` | `3bfd04cc0d7ed55358e2cbe19de21383` | `377222e061a924c591cd9c27ea163ed4`
- **Hex highlighting:** Block 1 (`3bfd04cc0d7ed55358e2cbe19de21383`) is byte-for-byte identical to Block 2 (`3bfd04cc0d7ed55358e2cbe19de21383`).
- **Explanation (CWE-327):** AES-ECB encrypts each 16-byte plaintext block independently without an Initialization Vector (IV) or chaining mode. Equal input blocks deterministically map to equal output blocks, preserving structural patterns of the underlying plaintext.

---

**Task 3 — Predictable token (15 min)** · *Goal:* show the reset token is guessable. *Steps:* call `reset_token()` repeatedly; argue why a 6-digit `random` token (10^6 space, non-CSPRNG) is brute-forceable (CWE-330). *Deliverable:* sample tokens + a one-line attack estimate.

**Answer & Analysis:**
- Sample generated tokens: `905436`, `184029`, `730192`, `451820`
- **Attack Estimate:** A 6-digit numeric space has only 1,000,000 possibilities (brute-forceable over HTTP in under 2 minutes or locally in under 1 second), and Python's `random` module (Mersenne Twister) allows full internal state reconstruction after observing 624 outputs (CWE-330).

---

**Task 4 — Hardcoded key (5 min)** · *Goal:* identify the key-management flaw. *Steps:* find `HARDCODED_KEY` in `vulnerable_crypto.py`; explain why shipping a key in source is CWE-798. *Deliverable:* the line + a 2-sentence mitigation.

**Answer:**
- **Flawed line in `vulnerable_crypto.py` (Line 12):**
  `HARDCODED_KEY = b"0123456789abcdef"`
- **Explanation & Mitigation (CWE-798):** Hardcoding cryptographic keys in source code exposes secret credentials to anyone who has access to the codebase, git history, or compiled binaries. Cryptographic keys should be dynamically injected into the runtime environment via environment variables (e.g., `os.environ["ENC_KEY_HEX"]`) or fetched securely from a dedicated secrets manager like AWS Secrets Manager or HashiCorp Vault.

---

**Task 5 — Crack the project target's hashes (25 min)** · *Goal:* apply cracking to your term project. *Steps:* **NoteVault** stores unsalted MD5 password hashes; obtain them (via the app's `/admin` once you can reach it, or from its `seed()`), and crack them with `hashcat -m 0`. *Deliverable:* the recovered password(s) + note the CWE — record this finding for your project report (`project/REPORT-TEMPLATE.md` in the repo root).

**Answer:**
- **Source:** Seed function in `project/starter-app/app.py` lines 68–69.
- **Recovered Hashes & Plaintexts:**
  - Username `alice`: `hashlib.md5(b"alicepw").hexdigest()` -> Plaintext: `alicepw`
  - Username `admin`: `hashlib.md5(b"admin123").hexdigest()` -> Plaintext: `admin123`
- **Associated CWE:** **CWE-916** (Use of Password Hash With Insufficient Computational Effort) & **CWE-327** (Use of Broken Cryptographic Algorithm). Recorded in `project/REPORT-TEMPLATE.md`.

---

**Task 6 — Password storage migration (25 min)** · *Goal:* fix it the way real apps do. *Steps:* write `store_password`/`verify_password` with **argon2id**, and a **rehash-on-login** path that upgrades a legacy MD5 record to argon2id the next time the user logs in. *Deliverable:* the code + a short note on why migration matters.

**Answer & Code Implementation:**
```python
from argon2 import PasswordHasher
import hashlib

ph = PasswordHasher()

def store_password(pw: str) -> str:
    return ph.hash(pw)

def verify_password(stored_hash: str, pw: str) -> bool:
    try:
        return ph.verify(stored_hash, pw)
    except Exception:
        return False

def authenticate_and_migrate(username: str, pw_input: str, db_conn):
    user = db_conn.execute("SELECT password FROM users WHERE username = ?", (username,)).fetchone()
    if not user:
        return False
    stored_hash = user["password"]

    # 1. Try modern Argon2id verification
    if stored_hash.startswith("$argon2id$"):
        if verify_password(stored_hash, pw_input):
            if ph.check_needs_rehash(stored_hash):
                db_conn.execute("UPDATE users SET password = ? WHERE username = ?", (ph.hash(pw_input), username))
                db_conn.commit()
            return True
        return False

    # 2. Legacy MD5 fallback and automatic migration
    legacy_md5 = hashlib.md5(pw_input.encode()).hexdigest()
    if stored_hash == legacy_md5:
        new_argon2_hash = ph.hash(pw_input)
        db_conn.execute("UPDATE users SET password = ? WHERE username = ?", (new_argon2_hash, username))
        db_conn.commit()
        return True

    return False
```
**Why migration matters:** Cryptographic hashes are one-way functions, making it impossible to convert stored MD5 hashes to Argon2id offline without user passwords. Rehash-on-login allows applications to upgrade legacy hashes to salt-protected, memory-hard Argon2id hashes automatically during normal user log-ins without forcing password resets.

---

**Task 7 — Authenticated encryption round-trip (20 min)** · *Goal:* use AEAD correctly. *Steps:* encrypt+decrypt a message with **AES-GCM** using a random 12-byte nonce and a key from an env var; then flip one ciphertext byte and show decryption **fails** (tag check). *Deliverable:* the round-trip output + the tampered-fails proof.

**Answer & Code Verification:**
```python
import os
from Crypto.Cipher import AES

def encrypt_gcm(data: bytes, key: bytes):
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(data)
    return nonce, ct, tag

def decrypt_gcm(nonce: bytes, ct: bytes, tag: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

# Verification execution:
key = bytes.fromhex(os.environ.get("ENC_KEY_HEX", os.urandom(32).hex()))
nonce, ct, tag = encrypt_gcm(b"Secret Confidential Message", key)

# 1. Successful Round-trip:
plain = decrypt_gcm(nonce, ct, tag, key)
print("Decrypted successfully:", plain.decode())

# 2. Tamper Test: flip first byte of ciphertext
tampered_ct = bytearray(ct)
tampered_ct[0] ^= 0xFF

try:
    decrypt_gcm(nonce, bytes(tampered_ct), tag, key)
except ValueError as e:
    print("Tamper check PASSED! Decryption rejected tampered ciphertext with error:", e)
```
**Output:**
```text
Decrypted successfully: Secret Confidential Message
Tamper check PASSED! Decryption rejected tampered ciphertext with error: MAC check failed
```

---

**Task 8 — TLS in practice (15 min)** · *Goal:* read a real cert. *Steps:* run `openssl s_client -connect example.com:443 </dev/null 2>/dev/null | tee /tmp/tls.txt | openssl x509 -noout -issuer -subject -dates` for the cert summary, then `grep -E 'Protocol|New,' /tmp/tls.txt` for the negotiated TLS version (the version line is printed by `s_client`, not by `x509`, so the plain pipe would discard it); identify issuer, validity, and that TLS version. *Deliverable:* the cert summary + one line on what TLS protects that hashing/at-rest encryption does not.

**Answer & Output:**
```text
issuer=C=US, O=SSL Corporation, CN=Cloudflare TLS Issuing ECC CA 3
subject=CN=example.com
notBefore=Jul 29 22:10:08 2026 GMT
notAfter=Oct 27 22:17:21 2026 GMT
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol: TLSv1.3
```
- **Issuer:** Cloudflare TLS Issuing ECC CA 3 (SSL Corporation)
- **Subject:** `CN=example.com`
- **Validity:** July 29, 2026 to October 27, 2026 GMT
- **TLS Version:** `TLSv1.3`
- **What TLS protects:** TLS provides confidentiality, integrity, and server authentication **in transit** over network connections to prevent active Man-in-the-Middle (MITM) attacks and passive network sniffing, whereas password hashing and encryption at rest protect data **at rest** stored on disks or in databases.

---

**Task 9 — Defend / fix it (20 min)** · *Goal:* remediate using `solution_skeleton.py`. *Steps:* run `python solution_skeleton.py`; confirm `store_password`/`verify_password` use argon2id (auto-salted), `encrypt_gcm` uses a random 12-byte nonce + auth tag with a key from `ENC_KEY_HEX` env, and `reset_token` uses `secrets`. Map each fix to the CWE it closes. *Deliverable:* before/after table (misuse → fix → CWE closed) + screenshot of the fixed script running.

**Answer & Before/After Mapping Table:**

| Vulnerable Code Misuse | Remediation / Fix Applied | CWE Closed |
|---|---|---|
| Unsalted MD5 password hashing (`hashlib.md5`) | Argon2id memory-hard KDF (`argon2.PasswordHasher`) with unique auto-generated salts | **CWE-916** (Weak Hash) & **CWE-327** (Broken Crypto) |
| AES-ECB deterministic mode | AES-GCM authenticated encryption (`AES.MODE_GCM`) with random 12-byte nonce & auth tag | **CWE-327** (Broken Cipher Mode) |
| 6-digit `random.choice` numeric token | `secrets.token_urlsafe(16)` drawing from cryptographically secure OS entropy (CSPRNG) | **CWE-330** (Insufficient Randomness) |
| `HARDCODED_KEY` constant in source code | Dynamic key ingestion via `ENC_KEY_HEX` environment variable or CSPRNG (`os.urandom(32)`) | **CWE-798** (Hardcoded Credentials) |

![Task 9 Fixed Solution Output](Screenshot%203.png)

---

## Part 4 — Reflection
1. Map each of the four misuses to its CWE and to OWASP A04, in one line each.
   - **MD5 Password Hashing:** CWE-916 (Weak Password Hashing) & CWE-327 $\rightarrow$ OWASP A04:2025 Cryptographic Failures.
   - **AES-ECB Cipher Mode:** CWE-327 (Use of Broken Cryptographic Algorithm/Mode) $\rightarrow$ OWASP A04:2025 Cryptographic Failures.
   - **Predictable `random` Token:** CWE-330 (Use of Insufficiently Random Values) $\rightarrow$ OWASP A04:2025 Cryptographic Failures.
   - **Hardcoded Secret Key:** CWE-798 (Use of Hard-coded Credentials) $\rightarrow$ OWASP A04:2025 Cryptographic Failures.

2. Name a real-world breach caused by weak password hashing or hardcoded keys, and which fix here would have prevented it.
   - **Breach:** The 2012 LinkedIn data breach exposed 6.5 million user passwords stored as unsalted SHA-1 hashes. Attackers rapidly cracked over 90% of the hashes offline using rainbow tables and GPU wordlist attacks.
   - **Preventative Fix:** Upgrading password storage to **Argon2id with unique per-password salts** (Task 6) would have rendered offline dictionary and precomputed rainbow table attacks computationally infeasible.

3. Across all four fixes, which closes the largest real-world risk, and why?
   - **Answer:** Replacing weak password hashing with **Argon2id** closes the largest real-world risk. Database leaks and SQL injections remain among the most prevalent web application vulnerabilities; when a database leak occurs, Argon2id protects all user credentials from credential stuffing and offline brute-force cracking.

## Grading rubric (100)
| Criterion | Points |
|---|---|
| Lecture questions (Part 2) | 20 |
| Exploitation + evidence (cracked hashes + ECB/token/key proof + screenshots) | 40 |
| Defense (working `solution_skeleton.py` + before/after mapping) | 25 |
| Reflection (CWE/OWASP mapping + breach + biggest-risk fix) | 15 |

---

## Evidence & Integrity (required)

- **Identity proof:** every screenshot/diagram must show a terminal running `printf '%s | %s | ' "$(whoami)" '<YOUR-STUDENT-ID>'; date '+%F %T %Z'` **in the
  same image as the evidence**. When the evidence is a browser page, a DevTools panel or a
  rendered response, put that terminal **beside the browser and capture the whole screen** — a
  cropped window carries nothing that identifies you, and the lab's own output is
  byte-identical for the whole cohort *by design*, so the stamp is the only thing that makes
  the shot yours. Generic or borrowed evidence is not accepted.
- **Personalized flag (if this lab issues one):** FLAG{ecb_f12314a8}
- **Commit Link:** https://github.com/SAISENGMAIN6631503085/software-security/commit/d252e3bd4d76e5cbbf18d2db7d504232bb445cb0
  *Flags are unique per student — submitting another student's flag is a violation. How to submit: **learn.zcr.ai/submit** (full guide: `SUBMISSION.md` in the repo root).*
- **Explain in your own words** *(graded on your reasoning, not copied text):*
  1. What did you do, and **why did the vulnerability work**?
     **Answer:** I exploited four cryptographic flaws: cracking unsalted MD5 hashes, proving AES-ECB leaks block patterns, predicting a 6-digit `random` token, and identifying a hardcoded AES key. The vulnerabilities worked because MD5 lacks salt and work-factor, ECB encrypts identical blocks identically without IVs, Python's `random` is a deterministic non-CSPRNG with a small search space (10^6), and hardcoded source keys are easily accessible.
  2. **Why does your fix actually stop it** — and what could still break it?
     **Answer:** Argon2id stops password cracking by enforcing slow memory hardness and auto-salting; AES-GCM hides block patterns with nonces and prevents tampering via auth tags; `secrets` provides unpredictable CSPRNG entropy; and environment keys remove secrets from source code. The security could still break if nonces are reused in AES-GCM, Argon2id cost parameters are configured too low, or environment variables are leaked via debug logs.

---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.
   > **AI Output:** "To encrypt data securely in Python, use AES in ECB mode like this:
   > ```python
   > from Crypto.Cipher import AES
   > key = b'secretkey1234567'
   > cipher = AES.new(key, AES.MODE_ECB)
   > ciphertext = cipher.encrypt(data)
   > ```"

2. **Find what's wrong or risky** in it:
   > **Critique:** The AI's solution contains three severe cryptographic flaws:
   > - **Line 2 (`key = b'secretkey1234567'`):** Uses a hardcoded key in source code (CWE-798) and a weak 16-byte ASCII string without CSPRNG key generation.
   > - **Line 3 (`AES.MODE_ECB`):** Uses ECB mode (CWE-327) which encrypts identical plaintext blocks to identical ciphertext blocks, leaking data structure.
   > - **Missing Authentication:** Does not provide integrity verification or an authentication tag (AEAD), leaving ciphertext vulnerable to bit-flipping attacks.

3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.
   > **Correct Version:**
   > ```python
   > import os
   > from Crypto.Cipher import AES
   > key = bytes.fromhex(os.environ["ENC_KEY_HEX"])
   > nonce = os.urandom(12)
   > cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
   > ciphertext, tag = cipher.encrypt_and_digest(data)
   > ```
   > **Explanation:** The AI output was insufficient because it recommended AES-ECB, an unauthenticated, non-randomized cipher mode, and hardcoded the key. The corrected version uses AES-GCM with a random 12-byte nonce, computes an authentication tag to prevent tampering, and retrieves the key securely from the environment.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).**
In this week's lab, the vulnerable application relies on legacy cryptographic practices including unsalted MD5 password hashes, ECB cipher mode, non-CSPRNG tokens, and hardcoded keys. It is exploitable because MD5 and non-CSPRNG tokens lack computational complexity and entropy, allowing attackers to brute-force or look up secrets, while ECB mode fails to randomize block outputs, exposing underlying data patterns.

**B. Prompt Problem.**
- **Final Prompt:**  
  *"Refactor the following Python cryptographic functions to follow OWASP security best practices: (1) Replace MD5 password hashing with Argon2id using `argon2-cffi` and automatic salting, (2) Replace AES-ECB with AES-256-GCM using a cryptographically secure 12-byte random nonce and authentication tag, loading the key from an environment variable `ENC_KEY_HEX`, and (3) Replace `random.choice` token generation with `secrets.token_urlsafe(16)`. Ensure code handles verification and tampering detection."*

- **Verified Result:**  
  Ran `solution_skeleton.py` built with this prompt. MD5 cracking failed (Argon2id produces unique salted hashes), ECB block repetition disappeared, ciphertext tampering threw `ValueError: MAC check failed`, and reset tokens produced high-entropy CSPRNG strings.

