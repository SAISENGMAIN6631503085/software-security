# Worksheet 4 — Injection & Input Handling (3 hrs)

> **Course:** Software Security (KOSEN69) · **Week 4**
> **Aligned:** OWASP 2025 **A05 Injection** · **CWE-89** (SQLi), **CWE-78** (OS command injection), **CWE-434** (unrestricted upload)
> **Signature game:** 🐉 **SQLi Boss Fight** — each successful injection lands a "hit" on the boss; the boss falls when you dump every credential and land an RCE.

> ⚠️ **Ethics note:** All payloads here are for the provided sandbox (`vulnerable_app.py`) and your own DVWA/Juice Shop containers **only**. Never test systems you do not own or have written permission to test. Unauthorized injection is a crime under most computer-misuse laws.

## Part 1 — Student Information

| Name | Student ID | Date | Group | AI Tools Used |
|------|-----------|------|-------|---------------|
| Sai Seng Main | 6631503085 | 2026-09-14 | | Claude / Antigravity (conceptual verification & audit) |

## Part 2 — Lecture Questions

Answer in 2–4 sentences each.

1. Why does a **parameterized query** (`execute(sql, (params,))`) defeat SQL injection, while string formatting (`"... '%s'" % user`) does not? Reference how the database treats data vs. code.

   **Answer:** In a parameterized query, the SQL query structure is pre-compiled by the database engine into an execution tree before untrusted parameters are bound. The database treats the parameter strictly as literal data (values), so input characters like single quotes (`'`) or comments (`--`) cannot alter the SQL syntax or command structure. In contrast, string formatting concatenates raw user input directly into the query string before compilation, allowing the input to become executable SQL code and subvert query logic.

2. In the `/ping` endpoint, `subprocess.run("ping -c 1 " + host, shell=True)` is vulnerable. Explain how `shell=True` turns user input into **CWE-78**, and how an argument array (`["ping","-c","1",host]`) removes the shell.

   **Answer:** When `shell=True` is enabled, Python passes the entire concatenated command string to the system shell (`/bin/sh -c`), which parses shell metacharacters such as `;`, `&`, `|`, and `$()`, enabling an attacker to chain and execute arbitrary OS commands. Passing an argument vector/array (`["ping", "-c", "1", host]`) with `shell=False` invokes the `/bin/ping` binary directly via the `execve()` system call without launching a command shell. The entire value of `host` is passed as a single argv element, meaning shell metacharacters are treated as literal characters of the hostname rather than command separators.

3. Distinguish **input validation** (allow-list) from **output handling**. Why is validation alone insufficient defense for SQLi?

   **Answer:** Input validation inspects incoming untrusted data at ingestion against an expected format or allow-list (e.g., verifying an alphanumeric string or integer), whereas output handling (encoding/parameterization) neutralizes special characters at the sink where data enters an interpreter. Validation alone is insufficient for SQLi because valid business inputs frequently require legitimate characters that are also SQL delimiters (such as apostrophes in names like `O'Connor` or quotes in text). Furthermore, complex validation rules often suffer from bypasses, whereas parameterized queries ensure safety at the database engine regardless of the input content.

4. The `/upload` route saves any filename to disk (**CWE-434**). What two properties must a directory and a filename have for an upload to become remote code execution, and which does `solution_app.py` remove?

   **Answer:** For an arbitrary file upload to become Remote Code Execution (RCE), the upload directory must be accessible/routable by an execution engine or web server (or path-traversable to an executable location), and the uploaded file must retain an executable extension (e.g., `.py`, `.php`, `.sh`) or executable permissions that the server executes upon request. `solution_app.py` removes the executable extension property by strictly enforcing an allow-list (`ALLOWED_EXT = {".txt", ".png", ".jpg", ".pdf"}`) and sanitizing filenames via `secure_filename()` to eliminate path traversal.

5. What is a **UNION-based** SQLi, and why must the injected `SELECT` return the same number of columns as the original query? Relate to `/search?q=' UNION SELECT username,password FROM users--`.

   **Answer:** A UNION-based SQL injection uses the SQL `UNION` operator to combine the result set of the original application query with the result set of an attacker-crafted `SELECT` statement, returning data from other tables in the same HTTP response. The SQL standard requires all queries combined with `UNION` to have the exact same number of columns and compatible data types so that the database engine can construct a single unified tabular result. In `/search?q=' UNION SELECT username,password FROM users--`, the original query selected two columns (`id, username`), which matches the two columns requested in the injected statement (`username, password`).

![One untrusted request value in the Week 4 lab fans out to three interpreters — the SQL engine (CWE-89), the OS shell (CWE-78) and the filesystem (CWE-434) — with the specific control that stops it at each sink: a parameterised query, an argument vector without a shell, and an extension allow-list.](img/injection-sinks.svg)

## Part 3 — Hands-on Lab (150 min)

**Learning goals:** extract data via SQLi, achieve OS command injection, exploit an unrestricted upload, then prove each fix in `solution_app.py` blocks the payload.

**Prerequisites:** Docker + Docker Compose, `curl`, a browser. Working dir: `labs/week04-injection/`.

### Environment setup

```bash
cd labs/week04-injection
docker compose up            # builds python:3.12-slim, installs flask, runs vulnerable_app.py
# vulnerable app -> http://localhost:8080   (service name: injection-lab, port 8080)
```
Optional secondary targets:
```bash
docker run --rm -it -p 80:80 vulnerables/web-dvwa        # DVWA  -> http://localhost
docker run --rm -p 3000:3000 bkimminich/juice-shop       # Juice Shop -> http://localhost:3000
```

**What to submit per task:** the exact **payload/command**, a **screenshot** of the response proving success, and a **2–3 sentence mitigation** in your own words.

---

**Task 0 — Onboarding (5 min).** Browse to `http://localhost:8080/login?user=alice&pw=alicepw` and confirm `Welcome alice`. Note the seeded users (`alice`, `bob`). Screenshot the working app. *Deliverable: screenshot.*

- **URL:** `http://localhost:8080/login?user=alice&pw=alicepw`
- **Output:** `Welcome alice`
- **Screenshot:**

  ![Task 0 Output](img/Screenshot%200.png)

**Before you start — see why concatenation is the flaw** 🔬 Type any input and watch which characters the database will parse as *SQL* rather than as a name. The point is not the payload; it is that with concatenation the input becomes syntax, and with a parameterised query it structurally cannot. You will be asked to state that difference in your own words in Task 5.

```sim
sqli-parse
```

**Task 1 — Auth bypass via SQLi (25 min) 🐉 Hit #1.**
- *Goal:* log in as `alice` with **no valid password**.
- *Steps:* hit `/login?user=alice'--&pw=x`, then `/login?user=x' OR '1'='1'--&pw=x` (the trailing `--` is required: without it, SQL binds `AND` tighter than `OR`, so `... OR '1'='1' AND password='x'` matches no row). Observe the comment in the query at lines 61–63 of `vulnerable_app.py`.
- *Deliverable:* both URLs + screenshot of `Welcome alice` + explain why `--` and `OR '1'='1` work.

- **URLs / Payloads:**
  1. Comment bypass: `http://localhost:8080/login?user=alice'--&pw=x`
  2. Tautology bypass: `http://localhost:8080/login?user=x' OR '1'='1'--&pw=x`
- **Why `--` and `OR '1'='1'` work:** In the vulnerable code, the query is built using string formatting `"... WHERE username = '%s' AND password = '%s'" % (user, pw)`. In the first payload, the single quote closes the username string literal and `--` comments out the password condition entirely, executing `WHERE username = 'alice'`. In the second payload, `'1'='1'` creates a condition that always evaluates to TRUE; because `AND` has higher operator precedence than `OR`, omitting `--` would cause `('1'='1' AND password='x')` to evaluate first and fail, but adding `--` comments out the `AND password='x'` clause completely, resulting in `WHERE username = 'x' OR '1'='1'`, which returns the first record in the database (`alice`).
- **Mitigation (2–3 sentences):** Use parameterized queries with bind variables (`WHERE username = ? AND password = ?`). This ensures that user input is transmitted to the database engine strictly as literal data rather than executable SQL syntax. Any quotes or comment dashes within the input will simply be matched literally against stored values.
- **Screenshot:**

  ![Task 1 Output](img/Screenshot%201.png)

**Task 2 — Credential dump via UNION SQLi (30 min) 🐉 Hit #2.**
- *Goal:* exfiltrate every username **and password** from the `users` table.
- *Steps:* request `/search?q=' UNION SELECT username,password FROM users--`. Confirm `alice:alicepw` and `bob:bobpw` appear.
- *Deliverable:* payload + screenshot of dumped credentials + note on why column count must match.

- **Payload:** `http://localhost:8080/search?q=' UNION SELECT username,password FROM users--`
- **Output:**
  ```text
  alice:alicepw
  bob:bobpw
  admin:FLAG{sqli_demo}
  ```
- **Why column count must match:** The `UNION` operator joins rows from two queries into a single unified result table. Relational database standards mandate that each query in a `UNION` statement must return the exact same number of columns with compatible data types. Because the original search query selects 2 columns (`SELECT id, username`), the injected query must select exactly 2 columns (`username, password`) to avoid a database syntax/schema mismatch error.
- **Mitigation (2–3 sentences):** Replace raw query string concatenation with parameterized queries using placeholder marks (`WHERE username LIKE ?`). Pass `"%" + term + "%"` as the bound data parameter tuple to ensure the input string is never evaluated as SQL command syntax or operators.
- **Screenshot:**

  ![Task 2 Output](img/Screenshot%202.png)

**Task 3 — OS command injection (30 min) 🐉 Hit #3.**
- *Goal:* run an arbitrary command through `/ping`.
- *Steps:* request `/ping?host=127.0.0.1;id` then `/ping?host=$(whoami)` (URL-encode if needed). Capture the injected command's output.
- *Deliverable:* both payloads + screenshot of `id`/`whoami` output + explanation of the `shell=True` flaw (CWE-78).

- **Payloads:**
  1. Command chaining: `http://localhost:8080/ping?host=127.0.0.1;id`
  2. Command substitution: `http://localhost:8080/ping?host=$(whoami)`
  *(Optional flag extraction: `http://localhost:8080/ping?host=127.0.0.1;cat /flag.txt` -> returns `FLAG{cmdi_demo}`)*
- **Explanation of `shell=True` flaw (CWE-78):** In `vulnerable_app.py`, `subprocess.run("ping -c 1 " + host, shell=True)` invokes the system shell (`/bin/sh -c`). When untrusted input containing command delimiters (such as `;`, `&`, `|`, or `$()`) is passed into a shell interpreter, the shell splits the string into distinct commands and executes them sequentially. This gives the remote attacker full OS command execution privileges under the user running the Flask process (`root`).
- **Mitigation (2–3 sentences):** Avoid invoking the system shell by setting `shell=False` and passing command arguments as a list (`["ping", "-c", "1", host]`). In addition, apply defense-in-depth input validation using an allow-list regular expression (e.g., `^[A-Za-z0-9_.-]+$`) to reject unexpected characters before execution.
- **Screenshot:**

  ![Task 3 Output](img/Screenshot%203.png)

**Task 4 — Unrestricted upload (25 min) 🐉 Hit #4.**
- *Goal:* show the upload accepts a dangerous file type with no checks (CWE-434).
- *Steps:* `GET /upload` (form), then upload a file named `shell.py`. Confirm `saved to /tmp/uploads/shell.py`. Discuss: if `UPLOAD_DIR` were web-served or executed, this is the RCE chain (here the dir is **not** served, so document the missing control rather than claiming auto-RCE).
- *Deliverable:* upload command/screenshot + 2–3 sentences on why extension allow-listing matters.

- **Upload Command:**
  ```bash
  curl -F "f=@shell.py" "http://localhost:8080/upload"
  ```
  *(or via browser form at `http://localhost:8080/upload` with field name `f`)*
- **Output:** `saved to /tmp/uploads/shell.py`
- **Why extension allow-listing matters (2–3 sentences):** Extension allow-listing ensures that only benign, non-executable media types (such as `.png`, `.jpg`, `.pdf`, `.txt`) are permitted to be saved on disk, rejecting dangerous executable extensions like `.py`, `.sh`, or `.php`. Without an allow-list, an attacker can upload scripts that execute arbitrary code if the directory is web-accessible or invoked by backend workers. Enforcing strict allow-lists along with filename sanitization prevents path traversal and server-side script execution.
- **Screenshot:**

  ![Task 4 Output](img/Screenshot%204.png)

**Task 5 — Defend / fix it (35 min) 🛡️ Boss defeated.**
- *Goal:* prove `solution_app.py` blocks Tasks 1–4.
- *Steps:* stop the vulnerable container (`Ctrl-C`), then run the fixed app on the same compose env:
  ```bash
  docker compose run --rm --service-ports injection-lab bash -c "pip install --no-cache-dir flask && python solution_app.py"
  ```
  Re-fire each payload from Tasks 1–4. Expected: `Login failed`, no credential dump, `invalid host` (400) on `127.0.0.1;id`, and `file type not allowed` for `shell.py`.
- *Deliverable:* screenshots of all four failures + name the fix line for each (parameterized query L52–55 login / L62–66 search, `shell=False`+regex L74–77, `secure_filename`+allow-list L86–93).

- **Defense Test Results:**
  1. **Login bypass payload:** `/login?user=alice'--&pw=x` -> Returns `Login failed` (HTTP 200).
  2. **UNION credential dump:** `/search?q=' UNION SELECT username,password FROM users--` -> Returns empty list.
  3. **Command injection:** `/ping?host=127.0.0.1;id` -> Returns `invalid host` (HTTP 400).
  4. **Unrestricted upload:** `curl -F "f=@shell.py" http://localhost:8080/upload` -> Returns `file type not allowed` (HTTP 400).
- **Citing Fix Lines in `solution_app.py`:**
  - **Login SQLi Fix:** Lines 52–55 (`db().execute("SELECT id, username FROM users WHERE username = ? AND password = ?", (user, pw))`) binds parameters instead of concatenating.
  - **Search SQLi Fix:** Lines 62–66 (`db().execute("SELECT id, username FROM users WHERE username LIKE ?", ("%" + term + "%",))`) binds the LIKE pattern as a parameter.
  - **Command Injection Fix:** Lines 74–77 (`re.fullmatch(r"[A-Za-z0-9_.-]+", host)` regex check and `subprocess.run(["ping", "-c", "1", host], shell=False)`).
  - **Upload Vulnerability Fix:** Lines 86–93 (`secure_filename(f.filename)` and verifying `ext in ALLOWED_EXT` allow-list).
- **Screenshot:**

  ![Task 5 Output](img/Screenshot%205.png)

## Part 4 — Reflection

1. **CWE/OWASP mapping:** map each of your four exploits to its CWE (89/78/434) and to OWASP 2025 **A05 Injection**.

   **Answer:**
   - **Task 1 & Task 2 (SQL Injection):** Maps to **CWE-89** (Improper Neutralization of Special Elements used in an SQL Command) and **OWASP 2025 A05 Injection**.
   - **Task 3 (OS Command Injection):** Maps to **CWE-78** (Improper Neutralization of Special Elements used in an OS Command) and **OWASP 2025 A05 Injection**.
   - **Task 4 (Unrestricted File Upload):** Maps to **CWE-434** (Unrestricted Upload of File with Dangerous Type), categorized under **OWASP 2025 A05 Injection** (and A01 Broken Access Control).

2. **Real breach:** the **2017 Equifax breach** exposed ~147M people after attackers exploited a known input-handling flaw (Apache Struts CVE-2017-5638). In 3–4 sentences, connect that failure to the lessons in this lab (untrusted input reaching a powerful interpreter; the cost of an unpatched/unvalidated input path).

   **Answer:** The 2017 Equifax breach occurred because untrusted data in an HTTP `Content-Type` header was passed directly to the OGNL expression interpreter in Apache Struts, enabling remote attackers to execute arbitrary system commands. This failure directly parallels the flaws in this lab's `/ping` and `/login` routes, where failing to neutralize untrusted input before passing it to powerful interpreters (the system shell and SQL database) allows attackers to gain full execution control. The breach demonstrated that neglecting strict input validation and timely dependency patching on an externally exposed input vector can lead to catastrophic data loss and systemic infrastructure compromise.

3. **Best mitigation:** of parameterized queries, allow-list validation, least privilege, and avoiding `shell=True`, which single control would have prevented the most damage in this lab, and why?

   **Answer:** Parameterized queries would have prevented the most severe damage in this lab because the primary business impact was the complete exposure of the user and credential database. While command injection is critical, database compromise via SQLi directly exposes sensitive customer identity records and authentication secrets across the entire platform. Parameterization structurally guarantees that user input cannot alter database syntax, neutralizing the root vulnerability at the architectural level without relying on fallible filter patterns.

## Grading rubric (100)

| Criterion | Points |
|-----------|-------:|
| Part 2 — Lecture questions (conceptual accuracy) | 20 |
| Part 3 — Exploitation + evidence (payloads + screenshots, Tasks 1–4) | 40 |
| Part 3 — Defense (Task 5: fixes proven, lines cited) | 25 |
| Part 4 — Reflection (CWE/OWASP mapping, breach, mitigation) | 15 |
| **Total** | **100** |

---

## Evidence & Integrity (required)

- **Identity proof:** every screenshot/diagram must show a terminal running `printf '%s | %s | ' "$(whoami)" '<YOUR-STUDENT-ID>'; date '+%F %T %Z'` **in the
  same image as the evidence**. When the evidence is a browser page, a DevTools panel or a
  rendered response, put that terminal **beside the browser and capture the whole screen** — a
  cropped window carries nothing that identifies you, and the lab's own output is
  byte-identical for the whole cohort *by design*, so the stamp is the only thing that makes
  the shot yours. Generic or borrowed evidence is not accepted.
- **Personalized flag (if this lab issues one):** `FLAG{sqli_demo}`
  *Flags are unique per student — submitting another student's flag is a violation. How to submit: **learn.zcr.ai/submit** (full guide: `SUBMISSION.md` in the repo root).*
- **Explain in your own words** *(graded on your reasoning, not copied text):*
  1. What did you do, and **why did the vulnerability work**?
     **Answer:** I exploited SQL injection, OS command injection, and unrestricted file upload vulnerabilities by supplying crafted input containing syntax metacharacters (`'`, `--`, `UNION`, `;`, `$()`). These vulnerabilities worked because the application directly concatenated untrusted HTTP parameters into query strings and shell commands without separating the code from the data, causing the SQLite parser and the OS shell to interpret attacker-controlled strings as commands rather than literal values.
  2. **Why does your fix actually stop it** — and what could still break it?
     **Answer:** The fixes in `solution_app.py` stop the attacks by using parameterized SQL queries where input is treated strictly as bound literal values, avoiding the shell with `shell=False` and argument arrays, and enforcing strict regex and file extension allow-lists. However, security could still break if dynamic queries are constructed using table or column names that cannot be parameterized, if the regex pattern contains subtle syntax flaws, or if uploaded files are stored in a web-accessible directory with execution permissions enabled.

---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.

   **AI Prompt:** *"How do I fix SQL injection in my Python SQLite login query: `SELECT * FROM users WHERE username = '%s' AND password = '%s'`?"*

   **AI Answer:**
   > *"To fix SQL injection, you can sanitize user input by escaping single quotes before concatenating it into the query string. In Python, you can do: `clean_user = user.replace("'", "''")` and `clean_pw = pw.replace("'", "''")`, and then format them into the query: `query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (clean_user, clean_pw)`. This prevents single quotes from breaking out of the string literal."*

2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).

   **Critique:**
   - **Insecure line:** `clean_user = user.replace("'", "''")` and `query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (clean_user, clean_pw)`
   - **Flaw:** Manual string sanitization and quote-doubling is a well-known anti-pattern. If the SQL query contains unquoted numeric parameters, or if the database configuration interprets backslashes as escape characters (`\'`), quote replacement is easily bypassed. It relies on blacklist sanitization rather than structural code-data separation.

3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.

   **Verified Secure Code:**
   ```python
   query = "SELECT id, username FROM users WHERE username = ? AND password = ?"
   row = db().execute(query, (user, pw)).fetchone()
   ```

   **Explanation:** The AI's recommendation was insufficient because it relied on error-prone string replacement rather than utilizing parameterized queries natively supported by the database engine. Parameterization compiles the SQL query structure in advance and binds input strictly as data values, completely eliminating injection regardless of any special characters or encoding tricks in the user input.

> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.

**Answer:** The vulnerable server takes words typed by the user directly from the website's web address and pastes them straight into instructions that it sends to its database and operating system. Because the server glues the text together instead of packaging it as separate data, the computer cannot tell where the original program ends and where the user's text begins. This allows an attacker to include special punctuation marks that make the computer believe the user's text is actually new commands to execute, letting them bypass login screens, steal stored passwords, and run commands on the machine.

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.
*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*

**Final Prompt:**
> *"Refactor the following vulnerable Python Flask endpoint to eliminate CWE-78 command injection: `subprocess.run('ping -c 1 ' + host, shell=True)`. Requirements: (1) Do NOT invoke a system shell (`shell=False`); (2) Pass the binary and its arguments as a list; (3) Implement defense-in-depth by validating that `host` matches strictly an alphanumeric hostname/IP allow-list regex (`^[A-Za-z0-9_.-]+$`) and returns HTTP 400 on failure; (4) Return the captured output safely."*

**Verified Result:**
```python
import re
import subprocess
from flask import abort, request


@app.route("/ping")
def ping():
  host = request.args.get("host", "127.0.0.1")
  # 1. Allow-list validation
  if not re.fullmatch(r"[A-Za-z0-9_.-]+", host):
    return "invalid host\n", 400
  # 2. Argument list with shell=False
  out = subprocess.run(
      ["ping", "-c", "1", host], shell=False, capture_output=True, text=True
  )
  return "<pre>%s</pre>" % (out.stdout + out.stderr)
```

**Verification:** When sending the exploit payload `127.0.0.1;id` to the refactored endpoint, the regex validation immediately triggers and returns HTTP 400 (`invalid host`), blocking the injection completely. Even if regex validation were bypassed, `shell=False` ensures `127.0.0.1;id` is treated as a single literal hostname string and not executed as a command.
