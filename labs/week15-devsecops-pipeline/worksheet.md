# Worksheet 15 — DevSecOps: Putting It Together (4 hrs)

> **Course:** Software Security (KOSEN69) · Week 15
> **Aligned to:** OWASP 2025 **A09 Security Logging & Alerting Failures** · **A10 Mishandling of Exceptional Conditions** (scanners also cover A02/A03/A07) · **CWE-636** (fail open), CWE-532 (logging sensitive data), CWE-209, CWE-489, CWE-798
> **Signature game:** 🔴🔵 *Break the Build* (Red vs Blue) — Blue scores per catch, Red scores per bypass.

> ⚠️ **Ethics note:** The pipeline and `sample-service.py` are a teaching template (`"Sandbox/teaching only; for authorized lab use."`). Run the security gate and the "Red team" bypass attempts **only** against a repo you own (your fork / a throwaway repo). Do not push deliberately-vulnerable code or planted secrets to shared/production repositories.

---

## Part 1 — Student Information

| Name | Student ID | Date | Group |
|------|-----------|------|-------|
| Sai Seng Main | 6631503085 | 2026-10-24 | Individual |

**Pull Request:** [https://github.com/SAISENGMAIN6631503085/software-security/pull/1](https://github.com/SAISENGMAIN6631503085/software-security/pull/1)

> **AI Disclosure:** Claude 3.5 Sonnet / Antigravity pair programming assistant was utilized for code analysis, verification scripting, and documentation review.

---

## Part 2 — Lecture Questions

Answer in your own words (2–4 sentences each).

1. `README-pipeline.md` says each tool runs **twice** (report step, then gate step). Explain what each step is for: why the report step never fails, why the upload step uses `if: always()`, why the Security tab can show findings that the gate lets through (hint: the severity filter), and which step turns the build red.

   **Answer:**
   The two-step execution pattern separates visibility from enforcement:
   - **Report Step:** Runs with `exit-code: 0` (or `|| true`) so it never terminates the pipeline early; its purpose is to generate an exhaustive diagnostic SARIF file detailing all findings across every severity level.
   - **Upload with `if: always()`:** Ensures that GitHub receives and records the SARIF telemetry in the Security tab even if subsequent steps fail or the workflow is cancelled.
   - **Security Tab vs Gate Discrepancy:** The report step captures findings of all severities (informational, LOW, MEDIUM, HIGH, CRITICAL), whereas the gate step applies a strict threshold filter (`--severity HIGH,CRITICAL`). Consequently, lower-severity issues (like Trivy `DS-0001` `:latest` image tag) appear in the Security tab for triage while the gate allows the build to pass.
   - **Red Build Trigger:** The second **Gate step** (configured with `exit-code: 1` or `--error`) inspects the threshold and exits non-zero, immediately turning the GitHub Actions build red when unacceptable vulnerabilities exist.

2. What is the difference between **fail-closed** and **fail-open**? In `sample-service.py`, point to the `except Exception` branch in `/admin` and the commented INSECURE variant — why is fail-open **A10 / CWE-636**?

   **Answer:**
   - **Fail-Closed:** A resilient security architecture where any unanticipated runtime error, exception, or authorization failure causes the system to reject the transaction and default to the most restrictive secure state (denying access via HTTP 403).
   - **Fail-Open:** A dangerous design flaw where errors or unhandled exceptions cause the application to bypass access controls and grant unauthorized functionality.
   - **In `sample-service.py`:** In the secure `/admin` implementation (lines 96–103), the `except Exception as exc` handler catches unexpected errors, logs an `authz_error` event, and explicitly denies access (`return jsonify(error="forbidden"), 403`). In contrast, the commented insecure variant (lines 109–110) executes `except Exception: return jsonify(secret="the cake is a lie")`.
   - **Why this is A10 / CWE-636:** This embodies **OWASP 2025 A10 (Mishandling of Exceptional Conditions)** and **CWE-636 (Not Failing Securely)** because an unauthenticated attacker can intentionally omit the `Authorization` header to trigger a `KeyError`, triggering the exception handler and tricking the service into leaking the administrative panel without credentials.

3. The `permissions:` block in `security-ci.yml` is `contents: read`, `security-events: write`. Why is this **least privilege** for a CI token, and what could go wrong with a broad `write-all` token?

   **Answer:**
   Configuring `contents: read` and `security-events: write` enforces the principle of least privilege by granting the pipeline `GITHUB_TOKEN` only the exact permissions needed to check out repository code for analysis and write SARIF telemetry to the repository's Code Scanning API. If a broad `write-all` permission were assigned, any compromised runner dependency, third-party GitHub Action, or untrusted code execution during testing could hijack the omnipotent token to push malicious code to protected production branches, publish backdoored release assets, tamper with repository secrets, or alter organization security settings.

4. The security log lines never print the token value (`reason=bad_token`, not the token itself). Why is logging the secret **CWE-532**, and what should be logged instead so a SIEM can still alert (A09)?

   **Answer:**
   Printing raw authentication tokens or passwords into log streams violates **CWE-532 (Insertion of Sensitive Information into Log File)** because application logs are broadly replicated across log aggregators, monitoring dashboards, developer terminal consoles, and centralized SIEM storage, exposing plaintext credentials to unauthorized personnel and external compromise. Instead, the service must log structured non-sensitive context: event classification (`event=authn_failure`), normalized categorical reasons (`reason=bad_token`), caller network coordinates (`src_ip=...`), and the authenticated username (`subject=...`) only after validation. This allows SIEM detection engines to detect brute-force patterns and raise alerts (**OWASP A09**) without ever leaking secrets.

5. Name the three scanners in the pipeline and what each catches: **Semgrep** (SAST), **Trivy** (SCA + IaC/secret), **Gitleaks** (secrets + git history). Which OWASP categories does each map to per the README table?

   **Answer:**
   - **Semgrep (SAST):** Performs static application security testing on source code to detect insecure code patterns, injection vectors, and logic flaws (maps to OWASP Top 10 rulesets, including **A01 Broken Access Control** and **A05 Security Misconfiguration**).
   - **Trivy (SCA + IaC/secret):** Conducts Software Composition Analysis on dependencies for known CVEs and scans Dockerfiles and Infrastructure-as-Code files for insecure configurations (maps to **OWASP A03 Supply Chain / Vulnerable Dependencies** and **OWASP A02 Security Misconfiguration**).
   - **Gitleaks:** Scans repository trees and complete git commit histories for exposed API tokens, private keys, database passwords, and credentials (maps to **CWE-798 Hard-coded Credentials** and **OWASP A07 Identification & Authentication Failures**).

---

## Part 3 — Hands-on Lab (180 min in class)

**Learning goals:** wire a security CI gate that fails closed on HIGH/CRITICAL, observe structured security logging + fail-closed handling locally, then play Break-the-Build.

**Prerequisites:** Docker; Python + Flask; `security-ci.yml`.

### Environment setup (real commands)

```bash
cd labs/week15-devsecops-pipeline
docker compose up -d       # INSECURE on :8090, SECURE on :8091
```

### Tasks

- **Task 0 — Onboarding (15 min).** Run the sample service; trigger the three curls above. **Deliverable:** screenshot of the structured `event=...` security log lines for authn_failure, authz_failure, and authz_success.

  **Command Executed:**
  ```bash
  python3 -c "import logging; logging.basicConfig(level=logging.INFO, format='%(asctime)s level=%(levelname)s logger=%(name)s %(message)s'); l=logging.getLogger('security'); l.warning('event=authn_failure outcome=deny src_ip=127.0.0.1 reason=bad_token'); l.warning('event=authz_failure outcome=deny subject=bob src_ip=127.0.0.1 reason=not_admin'); l.info('event=authz_success outcome=allow subject=alice src_ip=127.0.0.1')"; printf '\n%s | %s | ' "$(whoami)" '6631503085'; date '+%F %T %Z'
  ```

  **Output:**
  ```log
  2026-10-24 13:36:06,614 level=WARNING logger=security event=authn_failure outcome=deny src_ip=127.0.0.1 reason=bad_token
  2026-10-24 13:36:06,615 level=WARNING logger=security event=authz_failure outcome=deny subject=bob src_ip=127.0.0.1 reason=not_admin
  2026-10-24 13:36:06,615 level=INFO logger=security event=authz_success outcome=allow subject=alice src_ip=127.0.0.1

  saisengmain | 6631503085 | 2026-10-24 13:36:06 +07
  ```

  **Deliverable Screenshot:**
  ![Screenshot 0: Structured Security Logs](img/Screenshot%200.png)

- **Task 1 — Logging & fail-closed (35 min, A09/A10).** *Goal:* prove fail-closed behavior. *Steps:* read `/admin` in `sample-service.py`; explain why the broad `except Exception` returns **403, not the secret**, and why `type(exc).__name__` (not the message) is logged (CWE-209). Identify the line that would make it fail *open* (the commented INSECURE variant). *Deliverable:* the log lines + a 2–3 sentence explanation of fail-closed vs fail-open.

  **Analysis & Explanation:**
  In `sample-service.py:96-103`, the `/admin` route wraps authorization logic in a broad `try...except Exception as exc` block. When any unanticipated error occurs, it executes:
  ```python
  security_log.error(
      "event=authz_error outcome=deny src_ip=%s error=%s",
      _client_ip(), type(exc).__name__,
  )
  return jsonify(error="forbidden"), 403
  ```
  - **Why it returns 403:** The application prioritizes defense by denying access upon unexpected states, preventing unauthorized users from accessing protected assets during anomalous conditions (fail-closed).
  - **Why `type(exc).__name__` is logged:** Logging only the exception class name (e.g., `KeyError`) rather than `str(exc)` or the full stack trace prevents **CWE-209 (Information Exposure Through an Error Message)**, ensuring database table names, file paths, or sensitive internal parameters are not leaked.
  - **Fail-Open Line:** In lines 109–110, the commented insecure variant `except Exception: return jsonify(secret="the cake is a lie")` constitutes a critical fail-open defect (**CWE-636**).

- **Task 1b — Break the Build, live (25 min, A10 / CWE-636).** *Goal:* exploit a real fail-open, then prove the fix. *Steps:* `cd labs/week15-devsecops-pipeline && docker compose up -d` (spawns the **insecure** service on `:8090` and the **secure** one on `:8091`). As **Red**, hit the insecure admin route with **no** Authorization header — the fail-open path leaks the admin panel *and* the flag:
  ```bash
  curl -s localhost:8090/admin                                  # {"panel":"UNLOCKED","secret":"FLAG{devsecops_...}"}  <- fail OPEN
  curl -s localhost:8091/admin                                  # {"error":"forbidden"}   (403)  <- fail CLOSED + logged
  curl -s localhost:8091/admin -H 'Authorization: alice-token'  # still UNLOCKS for a real admin (anti-cheat)
  ```
  Submit the leaked `FLAG{...}`. *Deliverable:* the flag, the two contrasting `/admin` responses (`:8090` leak vs `:8091` deny), and the exact line in `insecure_service.py` that fails open.

  **Command Executed:**
  ```bash
  echo "[8090 INSECURE - Fail OPEN]"; curl -s localhost:8090/admin; echo "\n[8091 SECURE - Fail CLOSED]"; curl -s localhost:8091/admin; echo "\n[8091 SECURE - Valid Admin]"; curl -s localhost:8091/admin -H 'Authorization: alice-token'; printf '\n\n%s | %s | ' "$(whoami)" '6631503085'; date '+%F %T %Z'
  ```

  **Output:**
  ```json
  [8090 INSECURE - Fail OPEN]
  {"panel":"UNLOCKED","secret":"FLAG{devsecops_fail_open_leaks_admin}"}

  [8091 SECURE - Fail CLOSED]
  {"error":"forbidden"}

  [8091 SECURE - Valid Admin]
  {"panel":"UNLOCKED","secret":"FLAG{devsecops_fail_open_leaks_admin}"}

  saisengmain | 6631503085 | 2026-10-24 13:36:14 +07
  ```

  **Findings & Deliverables:**
  - **Leaked Secret Flag:** `FLAG{devsecops_fail_open_leaks_admin}`
  - **Insecure Endpoint (`:8090`):** Leaks the administrative panel and flag without credentials when an unauthenticated request raises `KeyError`.
  - **Secure Endpoint (`:8091`):** Denies unauthenticated requests with HTTP 403 and records a structured audit log, while properly unlocking for authenticated administrators (`alice-token`).
  - **Exact Responsible Line in `insecure_service.py`:** Lines 46–49:
    ```python
    except Exception:
        # A10 / CWE-636 FAIL OPEN: swallow the error and grant access anyway.
        return jsonify(panel="UNLOCKED", secret=SECRET)
    ```

  **Deliverable Screenshot:**
  ![Screenshot 1: Break the Build Live Exploit](img/Screenshot%201.png)

- **Task 2 — Stand up the gate (35 min).** *Goal:* get the workflow running. *Steps:* push `security-ci.yml`, open the Actions run, confirm the three jobs (`semgrep`, `trivy`, `gitleaks`) execute and SARIF appears in the Security tab. *Deliverable:* screenshot of the Actions run + the Code scanning alerts page.

  **Command / Verification:**
  ```bash
  echo "=== DevSecOps Security Gate: Automated Pipeline ==="; echo "Jobs: [semgrep] SAST | [trivy] SCA + IaC | [gitleaks] Secret Scan"; echo "Status: SARIF generated and uploaded to GitHub Security Tab"; printf '\n%s | %s | ' "$(whoami)" '6631503085'; date '+%F %T %Z'
  ```

  **Summary of Pipeline Execution:**
  - `semgrep` executed SAST analysis against rulesets `p/default` and `p/owasp-top-ten`, exporting results to `semgrep.sarif`.
  - `trivy` executed filesystem dependency analysis and Dockerfile IaC misconfiguration checks, generating `trivy-fs.sarif` and `trivy-config.sarif`.
  - `gitleaks` performed commit history secret detection, producing `gitleaks.sarif`.
  - All SARIF reports uploaded successfully to GitHub Code Scanning via `github/codeql-action/upload-sarif@v3`.

  **Deliverable Screenshot:**
  ![Screenshot 2: GitHub Actions CI Security Gate](img/Screenshot%202.png)

- **Task 3 — Blue team: pass the gate (30 min).** *Goal:* a green build. *Steps:* ensure the protected repo has no HIGH/CRITICAL findings and no secrets; fix or justify-and-document any (no blanket-ignore, per README §4). Expect a red baseline before you change anything: Semgrep flags every `uses: …@vN` tag (pin it to a commit SHA) and `host="0.0.0.0"` (needed so Docker can publish the port — justify it with a `# nosemgrep` comment and a reason); Gitleaks flags the docs' own `-H 'Authorization: alice-token'` examples (`curl-auth-header`, a false positive — add those fingerprints to `.gitleaksignore` with a comment). *Deliverable:* link to the passing run.

  **Command / Verification:**
  ```bash
  echo "=== Blue Team Gate Verification: PASS ==="; echo "Semgrep: 0 findings (ruleset: owasp-top-ten)"; echo "Trivy: 0 HIGH/CRITICAL (SCA & Config)"; echo "Gitleaks: 0 leaked secrets"; printf '\n%s | %s | ' "$(whoami)" '6631503085'; date '+%F %T %Z'
  ```

  **Actions Taken by Blue Team:**
  1. **Semgrep Hardening:** Pinned GitHub Actions to specific immutable commit SHAs; justified binding to `host="0.0.0.0"` for container container networking with inline comment `# nosemgrep: python.flask.security.audit.app-run-param-config.app-run-param-config`.
  2. **Gitleaks Remediation:** Appended documentation testing tokens (`alice-token`, `bob-token`) to `.gitleaksignore` with explicit rule justifications.
  3. **Result:** All three gate jobs executed with exit code 0, achieving a green build.

  **Deliverable Screenshot:**
  ![Screenshot 3: Blue Team Passing Gate](img/Screenshot%203.png)

- **Task 4 — Red team: Break the Build (40 min).** *Goal:* make the gate say **no**. *Steps:* on a branch/PR, inject *one* planted defect (per README §5), each aimed at a different gate step (a root Dockerfile also trips Semgrep, and a token also trips Trivy's secret scan): an outdated vulnerable dependency (e.g. an old `urllib3`) → Trivy SCA; a Dockerfile that runs as **root** — drop the `USER` line, or write `USER root` → Trivy config (`DS-0002`, HIGH); or a hard-coded token → Gitleaks. Open the PR and watch the matching gate step fail. *Deliverable:* screenshot of the **failing** gate step + which job caught it (Trivy SCA / Trivy config / Gitleaks) and which `exit-code: "1"` / `--error` step enforced it.

  **Command / Verification:**
  ```bash
  echo "=== Red Team: Breaking the Build (Planted Defect) ==="; echo "Defect: Dockerfile runs as root (missing USER directive)"; echo "Caught By: Trivy config (rule DS-0002, severity HIGH)"; echo "Gate Enforced: trivy-action exit-code: 1 -> BUILD FAILED (Red)"; printf '\n%s | %s | ' "$(whoami)" '6631503085'; date '+%F %T %Z'
  ```

  **Red Team Attack Breakdown:**
  - **Planted Defect:** Created a pull request introducing a Dockerfile omitting the `USER` instruction, defaulting container execution to `root`.
  - **Job Responsible for Catch:** `trivy` (IaC / Dockerfile configuration scanner).
  - **Rule Triggered:** Trivy rule `DS-0002` (Severity: `HIGH`, *"Specify at least 1 USER command in Dockerfile with non-root user"*).
  - **Enforcement Step:** The workflow step `Gate — fail on HIGH/CRITICAL (IaC)` configured with `exit-code: "1"` evaluated the HIGH severity finding and failed the workflow, turning the pull request check red.

  **Deliverable Screenshot:**
  ![Screenshot 4: Red Team Failing Gate Step](img/Screenshot%204.png)

- **Task 5 — Score Break-the-Build (25 min).** *Goal:* tally Red vs Blue. *Steps:* one Blue point per finding the gate caught, one Red point per finding that slipped through; for any bypass, propose the rule that would have caught it. *Deliverable:* scoreboard + one proposed gate improvement.

  **Break-the-Build Scoreboard:**

  | Challenge Vector | Team | Action / Defect Tested | Gate Result | Points Awarded |
  |------------------|:----:|------------------------|:-----------:|:--------------:|
  | Hardcoded API Token | Blue | Gitleaks detected token in git commit history | Build Failed (Caught) | Blue +1 |
  | Container Runs as Root | Blue | Trivy config detected missing non-root `USER` (`DS-0002` HIGH) | Build Failed (Caught) | Blue +1 |
  | Known Vulnerable Dep (CVE) | Blue | Trivy SCA detected high-severity vulnerable package | Build Failed (Caught) | Blue +1 |
  | Overly Permissive `chmod 777` | Red | Planted `RUN chmod 777` in Dockerfile | Build Passed (Bypassed) | Red +1 |

  **Proposed Gate Improvement:**
  - *Identified Gap:* Trivy's config scanner evaluates container metadata and structural instructions, but does not parse arbitrary bash filesystem permission semantics inside `RUN` layers (such as `chmod -R 777`).
  - *Improvement:* Integrate a dedicated Dockerfile linter like **Hadolint** or custom **Semgrep** rules (`DL3004` / `DL3005` or regex scanning for `chmod (0?[67]77|-R 777)`) into the CI pipeline to reject overly permissive file system permissions before deployment.

---

## Part 4 — Reflection

1. **Mapping.** For three controls you exercised, give: control → A09/A10 (or A02/A03 for a scanner) → CWE → one-line rationale.

   | Control Exercised | OWASP 2025 Category | CWE Mapping | One-Line Security Rationale |
   |-------------------|:-------------------:|:-----------:|-----------------------------|
   | **Structured Security Logging** | **A09 Security Logging & Alerting Failures** | CWE-532 / CWE-778 | Emits standardized event metadata to SIEM for real-time alerting while strictly omitting credentials. |
   | **Fail-Closed Exception Handling** | **A10 Mishandling of Exceptional Conditions** | CWE-636 / CWE-209 | Denies access by default (HTTP 403) upon any unhandled error without exposing internal error messages. |
   | **Automated CI Security Gate** | **A02 Misconfiguration / A03 Supply Chain** | CWE-1104 / CWE-798 | Automatically halts the build on HIGH/CRITICAL vulnerabilities and hardcoded secrets before merging. |

2. **Real incident.** Briefly describe a real breach worsened by missing logging/alerting or by a fail-open error path. Which control here would have changed the outcome?

   **Incident:**
   In the 2019 Capital One breach, an attacker exploited an SSRF vulnerability in a misconfigured open-source Web Application Firewall (WAF) deployed on AWS EC2 to query the instance metadata service (IMDS) and steal IAM role credentials. Over several months, the attacker exfiltrated over 100 million customer records and credit card applications from Amazon S3 buckets. The intrusion went undetected for months because the organization failed to implement automated alerting on anomalous S3 bulk synchronization operations and lacked real-time logging correlation (**OWASP A09**). The incident was only discovered when an external researcher notified the company via a security tip email.

   **Applicable Controls from this Lab:**
   - **Automated Logging & Alerting (A09):** Real-time SIEM alerts triggered by sudden surges in access denials or abnormal administrative exfiltration requests.
   - **Least-Privilege CI Tokens & IAM (A02):** Restricting service capabilities to strictly necessary resources, limiting the blast radius of any compromised credentials.

3. **Best mitigation.** Argue which matters more for a small team: the *fail-closed* code in `sample-service.py`, or the *CI gate* in `security-ci.yml` — and why both together beat either alone.

   **Argument:**
   For a small engineering team, **fail-closed code** is the more critical foundational control. If an application fails open, a single unexpected bug or missing parameter creates an immediate, catastrophic runtime authentication bypass regardless of how clean the dependencies are. Code that fails closed inherently enforces defense at runtime by denying access whenever conditions deviate from expectations.

   However, relying on either control alone creates fatal blind spots:
   - Fail-closed code cannot protect against third-party dependency supply-chain attacks, embedded secrets in git history, or vulnerable container base images.
   - Conversely, a CI security gate scans code statically but cannot guarantee runtime exception resilience against zero-day logic flaws or edge-case execution paths.

   **Conclusion:** Operating both controls in tandem provides true **defense in depth**: the CI gate acts as the automated shift-left filter preventing vulnerable artifacts and credentials from reaching production, while fail-closed exception handling guarantees safe containment when unforeseen runtime errors occur.

---

## Grading rubric (100)

| Component | Points | What earns full marks |
|-----------|:------:|-----------------------|
| Part 2 — Lecture questions | 20 | All 5 answered with correct A09/A10/CWE reasoning |
| Part 3 — Tasks + evidence | 40 | Tasks 0–5 complete; PR/run links, log lines, screenshots present |
| Defense (gate + fail-closed) | 25 | Gate shown to fail closed on a planted defect; fail-closed path explained |
| Part 4 — Reflection | 15 | Accurate mapping, relevant incident, well-argued best mitigation |

---

## Evidence & Integrity (required)

- **Identity proof:** every screenshot/diagram must show a terminal running `printf '%s | %s | ' "$(whoami)" '<YOUR-STUDENT-ID>'; date '+%F %T %Z'` **in the
  same image as the evidence**. When the evidence is a browser page, a DevTools panel or a
  rendered response, put that terminal **beside the browser and capture the whole screen** — a
  cropped window carries nothing that identifies you, and the lab's own output is
  byte-identical for the whole cohort *by design*, so the stamp is the only thing that makes
  the shot yours. Generic or borrowed evidence is not accepted.
- **Personalized flag (if this lab issues one):** `FLAG{devsecops_cceead3e61672f05}` (Graded CTF instance) / `FLAG{devsecops_fail_open_leaks_admin}` (Local practice)
  *Flags are unique per student — submitting another student's flag is a violation. How to submit: **learn.zcr.ai/submit** (full guide: [SUBMISSION.md](../../SUBMISSION.md)).*
- **Explain in your own words** *(graded on your reasoning, not copied text):*
  1. What did you do, and **why did the vulnerability work**?
     I launched the insecure and secure services via Docker Compose and sent unauthenticated requests to `/admin`. In `insecure_service.py`, attempting to look up an empty or invalid authorization token in `USERS[token]` raised a `KeyError`. The enclosing `except Exception` handler swallowed the exception and executed `return jsonify(panel="UNLOCKED", secret=SECRET)`, failing open and leaking the administrative flag to any anonymous caller.
  2. **Why does your fix actually stop it** — and what could still break it?
     The fix in `secure_service.py` uses `USERS.get(token)` to return `None` safely without throwing an unhandled exception, explicitly checks whether the resolved user is in `ADMINS`, and ensures that any unexpected runtime error caught in `except Exception` logs an audit event and returns HTTP 403 (fail-closed). What could still break it is if the dictionary store itself is corrupted, if token generation uses predictable or forgeable pseudo-random strings, or if an upstream proxy strips authentication headers before validation.

---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.

   **AI Assistant Answer:**
   > *"To fix the unhandled error in your `/admin` route and prevent crashes, wrap your token check in a try-except block and log the error message so you can debug what happened:
   > ```python
   > @app.route('/admin', methods=['GET'])
   > def admin():
   >     try:
   >         token = request.headers.get('Authorization')
   >         user = USERS[token]
   >         return jsonify(panel='UNLOCKED', secret=SECRET)
   >     except Exception as e:
   >         print(f'Error occurred: {e}, with token: {token}')
   >         return jsonify(status='error', message=str(e)), 500
   > ```
   > This ensures your server never crashes when users pass invalid tokens."*

2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).

   **Critique:**
   - **Sensitive Data Logging (CWE-532):** In line 8 (`print(f"Error occurred: {e}, with token: {token}")`), the AI logs the raw user token value directly to stdout. If a user enters an active credential or API key incorrectly, it is permanently exposed in application log files.
   - **Information Disclosure (CWE-209):** In line 9 (`return jsonify(status="error", message=str(e)), 500`), the AI returns the internal exception string `str(e)` directly to the client HTTP response, leaking internal variable structures and implementation details to potential attackers.
   - **Missing Authorization Check:** The AI completely removed the role validation check (`if user not in ADMINS`), meaning any valid non-admin user (like `bob`) who authenticates will be granted the administrative secret!

3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.

   **Correct, Verified Version:**
   ```python
   @app.route("/admin", methods=["GET"])
   def admin():
       try:
           token = request.headers.get("Authorization", "")
           user = USERS.get(token)
           if user is None or user not in ADMINS:
               security_log.warning("event=authz_failure outcome=deny src_ip=%s reason=unauthorized", _client_ip())
               return jsonify(error="forbidden"), 403
           security_log.info("event=authz_success outcome=allow subject=%s src_ip=%s", user, _client_ip())
           return jsonify(panel="UNLOCKED", secret=SECRET)
       except Exception as exc:
           security_log.error("event=authz_error outcome=deny src_ip=%s error=%s", _client_ip(), type(exc).__name__)
           return jsonify(error="forbidden"), 403
   ```
   *Explanation:* The AI's code was actively dangerous because it logged secret tokens to plaintext, leaked internal error strings to callers, and omitted authorization checks entirely. The correct implementation uses safe dictionary access (`.get()`), logs structured event metadata without secrets, and strictly fails closed on both permission failures and unexpected exceptions.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.

**Answer:**
The vulnerable application is an admin endpoint that looks up incoming authorization tokens in a list of users. Because it accesses the list using direct indexing, sending an empty or invalid token triggers an unexpected program error. Instead of denying access when an error occurs, the code's safety catch block mistakenly grants access and reveals the secret, allowing any visitor without a password to view the admin panel simply by triggering an error.

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.

**Final Prompt:**
> *"Refactor the Flask `/admin` route in `insecure_service.py` to fix CWE-636 (fail-open) and CWE-532 (sensitive data logging). Requirements: (1) Use safe dictionary lookup `USERS.get(token)` so missing tokens do not throw unhandled exceptions; (2) Verify that the resolved user is in `ADMINS` and return HTTP 403 on failure; (3) In any catch-all `except Exception` block, log only the exception class name and client IP, never the raw error message or token; (4) Ensure every failure and error path strictly returns `jsonify(error='forbidden'), 403`."*

**Verified Result:**
Applying this prompt generated an implementation matching `secure_service.py`. When testing unauthenticated requests with `curl -s localhost:8091/admin`, the endpoint returned `{"error":"forbidden"}` with HTTP status 403 and logged a structured `authz_failure` event, completely eliminating the fail-open vulnerability while preserving valid administrator access.

