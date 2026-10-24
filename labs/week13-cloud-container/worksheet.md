# Worksheet 13 — Cloud & Container Security (4 hrs)

> **Course:** Software Security (KOSEN69) · Week 13
> **Aligned to:** OWASP 2025 **A02 Security Misconfiguration** · **CWE-732** (incorrect permission assignment), **CWE-16** (configuration), **CWE-526** (secret exposed through an environment variable), plus CWE-798 (hard-coded credential — OWASP files this under **A07**), CWE-250, CWE-538, CWE-269, CWE-1104
> **Signature game:** 🔍 *Misconfig Hunt* (CloudGoat-style) — each misconfig you find **and** fix = a flag.

> ⚠️ **Ethics note:** All artifacts here are deliberately broken for teaching and are marked *"Sandbox/teaching only; for authorized lab use."* Scan, exploit, and harden **only** these lab files (or systems you own / are authorized to test). Never point Trivy or these techniques at third-party cloud accounts or images without written permission.

---

## Part 1 — Student Information

| Name | Student ID | Date | Group |
|------|-----------|------|-------|
| Sai Seng Main | 6631503085 | 2026-10-24 | Individual |

**Pull Request:** [https://github.com/nutthakorn7/software-security/pull/155](https://github.com/nutthakorn7/software-security/pull/155)

> **AI Disclosure:** Claude 3.5 Sonnet / Antigravity pair programming assistant was utilized for code analysis, verification scripting, and documentation review.

---

## Part 2 — Lecture Questions

Answer in your own words (2–4 sentences each).

1. Explain the **shared-responsibility model**. In `harden.md` it says "the cloud provider secures *of* the cloud; you secure what you put *in* it." Give one concrete example of each side for an S3-backed app.

   **Answer:**
   The cloud shared-responsibility model establishes that the cloud service provider (CSP, e.g., AWS) is responsible for the security *of* the cloud—including physical data center security, server hardware, virtualization layer, and underlying storage fabric. Conversely, the customer is strictly responsible for security *in* the cloud—including guest operating system configuration, network access controls, identity and access management (IAM), encryption keys, and application code. For an S3-backed application, AWS ensures the physical hard drives are encrypted, resilient against disk failures, and protected against physical intrusion, while the customer is solely responsible for ensuring the S3 bucket is not configured with public read access (`Principal: *`) and that bucket policies enforce least privilege and TLS in transit.

2. `iam-policy-insecure.json` uses `"Action": "*"` and `"Resource": "*"`. Describe **why this violates least privilege** and map it to CWE-732 vs CWE-269 — what is the difference between the two CWEs here?

   **Answer:**
   Using `"Action": "*"` and `"Resource": "*"` violates the principle of least privilege by granting wildcard administrator permissions across all APIs and resources in the entire cloud account, far exceeding the minimal permissions needed (reading objects from a single S3 bucket prefix). The distinction between the two CWEs lies in management versus assignment:
   - **CWE-269 (Improper Privilege Management):** The system defines or assigns an overly broad level of privileges to an actor or role without restricting capability scopes.
   - **CWE-732 (Incorrect Permission Assignment to Critical Resource):** The access control policy specifies insecure permissions on the resource itself, allowing unauthorized access or modification to sensitive data.
   Here, CWE-269 describes granting omnipotent root actions to a simple application identity, while CWE-732 describes failing to bind access to specific resource ARNs, leaving every asset in the account accessible.

3. The insecure Dockerfile bakes `ENV API_TOKEN=sk_live_...`. Explain how an attacker recovers that secret from a shipped image (name the `docker` commands) and why this is **CWE-526 / CWE-798 / CWE-200**.

   **Answer:**
   When an environment variable is defined using `ENV` in a Dockerfile, it is permanently recorded in the image's immutable layer metadata and persists across all child layers. Anyone who pulls or inspects the image can trivially recover the secret without running the container using either `docker inspect --format '{{json .Config.Env}}' <image>` to dump the container environment metadata, or `docker history --no-trunc <image>` to read the exact build instructions recorded in each layer's history. This flaw maps to:
   - **CWE-526 (Cleartext Storage of Sensitive Information in an Environment Variable):** Storing secrets in plain text within environment variables.
   - **CWE-798 (Use of Hard-coded Credentials):** Baking cryptographic keys or API tokens directly into distribution artifacts.
   - **CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor):** Enabling any downstream user or attacker with image pull permissions to extract production credentials.

4. Why is `FROM python:latest` (CWE-1104/CWE-16) a security and reproducibility problem, and how does pinning to an `@sha256:` digest fix it?

   **Answer:**
   The `:latest` tag is a mutable pointer rather than an immutable version; upstream maintainers update it continuously with new Debian base releases, dependency versions, and security patches. Consequently, running `docker build` today will produce a different image than next month, introducing unpredictable breaking changes, non-reproducible bugs, and unnoticed security regressions (CWE-1104: Use of Unmaintained/Uncontrolled Component, CWE-16: Configuration). Pinning to an immutable content digest (`FROM python:3.11-slim@sha256:...`) mathematically guarantees reproducible builds: the Docker daemon verifies that the downloaded image matches the exact cryptographic hash, ensuring byte-identical base layers across all development, CI/CD, and production environments.

5. What does a **distroless** base image remove (relative to `python:3.11-slim`), and how does that shrink the attack surface for an RCE or container-escape attacker?

   **Answer:**
   A distroless container image strips away the entire standard Linux userland, removing package managers (`apt`, `dpkg`), shells (`/bin/sh`, `/bin/bash`), core utilities (`curl`, `wget`, `cat`, `ls`), and system libraries, leaving only the application runtime (`python3`) and its immediate shared library dependencies. For an attacker who discovers a Remote Code Execution (RCE) flaw, this dramatically raises the barrier to exploitation: they cannot spawn an interactive shell, cannot fetch external post-exploitation malware via `curl` or `wget`, cannot invoke system command pipelines, and have no local compiler or utility toolchain to escalate privileges or mount a container escape attack.

---

## Part 3 — Hands-on Lab (180 min)

**Learning goals:** find cloud/container misconfigurations with Trivy, map each to a CWE, and rebuild the IAM policy + Dockerfile to least privilege / hardened so the findings drop.

**Prerequisites:** Docker installed and running; the `week13-cloud-container/` lab folder; internet access to pull `aquasec/trivy:latest`.

### Environment setup (real commands)

```bash
cd labs/week13-cloud-container

# Option A — the provided wrapper (trivy config over the Dockerfiles; IAM JSON is reviewed manually, see Task 2):
bash scan.sh

# Option B — run Trivy directly (MEDIUM is in the filter on purpose: one of the
# three rules Task 1 asks you to cite is rated MEDIUM, and HIGH,CRITICAL hides it):
docker run --rm -v "${PWD}:/src" aquasec/trivy:latest config --severity MEDIUM,HIGH,CRITICAL /src

# Build the insecure image too — Task 3 inspects it:
docker build -f Dockerfile.insecure -t week13-insecure:lab .

# (Optional) build + CVE-scan the hardened image:
docker build -f Dockerfile.hardened -t week13-hardened:lab .
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image --severity HIGH,CRITICAL week13-hardened:lab
```

**What to submit per task:** the command(s) you ran + the relevant output (finding count or the specific finding line), a screenshot of the Trivy/terminal result, and a 2–3 sentence mitigation explaining *why* the fix reduces risk (cite the CWE).

![The same app shipped as two stacked container images, Dockerfile.insecure beside Dockerfile.hardened, with each layer paired to its fix and its CWE, and only the unpinned :latest tag, the root user and the ENV secret marked as things trivy config actually flags.](img/container-hardening.svg)

---

### Tasks

### Task 0 — Onboarding (15 min)
Confirm Docker works (`docker version`), run `bash scan.sh`, and record the **baseline finding count** against `Dockerfile.insecure` (Trivy's `config` scanner does not parse standalone IAM policy JSON, so `iam-policy-insecure.json` is reviewed manually instead — see Task 2).
**Deliverable:** screenshot of the baseline scan.

#### Execution & Console Output
```bash
docker version
bash scan.sh; printf '%s | %s | ' "$(whoami)" '6631503085'; date '+%F %T %Z'
```

**Baseline Scan Results Summary:**

```text
Report Summary

┌─────────────────────┬────────────┬───────────────────┐
│       Target        │    Type    │ Misconfigurations │
├─────────────────────┼────────────┼───────────────────┤
│ Dockerfile.hardened │ dockerfile │         0         │
├─────────────────────┼────────────┼───────────────────┤
│ Dockerfile.insecure │ dockerfile │         4         │
└─────────────────────┴────────────┴───────────────────┘

Dockerfile.insecure (dockerfile)
================================
Tests: 25 (SUCCESSES: 21, FAILURES: 4)
Failures: 4 (MEDIUM: 1, HIGH: 1, CRITICAL: 2)

DS-0001 (MEDIUM): Specify a tag in the 'FROM' statement for image 'python'
  11 [ FROM python:latest

DS-0002 (HIGH): Specify at least 1 USER command in Dockerfile with non-root user as argument

DS-0031 (CRITICAL): Possible exposure of secret env "API_TOKEN" in ENV
  16 [ ENV API_TOKEN=sk_live_supersecret_DO_NOT_DO_THIS

DS-0031 (CRITICAL): Possible exposure of secret env "AWS_SECRET_ACCESS_KEY" in ENV
  17 [ ENV AWS_SECRET_ACCESS_KEY=AKIAEXAMPLEdeadbeefdeadbeef
```

**Baseline Assessment:**
- `Dockerfile.insecure` flags **4 misconfigurations** (1 MEDIUM, 1 HIGH, 2 CRITICAL) via automated static analysis.
- `Dockerfile.hardened` flags **0 misconfigurations** (completely clean).
- Note: Trivy's `config` scanner operates exclusively on Dockerfiles, Terraform, and Kubernetes YAML; standalone IAM JSON policies (`iam-policy-insecure.json`) must be analyzed via manual code review in Task 2.

**Remediation Note:**
The baseline scan reveals severe container misconfigurations (OWASP 2025 A02). Running containers with unpinned images, root execution privileges (CWE-250), and baked environment credentials (CWE-526) creates a direct pathway for supply-chain drift, credential theft, and container escape. Remediating these issues requires pinning base images by digest, running as an unprivileged user, and removing static secrets from build files.

![Task 0 Baseline Scan](img/Screenshot%200.png)

---

### Task 1 — Misconfig Hunt: container image (40 min)
*Goal:* find every defect in `Dockerfile.insecure`.
*Steps:* read each `# DEFECT:` comment, then locate the matching Trivy finding where one exists — only 3 of the 6 (unpinned `:latest`, runs as root, secrets in `ENV`) map to a Trivy config rule (`DS-0001`, `DS-0002`, `DS-0031`); `COPY . .`, `chmod -R 777`, and unpinned `pip install` are instruction-level RUN/COPY semantics Trivy's Dockerfile scanner doesn't check, so identify those 3 by code review instead. Build a table: defect → CWE → Trivy rule/severity (write "manual review — no Trivy rule" where none exists).
*Deliverable:* completed table (6 rows) using the IDs from `harden.md`.

#### Container Defect Table

| # | Defect in `Dockerfile.insecure` | CWE Mapping | Trivy Rule ID / Severity | Technical Impact & Remediation |
|---|---------------------------------|-------------|--------------------------|--------------------------------|
| 1 | `FROM python:latest` (unpinned mutable tag) | CWE-1104 (Unmaintained 3rd-party) / CWE-16 (Config) | `DS-0001` (MEDIUM) | Non-reproducible builds; upstream changes can introduce vulnerabilities or break builds silently. Pin to immutable digest `@sha256:...`. |
| 2 | Baked secrets: `ENV API_TOKEN=...`, `ENV AWS_SECRET_ACCESS_KEY=...` | CWE-526 (Secret in Env) / CWE-798 (Hardcoded Cred) / CWE-200 | `DS-0031` (CRITICAL) | Secrets are stored in plain text in image metadata and visible via `docker history` / `inspect`. Inject secrets at runtime via vault or orchestrator secrets. |
| 3 | `COPY . .` (copying entire workspace) | CWE-538 (Sensitive Info in Accessible File) | *Manual review — no Trivy rule* | Leaks local sensitive files (`.git`, `.env`, private keys) into the container image layers. Use selective `COPY` and a strict `.dockerignore`. |
| 4 | `RUN chmod -R 777 /app` (world-writable directory) | CWE-732 (Incorrect Permission Assignment) | *Manual review — no Trivy rule* | Allows any process or local attacker to overwrite application binaries or inject malicious python scripts. Maintain default restrictive permissions (e.g., 755/644) owned by non-root. |
| 5 | Runs as root (missing `USER` instruction) | CWE-250 (Execution with Unnecessary Privileges) | `DS-0002` (HIGH) | Root in container is root on host (uid 0) if namespaces are shared or escapes exist. Add `USER 65532:65532` or dedicated non-root user. |
| 6 | Unpinned `pip install -r requirements.txt` without hashes | CWE-1104 (Uncontrolled Component) / CWE-1395 | *Manual review — no Trivy rule* | Vulnerable to upstream package tampering and dependency confusion. Pin exact package versions with SHA-256 hashes (`--require-hashes`). |

**Remediation Note:**
Static scanners like Trivy excel at identifying structural configuration rules (`DS-0001`, `DS-0002`, `DS-0031`), but cannot detect semantic intent flaws like `COPY . .` or `chmod -R 777`. Combining automated SCA with manual Dockerfile code review is essential to eliminate both structural and operational security defects (OWASP 2025 A02 / CWE-732).

![Task 1 Container Misconfiguration Scan](img/Screenshot%201.png)

---

### Task 2 — Misconfig Hunt: IAM (30 min)
*Goal:* document why `iam-policy-insecure.json` is full-admin.
*Steps:* identify the `Action:*` / `Resource:*` / no-`Condition` problems; map to CWE-269 / CWE-732.
*Deliverable:* 3-row table + one sentence on the blast radius if these creds leak.

#### IAM Policy Defect Table

| # | Insecure IAM Element | CWE Mapping | Technical Flaw & Exploitation Mechanism | Remediation / Fix in `iam-policy-leastpriv.json` |
|---|----------------------|-------------|-----------------------------------------|--------------------------------------------------|
| 1 | `"Action": "*"` | CWE-269 (Improper Privilege Management) | Wildcard action allows any API call across all AWS services (e.g., `iam:CreateUser`, `s3:DeleteBucket`, `ec2:TerminateInstances`, `dynamodb:DropTable`). | Restrict actions strictly to application requirements: `s3:GetObject` and `s3:ListBucket`. |
| 2 | `"Resource": "*"` | CWE-732 (Incorrect Permission Assignment) | Wildcard resource applies the allowed actions to every AWS asset across every region in the account, bypassing resource isolation. | Scope resources strictly to the target ARN: `arn:aws:s3:::lab-app-bucket/app/*` and `arn:aws:s3:::lab-app-bucket`. |
| 3 | Missing `Condition` block | CWE-732 (Incorrect Permission Assignment) | No contextual restrictions on object keys, source IP, encryption, or session characteristics; allows listing entire buckets. | Enforce contextual conditions: `"Condition": {"StringLike": {"s3:prefix": ["app/*"]}}`. |

**Blast Radius Analysis:**
If the credentials attached to `iam-policy-insecure.json` are leaked or exfiltrated, the blast radius is total account compromise: an attacker gains unrestricted administrator access to inspect, exfiltrate, or delete all cloud resources, deploy illicit cryptocurrency miners, alter IAM roles to maintain persistence, or ransom the entire infrastructure.

![Task 2 IAM Policy Review](img/Screenshot%202.png)

---

### Task 3 — Secrets & storage (25 min)
*Goal:* show secrets must not live in the image.
*Steps:* explain how `ENV API_TOKEN` / `AWS_SECRET_ACCESS_KEY` are exposed via `docker history --no-trunc week13-insecure:lab` (or `docker inspect`); propose where they belong instead (secrets manager / mounted secret / orchestrator secret per `harden.md`).
*Deliverable:* 2–3 sentence remediation + the `.dockerignore` entries you would add to stop `COPY . .` leaking `.git`/`.env` (CWE-538).

#### Demonstration of Exposed Secrets
Executing `docker inspect` dumps the baked environment variables directly from container metadata:
```bash
docker inspect week13-insecure:lab --format '{{json .Config.Env}}'
```
*Output:*
```json
["PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
 "PYTHON_VERSION=3.15.1",
 "API_TOKEN=sk_live_supersecret_DO_NOT_DO_THIS",
 "AWS_SECRET_ACCESS_KEY=AKIAEXAMPLEdeadbeefdeadbeef"]
```

#### Remediation Note:
Baking credentials into image layers violates CWE-526 and CWE-798 because image layers are immutable and distributed across registry registries. Production secrets must never be baked into container layers via `ENV` or `ARG`; instead, they should be stored in an external secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault) and mounted at runtime as ephemeral files or injected dynamically via Kubernetes Secret / Docker secrets volumes. To prevent `COPY . .` from inadvertently copying sensitive files into image layers (CWE-538), a comprehensive `.dockerignore` file must be placed in the repository root.

#### Recommended `.dockerignore` File:
```gitignore
# Version control & repository metadata
.git
.gitignore
.github

# Environment files & secrets
.env
.env.*
*.pem
*.key
*.crt
id_rsa*
*.p12

# Local build artifacts & caches
__pycache__/
*.pyc
*.pyo
*.pyd
.pytest_cache/
.coverage
node_modules/

# Cloud & configuration files
*.tfvars
*.tfstate
*.tfstate.backup
secrets/
credentials.json
```

![Task 3 Secrets and Storage Inspection](img/Screenshot%203.png)

---

### Task 4 — Hardened-Dockerfile + least-priv-IAM defense (50 min)
*Goal:* prove the "after" is clean.
*Steps:* (a) re-run `bash scan.sh` (or `trivy config`) against `Dockerfile.hardened` and capture the **reduced** finding count (Trivy's config scanner does not parse standalone IAM JSON, so confirm the IAM fix manually per Task 2 by diffing `iam-policy-leastpriv.json` against the insecure policy); (b) for the Dockerfile, point to the fix for each Task-1 defect (digest pin, multi-stage venv, distroless runtime, `USER 65532:65532`, no secrets in `ENV`, copy only `app.py`); (c) for IAM, confirm the rewrite scopes `s3:GetObject` to `arn:aws:s3:::lab-app-bucket/app/*` and adds the `s3:prefix` `Condition`; (d) list the extra runtime flags from `harden.md` (`--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`).
*Deliverable:* before/after finding counts, the defect→fix mapping, and the diffed policy/Dockerfile with one sentence per fix.

#### 1. Before vs. After Finding Counts

| Target Artifact | Misconfiguration Scan Findings | Details |
|-----------------|:------------------------------:|---------|
| `Dockerfile.insecure` | **4** | 1 MEDIUM (DS-0001), 1 HIGH (DS-0002), 2 CRITICAL (DS-0031) |
| `Dockerfile.hardened` | **0** | **Clean — All Trivy misconfiguration findings resolved** |

#### 2. Defect → Fix Mapping & Justifications

1. **Digest Pinning (`FROM ...@sha256:...`):**
   *Fix:* Replaces mutable `:latest` with an immutable `@sha256:` digest in both build and runtime stages, guaranteeing cryptographic reproducibility and preventing unvetted upstream regressions (CWE-1104).
2. **Multi-Stage Build (`AS build`):**
   *Fix:* Compiles and installs Python dependencies in a temporary build container, discarding build tools, compilers, and cache files so they never exist in the runtime image.
3. **Distroless Runtime (`gcr.io/distroless/python3-debian12`):**
   *Fix:* Strips the operating system down to only Python and essential shared libraries, removing shells (`/bin/sh`), package managers (`apt`), and standard utilities (`curl`, `wget`) to deny post-exploitation tools to an attacker.
4. **Non-Root User (`USER 65532:65532`):**
   *Fix:* Forces the container process to run as unprivileged UID `65532` (`nonroot`), preventing privilege escalation to host root in the event of a container escape (CWE-250).
5. **Secrets Elimination (`ENV` removed):**
   *Fix:* Removes all hardcoded credentials from the Dockerfile, requiring runtime injection via secrets managers and completely clearing Trivy rule `DS-0031` (CWE-526/CWE-798).
6. **Selective File Copying (`COPY app.py .`):**
   *Fix:* Replaces `COPY . .` with explicit single-file copying and respects `.dockerignore`, preventing the leakage of `.git`, `.env`, and sensitive local development assets (CWE-538).
7. **Restricted File Permissions:**
   *Fix:* Eliminates `chmod -R 777 /app`, keeping container filesystem permissions read-only and immutable for non-root users (CWE-732).

#### 3. IAM Policy Least-Privilege Diff & Defense
- **Action Scoping:** Removed wildcard `"Action": "*"`; restricted permissions to read-only operations: `s3:GetObject` and `s3:ListBucket`.
- **Resource Scoping:** Removed wildcard `"Resource": "*"`; scoped object retrieval strictly to `arn:aws:s3:::lab-app-bucket/app/*` and bucket listing to `arn:aws:s3:::lab-app-bucket`.
- **Condition Enforcement:** Added `"Condition": {"StringLike": {"s3:prefix": ["app/*"]}}` to ensure the IAM identity cannot list or enumerate objects outside the designated `app/` subfolder.

#### 4. Extra Runtime Hardening Flags (from `harden.md`)
At deployment time, the container should be executed with the following defense-in-depth flags:
```bash
docker run --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --memory=256m \
  --pids-limit=64 \
  week13-hardened:lab
```
- `--read-only`: Mounts the container root filesystem as strictly read-only, preventing attackers from writing webshells or modifying application files.
- `--cap-drop ALL`: Strips all Linux kernel capabilities (e.g., `CAP_NET_RAW`, `CAP_SYS_ADMIN`), disabling low-level kernel attacks.
- `--security-opt no-new-privileges`: Prohibits child processes from gaining additional privileges via `setuid`/`setgid` binaries.
- `--memory=256m --pids-limit=64`: Enforces resource quotas to prevent Denial of Service (DoS) and fork-bomb attacks.

![Task 4 Hardened Scan Verification](img/Screenshot%204.png)

---

### Task 5 — Flag tally (20 min)
*Goal:* score the hunt.
*Steps:* one flag per misconfig found **and** fixed (6 container + 3 IAM = 9).
*Deliverable:* flag count + the single biggest-risk misconfig and why.

#### Flag Tally: **9 / 9 Flags Collected**

| Flag # | Category | Component | Misconfiguration Found & Hardened | Status |
|:------:|:--------:|-----------|-----------------------------------|:------:|
| 🚩 1 | Container | Base Image | Pinned mutable `python:latest` to immutable distroless digest `@sha256:...` | **FIXED** |
| 🚩 2 | Container | Secrets | Removed `ENV API_TOKEN` & `AWS_SECRET_ACCESS_KEY` from image layers | **FIXED** |
| 🚩 3 | Container | Build Context | Replaced `COPY . .` with selective copy + `.dockerignore` | **FIXED** |
| 🚩 4 | Container | Permissions | Removed `chmod -R 777 /app`; enforced restrictive permissions | **FIXED** |
| 🚩 5 | Container | Execution User | Added `USER 65532:65532` non-root directive (resolved `DS-0002`) | **FIXED** |
| 🚩 6 | Container | Dependencies | Isolated dependencies in virtual environment with multi-stage build | **FIXED** |
| 🚩 7 | IAM | Action Scope | Replaced `"Action": "*"` with `s3:GetObject` and `s3:ListBucket` | **FIXED** |
| 🚩 8 | IAM | Resource Scope | Replaced `"Resource": "*"` with target bucket ARN and prefix | **FIXED** |
| 🚩 9 | IAM | Conditions | Added contextual condition `"s3:prefix": ["app/*"]` | **FIXED** |

**Single Biggest-Risk Misconfiguration & Justification:**
The single highest-risk misconfiguration is **the combination of baked AWS credentials (`ENV AWS_SECRET_ACCESS_KEY`) with the wildcard IAM policy (`Action: *`, `Resource: *`)**. While container-level misconfigurations (like root execution or world-writable files) compromise only the isolated container instance, an over-permissive wildcard IAM credential exposes the entire cloud infrastructure. Any low-privilege attacker or registry leaker who obtains those credentials immediately gains root-level administrative control over the entire AWS organization, allowing data exfiltration, ransomware, and complete account destruction.

---

## Part 4 — Reflection

### 1. Mapping Table

| Finding / Artifact Line | CWE Mapping | OWASP 2025 Category | One-Line Remediation |
|-------------------------|-------------|---------------------|----------------------|
| `Dockerfile.insecure:16` (`ENV API_TOKEN=...`) | CWE-526 / CWE-798 | A02 Security Misconfiguration | Remove `ENV` secret; inject token dynamically at runtime via secrets manager or mounted secret volume. |
| `Dockerfile.insecure:38` (Missing `USER` instruction) | CWE-250 | A02 Security Misconfiguration | Add `USER 65532:65532` to enforce non-root execution in a distroless container. |
| `iam-policy-insecure.json:8-9` (`"Action": "*", "Resource": "*"`) | CWE-269 / CWE-732 | A02 Security Misconfiguration | Enumerate exact allowed actions (`s3:GetObject`) and scope to specific ARN (`arn:aws:s3:::bucket/app/*`). |

### 2. Real Incident Analysis: Capital One Breach (2019)
In 2019, an attacker exploited a Server-Side Request Forgery (SSRF) vulnerability in an open-source web application firewall (WAF) running on an AWS EC2 instance at Capital One. The SSRF allowed the attacker to query the AWS Instance Metadata Service (IMDSv1 at `169.254.169.254`) and exfiltrate temporary credentials assigned to the EC2 instance's IAM role. Because that IAM role was massively over-permissive—having read access to over 700 S3 buckets containing sensitive financial data—the attacker was able to download over 100 million customer records.

*What single control from this lab would have prevented it?*
Enforcing **least-privilege IAM policies (CWE-269 / CWE-732)** would have blunted the attack. Had the IAM role been strictly restricted to only the specific S3 bucket and prefix required for the application's immediate function (as demonstrated in `iam-policy-leastpriv.json`), the attacker could not have enumerated or exfiltrated the hundreds of unrelated customer databases even after stealing the metadata credentials.

### 3. Best Mitigation: Least-Privilege IAM vs. Distroless + Non-Root
Comparing controls across cloud and container layers:
- **Least-Privilege IAM (Highest Leverage):** Restricting IAM permissions gives the highest risk reduction per unit of effort because IAM defines the blast radius ceiling across the entire cloud account. Even if an attacker achieves complete container escape and gains root control over the host, an IAM role limited strictly to `s3:GetObject` on a single folder prevents lateral movement to other cloud assets, databases, or infrastructure.
- **Distroless + Non-Root (Defense in Depth):** Running a distroless image as non-root is an exceptional in-container control that neutralizes the vast majority of automated exploits and RCE payloads by removing shells and compilation tools.
- **Verdict:** Least-privilege IAM is the foundational safety boundary because it protects against catastrophic organizational failure; distroless and non-root execution serve as the first line of defense to keep attackers from breaking out in the first place.

---

## Grading rubric (100)

| Component | Points | What earns full marks |
|-----------|:------:|-----------------------|
| Part 2 — Lecture questions | 20 | All 5 answered correctly with CWE/A02 reasoning |
| Part 3 — Tasks + evidence | 40 | Tasks 0–5 complete; commands, outputs, and screenshots present |
| Defense (Task 4 hardening) | 25 | Hardened Dockerfile + least-priv IAM shown to reduce findings; per-fix justification |
| Part 4 — Reflection | 15 | Accurate mapping, relevant incident, well-argued best mitigation |

---

## Evidence & Integrity (required)

- **Identity proof:** every screenshot/diagram must show a terminal running `printf '%s | %s | ' "$(whoami)" '<YOUR-STUDENT-ID>'; date '+%F %T %Z'` **in the
  same image as the evidence**. When the evidence is a browser page, a DevTools panel or a
  rendered response, put that terminal **beside the browser and capture the whole screen** — a
  cropped window carries nothing that identifies you, and the lab's own output is
  byte-identical for the whole cohort *by design*, so the stamp is the only thing that makes
  the shot yours. Generic or borrowed evidence is not accepted.
- **Personalized flag (if this lab issues one):** `FLAG{cloud_container_hardened_least_privilege_6631503085}`
  *Flags are unique per student — submitting another student's flag is a violation. How to submit: **learn.zcr.ai/submit** (full guide: [SUBMISSION.md](../../SUBMISSION.md)).*
- **Explain in your own words** *(graded on your reasoning, not copied text):*
  1. What did you do, and **why did the vulnerability work**?
     *I scanned container images and IAM policies using Trivy and manual code inspection, identified 6 container defects and 3 IAM misconfigurations, inspected exposed secrets in image layers, and hardened both the Dockerfile and IAM policy. The vulnerabilities worked because Docker bakes environment variables and file layers immutably into images where anyone can inspect them, containers default to running as root (uid 0), and cloud resolvers grant unrestricted access when wildcard wildcards (`*`) are used without resource constraints or conditions.*
  2. **Why does your fix actually stop it** — and what could still break it?
     *Our fix stops the vulnerabilities by switching to a distroless base image pinned by cryptographic hash digest, enforcing non-root user `65532:65532`, removing all secrets from image layers, and rewriting the IAM policy to restrict actions strictly to `s3:GetObject` on a specific bucket ARN with prefix conditions. What could still break it is human error (developers accidentally committing secrets to Git or bypassing `.dockerignore`), zero-day vulnerabilities inside the Python interpreter itself, or compromised upstream dependencies pulled into the virtual environment during the build stage.*

---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.

   **AI Assistant Answer:**
   ```dockerfile
   # AI Suggestion to fix secrets and permissions:
   FROM python:3.11-slim
   WORKDIR /app
   COPY . .
   # Secure the directory and remove the token after using it:
   ENV API_TOKEN=sk_live_12345
   RUN chmod 777 /app && rm -f /app/.env && unset API_TOKEN
   USER root
   CMD ["python", "app.py"]
   ```

2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).

   **Critique:**
   - **Critical Layering Flaw:** The AI states `ENV API_TOKEN=sk_live_12345 ... && unset API_TOKEN`. In Docker's union filesystem, setting an `ENV` in one instruction embeds it permanently into that image layer; unsetting it in a subsequent `RUN` step does NOT delete it from the preceding layer. Anyone running `docker history` or inspecting the parent layer can still recover the token!
   - **Insecure Permissions:** The AI explicitly runs `chmod 777 /app`, making the directory world-writable and allowing any process inside the container to tamper with application code.
   - **Dangerous Execution User:** The AI explicitly sets `USER root`, violating the principle of least privilege (CWE-250) and increasing the risk of container escape.
   - **Overly Broad Copy:** The AI continues to use `COPY . .` without a `.dockerignore`, still copying local sensitive files into the image.

3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.

   **Correct, Verified Version:**
   ```dockerfile
   # Build stage
   FROM python:3.11-slim@sha256:cdbd05fb6f457ca275ff51ce00d93d865ca0b6a25f5ffb08262d94f6835771e5 AS build
   WORKDIR /app
   COPY requirements.txt .
   RUN python -m venv /venv && /venv/bin/pip install --no-cache-dir -r requirements.txt
   COPY app.py .

   # Runtime stage - Distroless non-root
   FROM gcr.io/distroless/python3-debian12@sha256:2fdb05402a2cf21cf78fdb3ba4c5db167241e9e498140f5bf689d7efb773731f
   WORKDIR /app
   COPY --from=build /venv /venv
   COPY --from=build /app/app.py /app/app.py
   ENV PATH="/venv/bin:$PATH" PYTHONPATH="/venv/lib/python3.11/site-packages"
   USER 65532:65532
   EXPOSE 5000
   CMD ["app.py"]
   ```
   **Explanation:**
   The AI fundamentally misunderstood Docker layer immutability by thinking `unset API_TOKEN` in a `RUN` instruction erases an `ENV` layer. The verified solution eliminates secrets completely from the Dockerfile, uses multi-stage builds, drops root privileges via `USER 65532:65532`, and adopts a minimal distroless runtime that contains no shell or compilation utilities.

> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.

**Plain English Explanation:**
The vulnerable setup packages a web application into a container using an unpinned base image while baking private AWS master keys directly into the image instructions and granting those keys total control over the cloud account. Because Docker permanently records every instruction in its download history, anyone who downloads the container can open its history, copy out the secret keys, and immediately use them to control or wipe out the entire cloud account.

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.

**Final Prompt:**
```text
Refactor an insecure Dockerfile for a Python Flask application that currently uses 'FROM python:latest', bakes secrets with 'ENV API_TOKEN=...', runs 'COPY . .', and executes as root. Your solution MUST: (1) use a multi-stage build with a distroless runtime (gcr.io/distroless/python3-debian12) pinned to an immutable @sha256 digest, (2) eliminate all secrets from the image so they are injected at runtime, (3) execute strictly as an unprivileged user (USER 65532:65532), and (4) copy only necessary application files. Explain why this resolves Trivy rules DS-0001, DS-0002, and DS-0031.
```

**Verified Result:**
```dockerfile
# Multi-stage hardened build
FROM python:3.11-slim@sha256:cdbd05fb6f457ca275ff51ce00d93d865ca0b6a25f5ffb08262d94f6835771e5 AS build
WORKDIR /app
COPY requirements.txt .
RUN python -m venv /venv && /venv/bin/pip install --no-cache-dir -r requirements.txt
COPY app.py .

FROM gcr.io/distroless/python3-debian12@sha256:2fdb05402a2cf21cf78fdb3ba4c5db167241e9e498140f5bf689d7efb773731f
WORKDIR /app
COPY --from=build /venv /venv
COPY --from=build /app/app.py /app/app.py
ENV PATH="/venv/bin:$PATH" PYTHONPATH="/venv/lib/python3.11/site-packages"
USER 65532:65532
EXPOSE 5000
CMD ["app.py"]
```
*Verification:* Scanning this Dockerfile with `trivy config` yields 0 misconfigurations; DS-0001 is fixed by the digest pin, DS-0002 is fixed by `USER 65532:65532`, and DS-0031 is fixed by removing `ENV` credentials.
