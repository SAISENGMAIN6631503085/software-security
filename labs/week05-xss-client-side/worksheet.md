# Worksheet 5 — Cross-Site Scripting & Client-Side Risks (3 hrs)

> **Course:** Software Security (KOSEN69) · **Week 5**
> **Aligned:** OWASP 2025 **A05 Injection** · **CWE-79** (XSS), **CWE-352** (CSRF), **CWE-1004** (cookie without HttpOnly)
> **Signature game:** ⛳ **XSS Golf** — fire `alert(1)` in the fewest characters possible. Lower payload length = lower score = better. Par for reflected is the `<img>` vector; can you go under par?

> ⚠️ **Ethics note:** Use only the provided `vulnerable_app.py` sandbox and your own Juice Shop container. Stealing real users' cookies or sessions is illegal. All "session theft" steps here target the sandbox cookie `session=abc123` only.

## Part 1 — Student Information

| Name | Student ID | Date | Group | AI Tools Used |
|------|-----------|------|-------|---------------|
| Sai Seng Main | 6631503085 | 2026-09-14 | | Claude / Antigravity (conceptual verification & audit) |

## Part 2 — Lecture Questions

Answer in 2–4 sentences each.

1. Distinguish **reflected**, **stored**, and **DOM-based** XSS by *where* the untrusted data is injected and *when* it executes. Which two does our `vulnerable_app.py` implement, and at which routes?

   **Answer:** Reflected XSS occurs when untrusted data from an immediate request (like a URL parameter) is reflected by the server into the HTTP response page and executes immediately in the victim's browser upon navigation. Stored XSS occurs when untrusted payload data is persisted in a database or server state and subsequently executed whenever any user views the stored content. DOM-based XSS occurs entirely client-side when browser JavaScript processes untrusted data from a source (like `location.hash`) into a dangerous sink (`innerHTML` or `eval`) without server involvement. Our `vulnerable_app.py` implements reflected XSS at `/hello` (via the `name` parameter) and stored XSS at `/comments` (via POST `body` appended to `COMMENTS`).

2. How does **contextual output encoding** (`markupsafe.escape`) stop `<script>` from executing? Why is HTML-context encoding different from JavaScript- or URL-context encoding?

   **Answer:** Contextual output encoding converts sensitive syntactic characters into their inert entity representations (e.g., `<` becomes `&lt;`, `>` becomes `&gt;`, `&` becomes `&amp;`, and `"` becomes `&#34;`), forcing the HTML parser to treat the data strictly as displayable text rather than markup tags. Different interpreters apply different parsing rules: HTML entity encoding works inside standard HTML bodies, but inside a JavaScript context (e.g., `<script>var x = '...';</script>`), HTML entities are not decoded before execution, requiring Unicode or backslash hex escapes (`\x22`) instead. Similarly, inside a URL context (e.g., `href`), parameters require percent-encoding (`%20`) rather than HTML entities to prevent schema manipulation like `javascript:`.

3. Explain how a strict **Content-Security-Policy** (`script-src 'self'`) defeats an *injected* inline script even when encoding is missing.

   **Answer:** A strict Content-Security-Policy with `script-src 'self'` restricts executable script execution to only external script files originating from the identical origin (same protocol, host, and port). The browser's script execution engine automatically refuses to parse and execute inline script blocks (`<script>...</script>`) and inline event handlers (`onload`, `onerror`), blocking injected scripts at the browser enforcement layer even if the backend server failed to encode the markup.

4. What do the cookie flags **HttpOnly**, **SameSite**, and **Secure** each protect against? Map each to a concrete attack (cookie theft via XSS, CSRF, network sniffing).

   **Answer:** **HttpOnly** prevents client-side scripts from reading the cookie via `document.cookie`, defeating cookie theft via XSS attacks. **SameSite** (`Strict` or `Lax`) restricts the browser from sending cookies on cross-origin requests, directly blunting Cross-Site Request Forgery (CSRF). **Secure** ensures the browser transmits the cookie strictly over encrypted HTTPS connections, protecting against network eavesdropping and sniffing attacks on untrusted networks (e.g., open public Wi-Fi).

5. Why does **CSRF** (CWE-352) work even without any script injection, and how does `SameSite=Strict` plus the same-origin policy blunt it?

   **Answer:** CSRF exploits the browser's default credential-handling behavior, where ambient credentials (session cookies) are automatically attached by the browser to every outgoing HTTP request targeting the destination origin, regardless of which external domain originated the request. `SameSite=Strict` instructs the browser to completely withhold the session cookie whenever a request is initiated from a different third-party origin or top-level navigation, meaning the forged cross-site request arrives at the server without authentication credentials. Combined with the Same-Origin Policy (SOP), which prevents the attacker's script from reading cross-origin response data, CSRF attempts are neutralized before any authenticated state changes can occur.

![Stored XSS carries the attacker's payload through the server to the victim, where it runs in the victim's origin and reads the cookie, while CSRF runs the opposite way and has the victim's own browser attach that cookie to the attacker's forged POST.](img/xss-and-csrf.svg)

## Part 3 — Hands-on Lab (150 min)

**Learning goals:** land reflected + stored XSS, abuse a JS-readable cookie, build a CSRF PoC against the comment board, then prove `fixed_app.py` blocks all of it.

**Prerequisites:** Docker + Docker Compose, a browser with DevTools, a text editor. Working dir: `labs/week05-xss-client-side/`.

### Environment setup

```bash
cd labs/week05-xss-client-side
docker compose up            # python:3.12-slim + flask, runs vulnerable_app.py
# vulnerable app -> http://localhost:8080   (service name: xss-lab, port 8080)
```
Optional secondary target (for DOM XSS, which our app does not expose):
```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop       # -> http://localhost:3000
```

**What to submit per task:** the exact **payload**, a **screenshot** of the alert/effect, and a **2–3 sentence mitigation**.

---

**Task 0 — Onboarding (5 min).** Browse `http://localhost:8080/`. Open DevTools → Application → Cookies and confirm `session=abc123` is set with **no HttpOnly / SameSite**. Screenshot it. *Deliverable: screenshot.*

- **Action:** Open `http://localhost:8080/` in browser. Inspect DevTools -> Application -> Storage -> Cookies -> `http://localhost:8080`.
- **Observation:** `session` cookie value is `abc123`. The `HttpOnly`, `Secure`, and `SameSite` columns are all blank/unset.
- **Screenshot:**

  ![Task 0 Output](img/Screenshot%200.png)

**Task 1 — Reflected XSS + XSS Golf (30 min) ⛳.**
- *Goal:* execute JS via `/hello`, then minimize the payload.
- *Steps:* visit `/hello?name=<script>alert(1)</script>`, then the alternate `/hello?name=<img src=x onerror=alert(1)>` (useful when `<script>` tags specifically are filtered — note it's actually 3 characters longer, not shorter). Record each payload's character count for your golf score.
- *Deliverable:* both payloads + char counts + screenshot of `alert(1)` + your lowest score.

- **Payloads & Character Counts:**
  1. `<script>alert(1)</script>` — **25 characters**
  2. `<img src=x onerror=alert(1)>` — **28 characters**
  3. Shortest golf vector: `<svg onload=alert(1)>` — **22 characters**
- **Lowest Golf Score:** 22 characters (`<svg onload=alert(1)>`)
- **Mitigation (2–3 sentences):** Contextually encode all user-supplied data using HTML entity encoding (`markupsafe.escape()` in Flask) before echoing it into the HTML document. In addition, implement a Content-Security-Policy header restricting script execution to authorized origins (`script-src 'self'`), preventing inline script payloads from running even if reflection occurs.
- **Screenshot:**

  ![Task 1 Output](img/Screenshot%201.png)

**Task 2 — Stored XSS (30 min) ⛳.**
- *Goal:* persist a script that runs for every visitor of `/comments`.
- *Steps:* POST a comment with body `<script>alert(document.cookie)</script>` (use the form or `curl -d 'body=...'`). Reload `/comments` and watch the cookie pop.
- *Deliverable:* payload + screenshot of the alert showing `session=abc123` + why stored XSS is more dangerous than reflected.

- **Payload:** `<script>alert(document.cookie)</script>` (posted to `/comments`)
- **Output:** Alert popup displaying `session=abc123`.
- **Why Stored XSS is more dangerous than Reflected:** Stored XSS does not require social engineering or enticing a victim to click a specially crafted malicious link. The payload is stored permanently on the server and executes automatically and unconditionally for any legitimate user who accesses the compromised page, making it scalable for mass session hijacking and persistent worm propagation.
- **Mitigation (2–3 sentences):** Use templating engines that enforce automatic contextual escaping by default (such as Jinja2's `render_template` or `render_template_string`). Never concatenate raw database strings into HTML output without entity escaping, and enforce strict CSP policies.
- **Screenshot:**

  ![Task 2 Output](img/Screenshot%202.png)

**Task 3 — Cookie theft via XSS (25 min).**
- *Goal:* show the cookie is readable by injected JS because **HttpOnly is missing** (CWE-1004).
- *Steps:* store `<script>new Image().src='http://localhost:8080/hello?name='+document.cookie</script>` (a beacon), or simply `<img src=x onerror=alert(document.cookie)>`. Observe the cookie value being exfiltrated/displayed.
- *Deliverable:* payload + screenshot + 2–3 sentences on how HttpOnly would have stopped this.

- **Payload:** `<img src=x onerror=alert(document.cookie)>` (or beacon `<script>new Image().src='http://localhost:8080/hello?name='+document.cookie</script>`)
- **Output:** The browser executes the handler and reveals `session=abc123` to client JavaScript.
- **How HttpOnly would have stopped this (2–3 sentences):** Setting the `HttpOnly` flag on the `session` cookie instructs the browser engine to block all client-side script access to the cookie through the `document.cookie` DOM API. Even if an attacker successfully achieves script execution via XSS, `document.cookie` will not return the session token, preventing credential theft and session hijacking.
- **Screenshot:**

  ![Task 3 Output](img/Screenshot%203.png)

**Task 4 — CSRF PoC (30 min).**
- *Goal:* make a third-party page force a state-changing POST to `/comments`.
- *Steps:* create a local `csrf.html` with an auto-submitting form targeting the board (no token exists, cookie has no SameSite, so the browser attaches `session` cross-site):
  ```html
  <body onload="document.forms[0].submit()">
    <form action="http://localhost:8080/comments" method="POST">
      <input name="body" value="CSRF posted this comment">
    </form>
  </body>
  ```
  Open the file and confirm the comment appears on `/comments`.
- *Deliverable:* the HTML + screenshot of the forged comment + why `SameSite=Strict` blocks it.

- **CSRF HTML Code:**
  ```html
  <!DOCTYPE html>
  <html>
  <body onload="document.forms[0].submit()">
    <form action="http://localhost:8080/comments" method="POST">
      <input type="hidden" name="body" value="CSRF posted this comment">
    </form>
  </body>
  </html>
  ```
- **Output:** Opening `csrf.html` in the browser immediately submits the POST request to `http://localhost:8080/comments`, creating a comment reading `"CSRF posted this comment"`.
- **Why `SameSite=Strict` blocks it:** When a cookie has `SameSite=Strict`, the browser guarantees that the cookie will never be sent with cross-site requests, including form submissions and links originated from external sites. Because the forged request from `csrf.html` arrives without the authenticated session cookie, the server will either reject the request as unauthenticated or handle it without user context.
- **Screenshot:**

  ![Task 4 Output](img/Screenshot%204.png)

```sim
xss-context
```

**Task 5 — Defend / fix it (30 min) 🛡️.**
- *Goal:* prove `fixed_app.py` blocks Tasks 1–3, then show that Task 4's CSRF PoC still gets through and explain why.
- *Steps:* stop the vulnerable container (`Ctrl-C`), then:
  ```bash
  docker compose run --rm --service-ports xss-lab bash -c "pip install --no-cache-dir flask && python fixed_app.py"
  ```
  Re-fire each payload. Expected: `/hello` renders the script **as text** (escape, L21), stored comments render literally (Jinja autoescape, L30–33), a strict CSP header is now present as defense-in-depth (`Content-Security-Policy: script-src 'self'`, L12 — check DevTools → Network → Response Headers; escaping already neutralizes these payloads, so no CSP *violation* fires in the console), and the cookie now has `HttpOnly; SameSite=Strict; Secure` (L42). Then re-run Task 4's `csrf.html` PoC against `fixed_app.py`: it **still posts the forged comment** — `/comments` (L25–28) never checks the `session` cookie or a CSRF token before accepting a POST, so hardening the cookie only stops the browser from *attaching* it cross-site; it doesn't stop the request itself from being processed.
- *Deliverable:* screenshots of escaped output + the CSP response header + the hardened cookie flags + the still-successful Task 4 forgery against `fixed_app.py`, with 2–3 sentences on why cookie hardening alone doesn't close CSRF here (no server-side check tied to the cookie, and no CSRF token).

- **Defense Results & Proof:**
  1. **Reflected XSS on `/hello`:** Script tags are rendered as literal text on screen (`escape()`, line 21).
  2. **Stored XSS on `/comments`:** Jinja2 autoescaping treats stored input as raw text (`render_template_string()`, lines 30–33).
  3. **Strict CSP Header:** `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'` is present in HTTP response headers (line 12).
  4. **Hardened Cookie:** `Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict` prevents script access and cross-site transmission (line 42).
  5. **Task 4 CSRF still succeeds:** The forged comment is still accepted because `/comments` (lines 25–28) accepts any incoming POST without validating an anti-CSRF token or requiring authenticated session verification.
- **Why cookie hardening alone doesn't close CSRF here (2–3 sentences):** Hardening cookies with `SameSite=Strict` only prevents the browser from attaching session cookies across sites. If the application endpoint does not check or require session authentication to process a POST request, any unauthenticated cross-origin request will still execute state changes. Complete CSRF defense requires synchronizer token validation (CSRF tokens) checked server-side for all state-changing requests.
- **Screenshot:**

  ![Task 5 Output](img/Screenshot%205.png)

## Part 4 — Reflection

1. **CWE/OWASP mapping:** map your reflected/stored XSS to **CWE-79** and your CSRF PoC to **CWE-352**, both under OWASP 2025 **A05 Injection** (CSRF historically A01/A05).

   **Answer:**
   - **Reflected & Stored XSS:** Maps to **CWE-79** (Improper Neutralization of Input During Web Page Generation / Cross-Site Scripting) and OWASP 2025 **A05 Injection**.
   - **Missing Cookie Protections:** Maps to **CWE-1004** (Sensitive Cookie Without 'HttpOnly' Flag), categorized under **A05 Injection** / A02 Security Misconfiguration.
   - **CSRF PoC:** Maps to **CWE-352** (Cross-Site Request Forgery), aligned with OWASP 2025 **A05 Injection** and historically **A01 Broken Access Control**.

2. **Real breach:** the **2018 British Airways breach** (~380k payment records) used malicious JavaScript (Magecart) injected into the site to skim card data — a client-side script-injection failure. In 3–4 sentences relate it to this lab's XSS and CSP lessons.

   **Answer:** In the 2018 British Airways breach, attackers modified a 22-line JavaScript file hosted on the airline's website (Magecart attack) to siphon credit card data from booking forms to an attacker-controlled drop server. This directly parallels this lab's XSS lessons: once untrusted or malicious JavaScript executes in the victim's origin, it possesses unrestricted access to DOM data, form inputs, and ambient user actions. A strict Content-Security-Policy (`script-src` and `connect-src`) and Subresource Integrity (SRI) would have prevented unauthorized third-party scripts from executing and blocked exfiltration beacons to external domains.

3. **Best mitigation:** between output encoding, a strict CSP, and HttpOnly+SameSite cookies, which gives the broadest defense-in-depth, and why is "encoding alone" still risky?

   **Answer:** A strict Content-Security-Policy (CSP) provides the broadest defense-in-depth because it acts as an independent browser-enforced security boundary that neutralizes injected scripts across the entire origin regardless of where server-side encoding mistakes occur. Output encoding alone remains risky because developers must correctly apply context-dependent encoding across multiple nested contexts (HTML body, attributes, JavaScript variables, URLs, and CSS), where a single omission or mismatched encoding function immediately reintroduces executable XSS vulnerabilities.

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
- **Personalized flag (if this lab issues one):** *None (Week 5 scores on alert execution & CSRF proof)*
- **Commit Link:** https://github.com/SAISENGMAIN6631503085/software-security/commit/ae99638b1a7a0f4514dc16a464919c4fcd4ca39a
- **Pull Request:** https://github.com/nutthakorn7/software-security/pull/89
  *Flags are unique per student — submitting another student's flag is a violation. How to submit: **learn.zcr.ai/submit** (full guide: `SUBMISSION.md` in the repo root).*
- **Explain in your own words** *(graded on your reasoning, not copied text):*
  1. What did you do, and **why did the vulnerability work**?
     **Answer:** I executed reflected XSS on `/hello`, stored XSS on `/comments`, stole session cookies via unhardened cookies, and constructed a cross-site POST CSRF exploit. The vulnerabilities worked because user input was concatenated directly into HTML response strings without contextual sanitization or entity encoding, cookies lacked HttpOnly/SameSite restrictions, and state-changing actions lacked anti-CSRF token verification.
  2. **Why does your fix actually stop it** — and what could still break it?
     **Answer:** The fix stops XSS by applying contextual HTML entity encoding via `markupsafe.escape` and Jinja2 autoescaping, restricts script sources via a strict CSP header (`script-src 'self'`), and secures cookies with `HttpOnly; SameSite=Strict; Secure`. However, it could still be broken if user input is reflected into unsafe JavaScript code blocks (`eval`, `innerHTML`), if CSP policy directives are loosened with `'unsafe-inline'`, or if unauthenticated POST endpoints remain open without CSRF tokens.

---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.

   **AI Prompt:** *"How do I protect my Flask application from Cross-Site Scripting (XSS) when displaying user names?"*

   **AI Answer:**
   > *"To protect against XSS in Flask, you can sanitize user input by stripping `<script>` tags using regular expressions before rendering it: `clean_name = re.sub(r'<\s*script[^>]*>.*?<\s*/\s*script\s*>', '', name, flags=re.I | re.DOTALL)` and then return `<h1>Hello, ' + clean_name + '!</h1>'`. This removes any malicious script blocks."*

2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).

   **Critique:**
   - **Insecure line:** `clean_name = re.sub(r'<\s*script[^>]*>.*?<\s*/\s*script\s*>', '', name, flags=re.I | re.DOTALL)`
   - **Flaw:** Blacklisting `<script>` tags using regular expressions is notoriously easy to bypass. It completely misses non-script execution vectors like event handlers (`<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`), iframe injections, and nested bypasses (e.g., `<scr<script>ipt>`). Blacklist sanitization is fundamentally flawed compared to proper contextual output encoding.

3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.

   **Verified Secure Code:**
   ```python
   from flask import Response
   from markupsafe import escape


   @app.route("/hello")
   def hello():
     name = request.args.get("name", "world")
     html = "<h1>Hello, " + str(escape(name)) + "!</h1>"
     return Response(html, mimetype="text/html")
```

   **Explanation:** The AI's answer was insufficient because it attempted regex-based blacklist filtering, which cannot anticipate every HTML tag or JavaScript event execution context. The correct approach uses `markupsafe.escape()`, which neutralizes all HTML special characters (`<`, `>`, `&`, `"`, `'`) into harmless character entities, ensuring that the browser always treats the input as display text rather than executable markup.

> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.

**Answer:** The vulnerable web application accepts comments and names directly from visitors and pastes them raw into the website's HTML page without cleaning them. Because web browsers read HTML tags to determine how to format text and run programs, any visitor can submit code tags disguised as text, tricking other visitors' browsers into executing the attacker's script and stealing their private session information.

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.
*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*

**Final Prompt:**
> *"Refactor the following vulnerable Python Flask endpoint to completely eliminate CWE-79 (XSS): `def hello(): name = request.args.get('name', 'world'); return Response('<h1>Hello, ' + name + '!</h1>', mimetype='text/html')`. Requirements: (1) Use contextual output escaping via `markupsafe.escape()`; (2) Add a strict Content-Security-Policy header (`default-src 'self'; script-src 'self'; object-src 'none'`) to the response; (3) Explain why regex filtering was avoided."*

**Verified Result:**
```python
from flask import Response, request
from markupsafe import escape


@app.route("/hello")
def hello():
  name = request.args.get("name", "world")
  # 1. Contextual output encoding
  html = "<h1>Hello, " + str(escape(name)) + "!</h1>"
  resp = Response(html, mimetype="text/html")
  # 2. Defense-in-depth CSP
  resp.headers["Content-Security-Policy"] = (
      "default-src 'self'; script-src 'self'; object-src 'none'"
  )
  resp.headers["X-Content-Type-Options"] = "nosniff"
  return resp
```

**Verification:** When requesting `/hello?name=<script>alert(1)</script>`, the response returns `&lt;script&gt;alert(1)&lt;/script&gt;`, which renders as plain readable text in the browser. Even if HTML injection occurred, the CSP header blocks inline script execution from firing.
