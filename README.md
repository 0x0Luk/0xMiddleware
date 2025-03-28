# CVE-2025-29927: Next.js Middleware Bypass Exploit Tool

This tool demonstrates and automates the exploitation of **CVE-2025-29927**, a vulnerability in **Next.js** that allows an attacker to **bypass middleware checks** (like authentication) by abusing the internal header `x-middleware-subrequest`.

## 🔧 How the Exploit Works

Next.js internally uses the header `x-middleware-subrequest` to prevent infinite loops in recursive requests. However, this header is **not protected against external manipulation** in certain versions, allowing a malicious actor to spoof it.

By setting this header manually, middleware logic responsible for enforcing **authentication, redirects, logging, or filtering** is **completely skipped**.

### What This Tool Does:
- Sends a baseline request (without header)
- Iterates over multiple payloads for `x-middleware-subrequest`
- Compares response body content
- Detects and reports:
  - ✅ **Confirmed Bypass**: status `403` becomes `200`
  - ⚠️ **Response Difference**: status stays the same, but content differs (partial bypass or unintended behavior)
- Saves results in clean output files for further analysis

---

## 🔖 Affected Versions

- **Next.js 15.x** < `15.2.3`
- **Next.js 14.x** < `14.2.25`
- **Next.js 13.x** < `13.5.9`

### Vulnerable Targets:
- Self-hosted Next.js apps using middleware (e.g., `next start` with output: `standalone`)
- Applications where middleware is used for authentication or security enforcement, and not re-validated at runtime

### Not Vulnerable:
- Apps hosted on **Vercel** or **Netlify**
- Static exports (`next export`)

---

## 👁️ Exploit in Action

### Example Middleware Bypass:
```
Normal Request:
  GET /admin --> 403 Forbidden

Request with Header:
  GET /admin --> 200 OK
  x-middleware-subrequest: middleware 
```

Even if the target checks auth via middleware, **this bypasses it completely**.

---

## ⚖️ Usage

### 📂 Input
Provide a file (`urls.txt`) with one URL per line.

```
https://target.com/admin
https://target.com/_next/static/asset.js
```

### 🔧 Run the Tool
```bash
python3 middleware_bypass_checker.py urls.txt
```

### ⚙️ What It Does
- Sends requests to each URL with and without the exploit header
- Uses multiple payload variations:
  - `middleware`
  - `pages/_middleware`
  - `src/middleware`
  - (and more)
 
- Logs:
  - ✅ `middleware_bypass_confirmed.txt`: for true bypasses (403 → 200)
  - ⚠️ `middleware_response_diff.txt`: when response content differs

---

## 🚨 Fix / Mitigation

**Upgrade Next.js immediately** to a secure version:
- `15.2.3+`
- `14.2.25+`
- `13.5.9+`

Also:
- Ensure middleware validation is **rechecked server-side** (e.g. via `getServerSideProps`, JWT, sessions)
- Sanitize or reject external usage of internal headers

---

## ✨ Output Sample
```
[✔] Bypass successful: https://target.com/admin (payload: middleware)
[•] Response difference detected: https://target.com/login (payload: src/middleware)

[✔] Found 3 bypasses > middleware_bypass_confirmed.txt
[•] Found 5 response diffs > middleware_response_diff.txt
```

---

## 🔗 References
- ✨ CVE: https://nextjs.org/blog/cve-2025-29927

---



