# **Secure Chat 4 – Write-Up**

## **Challenge Context**

Secure Chat 4 builds on SC3 but introduces a new layer of access control.
In SC3, we bypassed protections to modify user data using XSS and crafted payloads.
In SC4, the developers added an **Admin PIN check** to make sure only authenticated admins can modify *other users’* accounts.

The logic:

* Non-admins can **only modify their own password**.
* Admins can modify *any user’s data*, but only if they provide the correct `admin_pin`.
* Verification is delegated to an external binary (`check-admin-pin`), which validates the submitted `admin_pin` against the file `admin.pin`.

This means that **even if we inject requests as “admin”**, without knowing the PIN, modifications should fail.

---

## **Vulnerability**

The web application still allows **injection via stored XSS** in chat messages.
If we can plant JavaScript in Alice’s chat session, the script will run in the admin’s browser with admin privileges.

Our goal:

* Trigger the `/user/<username>/modify` endpoint.
* Provide a fake but correctly structured `admin_pin` field.
* Since the admin’s browser executes our script, the server accepts the input as coming from the admin.

---

## **Exploit Strategy**

1. **Reuse SC3 injection**: We still exploit the XSS channel to send crafted requests.
2. **Bypass Admin PIN check**: Instead of actually knowing the PIN, we base64-encode a chosen payload that mimics the expected input structure.

   * Our payload fills the `admin_pin` field with attacker-controlled bytes.
   * The key trick: we don’t need to *succeed* in pin validation. We just need the server to accept the injected request under admin context.
3. **Automate modification**: We build a malicious `<script>` payload that:

   * Decodes the fake PIN string.
   * Sends a `fetch` POST request to `/user/<target_user>/modify`.
   * Includes `username`, `password`, and our crafted `admin_pin` in the POST body.

---

## **Payload**

The crafted payload in your modified `rename()` function looks like this (simplified):

```javascript
<script>
dec_data = window.atob("QUFBQUFB...VYSQAAAAAAA");  
fetch("http://127.0.0.1/user/alice/modify", {
    method: "POST",
    headers: {"Content-Type": "application/x-www-form-urlencoded"},
    credentials: "include",
    body: "username=newname&password=A&admin_pin=" + dec_data
}).then(r => r.text()).then(console.log);
</script>
```

* `dec_data`: Our fake PIN, base64-decoded inside the browser.
* `credentials: "include"`: Ensures the request carries the admin’s session cookies.
* Body: Contains the malicious rename request with our fake PIN.

---

## **Execution Flow**

1. Attacker sends the malicious payload to the victim’s chat.
2. Admin opens the chat → payload executes in their browser.
3. The script automatically submits the malicious request to `/user/<victim>/modify`.
4. The admin’s session and fake pin bypass the server-side protections.
5. User data (like username) is successfully modified.

---

## **Lessons Learned**

* **New defense isn’t enough**: Adding a PIN requirement doesn’t matter if XSS is still possible, because an attacker can always make the admin’s browser supply any value.
* **Defense in depth**: Sanitization and output encoding should have been applied to prevent XSS in the first place.
* **Admin verification flaws**: Tying admin privileges only to client-supplied form fields (`admin_pin`) makes the system vulnerable to client-side injection attacks.

---

✅ **In short**:
The difference in SC4 was the new `admin_pin` check, but we bypassed it using **XSS to trick the admin’s browser** into supplying the `admin_pin` field.


