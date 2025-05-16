# Authentication Bypass via Unprotected Session Parameter

## Challenge Description
A web application with login functionality requires users to authenticate as "admin" to view the flag. The authentication check contains a critical flaw.

## Vulnerability
**Type**: Insecure Direct Object Reference (IDOR)  
**Location**: Session validation in `challenge_get()`  
**Root Cause**: Blind trust in client-supplied `session_user` parameter without server-side session verification.

## Exploitation
### Method
Directly set the `session_user` parameter to "admin":
```bash
curl "http://challenge.localhost/?session_user=admin"
Why It Works
The application checks only the URL parameter value

No validation of actual authentication state

Database credentials are completely bypassed

Impact
Full authentication bypass

Access to admin privileges without valid credentials

Disclosure of sensitive data (the flag)

Remediation
Implement proper session management using:

Signed cookies

Server-side session storage

Never use client-controlled parameters for authentication decisions

Add secondary verification (e.g., session tokens)

Lesson Learned
Client-provided data should never be trusted for authentication/authorization checks without server-side validation.

