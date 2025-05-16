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
