# Command Injection Level: Bypassing Quote Context

## Challenge Overview

In this level, we are dealing with a **command injection vulnerability** that involves a specific context where user input is enclosed within **single quotes (`'`)** in a shell command. The developer intended to prevent command injection by enclosing the user input in quotes, but this can be bypassed by properly crafting the input to break out of the quotes and inject malicious commands.

### Code Breakdown

```python
command = f"ls -l '{arg}'"
````

In this code, the user input (`arg`) is directly inserted into the shell command after being enclosed in single quotes. This approach is meant to ensure that the user input is treated as a single string. However, when you pass user input within single quotes, **special shell characters** like `;`, `|`, and others are treated as literal characters inside the quotes.

To exploit this, we need to break out of the quotes and inject our own commands.

## Bypassing the Input Validation

### Problem with Single Quotes

When the user input is enclosed in single quotes, it is treated as a **literal string**, and any special characters (e.g., `;`, `|`) do not trigger any special behavior. Therefore, we cannot simply inject a `;` or `|` inside the quotes to chain commands.

### The Solution: Breaking Out of the Quotes

To exploit this, we must **break out of the single quotes**, inject our desired command, and then (if needed) **reopen the quote**.

#### Exploit Steps:

1. **Close the current quote** with a single quote (`'`).
2. **Inject the desired command**.
3. **Reopen the quote** (if necessary to balance the syntax).

For example:

```bash
ls -l ''; cat /flag; echo ''
```

* `'` closes the current quote.
* `;` separates the commands in the shell.
* `cat /flag` reads the flag.
* `echo ''` is a harmless command that ensures the shell stays valid.

Thus, the payload is:

```bash
'; cat /flag; echo ''
```

### URL-Encoded Payload

To submit this payload via a GET request, we need to URL-encode the special characters:

* `'` becomes `%27`
* `;` becomes `%3B`
* space becomes `%20`

The final URL becomes:

```bash
curl "http://challenge.localhost/initiative?destination=%27%3Bcat%20/flag%3Becho%20%27"
```

## Conclusion

By breaking out of the single quotes and injecting a valid shell command, we can read the contents of `/flag`. The `;` character allows us to chain the `cat /flag` command after the closing quote, which effectively leaks the flag.

### Final Solution

```bash
curl "http://challenge.localhost/initiative?destination=%27%3Bcat%20/flag%3Becho%20%27"
```

This command successfully executes the `cat /flag` command after escaping the single quotes, thus retrieving the flag.

---

### Key Takeaways

* **Single quotes** are used to escape special characters in shell commands, but they can be bypassed by breaking out of the quotes.
* **Command injection** vulnerabilities often arise when user input is passed directly into shell commands without proper sanitization.
* **Payload crafting** is crucial in bypassing input validation mechanisms like quotes.
