# Command Injection Bypass Writeup

**Challenge**: Web page takes a directory input and lists its contents using `ls -l`. The flag is at `/flag`.

**Vulnerability**:  
The input is inserted into a shell command with incomplete filtering (blocks `; & | > < ( ) ` $` but misses newlines).

**Solution**:  
Use URL-encoded newline (`%0a`) to inject commands:
%0acat /flag%0a


**Why it works**:  
1. Newlines separate commands in shell (like `;`)  
2. The server doesn't filter newlines  
3. Turns into:
   ```bash
   ls -l 
   cat /flag
Fix:
Don't use shell=True or properly validate all command separators.
