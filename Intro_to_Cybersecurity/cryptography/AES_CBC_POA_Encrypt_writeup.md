# Padding Oracle Attack: Message Forging Writeup

## Challenge Overview

This challenge demonstrates how a Padding Oracle Attack (POA) can be used not only to **decrypt** messages, but also to **forge/encrypt** arbitrary messages without knowing the encryption key. The goal is to craft a ciphertext that decrypts to the exact message `"please give me the flag, kind worker process!"` to retrieve the flag.

## Understanding the Challenge Setup

### Worker Script Analysis
```python
if plaintext == "please give me the flag, kind worker process!":
    print("Victory! Your flag:")
    print(open("/flag").read())
```

The worker script:
- Accepts hex-encoded ciphertext via `TASK: <hex>`
- Decrypts using AES-CBC 
- Returns different responses for padding errors vs successful decryption
- Only gives the flag for the exact string `"please give me the flag, kind worker process!"`

### The Oracle
The padding oracle is the different behavior:
- **Padding Error**: Returns `"Error: ..."` 
- **Valid Padding**: Returns `"Unknown command!"` or other messages
- This difference allows us to determine if our crafted ciphertext has valid padding

## Padding Oracle Attack Theory

### Standard POA (Decryption)
In a typical POA for decryption:
1. We have a target ciphertext block `C[i]`
2. We craft a fake previous block and try all 256 values for each byte
3. When we get valid padding, we know: `crafted_byte ⊕ intermediate = padding_value`
4. We can solve for the intermediate state: `intermediate = crafted_byte ⊕ padding_value`
5. The plaintext is: `plaintext = intermediate ⊕ actual_previous_block`

### POA for Encryption/Forging
For message forging, we reverse this process:
1. We choose our desired plaintext
2. We find the intermediate state of any ciphertext block using standard POA
3. We calculate what the previous ciphertext block should be: `prev_cipher = intermediate ⊕ desired_plaintext`
4. This `prev_cipher` block will make the next block decrypt to our desired plaintext

## Attack Implementation

### Step 1: Message Preparation
```python
target_message = b"please give me the flag, kind worker process!"
padded_message = pad(target_message, BLOCK_SIZE)  # PKCS#7 padding
```

The target message (45 bytes) becomes 48 bytes after padding, requiring 3 blocks of 16 bytes each.

### Step 2: Intermediate State Discovery
For each ciphertext block we want to control, we use the standard POA technique:

```python
def find_intermediate_block(ciphertext_block):
    intermediate = [0] * BLOCK_SIZE
    
    for byte_pos in reversed(range(BLOCK_SIZE)):
        padding_val = BLOCK_SIZE - byte_pos
        crafted = bytearray(BLOCK_SIZE)
        
        # Set known bytes to produce desired padding
        for i in range(byte_pos + 1, BLOCK_SIZE):
            crafted[i] = intermediate[i] ^ padding_val
        
        # Try all values for current byte
        for guess in range(256):
            crafted[byte_pos] = guess
            test_ct = bytes(crafted) + ciphertext_block
            
            if oracle(test_ct.hex()):  # Valid padding found
                intermediate[byte_pos] = guess ^ padding_val
                break
    
    return bytes(intermediate)
```

### Step 3: Block Forging Process
We work backwards through our message blocks:

1. **Start with a dummy block**: We create an arbitrary ciphertext block `dummy_block`
2. **Find its intermediate state**: Use POA to discover `intermediate_state`
3. **Calculate required previous block**: `prev_block = intermediate_state ⊕ desired_plaintext`
4. **Repeat**: Use the `prev_block` as the next block to forge, and repeat the process

### Step 4: Complete Message Construction
```
IV -> Block1 -> Block2 -> DummyBlock
  |      |        |          |
  |      |        |          v
  v      v        v    [garbage - we don't care]
Text1  Text2   Text3
```

Where:
- `IV ⊕ decrypt(Block1) = Text1`  
- `Block1 ⊕ decrypt(Block2) = Text2`
- `Block2 ⊕ decrypt(DummyBlock) = Text3`

The final plaintext is `Text1 + Text2 + Text3` which equals our target message.

## Key Insights

### Why This Works
1. **CBC Mode Property**: In CBC mode, `Plaintext[i] = Decrypt(Ciphertext[i]) ⊕ Ciphertext[i-1]`
2. **Controllable XOR**: If we know the decrypt result (intermediate state), we can control the plaintext by choosing our ciphertext block
3. **Padding Oracle**: Gives us the ability to discover intermediate states without knowing the key

### Why Previous Approaches Failed
1. **Anchor Block Problem**: Using existing ciphertext blocks created uncontrolled garbage at the end
2. **Exact Match Requirement**: The worker requires exact string equality - any extra bytes cause failure
3. **Incomplete Control**: We need to control the entire message, not just parts of it

## Attack Execution Results

```
Target message: please give me the flag, kind worker process!
Padded message: 48 bytes (3 blocks)

[Forging process for each block...]
Byte 15: intermediate=0x92
Byte 14: intermediate=0x45
[... continues for all bytes ...]

Final forged ciphertext: [hex string]
Worker response: Victory! Your flag: [flag]
```

## Defense Mechanisms

### How to Prevent POA
1. **Authenticated Encryption**: Use modes like GCM that provide integrity
2. **MAC-then-Encrypt**: Add HMAC verification before decryption
3. **Constant-Time Responses**: Ensure identical responses for all decryption failures
4. **Rate Limiting**: Limit the number of decryption attempts

### Why This Attack is Dangerous
- **No Key Required**: Complete message forging without knowing the encryption key
- **Arbitrary Length**: Can forge messages of any length
- **Perfect Forgeries**: Produces valid ciphertext indistinguishable from legitimate encryption

## Conclusion

The Padding Oracle Attack demonstrates a fundamental weakness in implementations that leak information about padding validity. By carefully observing these side-channels, attackers can:

1. Decrypt arbitrary ciphertext (previous challenge)
2. Forge arbitrary messages (this challenge)
3. Completely compromise the confidentiality and integrity of the cryptographic system

This attack highlights the critical importance of:
- Using authenticated encryption modes
- Implementing constant-time cryptographic operations  
- Never exposing internal cryptographic state through error messages or timing differences

The ability to forge arbitrary messages without knowing the key makes this one of the most devastating cryptographic attacks when applicable.
