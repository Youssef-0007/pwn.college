#!/usr/bin/env python3
import base64
import subprocess
import sys

def main():
    print("RSA Signature Attack - Exploiting Multiplicative Property")
    print("=" * 60)
    
    # Step 1: Convert "flag" to integer and find factors
    target = b"flag"
    target_int = int.from_bytes(target, "little")
    print(f"Target 'flag' as little-endian integer: {target_int}")
    print(f"Target in hex: 0x{target_int:x}")
    
    # Check if the number is even (divisible by 2)
    if target_int % 2 == 0:
        factor1 = 2
        factor2 = target_int // 2
        print(f"Found factors: {factor1} × {factor2} = {target_int}")
    else:
        print("Number is odd, trying other small factors...")
        factor1 = None
        factor2 = None
        
        # Try small prime factors
        for i in range(3, 1000, 2):  # Try odd numbers
            if target_int % i == 0:
                factor1 = i
                factor2 = target_int // i
                print(f"Found factors: {factor1} × {factor2} = {target_int}")
                break
        
        if factor1 is None:
            print("Could not find small factors. Number might be prime.")
            return
    
    # Step 2: Convert factors to bytes and check they don't contain "flag"
    factor1_bytes = factor1.to_bytes(256, "little").rstrip(b"\x00")
    factor2_bytes = factor2.to_bytes(256, "little").rstrip(b"\x00")
    
    print(f"\nFactor 1 as bytes: {factor1_bytes}")
    print(f"Factor 2 as bytes: {factor2_bytes}")
    
    # Safety check
    if b"flag" in factor1_bytes:
        print("ERROR: Factor 1 contains 'flag' string!")
        return
    if b"flag" in factor2_bytes:
        print("ERROR: Factor 2 contains 'flag' string!")
        return
    
    print("✓ Neither factor contains 'flag' string - safe to proceed")
    
    # Step 3: Base64 encode factors for the dispatcher
    factor1_b64 = base64.b64encode(factor1_bytes).decode()
    factor2_b64 = base64.b64encode(factor2_bytes).decode()
    
    print(f"\nFactor 1 (base64): {factor1_b64}")
    print(f"Factor 2 (base64): {factor2_b64}")
    
    # Step 4: Get signatures from dispatcher
    print("\n" + "="*40)
    print("Getting signature for factor 1...")
    try:
        result1 = subprocess.run(
            ["/challenge/dispatcher", factor1_b64], 
            capture_output=True, 
            text=True, 
            check=True
        )
        print(f"Dispatcher output: {result1.stdout.strip()}")
        sig1_b64 = result1.stdout.split("Signed command (b64): ")[1].strip()
    except subprocess.CalledProcessError as e:
        print(f"Error signing factor 1: {e}")
        print(f"Stderr: {e.stderr}")
        return
    except IndexError:
        print(f"Could not parse signature from output: {result1.stdout}")
        return
    
    print("\nGetting signature for factor 2...")
    try:
        result2 = subprocess.run(
            ["/challenge/dispatcher", factor2_b64], 
            capture_output=True, 
            text=True, 
            check=True
        )
        print(f"Dispatcher output: {result2.stdout.strip()}")
        sig2_b64 = result2.stdout.split("Signed command (b64): ")[1].strip()
    except subprocess.CalledProcessError as e:
        print(f"Error signing factor 2: {e}")
        print(f"Stderr: {e.stderr}")
        return
    except IndexError:
        print(f"Could not parse signature from output: {result2.stdout}")
        return
    
    print(f"\nSignature 1 (base64): {sig1_b64}")
    print(f"Signature 2 (base64): {sig2_b64}")
    
    # Step 5: Combine signatures using multiplicative property
    print("\n" + "="*40)
    print("Combining signatures using multiplicative property...")
    
    try:
        # Read the public modulus n
        with open("/challenge/key-n", "r") as f:
            n = int(f.read().strip(), 16)
        
        # Decode signatures to integers
        sig1_bytes = base64.b64decode(sig1_b64)
        sig2_bytes = base64.b64decode(sig2_b64)
        
        sig1_int = int.from_bytes(sig1_bytes, "little")
        sig2_int = int.from_bytes(sig2_bytes, "little")
        
        print(f"Signature 1 as integer: {sig1_int}")
        print(f"Signature 2 as integer: {sig2_int}")
        print(f"Modulus n: {n}")
        
        # Apply multiplicative property: (sig1 * sig2) mod n = (m1 * m2)^d mod n
        combined_sig_int = (sig1_int * sig2_int) % n
        print(f"Combined signature (integer): {combined_sig_int}")
        
        # Convert back to bytes and base64
        combined_sig_bytes = combined_sig_int.to_bytes(256, "little")
        combined_sig_b64 = base64.b64encode(combined_sig_bytes).decode()
        
        print(f"Combined signature (base64): {combined_sig_b64}")
        
    except Exception as e:
        print(f"Error combining signatures: {e}")
        return
    
    # Step 6: Submit combined signature to worker
    print("\n" + "="*40)
    print("Submitting combined signature to worker...")
    
    try:
        result3 = subprocess.run(
            ["/challenge/worker", combined_sig_b64], 
            capture_output=True, 
            text=True, 
            check=True
        )
        print("Worker output:")
        print(result3.stdout)
        
        if "flag" in result3.stdout and result3.stdout.count('\n') > 1:
            print("\n🎉 SUCCESS! Flag obtained!")
        
    except subprocess.CalledProcessError as e:
        print(f"Error with worker: {e}")
        print(f"Stderr: {e.stderr}")
        return
    
    print("\n" + "="*60)
    print("Attack completed!")

if __name__ == "__main__":
    main()
