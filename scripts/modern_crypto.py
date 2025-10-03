#!/usr/bin/env python3
"""
Modern Cryptography Tools for CTF Challenges
RSA, AES, and other modern cryptographic operations
"""

import argparse
import base64
import os
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime, inverse, GCD
import math

class ModernCrypto:
    def __init__(self):
        pass
    
    # AES Encryption/Decryption
    def aes_encrypt(self, plaintext, key, mode='ECB', iv=None):
        """AES encryption with various modes"""
        # Pad key to 16, 24, or 32 bytes
        key = self._pad_key(key)
        
        # Pad plaintext to multiple of 16 bytes
        plaintext = self._pad_data(plaintext.encode('utf-8'))
        
        if mode == 'ECB':
            cipher = AES.new(key, AES.MODE_ECB)
            ciphertext = cipher.encrypt(plaintext)
        elif mode == 'CBC':
            if iv is None:
                iv = os.urandom(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            ciphertext = iv + cipher.encrypt(plaintext)
        else:
            return "Error: Unsupported AES mode"
        
        return base64.b64encode(ciphertext).decode('utf-8')
    
    def aes_decrypt(self, ciphertext_b64, key, mode='ECB', iv=None):
        """AES decryption with various modes"""
        try:
            ciphertext = base64.b64decode(ciphertext_b64)
            key = self._pad_key(key)
            
            if mode == 'ECB':
                cipher = AES.new(key, AES.MODE_ECB)
                plaintext = cipher.decrypt(ciphertext)
            elif mode == 'CBC':
                if iv is None:
                    iv = ciphertext[:16]
                    ciphertext = ciphertext[16:]
                cipher = AES.new(key, AES.MODE_CBC, iv)
                plaintext = cipher.decrypt(ciphertext)
            else:
                return "Error: Unsupported AES mode"
            
            # Remove padding
            plaintext = self._unpad_data(plaintext)
            return plaintext.decode('utf-8')
        except Exception as e:
            return f"Error: {e}"
    
    def _pad_key(self, key):
        """Pad key to valid AES key length"""
        key_bytes = key.encode('utf-8')
        if len(key_bytes) <= 16:
            return key_bytes.ljust(16, b'\x00')
        elif len(key_bytes) <= 24:
            return key_bytes.ljust(24, b'\x00')
        else:
            return key_bytes[:32].ljust(32, b'\x00')
    
    def _pad_data(self, data):
        """PKCS7 padding"""
        pad_length = 16 - (len(data) % 16)
        return data + bytes([pad_length] * pad_length)
    
    def _unpad_data(self, data):
        """Remove PKCS7 padding"""
        pad_length = data[-1]
        return data[:-pad_length]
    
    # RSA Operations
    def generate_rsa_keys(self, key_size=1024):
        """Generate RSA key pair"""
        key = RSA.generate(key_size)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        
        return {
            'private': private_key.decode('utf-8'),
            'public': public_key.decode('utf-8'),
            'n': key.n,
            'e': key.e,
            'd': key.d,
            'p': key.p,
            'q': key.q
        }
    
    def rsa_encrypt(self, plaintext, public_key_pem):
        """RSA encryption using public key"""
        try:
            public_key = RSA.import_key(public_key_pem)
            cipher = PKCS1_OAEP.new(public_key)
            ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
            return base64.b64encode(ciphertext).decode('utf-8')
        except Exception as e:
            return f"Error: {e}"
    
    def rsa_decrypt(self, ciphertext_b64, private_key_pem):
        """RSA decryption using private key"""
        try:
            private_key = RSA.import_key(private_key_pem)
            cipher = PKCS1_OAEP.new(private_key)
            ciphertext = base64.b64decode(ciphertext_b64)
            plaintext = cipher.decrypt(ciphertext)
            return plaintext.decode('utf-8')
        except Exception as e:
            return f"Error: {e}"
    
    def rsa_sign(self, message, private_key_pem):
        """RSA digital signature"""
        try:
            private_key = RSA.import_key(private_key_pem)
            hash_obj = SHA256.new(message.encode('utf-8'))
            signature = pkcs1_15.new(private_key).sign(hash_obj)
            return base64.b64encode(signature).decode('utf-8')
        except Exception as e:
            return f"Error: {e}"
    
    def rsa_verify(self, message, signature_b64, public_key_pem):
        """RSA signature verification"""
        try:
            public_key = RSA.import_key(public_key_pem)
            hash_obj = SHA256.new(message.encode('utf-8'))
            signature = base64.b64decode(signature_b64)
            pkcs1_15.new(public_key).verify(hash_obj, signature)
            return "Signature valid"
        except Exception as e:
            return f"Signature invalid: {e}"
    
    # RSA Attacks for CTF
    def rsa_common_attacks(self, n, e, c=None):
        """Common RSA attacks for CTF challenges"""
        results = {}
        
        # Attack 1: Small e attack
        if e == 3 or e == 65537:
            results['small_e'] = self._rsa_small_e_attack(n, e, c) if c else "Need ciphertext for small e attack"
        
        # Attack 2: Factor n (small primes)
        factors = self._rsa_factor_n(n)
        if factors:
            results['factorization'] = factors
            if len(factors) == 2:
                p, q = factors
                phi = (p - 1) * (q - 1)
                try:
                    d = inverse(e, phi)
                    results['private_key'] = d
                    if c:
                        m = pow(c, d, n)
                        results['decrypted'] = self._number_to_text(m)
                except:
                    results['private_key'] = "Could not compute private key"
        
        # Attack 3: Wiener's attack (when d is small)
        results['wiener'] = "Wiener's attack not implemented (complex)"
        
        return results
    
    def _rsa_small_e_attack(self, n, e, c):
        """RSA small exponent attack"""
        if e == 3:
            # Try cube root of ciphertext
            m = self._nth_root(c, 3)
            if pow(m, 3, n) == c:
                return self._number_to_text(m)
        return "Small e attack failed"
    
    def _rsa_factor_n(self, n):
        """Simple factorization for small n"""
        # Trial division up to sqrt(n) or reasonable limit
        limit = min(int(math.sqrt(n)) + 1, 1000000)
        
        for i in range(2, limit):
            if n % i == 0:
                return [i, n // i]
        return None
    
    def _nth_root(self, x, n):
        """Calculate nth root of x"""
        if x < 0 and n % 2 == 0:
            return None
        
        # Binary search for nth root
        low = 0
        high = x
        
        while low <= high:
            mid = (low + high) // 2
            mid_pow = mid ** n
            
            if mid_pow == x:
                return mid
            elif mid_pow < x:
                low = mid + 1
            else:
                high = mid - 1
        
        return high  # Return floor of nth root
    
    def _number_to_text(self, num):
        """Convert number to text (assuming ASCII encoding)"""
        try:
            hex_str = hex(num)[2:]
            if len(hex_str) % 2:
                hex_str = '0' + hex_str
            return bytes.fromhex(hex_str).decode('ascii', errors='ignore')
        except:
            return f"Number: {num}"
    
    # XOR Operations
    def xor_encrypt_decrypt(self, data, key):
        """XOR encryption/decryption (same operation)"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        if isinstance(key, str):
            key = key.encode('utf-8')
        
        result = bytearray()
        for i in range(len(data)):
            result.append(data[i] ^ key[i % len(key)])
        
        return result
    
    def xor_bruteforce_single_byte(self, ciphertext_hex):
        """Bruteforce single-byte XOR"""
        try:
            ciphertext = bytes.fromhex(ciphertext_hex.replace(' ', ''))
        except ValueError:
            return "Error: Invalid hex string"
        
        results = {}
        for key in range(256):
            decrypted = bytes(b ^ key for b in ciphertext)
            try:
                text = decrypted.decode('ascii')
                # Check if result looks like readable text
                if all(c.isprintable() for c in text):
                    results[f"Key {key} ('{chr(key)}')"] = text
            except UnicodeDecodeError:
                pass
        
        return results
    
    def analyze_xor_key_length(self, ciphertext_hex):
        """Analyze XOR key length using Hamming distance"""
        try:
            ciphertext = bytes.fromhex(ciphertext_hex.replace(' ', ''))
        except ValueError:
            return "Error: Invalid hex string"
        
        def hamming_distance(s1, s2):
            return sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(s1, s2))
        
        key_lengths = {}
        
        for key_length in range(2, min(40, len(ciphertext) // 2)):
            distances = []
            for i in range(0, len(ciphertext) - 2 * key_length, key_length):
                block1 = ciphertext[i:i + key_length]
                block2 = ciphertext[i + key_length:i + 2 * key_length]
                if len(block1) == len(block2) == key_length:
                    distances.append(hamming_distance(block1, block2) / key_length)
            
            if distances:
                avg_distance = sum(distances) / len(distances)
                key_lengths[key_length] = avg_distance
        
        # Sort by average Hamming distance (lower is better)
        sorted_lengths = sorted(key_lengths.items(), key=lambda x: x[1])
        return dict(sorted_lengths[:5])  # Return top 5 candidates

def main():
    parser = argparse.ArgumentParser(description='Modern Cryptography Tools for CTF')
    
    # AES arguments
    parser.add_argument('--aes-encrypt', nargs=2, metavar=('TEXT', 'KEY'),
                       help='AES encrypt text with key')
    parser.add_argument('--aes-decrypt', nargs=2, metavar=('CIPHERTEXT', 'KEY'),
                       help='AES decrypt ciphertext with key')
    parser.add_argument('--mode', choices=['ECB', 'CBC'], default='ECB',
                       help='AES mode (default: ECB)')
    
    # RSA arguments
    parser.add_argument('--rsa-genkeys', type=int, metavar='KEYSIZE',
                       help='Generate RSA key pair with specified size')
    parser.add_argument('--rsa-encrypt', nargs=2, metavar=('TEXT', 'PUBKEY_FILE'),
                       help='RSA encrypt text with public key file')
    parser.add_argument('--rsa-decrypt', nargs=2, metavar=('CIPHERTEXT', 'PRIVKEY_FILE'),
                       help='RSA decrypt ciphertext with private key file')
    parser.add_argument('--rsa-attack', nargs=2, metavar=('N', 'E'), type=int,
                       help='Try common RSA attacks')
    parser.add_argument('--rsa-attack-c', type=int, metavar='C',
                       help='Ciphertext for RSA attacks')
    
    # XOR arguments
    parser.add_argument('--xor', nargs=2, metavar=('DATA', 'KEY'),
                       help='XOR encrypt/decrypt data with key')
    parser.add_argument('--xor-bruteforce', metavar='HEX',
                       help='Bruteforce single-byte XOR on hex string')
    parser.add_argument('--xor-keylen', metavar='HEX',
                       help='Analyze XOR key length')
    
    args = parser.parse_args()
    crypto = ModernCrypto()
    
    if args.aes_encrypt:
        result = crypto.aes_encrypt(args.aes_encrypt[0], args.aes_encrypt[1], args.mode)
        print(f"AES Encrypted: {result}")
    
    elif args.aes_decrypt:
        result = crypto.aes_decrypt(args.aes_decrypt[0], args.aes_decrypt[1], args.mode)
        print(f"AES Decrypted: {result}")
    
    elif args.rsa_genkeys:
        keys = crypto.generate_rsa_keys(args.rsa_genkeys)
        print("RSA Key Pair Generated:")
        print(f"Public Key:\n{keys['public']}")
        print(f"Private Key:\n{keys['private']}")
        print(f"n = {keys['n']}")
        print(f"e = {keys['e']}")
        print(f"d = {keys['d']}")
    
    elif args.rsa_attack:
        n, e = args.rsa_attack
        c = args.rsa_attack_c
        results = crypto.rsa_common_attacks(n, e, c)
        print("RSA Attack Results:")
        for attack, result in results.items():
            print(f"{attack}: {result}")
    
    elif args.xor:
        result = crypto.xor_encrypt_decrypt(args.xor[0], args.xor[1])
        print(f"XOR Result: {result.hex()}")
        try:
            print(f"XOR Result (ASCII): {result.decode('ascii')}")
        except:
            pass
    
    elif args.xor_bruteforce:
        results = crypto.xor_bruteforce_single_byte(args.xor_bruteforce)
        print("Single-byte XOR bruteforce results:")
        for key, plaintext in results.items():
            print(f"{key}: {plaintext}")
    
    elif args.xor_keylen:
        results = crypto.analyze_xor_key_length(args.xor_keylen)
        print("XOR key length analysis (lower score is better):")
        for length, score in results.items():
            print(f"Length {length}: {score:.3f}")
    
    else:
        print("Please specify an operation. Use -h for help.")
        print("Examples:")
        print("  python modern_crypto.py --aes-encrypt 'Hello World' 'mysecretkey'")
        print("  python modern_crypto.py --rsa-genkeys 1024")
        print("  python modern_crypto.py --xor-bruteforce '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'")

if __name__ == "__main__":
    main()