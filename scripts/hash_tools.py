#!/usr/bin/env python3
"""
Hash Analysis Tools for CTF Challenges
Tools for generating, identifying, and cracking common hash types
"""

import hashlib
import hmac
import argparse
import itertools
import string
from pathlib import Path
import requests
import time

class HashTools:
    def __init__(self):
        self.hash_types = {
            32: ['md5'],
            40: ['sha1'],
            56: ['sha224'],
            64: ['sha256', 'sha3_256'],
            96: ['sha384'],
            128: ['sha512', 'sha3_512']
        }
        
    def identify_hash(self, hash_string):
        """Identify possible hash types based on length"""
        hash_length = len(hash_string)
        possible_types = self.hash_types.get(hash_length, ['unknown'])
        return possible_types
    
    def generate_hash(self, text, hash_type, salt=None):
        """Generate hash of given type"""
        text_bytes = text.encode('utf-8')
        
        if salt:
            text_bytes = salt.encode('utf-8') + text_bytes
        
        hash_functions = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha224': hashlib.sha224,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512,
            'sha3_224': hashlib.sha3_224,
            'sha3_256': hashlib.sha3_256,
            'sha3_384': hashlib.sha3_384,
            'sha3_512': hashlib.sha3_512
        }
        
        if hash_type.lower() in hash_functions:
            return hash_functions[hash_type.lower()](text_bytes).hexdigest()
        else:
            return f"Error: Unsupported hash type '{hash_type}'"
    
    def generate_hmac(self, message, key, hash_type='sha256'):
        """Generate HMAC"""
        hash_functions = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }
        
        if hash_type.lower() in hash_functions:
            return hmac.new(
                key.encode('utf-8'),
                message.encode('utf-8'),
                hash_functions[hash_type.lower()]
            ).hexdigest()
        else:
            return f"Error: Unsupported HMAC hash type '{hash_type}'"
    
    def bruteforce_hash(self, target_hash, hash_type='md5', max_length=4, charset=None):
        """Bruteforce hash with given parameters"""
        if charset is None:
            charset = string.ascii_lowercase + string.digits
        
        target_hash = target_hash.lower()
        
        print(f"Bruteforcing {hash_type.upper()} hash: {target_hash}")
        print(f"Max length: {max_length}, Charset: {charset[:10]}{'...' if len(charset) > 10 else ''}")
        
        attempts = 0
        start_time = time.time()
        
        for length in range(1, max_length + 1):
            print(f"Trying length {length}...")
            for candidate in itertools.product(charset, repeat=length):
                candidate_str = ''.join(candidate)
                candidate_hash = self.generate_hash(candidate_str, hash_type)
                attempts += 1
                
                if candidate_hash == target_hash:
                    elapsed = time.time() - start_time
                    print(f"Found: '{candidate_str}' after {attempts} attempts in {elapsed:.2f}s")
                    return candidate_str
                
                if attempts % 10000 == 0:
                    elapsed = time.time() - start_time
                    rate = attempts / elapsed if elapsed > 0 else 0
                    print(f"Attempts: {attempts}, Rate: {rate:.0f}/s")
        
        print(f"Hash not found after {attempts} attempts")
        return None
    
    def dictionary_attack(self, target_hash, hash_type='md5', wordlist_path=None, salt=None):
        """Dictionary attack on hash"""
        if wordlist_path and Path(wordlist_path).exists():
            wordlist = self._load_wordlist(wordlist_path)
        else:
            # Use common passwords if no wordlist provided
            wordlist = self._get_common_passwords()
        
        target_hash = target_hash.lower()
        
        print(f"Dictionary attack on {hash_type.upper()} hash: {target_hash}")
        print(f"Using {len(wordlist)} words from {'file' if wordlist_path else 'common passwords'}")
        
        for i, word in enumerate(wordlist):
            word = word.strip()
            candidate_hash = self.generate_hash(word, hash_type, salt)
            
            if candidate_hash == target_hash:
                print(f"Found: '{word}' (attempt {i+1})")
                return word
            
            if i % 1000 == 0 and i > 0:
                print(f"Tried {i} words...")
        
        print("Hash not found in dictionary")
        return None
    
    def _load_wordlist(self, wordlist_path):
        """Load wordlist from file"""
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.readlines()
        except Exception as e:
            print(f"Error loading wordlist: {e}")
            return []
    
    def _get_common_passwords(self):
        """Get list of common passwords"""
        return [
            'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey',
            'letmein', 'dragon', '111111', 'baseball', 'iloveyou', 'trustno1',
            'sunshine', 'master', '123123', 'welcome', 'shadow', 'ashley',
            'football', 'jesus', 'michael', 'ninja', 'mustang', 'password1',
            'admin', 'root', 'toor', 'pass', 'test', 'guest', 'info',
            '12345', '54321', '1234', 'a', 'aa', 'aaa', 'aaaa', 'aaaaa',
            'secret', 'god', 'love', 'sex', 'money', 'princess', 'charlie'
        ]
    
    def online_hash_lookup(self, hash_string):
        """Lookup hash in online databases"""
        print(f"Looking up hash online: {hash_string}")
        
        # Note: This is for educational purposes
        # In real CTF, check if online lookups are allowed
        
        # HashKiller API (free)
        try:
            url = f"https://hashkiller.co.uk/Cracker/Search"
            headers = {'User-Agent': 'CTF-Tool/1.0'}
            data = {'hash': hash_string}
            
            response = requests.post(url, headers=headers, data=data, timeout=10)
            if "Sorry, we were unable to crack your hash" not in response.text:
                # Parse result (this would need to be adapted to actual API response)
                print("Hash found in online database!")
                return "Check HashKiller manually for result"
        except Exception as e:
            print(f"Online lookup failed: {e}")
        
        print("Hash not found in online databases or lookup failed")
        return None
    
    def hash_length_extension_attack(self, original_hash, known_message, secret_length, new_data, hash_type='md5'):
        """Perform hash length extension attack"""
        print(f"Hash Length Extension Attack on {hash_type.upper()}")
        print(f"Original hash: {original_hash}")
        print(f"Known message: '{known_message}'")
        print(f"Secret length: {secret_length}")
        print(f"New data to append: '{new_data}'")
        
        # This is a simplified version - real implementation would be more complex
        # For educational purposes in CTF
        
        # Calculate padding
        message_length = secret_length + len(known_message)
        padding_length = 64 - (message_length % 64)
        if padding_length < 9:
            padding_length += 64
        
        # Create new message (simplified)
        padding = b'\x80' + b'\x00' * (padding_length - 9) + (message_length * 8).to_bytes(8, 'big')
        new_message = known_message.encode() + padding + new_data.encode()
        
        print(f"New message length: {len(new_message)}")
        print(f"Use this for further hash computation")
        
        return new_message.hex()

def main():
    parser = argparse.ArgumentParser(description='Hash Analysis Tools for CTF')
    parser.add_argument('hash_or_text', help='Hash to analyze or text to hash')
    parser.add_argument('-g', '--generate', help='Generate hash (specify type: md5, sha1, sha256, etc.)')
    parser.add_argument('-i', '--identify', action='store_true', help='Identify hash type')
    parser.add_argument('-b', '--bruteforce', help='Bruteforce hash (specify type)')
    parser.add_argument('-d', '--dictionary', help='Dictionary attack (specify type)')
    parser.add_argument('-o', '--online', action='store_true', help='Online hash lookup')
    parser.add_argument('-m', '--hmac', help='Generate HMAC with key')
    parser.add_argument('--salt', help='Salt for hash generation')
    parser.add_argument('--max-length', type=int, default=4, help='Max length for bruteforce')
    parser.add_argument('--charset', help='Charset for bruteforce')
    parser.add_argument('--wordlist', help='Wordlist file for dictionary attack')
    
    args = parser.parse_args()
    
    tools = HashTools()
    
    if args.generate:
        result = tools.generate_hash(args.hash_or_text, args.generate, args.salt)
        print(f"{args.generate.upper()}: {result}")
    
    elif args.identify:
        possible_types = tools.identify_hash(args.hash_or_text)
        print(f"Possible hash types: {', '.join(possible_types)}")
    
    elif args.bruteforce:
        charset = args.charset if args.charset else string.ascii_lowercase + string.digits
        result = tools.bruteforce_hash(
            args.hash_or_text, 
            args.bruteforce, 
            args.max_length, 
            charset
        )
    
    elif args.dictionary:
        result = tools.dictionary_attack(
            args.hash_or_text,
            args.dictionary,
            args.wordlist
        )
    
    elif args.online:
        result = tools.online_hash_lookup(args.hash_or_text)
    
    elif args.hmac:
        result = tools.generate_hmac(args.hash_or_text, args.hmac)
        print(f"HMAC: {result}")
    
    else:
        print("Please specify an operation: -g, -i, -b, -d, -o, or -m")
        print("Example: python hash_tools.py 'hello' -g md5")
        print("Example: python hash_tools.py '5d41402abc4b2a76b9719d911017c592' -i")

if __name__ == "__main__":
    main()