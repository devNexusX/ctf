#!/usr/bin/env python3
"""
Classical Cipher Tools for CTF Challenges
Implements various historical ciphers commonly used in CTF competitions
"""

import string
import argparse
import itertools
from collections import Counter

class ClassicalCiphers:
    def __init__(self):
        self.alphabet = string.ascii_uppercase
        
    def caesar_cipher(self, text, shift, decrypt=False):
        """Caesar cipher with specified shift"""
        if decrypt:
            shift = -shift
        
        result = ""
        for char in text:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                shifted = (ord(char) - ascii_offset + shift) % 26
                result += chr(shifted + ascii_offset)
            else:
                result += char
        return result
    
    def caesar_bruteforce(self, text):
        """Try all possible Caesar cipher shifts"""
        results = {}
        for shift in range(26):
            decrypted = self.caesar_cipher(text, shift, decrypt=True)
            results[shift] = decrypted
        return results
    
    def vigenere_cipher(self, text, key, decrypt=False):
        """Vigenère cipher with specified key"""
        result = ""
        key = key.upper()
        key_index = 0
        
        for char in text:
            if char.isalpha():
                # Get the shift value from the key
                key_char = key[key_index % len(key)]
                shift = ord(key_char) - ord('A')
                
                if decrypt:
                    shift = -shift
                
                # Apply shift
                if char.isupper():
                    result += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
                else:
                    result += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
                
                key_index += 1
            else:
                result += char
        
        return result
    
    def atbash_cipher(self, text):
        """Atbash cipher (A=Z, B=Y, etc.)"""
        result = ""
        for char in text:
            if char.isalpha():
                if char.isupper():
                    result += chr(ord('Z') - (ord(char) - ord('A')))
                else:
                    result += chr(ord('z') - (ord(char) - ord('a')))
            else:
                result += char
        return result
    
    def substitution_cipher(self, text, key_alphabet, decrypt=False):
        """Simple substitution cipher"""
        if decrypt:
            # Create reverse mapping
            trans_table = str.maketrans(key_alphabet, self.alphabet)
        else:
            trans_table = str.maketrans(self.alphabet, key_alphabet)
        
        return text.upper().translate(trans_table)
    
    def rail_fence_cipher(self, text, rails, decrypt=False):
        """Rail fence cipher"""
        if decrypt:
            return self._rail_fence_decrypt(text, rails)
        else:
            return self._rail_fence_encrypt(text, rails)
    
    def _rail_fence_encrypt(self, text, rails):
        """Rail fence encryption"""
        fence = [['\n' for i in range(len(text))] for j in range(rails)]
        rail = 0
        direction = False
        
        for i in range(len(text)):
            fence[rail][i] = text[i]
            
            if rail == 0 or rail == rails - 1:
                direction = not direction
            
            rail += 1 if direction else -1
        
        result = ""
        for i in range(rails):
            for j in range(len(text)):
                if fence[i][j] != '\n':
                    result += fence[i][j]
        return result
    
    def _rail_fence_decrypt(self, text, rails):
        """Rail fence decryption"""
        fence = [['\n' for i in range(len(text))] for j in range(rails)]
        rail = 0
        direction = False
        
        # Mark the positions
        for i in range(len(text)):
            fence[rail][i] = '*'
            if rail == 0 or rail == rails - 1:
                direction = not direction
            rail += 1 if direction else -1
        
        # Fill the fence with ciphertext
        index = 0
        for i in range(rails):
            for j in range(len(text)):
                if fence[i][j] == '*' and index < len(text):
                    fence[i][j] = text[index]
                    index += 1
        
        # Read the fence
        result = ""
        rail = 0
        direction = False
        for i in range(len(text)):
            result += fence[rail][i]
            if rail == 0 or rail == rails - 1:
                direction = not direction
            rail += 1 if direction else -1
        
        return result
    
    def playfair_cipher(self, text, key, decrypt=False):
        """Playfair cipher implementation"""
        # Create the 5x5 key square
        key_square = self._create_playfair_square(key)
        
        # Prepare text
        prepared_text = self._prepare_playfair_text(text)
        
        # Split into pairs
        pairs = [prepared_text[i:i+2] for i in range(0, len(prepared_text), 2)]
        
        result = ""
        for pair in pairs:
            if len(pair) == 2:
                result += self._playfair_encrypt_pair(pair, key_square, decrypt)
        
        return result
    
    def _create_playfair_square(self, key):
        """Create 5x5 Playfair key square"""
        key = key.upper().replace('J', 'I')
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # No J
        
        # Remove duplicates from key
        key_chars = []
        for char in key:
            if char not in key_chars and char in alphabet:
                key_chars.append(char)
        
        # Add remaining alphabet
        for char in alphabet:
            if char not in key_chars:
                key_chars.append(char)
        
        # Create 5x5 grid
        square = []
        for i in range(5):
            square.append(key_chars[i*5:(i+1)*5])
        
        return square
    
    def _prepare_playfair_text(self, text):
        """Prepare text for Playfair cipher"""
        text = text.upper().replace('J', 'I')
        text = ''.join(c for c in text if c.isalpha())
        
        # Insert X between repeated letters and ensure even length
        prepared = ""
        i = 0
        while i < len(text):
            prepared += text[i]
            if i + 1 < len(text) and text[i] == text[i + 1]:
                prepared += 'X'
            elif i + 1 < len(text):
                prepared += text[i + 1]
                i += 1
            i += 1
        
        # Ensure even length
        if len(prepared) % 2 == 1:
            prepared += 'X'
        
        return prepared
    
    def _playfair_encrypt_pair(self, pair, square, decrypt=False):
        """Encrypt/decrypt a pair using Playfair rules"""
        char1, char2 = pair[0], pair[1]
        
        # Find positions
        pos1 = pos2 = None
        for i in range(5):
            for j in range(5):
                if square[i][j] == char1:
                    pos1 = (i, j)
                if square[i][j] == char2:
                    pos2 = (i, j)
        
        if not pos1 or not pos2:
            return pair
        
        row1, col1 = pos1
        row2, col2 = pos2
        
        if row1 == row2:  # Same row
            if decrypt:
                new_col1 = (col1 - 1) % 5
                new_col2 = (col2 - 1) % 5
            else:
                new_col1 = (col1 + 1) % 5
                new_col2 = (col2 + 1) % 5
            return square[row1][new_col1] + square[row2][new_col2]
        elif col1 == col2:  # Same column
            if decrypt:
                new_row1 = (row1 - 1) % 5
                new_row2 = (row2 - 1) % 5
            else:
                new_row1 = (row1 + 1) % 5
                new_row2 = (row2 + 1) % 5
            return square[new_row1][col1] + square[new_row2][col2]
        else:  # Rectangle
            return square[row1][col2] + square[row2][col1]
    
    def analyze_text_frequency(self, text):
        """Analyze character frequency for cryptanalysis"""
        text = ''.join(c.upper() for c in text if c.isalpha())
        total_chars = len(text)
        
        if total_chars == 0:
            return {}
        
        counter = Counter(text)
        frequencies = {}
        
        for char, count in counter.most_common():
            frequencies[char] = {
                'count': count,
                'percentage': (count / total_chars) * 100
            }
        
        return frequencies

def main():
    parser = argparse.ArgumentParser(description='Classical Cipher Tools for CTF')
    parser.add_argument('text', help='Text to encrypt/decrypt')
    parser.add_argument('-c', '--cipher', 
                       choices=['caesar', 'vigenere', 'atbash', 'substitution', 
                              'railfence', 'playfair'],
                       required=True, help='Cipher type')
    parser.add_argument('-k', '--key', help='Encryption key (if required)')
    parser.add_argument('-s', '--shift', type=int, help='Caesar cipher shift')
    parser.add_argument('-r', '--rails', type=int, help='Rail fence cipher rails')
    parser.add_argument('-d', '--decrypt', action='store_true', help='Decrypt mode')
    parser.add_argument('-b', '--bruteforce', action='store_true', 
                       help='Bruteforce mode (Caesar only)')
    parser.add_argument('-f', '--frequency', action='store_true', 
                       help='Show frequency analysis')
    
    args = parser.parse_args()
    
    ciphers = ClassicalCiphers()
    
    if args.frequency:
        frequencies = ciphers.analyze_text_frequency(args.text)
        print("Character Frequency Analysis:")
        for char, data in frequencies.items():
            print(f"{char}: {data['count']} ({data['percentage']:.1f}%)")
        return
    
    if args.cipher == 'caesar':
        if args.bruteforce:
            print("Caesar Cipher Bruteforce Results:")
            results = ciphers.caesar_bruteforce(args.text)
            for shift, decrypted in results.items():
                print(f"Shift {shift:2d}: {decrypted}")
        elif args.shift is not None:
            result = ciphers.caesar_cipher(args.text, args.shift, args.decrypt)
            print(result)
        else:
            print("Error: Caesar cipher requires --shift or --bruteforce")
    
    elif args.cipher == 'vigenere':
        if not args.key:
            print("Error: Vigenère cipher requires --key")
            return
        result = ciphers.vigenere_cipher(args.text, args.key, args.decrypt)
        print(result)
    
    elif args.cipher == 'atbash':
        result = ciphers.atbash_cipher(args.text)
        print(result)
    
    elif args.cipher == 'substitution':
        if not args.key or len(args.key) != 26:
            print("Error: Substitution cipher requires --key with 26 characters")
            return
        result = ciphers.substitution_cipher(args.text, args.key.upper(), args.decrypt)
        print(result)
    
    elif args.cipher == 'railfence':
        if not args.rails:
            print("Error: Rail fence cipher requires --rails")
            return
        result = ciphers.rail_fence_cipher(args.text, args.rails, args.decrypt)
        print(result)
    
    elif args.cipher == 'playfair':
        if not args.key:
            print("Error: Playfair cipher requires --key")
            return
        result = ciphers.playfair_cipher(args.text, args.key, args.decrypt)
        print(result)

if __name__ == "__main__":
    main()