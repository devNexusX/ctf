#!/usr/bin/env python3
"""
Encoding and Decoding Tools for CTF Challenges
Handles common encoding formats used in CTF competitions
"""

import base64
import binascii
import urllib.parse
import html
import codecs
import sys
import argparse

class EncodingTools:
    def __init__(self):
        self.methods = {
            'base64': {'encode': self.base64_encode, 'decode': self.base64_decode},
            'hex': {'encode': self.hex_encode, 'decode': self.hex_decode},
            'url': {'encode': self.url_encode, 'decode': self.url_decode},
            'html': {'encode': self.html_encode, 'decode': self.html_decode},
            'rot13': {'encode': self.rot13_encode, 'decode': self.rot13_decode},
            'binary': {'encode': self.binary_encode, 'decode': self.binary_decode},
            'ascii': {'encode': self.ascii_encode, 'decode': self.ascii_decode},
            'morse': {'encode': self.morse_encode, 'decode': self.morse_decode},
        }
    
    def base64_encode(self, text):
        """Base64 encode"""
        return base64.b64encode(text.encode('utf-8')).decode('utf-8')
    
    def base64_decode(self, text):
        """Base64 decode"""
        try:
            # Remove whitespace and padding issues
            text = text.replace(' ', '').replace('\n', '').replace('\r', '')
            # Add padding if needed
            missing_padding = len(text) % 4
            if missing_padding:
                text += '=' * (4 - missing_padding)
            return base64.b64decode(text).decode('utf-8')
        except Exception as e:
            return f"Error: {e}"
    
    def hex_encode(self, text):
        """Hexadecimal encode"""
        return text.encode('utf-8').hex()
    
    def hex_decode(self, text):
        """Hexadecimal decode"""
        try:
            # Remove spaces and common prefixes
            text = text.replace(' ', '').replace('0x', '').replace('\\x', '')
            return bytes.fromhex(text).decode('utf-8')
        except Exception as e:
            return f"Error: {e}"
    
    def url_encode(self, text):
        """URL encode"""
        return urllib.parse.quote(text)
    
    def url_decode(self, text):
        """URL decode"""
        try:
            return urllib.parse.unquote(text)
        except Exception as e:
            return f"Error: {e}"
    
    def html_encode(self, text):
        """HTML encode"""
        return html.escape(text)
    
    def html_decode(self, text):
        """HTML decode"""
        try:
            return html.unescape(text)
        except Exception as e:
            return f"Error: {e}"
    
    def rot13_encode(self, text):
        """ROT13 encode"""
        return codecs.encode(text, 'rot13')
    
    def rot13_decode(self, text):
        """ROT13 decode (same as encode)"""
        return codecs.decode(text, 'rot13')
    
    def binary_encode(self, text):
        """Binary encode"""
        return ' '.join(format(ord(char), '08b') for char in text)
    
    def binary_decode(self, text):
        """Binary decode"""
        try:
            # Remove spaces and split into 8-bit chunks
            binary_str = text.replace(' ', '')
            if len(binary_str) % 8 != 0:
                return "Error: Binary string length must be multiple of 8"
            
            result = ''
            for i in range(0, len(binary_str), 8):
                byte = binary_str[i:i+8]
                result += chr(int(byte, 2))
            return result
        except Exception as e:
            return f"Error: {e}"
    
    def ascii_encode(self, text):
        """ASCII encode (decimal values)"""
        return ' '.join(str(ord(char)) for char in text)
    
    def ascii_decode(self, text):
        """ASCII decode from decimal values"""
        try:
            numbers = text.split()
            return ''.join(chr(int(num)) for num in numbers)
        except Exception as e:
            return f"Error: {e}"
    
    def morse_encode(self, text):
        """Morse code encode"""
        morse_dict = {
            'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
            'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
            'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
            'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
            'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
            '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
            '8': '---..', '9': '----.', ' ': '/'
        }
        return ' '.join(morse_dict.get(char.upper(), char) for char in text)
    
    def morse_decode(self, text):
        """Morse code decode"""
        morse_dict = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
            '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
            '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
            '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
            '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
            '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
            '---..': '8', '----.': '9', '/': ' '
        }
        try:
            return ''.join(morse_dict.get(code, code) for code in text.split())
        except Exception as e:
            return f"Error: {e}"
    
    def detect_encoding(self, text):
        """Try to detect the encoding type"""
        results = {}
        
        # Try all decoding methods
        for method_name, methods in self.methods.items():
            try:
                decoded = methods['decode'](text)
                if not decoded.startswith('Error:') and decoded != text:
                    # Check if result looks like readable text
                    printable_ratio = sum(c.isprintable() for c in decoded) / len(decoded) if decoded else 0
                    if printable_ratio > 0.8:  # 80% printable characters
                        results[method_name] = decoded
            except:
                pass
        
        return results
    
    def process_text(self, text, method, operation):
        """Process text with specified method and operation"""
        if method not in self.methods:
            return f"Error: Unknown method '{method}'"
        
        if operation not in ['encode', 'decode']:
            return f"Error: Operation must be 'encode' or 'decode'"
        
        try:
            return self.methods[method][operation](text)
        except Exception as e:
            return f"Error: {e}"

def main():
    parser = argparse.ArgumentParser(description='Encoding/Decoding Tools for CTF')
    parser.add_argument('text', help='Text to encode/decode')
    parser.add_argument('-m', '--method', 
                       choices=['base64', 'hex', 'url', 'html', 'rot13', 'binary', 'ascii', 'morse'],
                       help='Encoding method to use')
    parser.add_argument('-o', '--operation', choices=['encode', 'decode'],
                       help='Operation to perform')
    parser.add_argument('-a', '--auto', action='store_true',
                       help='Auto-detect encoding and try to decode')
    
    args = parser.parse_args()
    
    tools = EncodingTools()
    
    if args.auto:
        print("Auto-detecting encoding...")
        results = tools.detect_encoding(args.text)
        if results:
            print("Possible decodings:")
            for method, decoded in results.items():
                print(f"{method.upper()}: {decoded}")
        else:
            print("No valid decodings found")
    elif args.method and args.operation:
        result = tools.process_text(args.text, args.method, args.operation)
        print(result)
    else:
        print("Error: Please specify method and operation, or use --auto")
        print("Example: python encoding_tools.py 'SGVsbG8gV29ybGQ=' -m base64 -d decode")
        print("Example: python encoding_tools.py 'Hello World' -a")

if __name__ == "__main__":
    main()