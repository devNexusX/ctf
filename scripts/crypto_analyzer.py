#!/usr/bin/env python3
"""
Unified Crypto Analyzer for CTF Challenges
Automatically tries multiple decryption methods to find the solution
"""

import sys
import os
import re
import argparse
from pathlib import Path

# Import our other crypto tools
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from encoding_tools import EncodingTools
    from classical_ciphers import ClassicalCiphers
    from hash_tools import HashTools
    from modern_crypto import ModernCrypto
    from frequency_analysis import FrequencyAnalyzer
except ImportError as e:
    print(f"Error importing crypto tools: {e}")
    print("Make sure all crypto tool files are in the same directory")
    sys.exit(1)

class CryptoAnalyzer:
    def __init__(self):
        self.encoding_tools = EncodingTools()
        self.classical_ciphers = ClassicalCiphers()
        self.hash_tools = HashTools()
        self.modern_crypto = ModernCrypto()
        self.frequency_analyzer = FrequencyAnalyzer()
        
        # Common flag patterns for CTF
        self.flag_patterns = [
            r'AKSO{.*?}', r'akso{.*?}', r'flag{.*?}', r'FLAG{.*?}', 
            r'ctf{.*?}', r'CTF{.*?}', r'picoCTF{.*?}', r'HTB{.*?}',
            r'\w+{[^}]+}'  # Generic flag pattern
        ]
        
        self.results = []
    
    def analyze_input(self, input_text):
        """Determine what type of input we're dealing with"""
        input_info = {
            'length': len(input_text),
            'hex_like': bool(re.match(r'^[0-9a-fA-F\s]+$', input_text.strip())),
            'base64_like': bool(re.match(r'^[A-Za-z0-9+/=\s]+$', input_text.strip())),
            'binary_like': bool(re.match(r'^[01\s]+$', input_text.strip())),
            'url_encoded': '%' in input_text,
            'html_encoded': '&' in input_text and ';' in input_text,
            'has_spaces': ' ' in input_text,
            'alpha_only': input_text.replace(' ', '').isalpha(),
            'mixed_case': input_text != input_text.upper() and input_text != input_text.lower()
        }
        
        return input_info
    
    def check_for_flags(self, text):
        """Check if text contains any flag patterns"""
        flags_found = []
        for pattern in self.flag_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                flags_found.extend(matches)
        return flags_found
    
    def try_encodings(self, input_text):
        """Try common encoding schemes"""
        print("🔍 Trying encoding/decoding methods...")
        
        methods_to_try = ['base64', 'hex', 'url', 'html', 'rot13', 'binary', 'ascii', 'morse']
        
        for method in methods_to_try:
            try:
                decoded = self.encoding_tools.process_text(input_text, method, 'decode')
                if not decoded.startswith('Error:') and decoded != input_text:
                    flags = self.check_for_flags(decoded)
                    if flags:
                        result = f"🚩 FLAG FOUND via {method.upper()} decode: {flags[0]}"
                        print(result)
                        self.results.append(result)
                        return flags[0]
                    
                    # Check if it looks like readable text
                    if self.looks_like_text(decoded):
                        result = f"✓ {method.upper()} decode: {decoded[:100]}{'...' if len(decoded) > 100 else ''}"
                        print(result)
                        self.results.append(result)
                        
                        # Recursively analyze the decoded text
                        recursive_result = self.try_encodings(decoded)
                        if recursive_result:
                            return recursive_result
            except:
                pass
        
        return None
    
    def try_classical_ciphers(self, input_text):
        """Try classical cipher methods"""
        print("\n🔍 Trying classical ciphers...")
        
        # Caesar cipher bruteforce
        try:
            caesar_results = self.classical_ciphers.caesar_bruteforce(input_text)
            for shift, decoded in caesar_results.items():
                flags = self.check_for_flags(decoded)
                if flags:
                    result = f"🚩 FLAG FOUND via Caesar cipher (shift {shift}): {flags[0]}"
                    print(result)
                    self.results.append(result)
                    return flags[0]
                
                if self.looks_like_english(decoded):
                    result = f"✓ Caesar shift {shift}: {decoded[:100]}{'...' if len(decoded) > 100 else ''}"
                    print(result)
                    self.results.append(result)
        except:
            pass
        
        # Atbash cipher
        try:
            atbash_decoded = self.classical_ciphers.atbash_cipher(input_text)
            flags = self.check_for_flags(atbash_decoded)
            if flags:
                result = f"🚩 FLAG FOUND via Atbash cipher: {flags[0]}"
                print(result)
                self.results.append(result)
                return flags[0]
            
            if self.looks_like_english(atbash_decoded):
                result = f"✓ Atbash: {atbash_decoded[:100]}{'...' if len(atbash_decoded) > 100 else ''}"
                print(result)
                self.results.append(result)
        except:
            pass
        
        return None
    
    def try_xor_analysis(self, input_text):
        """Try XOR-based attacks"""
        print("\n🔍 Trying XOR analysis...")
        
        # Check if it looks like hex for XOR bruteforce
        input_info = self.analyze_input(input_text)
        if input_info['hex_like'] and len(input_text.replace(' ', '')) % 2 == 0:
            try:
                xor_results = self.modern_crypto.xor_bruteforce_single_byte(input_text)
                for key, decoded in xor_results.items():
                    flags = self.check_for_flags(decoded)
                    if flags:
                        result = f"🚩 FLAG FOUND via XOR ({key}): {flags[0]}"
                        print(result)
                        self.results.append(result)
                        return flags[0]
                    
                    if self.looks_like_english(decoded):
                        result = f"✓ XOR {key}: {decoded[:100]}{'...' if len(decoded) > 100 else ''}"
                        print(result)
                        self.results.append(result)
            except:
                pass
        
        return None
    
    def try_hash_analysis(self, input_text):
        """Analyze if input might be a hash"""
        print("\n🔍 Analyzing as potential hash...")
        
        # Check if it looks like a hash
        hash_types = self.hash_tools.identify_hash(input_text.strip())
        if hash_types and hash_types != ['unknown']:
            result = f"🔍 Possible hash types: {', '.join(hash_types)}"
            print(result)
            self.results.append(result)
            
            # Try dictionary attack on common hash types
            for hash_type in hash_types[:2]:  # Try first 2 types
                try:
                    cracked = self.hash_tools.dictionary_attack(input_text.strip(), hash_type)
                    if cracked:
                        flags = self.check_for_flags(cracked)
                        if flags:
                            result = f"🚩 FLAG FOUND via {hash_type.upper()} hash crack: {flags[0]}"
                            print(result)
                            self.results.append(result)
                            return flags[0]
                        
                        result = f"✓ {hash_type.upper()} hash cracked: {cracked}"
                        print(result)
                        self.results.append(result)
                except:
                    pass
        
        return None
    
    def try_frequency_analysis(self, input_text):
        """Perform frequency analysis for substitution ciphers"""
        print("\n🔍 Performing frequency analysis...")
        
        if not input_text.replace(' ', '').isalpha():
            return None
        
        try:
            # Get cipher suggestions
            suggestions = self.frequency_analyzer.suggest_cipher_type(input_text)
            for suggestion in suggestions:
                result = f"📊 {suggestion}"
                print(result)
                self.results.append(result)
            
            # Try frequency-based substitution
            mapping = self.frequency_analyzer.generate_substitution_mapping(input_text)
            if mapping:
                decoded = self.frequency_analyzer.apply_substitution_mapping(input_text, mapping)
                flags = self.check_for_flags(decoded)
                if flags:
                    result = f"🚩 FLAG FOUND via frequency substitution: {flags[0]}"
                    print(result)
                    self.results.append(result)
                    return flags[0]
                
                if self.looks_like_english(decoded):
                    result = f"✓ Frequency substitution: {decoded[:100]}{'...' if len(decoded) > 100 else ''}"
                    print(result)
                    self.results.append(result)
        except:
            pass
        
        return None
    
    def looks_like_text(self, text):
        """Check if text looks like readable text"""
        if not text:
            return False
        
        # Check if most characters are printable
        printable_ratio = sum(c.isprintable() for c in text) / len(text)
        return printable_ratio > 0.8
    
    def looks_like_english(self, text):
        """Check if text looks like English"""
        if not self.looks_like_text(text):
            return False
        
        # Check for common English words
        common_words = ['THE', 'AND', 'FOR', 'ARE', 'BUT', 'NOT', 'YOU', 'ALL', 'CAN', 'HER', 'WAS', 'ONE', 'OUR', 'HAD', 'BY', 'WORD', 'WHAT', 'SAY']
        text_upper = text.upper()
        
        # Count how many common words appear
        word_count = sum(1 for word in common_words if word in text_upper)
        
        # Also check if it has reasonable letter frequency
        try:
            ic = self.frequency_analyzer.calculate_index_of_coincidence(text)
            reasonable_ic = 0.060 <= ic <= 0.075
        except:
            reasonable_ic = False
        
        return word_count >= 2 or reasonable_ic
    
    def auto_analyze(self, input_text):
        """Perform comprehensive automatic analysis"""
        print("🤖 AUTOMATIC CRYPTO ANALYSIS")
        print("=" * 50)
        
        # Basic input analysis
        input_info = self.analyze_input(input_text)
        print(f"📝 Input length: {input_info['length']} characters")
        print(f"📝 Input characteristics: ", end="")
        characteristics = []
        if input_info['hex_like']:
            characteristics.append("hex-like")
        if input_info['base64_like']:
            characteristics.append("base64-like")
        if input_info['binary_like']:
            characteristics.append("binary-like")
        if input_info['alpha_only']:
            characteristics.append("alphabetic")
        print(", ".join(characteristics) if characteristics else "mixed")
        
        # Check for immediate flags (but continue analysis in case it's encoded)
        flags = self.check_for_flags(input_text)
        if flags:
            result = f"🚩 Potential flag found in input: {flags[0]}"
            print(result)
            self.results.append(result)
            # Don't return yet - might be encoded, so continue analysis
        
        # Try different analysis methods
        methods = [
            self.try_encodings,
            self.try_classical_ciphers,
            self.try_xor_analysis,
            self.try_hash_analysis,
            self.try_frequency_analysis
        ]
        
        for method in methods:
            try:
                result = method(input_text)
                if result:  # Flag found
                    return result
            except Exception as e:
                print(f"⚠️ Error in {method.__name__}: {e}")
        
        print("\n❌ No flags found with automatic analysis")
        print("\n💡 Try manual analysis with specific tools:")
        print("   • encoding_tools.py for specific encodings")
        print("   • classical_ciphers.py for specific ciphers")
        print("   • hash_tools.py for hash cracking")
        print("   • frequency_analysis.py for detailed frequency analysis")
        
        return None
    
    def generate_report(self):
        """Generate analysis report"""
        print("\n" + "=" * 50)
        print("ANALYSIS SUMMARY")
        print("=" * 50)
        
        if not self.results:
            print("No significant results found")
        else:
            for i, result in enumerate(self.results, 1):
                print(f"{i}. {result}")

def main():
    parser = argparse.ArgumentParser(description='Unified Crypto Analyzer for CTF')
    parser.add_argument('input', help='Text to analyze or filename (use -f for file)')
    parser.add_argument('-f', '--file', action='store_true', help='Read input from file')
    parser.add_argument('-r', '--report', action='store_true', help='Generate detailed report')
    
    args = parser.parse_args()
    
    # Read input
    if args.file:
        try:
            with open(args.input, 'r', encoding='utf-8') as f:
                input_text = f.read().strip()
        except Exception as e:
            print(f"Error reading file: {e}")
            return
    else:
        input_text = args.input
    
    # Analyze
    analyzer = CryptoAnalyzer()
    result = analyzer.auto_analyze(input_text)
    
    if args.report:
        analyzer.generate_report()
    
    if result:
        print(f"\n🎉 FINAL RESULT: {result}")
    else:
        print(f"\n🤔 No automatic solution found. Try manual analysis.")

if __name__ == "__main__":
    main()