#!/usr/bin/env python3
"""
Frequency Analysis Tool for CTF Challenges
Analyzes text patterns to help break substitution ciphers
"""

import argparse
import string
from collections import Counter
import matplotlib.pyplot as plt

class FrequencyAnalyzer:
    def __init__(self):
        # English letter frequencies (approximate)
        self.english_freq = {
            'E': 12.02, 'T': 9.10, 'A': 8.12, 'O': 7.68, 'I': 6.97, 'N': 6.75,
            'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78,
            'U': 2.76, 'M': 2.41, 'W': 2.36, 'F': 2.23, 'G': 2.02, 'Y': 1.97,
            'P': 1.93, 'B': 1.29, 'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15,
            'Q': 0.10, 'Z': 0.07
        }
        
        # Common English digrams (two-letter combinations)
        self.english_digrams = [
            'TH', 'HE', 'IN', 'ER', 'AN', 'RE', 'ED', 'ND', 'ON', 'EN',
            'AT', 'OU', 'EA', 'HA', 'NG', 'AS', 'OR', 'TI', 'IS', 'ET'
        ]
        
        # Common English trigrams (three-letter combinations)
        self.english_trigrams = [
            'THE', 'AND', 'ING', 'HER', 'HAT', 'HIS', 'THA', 'ERE', 'FOR', 'ENT',
            'ION', 'TER', 'HAS', 'YOU', 'ITH', 'VER', 'ALL', 'WIT', 'THI', 'TIO'
        ]
    
    def analyze_character_frequency(self, text):
        """Analyze single character frequencies"""
        # Remove non-alphabetic characters and convert to uppercase
        clean_text = ''.join(c.upper() for c in text if c.isalpha())
        
        if not clean_text:
            return {}
        
        total_chars = len(clean_text)
        char_count = Counter(clean_text)
        
        frequency_data = {}
        for char in string.ascii_uppercase:
            count = char_count.get(char, 0)
            percentage = (count / total_chars) * 100 if total_chars > 0 else 0
            frequency_data[char] = {
                'count': count,
                'percentage': percentage,
                'expected': self.english_freq.get(char, 0)
            }
        
        return frequency_data
    
    def analyze_digrams(self, text):
        """Analyze two-character combinations"""
        clean_text = ''.join(c.upper() for c in text if c.isalpha())
        
        digrams = []
        for i in range(len(clean_text) - 1):
            digrams.append(clean_text[i:i+2])
        
        digram_count = Counter(digrams)
        total_digrams = len(digrams)
        
        digram_data = {}
        for digram, count in digram_count.most_common(20):
            percentage = (count / total_digrams) * 100 if total_digrams > 0 else 0
            digram_data[digram] = {
                'count': count,
                'percentage': percentage,
                'common_english': digram in self.english_digrams
            }
        
        return digram_data
    
    def analyze_trigrams(self, text):
        """Analyze three-character combinations"""
        clean_text = ''.join(c.upper() for c in text if c.isalpha())
        
        trigrams = []
        for i in range(len(clean_text) - 2):
            trigrams.append(clean_text[i:i+3])
        
        trigram_count = Counter(trigrams)
        total_trigrams = len(trigrams)
        
        trigram_data = {}
        for trigram, count in trigram_count.most_common(15):
            percentage = (count / total_trigrams) * 100 if total_trigrams > 0 else 0
            trigram_data[trigram] = {
                'count': count,
                'percentage': percentage,
                'common_english': trigram in self.english_trigrams
            }
        
        return trigram_data
    
    def calculate_index_of_coincidence(self, text):
        """Calculate Index of Coincidence (useful for determining if text is random)"""
        clean_text = ''.join(c.upper() for c in text if c.isalpha())
        n = len(clean_text)
        
        if n <= 1:
            return 0
        
        char_count = Counter(clean_text)
        ic = sum(count * (count - 1) for count in char_count.values()) / (n * (n - 1))
        
        return ic
    
    def suggest_cipher_type(self, text):
        """Suggest possible cipher type based on frequency analysis"""
        ic = self.calculate_index_of_coincidence(text)
        freq_data = self.analyze_character_frequency(text)
        
        suggestions = []
        
        # Index of Coincidence analysis
        if 0.060 <= ic <= 0.075:
            suggestions.append("Likely monoalphabetic substitution cipher (IC ≈ English)")
        elif 0.038 <= ic <= 0.050:
            suggestions.append("Possible polyalphabetic cipher (Vigenère, etc.)")
        elif ic < 0.038:
            suggestions.append("Possibly random text or complex cipher")
        elif ic > 0.075:
            suggestions.append("Possibly Caesar cipher or simple shift")
        
        # Character frequency analysis
        most_common = max(freq_data.items(), key=lambda x: x[1]['percentage'])
        if most_common[1]['percentage'] > 15:
            suggestions.append(f"High frequency letter '{most_common[0]}' ({most_common[1]['percentage']:.1f}%) - possibly 'E' in substitution")
        
        # Look for patterns that suggest Caesar cipher
        freq_order = sorted(freq_data.items(), key=lambda x: x[1]['percentage'], reverse=True)
        top_3_letters = [item[0] for item in freq_order[:3]]
        
        if 'E' in top_3_letters or 'T' in top_3_letters or 'A' in top_3_letters:
            suggestions.append("Frequency distribution similar to English - check Caesar cipher shifts")
        
        return suggestions
    
    def create_frequency_chart(self, text, output_file=None):
        """Create a visual frequency chart"""
        freq_data = self.analyze_character_frequency(text)
        
        letters = list(string.ascii_uppercase)
        actual_freq = [freq_data[letter]['percentage'] for letter in letters]
        expected_freq = [freq_data[letter]['expected'] for letter in letters]
        
        plt.figure(figsize=(15, 8))
        
        x_pos = range(len(letters))
        width = 0.35
        
        plt.bar([p - width/2 for p in x_pos], actual_freq, width, 
                label='Actual', alpha=0.7, color='blue')
        plt.bar([p + width/2 for p in x_pos], expected_freq, width, 
                label='Expected English', alpha=0.7, color='red')
        
        plt.xlabel('Letters')
        plt.ylabel('Frequency (%)')
        plt.title('Character Frequency Analysis')
        plt.xticks(x_pos, letters)
        plt.legend()
        plt.grid(True, alpha=0.3)
        
        if output_file:
            plt.savefig(output_file)
            print(f"Chart saved to: {output_file}")
        else:
            plt.show()
        
        plt.close()
    
    def generate_substitution_mapping(self, text):
        """Generate possible substitution mapping based on frequency"""
        freq_data = self.analyze_character_frequency(text)
        
        # Sort by frequency (descending)
        cipher_freq_order = sorted(freq_data.items(), 
                                 key=lambda x: x[1]['percentage'], 
                                 reverse=True)
        
        # English letters by frequency (descending)
        english_freq_order = sorted(self.english_freq.items(), 
                                  key=lambda x: x[1], 
                                  reverse=True)
        
        mapping = {}
        for i, (cipher_char, _) in enumerate(cipher_freq_order):
            if i < len(english_freq_order) and cipher_char != ' ':
                english_char = english_freq_order[i][0]
                mapping[cipher_char] = english_char
        
        return mapping
    
    def apply_substitution_mapping(self, text, mapping):
        """Apply a substitution mapping to decode text"""
        result = ""
        for char in text:
            if char.upper() in mapping:
                mapped_char = mapping[char.upper()]
                result += mapped_char.lower() if char.islower() else mapped_char
            else:
                result += char
        return result
    
    def full_analysis_report(self, text):
        """Generate comprehensive frequency analysis report"""
        report = []
        report.append("=" * 60)
        report.append("COMPREHENSIVE FREQUENCY ANALYSIS REPORT")
        report.append("=" * 60)
        
        # Basic statistics
        clean_text = ''.join(c for c in text if c.isalpha())
        report.append(f"Text length: {len(text)} characters")
        report.append(f"Alphabetic characters: {len(clean_text)}")
        report.append(f"Unique letters: {len(set(clean_text.upper()))}")
        
        # Index of Coincidence
        ic = self.calculate_index_of_coincidence(text)
        report.append(f"Index of Coincidence: {ic:.4f}")
        
        # Character frequencies
        report.append("\nCHARACTER FREQUENCIES:")
        freq_data = self.analyze_character_frequency(text)
        freq_sorted = sorted(freq_data.items(), 
                           key=lambda x: x[1]['percentage'], 
                           reverse=True)
        
        for char, data in freq_sorted:
            if data['count'] > 0:
                report.append(f"{char}: {data['count']:3d} ({data['percentage']:5.1f}%) "
                            f"[Expected: {data['expected']:4.1f}%]")
        
        # Top digrams
        report.append("\nTOP DIGRAMS:")
        digram_data = self.analyze_digrams(text)
        for digram, data in list(digram_data.items())[:10]:
            marker = " ✓" if data['common_english'] else ""
            report.append(f"{digram}: {data['count']:3d} ({data['percentage']:5.1f}%){marker}")
        
        # Top trigrams
        report.append("\nTOP TRIGRAMS:")
        trigram_data = self.analyze_trigrams(text)
        for trigram, data in list(trigram_data.items())[:10]:
            marker = " ✓" if data['common_english'] else ""
            report.append(f"{trigram}: {data['count']:3d} ({data['percentage']:5.1f}%){marker}")
        
        # Cipher suggestions
        report.append("\nCIPHER TYPE SUGGESTIONS:")
        suggestions = self.suggest_cipher_type(text)
        for suggestion in suggestions:
            report.append(f"• {suggestion}")
        
        # Substitution mapping
        report.append("\nSUGGESTED SUBSTITUTION MAPPING (based on frequency):")
        mapping = self.generate_substitution_mapping(text)
        for cipher_char, english_char in mapping.items():
            report.append(f"{cipher_char} → {english_char}")
        
        # Try the mapping
        if mapping:
            decoded = self.apply_substitution_mapping(text, mapping)
            report.append("\nDECODED TEXT (using frequency mapping):")
            report.append(decoded[:200] + "..." if len(decoded) > 200 else decoded)
        
        return "\n".join(report)

def main():
    parser = argparse.ArgumentParser(description='Frequency Analysis Tool for CTF')
    parser.add_argument('text', help='Text to analyze (or filename if using -f)')
    parser.add_argument('-f', '--file', action='store_true', 
                       help='Treat input as filename')
    parser.add_argument('-c', '--chart', help='Save frequency chart to file')
    parser.add_argument('-r', '--report', action='store_true', 
                       help='Generate full analysis report')
    parser.add_argument('-m', '--mapping', action='store_true',
                       help='Generate and apply substitution mapping')
    parser.add_argument('-i', '--ic', action='store_true',
                       help='Calculate Index of Coincidence only')
    
    args = parser.parse_args()
    
    # Load text
    if args.file:
        try:
            with open(args.text, 'r', encoding='utf-8') as f:
                text = f.read()
        except Exception as e:
            print(f"Error reading file: {e}")
            return
    else:
        text = args.text
    
    analyzer = FrequencyAnalyzer()
    
    if args.ic:
        ic = analyzer.calculate_index_of_coincidence(text)
        print(f"Index of Coincidence: {ic:.4f}")
        
    elif args.mapping:
        mapping = analyzer.generate_substitution_mapping(text)
        print("Suggested substitution mapping:")
        for cipher_char, english_char in mapping.items():
            print(f"{cipher_char} → {english_char}")
        
        decoded = analyzer.apply_substitution_mapping(text, mapping)
        print(f"\nDecoded text:\n{decoded}")
        
    elif args.report:
        report = analyzer.full_analysis_report(text)
        print(report)
        
    else:
        # Basic frequency analysis
        freq_data = analyzer.analyze_character_frequency(text)
        print("Character Frequencies:")
        freq_sorted = sorted(freq_data.items(), 
                           key=lambda x: x[1]['percentage'], 
                           reverse=True)
        
        for char, data in freq_sorted:
            if data['count'] > 0:
                print(f"{char}: {data['count']:3d} ({data['percentage']:5.1f}%) "
                      f"[Expected: {data['expected']:4.1f}%]")
    
    # Generate chart if requested
    if args.chart:
        analyzer.create_frequency_chart(text, args.chart)

if __name__ == "__main__":
    main()