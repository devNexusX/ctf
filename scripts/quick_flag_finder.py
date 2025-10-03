#!/usr/bin/env python3
"""
Quick steganography detection script for CTF challenges
Focuses on the most common hiding techniques
"""

import sys
import os
from PIL import Image
import numpy as np
from stegano import lsb
import re

def quick_flag_search(image_path):
    """Quick search for flags using common techniques"""
    print(f"Analyzing: {image_path}")
    print("=" * 40)
    
    # Define flag patterns at the beginning
    flag_patterns = [r'AKSO{.*?}', r'akso{.*?}', r'flag{.*?}', r'FLAG{.*?}', r'ctf{.*?}', r'CTF{.*?}', r'picoCTF{.*?}']
    
    try:
        # 1. LSB Steganography
        print("1. Checking LSB steganography...")
        hidden_message = lsb.reveal(image_path)
        if hidden_message:
            print(f"✓ LSB message found: {hidden_message}")
            
            # Check if it contains a flag
            for pattern in flag_patterns:
                matches = re.findall(pattern, hidden_message, re.IGNORECASE)
                if matches:
                    print(f"🚩 FLAG FOUND: {matches[0]}")
                    return matches[0]
        else:
            print("  No LSB message found")
    except Exception as e:
        print(f"  LSB error: {e}")
    
    # 2. EXIF Data
    print("\n2. Checking EXIF data...")
    try:
        image = Image.open(image_path)
        exif_data = image.getexif()
        if exif_data:
            for tag_id, value in exif_data.items():
                value_str = str(value)
                for pattern in flag_patterns:
                    matches = re.findall(pattern, value_str, re.IGNORECASE)
                    if matches:
                        print(f"🚩 FLAG FOUND in EXIF: {matches[0]}")
                        return matches[0]
            print("  EXIF data present but no flags found")
        else:
            print("  No EXIF data found")
    except Exception as e:
        print(f"  EXIF error: {e}")
    
    # 3. Check filename
    print("\n3. Checking filename...")
    filename = os.path.basename(image_path)
    for pattern in flag_patterns:
        matches = re.findall(pattern, filename, re.IGNORECASE)
        if matches:
            print(f"🚩 FLAG FOUND in filename: {matches[0]}")
            return matches[0]
    print("  No flags in filename")
    
    # 4. Manual LSB bit extraction
    print("\n4. Manual LSB extraction...")
    try:
        image = Image.open(image_path)
        img_array = np.array(image)
        
        if len(img_array.shape) == 3:  # Color image
            for i, channel in enumerate(['Red', 'Green', 'Blue']):
                lsb_bits = img_array[:, :, i] & 1
                binary_string = ''.join(lsb_bits.flatten().astype(str))
                
                # Convert to text (first 1000 chars to avoid memory issues)
                text = binary_to_text(binary_string[:8000])  # First 1000 characters
                if text:
                    for pattern in flag_patterns:
                        matches = re.findall(pattern, text, re.IGNORECASE)
                        if matches:
                            print(f"🚩 FLAG FOUND in {channel} LSB: {matches[0]}")
                            return matches[0]
        
        print("  No flags found in manual LSB extraction")
    except Exception as e:
        print(f"  Manual LSB error: {e}")
    
    print("\n❌ No flags found with quick methods")
    print("Try running the full analyzer: python scripts/stego_analyzer.py <image>")
    return None

def binary_to_text(binary_string):
    """Convert binary string to text"""
    try:
        chars = []
        for i in range(0, len(binary_string), 8):
            byte = binary_string[i:i+8]
            if len(byte) == 8:
                char_code = int(byte, 2)
                if 32 <= char_code <= 126:  # Printable ASCII
                    chars.append(chr(char_code))
                elif char_code == 0:  # Null terminator
                    break
        return ''.join(chars)
    except:
        return None

def main():
    if len(sys.argv) != 2:
        print("Usage: python quick_flag_finder.py <image_path>")
        sys.exit(1)
    
    image_path = sys.argv[1]
    if not os.path.exists(image_path):
        print(f"Error: File {image_path} not found!")
        sys.exit(1)
    
    flag = quick_flag_search(image_path)
    if flag:
        print(f"\n🎉 SUCCESS! Flag: {flag}")
    else:
        print(f"\n💡 Try additional analysis techniques or check for other files")

if __name__ == "__main__":
    main()