#!/usr/bin/env python3
"""
Comprehensive Steganography Analysis Tool for CTF Challenges
Analyzes images for hidden data using various techniques
"""

import os
import sys
from PIL import Image
from PIL.ExifTags import TAGS
import numpy as np
import matplotlib.pyplot as plt
import cv2
import hashlib
import binascii
from stegano import lsb
from stegano import exifHeader
import argparse

class StegoAnalyzer:
    def __init__(self, image_path):
        self.image_path = image_path
        self.image = Image.open(image_path)
        self.cv_image = cv2.imread(image_path)
        
    def basic_info(self):
        """Extract basic image information"""
        print("=" * 50)
        print("BASIC IMAGE INFORMATION")
        print("=" * 50)
        print(f"File: {self.image_path}")
        print(f"Format: {self.image.format}")
        print(f"Mode: {self.image.mode}")
        print(f"Size: {self.image.size}")
        print(f"File size: {os.path.getsize(self.image_path)} bytes")
        
        # Calculate file hashes
        with open(self.image_path, 'rb') as f:
            data = f.read()
            print(f"MD5: {hashlib.md5(data).hexdigest()}")
            print(f"SHA1: {hashlib.sha1(data).hexdigest()}")
    
    def extract_exif(self):
        """Extract and display EXIF data"""
        print("\n" + "=" * 50)
        print("EXIF METADATA")
        print("=" * 50)
        
        exif_data = self.image.getexif()
        if exif_data:
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)
                print(f"{tag}: {value}")
        else:
            print("No EXIF data found")
    
    def lsb_analysis(self):
        """Analyze LSB steganography"""
        print("\n" + "=" * 50)
        print("LSB STEGANOGRAPHY ANALYSIS")
        print("=" * 50)
        
        try:
            # Try to extract hidden message using stegano library
            hidden_message = lsb.reveal(self.image_path)
            if hidden_message:
                print(f"LSB Hidden message found: {hidden_message}")
                return hidden_message
            else:
                print("No LSB hidden message found with stegano library")
        except Exception as e:
            print(f"LSB extraction error: {e}")
        
        # Manual LSB extraction for each channel
        self._manual_lsb_extraction()
        
    def _manual_lsb_extraction(self):
        """Manual LSB bit extraction"""
        print("\nManual LSB extraction:")
        
        # Convert image to numpy array
        img_array = np.array(self.image)
        
        if len(img_array.shape) == 3:  # Color image
            channels = ['Red', 'Green', 'Blue']
            for i, channel in enumerate(channels):
                lsb_bits = img_array[:, :, i] & 1
                binary_string = ''.join(lsb_bits.flatten().astype(str))
                
                # Try to extract text
                text = self._binary_to_text(binary_string)
                if text and any(c.isprintable() for c in text[:100]):
                    print(f"{channel} channel LSB: {text[:100]}...")
        else:  # Grayscale
            lsb_bits = img_array & 1
            binary_string = ''.join(lsb_bits.flatten().astype(str))
            text = self._binary_to_text(binary_string)
            if text and any(c.isprintable() for c in text[:100]):
                print(f"Grayscale LSB: {text[:100]}...")
    
    def _binary_to_text(self, binary_string):
        """Convert binary string to text"""
        try:
            # Split into 8-bit chunks and convert to characters
            chars = []
            for i in range(0, len(binary_string), 8):
                byte = binary_string[i:i+8]
                if len(byte) == 8:
                    char_code = int(byte, 2)
                    if 32 <= char_code <= 126:  # Printable ASCII
                        chars.append(chr(char_code))
            return ''.join(chars)
        except:
            return None
    
    def pixel_difference_analysis(self):
        """Analyze pixel differences for hidden data"""
        print("\n" + "=" * 50)
        print("PIXEL DIFFERENCE ANALYSIS")
        print("=" * 50)
        
        img_array = np.array(self.image)
        
        if len(img_array.shape) == 3:
            # Calculate differences between adjacent pixels
            diff_x = np.diff(img_array, axis=1)
            diff_y = np.diff(img_array, axis=0)
            
            # Look for patterns in differences
            print(f"Max X difference: {np.max(diff_x)}")
            print(f"Min X difference: {np.min(diff_x)}")
            print(f"Max Y difference: {np.max(diff_y)}")
            print(f"Min Y difference: {np.min(diff_y)}")
    
    def color_plane_analysis(self):
        """Analyze individual color planes"""
        print("\n" + "=" * 50)
        print("COLOR PLANE ANALYSIS")
        print("=" * 50)
        
        if self.image.mode == 'RGB':
            r, g, b = self.image.split()
            
            # Save individual color planes
            output_dir = os.path.join(os.path.dirname(self.image_path), 'analysis_output')
            os.makedirs(output_dir, exist_ok=True)
            
            r.save(os.path.join(output_dir, 'red_channel.png'))
            g.save(os.path.join(output_dir, 'green_channel.png'))
            b.save(os.path.join(output_dir, 'blue_channel.png'))
            
            print(f"Color planes saved to: {output_dir}")
    
    def bit_plane_analysis(self):
        """Analyze individual bit planes"""
        print("\n" + "=" * 50)
        print("BIT PLANE ANALYSIS")
        print("=" * 50)
        
        img_array = np.array(self.image.convert('L'))  # Convert to grayscale
        output_dir = os.path.join(os.path.dirname(self.image_path), 'analysis_output')
        os.makedirs(output_dir, exist_ok=True)
        
        # Extract each bit plane
        for bit in range(8):
            bit_plane = (img_array >> bit) & 1
            bit_plane = bit_plane * 255  # Scale to 0-255
            
            bit_image = Image.fromarray(bit_plane.astype('uint8'))
            bit_image.save(os.path.join(output_dir, f'bit_plane_{bit}.png'))
            
            print(f"Bit plane {bit} saved")
    
    def histogram_analysis(self):
        """Analyze color histograms for anomalies"""
        print("\n" + "=" * 50)
        print("HISTOGRAM ANALYSIS")
        print("=" * 50)
        
        if self.image.mode == 'RGB':
            colors = ['red', 'green', 'blue']
            plt.figure(figsize=(12, 4))
            
            for i, color in enumerate(colors):
                plt.subplot(1, 3, i+1)
                hist = self.image.histogram()[i*256:(i+1)*256]
                plt.plot(hist, color=color)
                plt.title(f'{color.capitalize()} Channel Histogram')
                plt.xlabel('Pixel Value')
                plt.ylabel('Frequency')
            
            output_dir = os.path.join(os.path.dirname(self.image_path), 'analysis_output')
            os.makedirs(output_dir, exist_ok=True)
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, 'histograms.png'))
            plt.close()
            
            print("Histograms saved to analysis_output/histograms.png")
    
    def search_for_flags(self):
        """Search for common CTF flag patterns"""
        print("\n" + "=" * 50)
        print("CTF FLAG SEARCH")
        print("=" * 50)
        
        # Common flag patterns
        flag_patterns = [
            r'flag{.*?}',
            r'FLAG{.*?}',
            r'ctf{.*?}',
            r'CTF{.*?}',
            r'picoCTF{.*?}',
            r'[a-fA-F0-9]{32}',  # MD5
            r'[a-fA-F0-9]{40}',  # SHA1
        ]
        
        # Search in various extracted data
        search_data = []
        
        # Add LSB extracted data
        try:
            lsb_data = lsb.reveal(self.image_path)
            if lsb_data:
                search_data.append(lsb_data)
        except:
            pass
        
        # Add EXIF data
        exif_data = self.image.getexif()
        if exif_data:
            for value in exif_data.values():
                search_data.append(str(value))
        
        # Search for patterns
        import re
        for data in search_data:
            for pattern in flag_patterns:
                matches = re.findall(pattern, data, re.IGNORECASE)
                if matches:
                    print(f"Potential flag found: {matches}")
    
    def run_full_analysis(self):
        """Run complete steganography analysis"""
        self.basic_info()
        self.extract_exif()
        self.lsb_analysis()
        self.pixel_difference_analysis()
        self.color_plane_analysis()
        self.bit_plane_analysis()
        self.histogram_analysis()
        self.search_for_flags()
        
        print("\n" + "=" * 50)
        print("ANALYSIS COMPLETE")
        print("=" * 50)
        print("Check the 'analysis_output' folder for generated files.")

def main():
    parser = argparse.ArgumentParser(description='Steganography Analysis Tool')
    parser.add_argument('image_path', help='Path to the image file to analyze')
    parser.add_argument('--method', choices=['all', 'lsb', 'exif', 'basic'], 
                       default='all', help='Analysis method to use')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.image_path):
        print(f"Error: File {args.image_path} not found!")
        return
    
    analyzer = StegoAnalyzer(args.image_path)
    
    if args.method == 'all':
        analyzer.run_full_analysis()
    elif args.method == 'lsb':
        analyzer.lsb_analysis()
    elif args.method == 'exif':
        analyzer.extract_exif()
    elif args.method == 'basic':
        analyzer.basic_info()

if __name__ == "__main__":
    main()