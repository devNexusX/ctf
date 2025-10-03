# CTF Steganography Challenge Workspace

This workspace is set up for analyzing steganography challenges in CTF competitions.

## Tools Available

### 1. Quick Flag Finder
**File:** `scripts/quick_flag_finder.py`
**Usage:** `python scripts/quick_flag_finder.py <image_path>`

Quick analysis tool that checks:
- LSB steganography using stegano library
- EXIF metadata for hidden flags
- Filename analysis
- Manual LSB bit extraction from each color channel

### 2. Full Steganography Analyzer
**File:** `scripts/stego_analyzer.py` 
**Usage:** `python scripts/stego_analyzer.py <image_path> [--method all|lsb|exif|basic]`

Comprehensive analysis including:
- Basic image information and hashes
- Complete EXIF metadata extraction
- LSB analysis (automated and manual)
- Pixel difference analysis
- Color plane separation
- Bit plane analysis
- Histogram analysis
- Flag pattern searching

## Installed Libraries

- **PIL/Pillow**: Image processing
- **numpy**: Numerical operations on image arrays
- **matplotlib**: Plotting histograms and visualizations
- **opencv-python**: Computer vision operations
- **stegano**: LSB steganography detection
- **exifread**: EXIF data extraction
- **pycryptodome**: Cryptographic operations
- **binwalk**: File analysis and extraction

## Usage Instructions

1. **Save your challenge image** to the `images/` folder
2. **Run quick analysis** first: `python scripts/quick_flag_finder.py images/your_image.jpg`
3. **If no flag found**, run full analysis: `python scripts/stego_analyzer.py images/your_image.jpg`
4. **Check the `analysis_output/` folder** for generated files (bit planes, color channels, histograms)

## Common CTF Flag Patterns

The tools search for these patterns:
- `flag{...}`
- `FLAG{...}`
- `ctf{...}`
- `CTF{...}`
- `picoCTF{...}`
- MD5 hashes (32 hex chars)
- SHA1 hashes (40 hex chars)

## Additional Techniques to Try

If automated tools don't find the flag:
1. **Manual bit plane inspection** - Check the generated bit plane images
2. **Color channel analysis** - Examine individual R, G, B channels
3. **Histogram anomalies** - Look for unusual patterns in the histograms
4. **Text extraction** - Search for readable text in LSB data
5. **File format analysis** - Use binwalk to check for embedded files
6. **Steganography-specific tools** - Try steghide, outguess, or other specialized tools

## Workflow

1. Place image in `images/` folder
2. Run `python scripts/quick_flag_finder.py images/challenge.jpg`
3. If successful, you'll see: 🚩 FLAG FOUND: flag{...}
4. If not, run full analysis and manually inspect outputs