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

## Cryptography Tools

### 1. Encoding/Decoding Tools
**File:** `scripts/encoding_tools.py`
**Usage:** `python scripts/encoding_tools.py <text> -m <method> -o <operation>`

Supports: Base64, Hex, URL, HTML, ROT13, Binary, ASCII, Morse code
- Auto-detection: `python scripts/encoding_tools.py <text> -a`

### 2. Classical Cipher Tools
**File:** `scripts/classical_ciphers.py`
**Usage:** `python scripts/classical_ciphers.py <text> -c <cipher> [options]`

Supports: Caesar, Vigenère, Atbash, Substitution, Rail Fence, Playfair
- Caesar bruteforce: `python scripts/classical_ciphers.py <text> -c caesar -b`
- Frequency analysis: `python scripts/classical_ciphers.py <text> -f`

### 3. Hash Analysis Tools
**File:** `scripts/hash_tools.py`
**Usage:** `python scripts/hash_tools.py <hash> [options]`

Features: Hash identification, generation, dictionary attacks, bruteforce
- Identify hash: `python scripts/hash_tools.py <hash> -i`
- Dictionary attack: `python scripts/hash_tools.py <hash> -d md5`

### 4. Modern Cryptography Tools
**File:** `scripts/modern_crypto.py`
**Usage:** `python scripts/modern_crypto.py [options]`

Features: AES encryption/decryption, RSA operations, XOR analysis
- AES encrypt: `python scripts/modern_crypto.py --aes-encrypt "text" "key"`
- XOR bruteforce: `python scripts/modern_crypto.py --xor-bruteforce <hex>`
- RSA attacks: `python scripts/modern_crypto.py --rsa-attack <n> <e>`

### 5. Frequency Analysis
**File:** `scripts/frequency_analysis.py`
**Usage:** `python scripts/frequency_analysis.py <text> [options]`

Features: Character frequency, substitution mapping, cipher type detection
- Full report: `python scripts/frequency_analysis.py <text> -r`
- Generate mapping: `python scripts/frequency_analysis.py <text> -m`

### 6. Unified Crypto Analyzer
**File:** `scripts/crypto_analyzer.py`
**Usage:** `python scripts/crypto_analyzer.py <text>`

Automatically tries multiple methods:
- Encoding/decoding (base64, hex, etc.)
- Classical ciphers (Caesar, Atbash, etc.)
- XOR analysis
- Hash cracking
- Frequency analysis

## Additional Techniques to Try

If automated tools don't find the flag:
1. **Manual bit plane inspection** - Check the generated bit plane images
2. **Color channel analysis** - Examine individual R, G, B channels
3. **Histogram anomalies** - Look for unusual patterns in the histograms
4. **Text extraction** - Search for readable text in LSB data
5. **File format analysis** - Use binwalk to check for embedded files
6. **Steganography-specific tools** - Try steghide, outguess, or other specialized tools

## Workflow

### For Steganography:
1. Place image in `images/` folder
2. Run `python scripts/quick_flag_finder.py images/challenge.jpg`
3. If successful, you'll see: 🚩 FLAG FOUND: flag{...}
4. If not, run full analysis and manually inspect outputs

### For Cryptography:
1. Try the unified analyzer first: `python scripts/crypto_analyzer.py "encrypted_text"`
2. If no flag found, use specific tools based on the challenge type
3. For unknown cipher types, use frequency analysis
4. For hash-like strings, try hash cracking tools