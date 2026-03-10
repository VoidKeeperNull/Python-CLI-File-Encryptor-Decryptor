# File Encryptor/Decryptor

A command-line tool that encrypts and decrypts files with automatic mode detection and key verification. Supports two encryption modes: a basic XOR cipher and a stronger PBKDF2-derived key mode with salt.

## How It Works

**Standard Mode (XOR):**
- XORs file bytes with a repeating key
- Prepends a header with a SHA-256 hash of the key for verification
- Auto-detects encrypt/decrypt based on header presence

**VKN Mode (`-v`):**
- Derives a 256-bit key from the passphrase using PBKDF2-HMAC-SHA256 with 100,000 iterations
- Generates a random 16-byte salt per encryption (stored in the file header)
- Uses the derived key for XOR encryption instead of the raw passphrase
- Auto-detects and reads the stored salt on decryption

Both modes work on any file type — text, images, binaries. Decryption verifies the key against a stored SHA-256 hash before proceeding.

## Usage

```bash
# Encrypt a file (standard XOR)
python encryptor.py -i secret.txt -o secret.enc -k mypassword

# Decrypt it back
python encryptor.py -i secret.enc -o secret.txt -k mypassword

# Encrypt with VKN mode (PBKDF2-derived key)
python encryptor.py -i secret.txt -o secret -k mypassword -v

# Decrypt a .vkn file
python encryptor.py -i secret.vkn -o secret.txt -k mypassword -v

# Wrong key is rejected in both modes
python encryptor.py -i secret.enc -o secret.txt -k wrongkey
# Error: Hash mismatch. File may be corrupted or key is incorrect.

# Specify output directory
python encryptor.py -i secret.txt -o secret.enc -k mypassword -p C:\Users\Me\Documents
```

## Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--input` | `-i` | Input file (required) |
| `--output` | `-o` | Output file (required) |
| `--key` | `-k` | Encryption key (required) |
| `--path` | `-p` | Output directory (default: current) |
| `--vkn` | `-v` | Use VKN mode with PBKDF2 key derivation |

## File Format

**Standard (.enc):**
```
[ENCRYPTED header (8 bytes)][SHA-256 hash (32 bytes)][XOR encrypted data]
```

**VKN (.vkn):**
```
[VKNFILE header (7 bytes)][Salt (16 bytes)][SHA-256 hash (32 bytes)][Derived-key XOR encrypted data]
```

## Security Note

Both modes use XOR as the underlying cipher, which is not cryptographically secure — it is vulnerable to frequency analysis and known-plaintext attacks. VKN mode improves key strength through PBKDF2 derivation and per-file salting, but the XOR cipher itself remains the weak link.

A production implementation would use AES-GCM or similar authenticated encryption. This project demonstrates bitwise operations, binary file I/O, key derivation, and CLI design.

## Dependencies

```bash
pip install cryptography
```

## Built With

- Python 3
- cryptography (PBKDF2HMAC)"# Python-CLI-File-Encryptor-Decryptor" 
