# Z-HESP2 — Zero's Hash Encryption Secure Protocol

Z-HESP2 is a terminal-based encryption tool designed for secure and efficient data protection. It features modern cryptographic techniques, including Argon2id key derivation and AES-GCM encryption, with support for metadata timestamping and security profiles.

## Features

- **Strong Encryption:** Uses AES-GCM with Argon2id key derivation for robust security.
- **Security Profiles:** Choose from three security levels:
  - **Fast:** Optimized for speed with reasonable security
  - **Secure:** Balanced security and performance (default)
  - **Paranoid:** Maximum security with higher computational cost
- **Metadata Support:** Includes encrypted metadata such as timestamps, versioning, and security profile used.
- **File and Directory Encryption:** Encrypt and decrypt individual files or entire directories recursively.
- **Filename Encryption:** Encrypted files use encrypted filenames with a `.zh` extension for enhanced security.
- **Command Line Interface:** Easy-to-use CLI with commands for encryption, decryption, key generation, and version listing.
- **Help System:** Detailed help available for all commands and specific command summaries.
- **First-Time Integrity Check:** Ensures encryption system integrity on first use.

## Installation

```bash
gh repo clone CEO-netizen/zhesp2
# or git clone
cd zhesp2
pip install .
```

## Usage

Run the CLI tool:

```bash
zhesp2
```

Available commands:

- `encrypt` — Encrypt a plaintext message (prompts for security profile).
- `decrypt` — Decrypt an encrypted token.
- `genkey` — Generate a new encryption key.
- `listversions` — List supported encryption versions.
- `encryptfile` — Encrypt a file or directory (prompts for security profile).
- `decryptfile` — Decrypt a file or directory.
- `help` — Show detailed help or help for a specific command.
- `exit` — Exit the program.

### Security Profile Selection

When encrypting text or files, you'll be prompted to select a security profile:

```
Select a security profile for encryption:
  1. Fast - Optimized for speed with reasonable security
  2. Secure - Balanced security and performance (default)
  3. Paranoid - Maximum security with higher computational cost
Enter choice (1-3) [default secure]: 
```

Example:

```bash
zhesp2 > encryptfile
Input file path: ~/Documents/secret.txt
Output file path: ~/Encrypted/
Select a security profile for encryption:
  1. Fast - Optimized for speed with reasonable security
  2. Secure - Balanced security and performance (default)
  3. Paranoid - Maximum security with higher computational cost
Enter choice (1-3) [default secure]: 2
Using security profile: secure
[+] Encrypted file: /home/username/Documents/secret.txt -> /home/username/Encrypted/ENCRYPTEDFILENAME.zh
```

## Development

The project is structured as a Python package with the following key modules:

- `crypto.py` — Core cryptographic functions, including filename encryption and path resolution.
- `cli.py` — Command implementations and utilities, including file and directory encryption with filename encryption.
- `__main__.py` — CLI entry point and command dispatcher.

### Security Profile Details

Each security profile uses different Argon2 parameters:

- **Fast:** time_cost=2, memory_cost=65536 (64MB), parallelism=2 (AES-GCM)
- **Secure:** time_cost=5, memory_cost=131072 (128MB), parallelism=4 (AES-GCM)
- **Paranoid:** time_cost=10, memory_cost=262144 (256MB), parallelism=8 (Uses XChaCha20-poly1305)

### New Utility Function: resolve_path

A new utility function `resolve_path(path: str) -> str` has been added to `crypto.py`. This function expands the tilde (`~`) in file paths to the current user's home directory, ensuring that paths using `~` are correctly resolved when encrypting or decrypting files.

## Author

CEO-netizen

# note
Sorry I didnt maintain sooner I was dealing with some family stuff I hope you understand.