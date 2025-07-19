# Z-HESP2 — Zero’s Hash Encryption Secure Protocol

Z-HESP2 is a terminal-based encryption tool designed for secure and efficient data protection. It features modern cryptographic techniques, including Argon2id key derivation and AES-GCM encryption, with support for metadata and multiple encryption versions.

## Features

- **Strong Encryption:** Uses AES-GCM with Argon2id key derivation for robust security.
- **Metadata Support:** Includes encrypted metadata such as timestamps and versioning.
- **Multiple Versions:** Supports legacy and current encryption formats.
- **File and Directory Encryption:** Encrypt and decrypt individual files or entire directories recursively.
- **Command Line Interface:** Easy-to-use CLI with commands for encryption, decryption, key generation, and version listing.
- **Help System:** Detailed help available for all commands and specific command summaries.
- **First-Time Integrity Check:** Ensures encryption system integrity on first use.

## Installation

Install the required dependencies:

```bash
pip install -r requirements.txt
```

Or install directly:

```bash
pip install pycryptodome argon2-cffi
```

## Usage

Run the CLI tool:

```bash
python -m zhesp2
```

Available commands:

- `encrypt` — Encrypt a plaintext message.
- `decrypt` — Decrypt an encrypted token.
- `genkey` — Generate a new encryption key.
- `listversions` — List supported encryption versions.
- `encryptfile` — Encrypt a file or directory.
- `decryptfile` — Decrypt a file or directory.
- `help` — Show detailed help or help for a specific command.
- `exit` — Exit the program.

Example:

```bash
zhesp2 > encrypt
Message: Hello World
Passphrase: 
[+] Encrypted token:
ZH2:...
```

## Development

The project is structured as a Python package with the following key modules:

- `crypto.py` — Core cryptographic functions.
- `cli.py` — Command implementations and utilities.
- `__main__.py` — CLI entry point and command dispatcher.

## License

MIT License

## Author

Zero

## donation address
#Ethereum or Ethereum based cryptos
```ethereum
0x2800aBdF356809F4EbE2c9158630CcF975E1Ee67
```
