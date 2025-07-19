# Z-HESP2 — Zero’s Hash Encryption Secure Protocol

Z-HESP2 is a terminal-based encryption tool designed for secure and efficient data protection. It features modern cryptographic techniques, including Argon2id key derivation and AES-GCM encryption, with support for metadata and multiple encryption versions.

## Features

- **Strong Encryption:** Uses AES-GCM with Argon2id key derivation for robust security.
- **Metadata Support:** Includes encrypted metadata such as timestamps and versioning.
- **File and Directory Encryption:** Encrypt and decrypt individual files or entire directories recursively.
- **Filename Encryption:** Encrypted files use encrypted filenames with a `.zh` extension for enhanced security.
- **Command Line Interface:** Easy-to-use CLI with commands for encryption, decryption, key generation, and version listing.
- **Help System:** Detailed help available for all commands and specific command summaries.
- **First-Time Integrity Check:** Ensures encryption system integrity on first use.


## Installation

```bash
pip install zhesp2
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
zhesp2 > encryptfile
Input file path: /path/to/input
Output file path: /path/to/output
Passphrase: 
[+] Encrypted file: /path/to/input/secret.txt -> /path/to/output/ENCRYPTEDFILENAME.zh
```

## Development
[+] Encrypted file: /path/to/input/secret.txt -> /path/to/output/ENCRYPTEDFILENAME.zh

The project is structured as a Python package with the following key modules:

- `crypto.py` — Core cryptographic functions, including filename encryption.
- `cli.py` — Command implementations and utilities, including file and directory encryption with filename encryption.
- `__main__.py` — CLI entry point and command dispatcher.

## License

GNU License Genral Public License v3.0
**note** This software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from, out of or in connection with this software or the use or other dealings in this software

## Author

Zero

## Donation Address

Support development with Ethereum or Ethereum-based tokens:

[![Ethereum](https://img.shields.io/badge/ETH-0x2800aBdF...-627eea?style=flat-square&logo=ethereum&logoColor=white)](https://etherscan.io/address/0x2800aBdF356809F4EbE2c9158630CcF975E1Ee67)

Thank you for helping keep ZHESP secure and evolving!