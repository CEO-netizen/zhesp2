# 🔐 ZHESP 2.0 — Zero's Hash Encryption Secure Protocol

![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Termux%20%7C%20Linux-orange)
![Version](https://img.shields.io/badge/version-2.3.0-informational)

**ZHESP** (Zero’s Hash Encryption Secure Protocol) is a secure, text-focused encryption CLI tool designed to be fast, safe, and hacker-friendly. It’s part of the [Anonymity 2.0 Project](https://github.com/4n0nym0us) — a suite of privacy tools for developers, pen-testers, and digital survivalists.

Built entirely in **Termux on Android**, ZHESP focuses on clean UX, hardened key derivation, non-deterministic encryption, and complete CLI control — without depending on heavyweight file systems or bloated GUI wrappers.

---

## 🚀 Features

- 🔑 `genkey`: Secure passphrase/key generation
- 🧂 Salted PBKDF2-HMAC-SHA256 with strong iteration count
- ✨ AES encryption of **text**, with fully encoded output
- 🔒 Encrypted headers and optional obfuscation
- 📋 Clipboard-friendly output, with optional auto-clear
- 🧠 Passphrase confirmation, entropy scoring, and warnings
- 🧱 Hardened decryptor with **delay-based throttling**
- ⚙️ Configurable security profiles (basic, strong, paranoid)
- 🛡️ Future-ready with versioned metadata and upgrade paths

> 🧠 **Note:** ZHESP is **not a file encryption tool** — it's a **secure text encryption utility**, built for CLI environments, scripts, and key-based workflows.

---

## 🧪 Example Usage

```bash
zhesp2 genkey
# → Generates a strong key with embedded metadata

zhesp2 encrypt "My secret message"
# → Encrypts and returns an obfuscated Base64 blob

zhesp2 decrypt "rHrNJkvSo..."
# → Prompts for key or passphrase, then decrypts

---

## Installation

Install from PyPI:

pip install zhesp2

Or install from source:

git clone https://github.com/CEO-netizen/zhesp2.git
cd zhesp2
python -m build
pip install dist/*.whl


---

🛡️ Security Overview

ZHESP uses best-practice cryptographic patterns:

Component	Method

Key Derivation	PBKDF2-HMAC-SHA256 (configurable iterations)
Salt	128-bit per-run random salt
Encryption	AES (CBC or GCM, based on profile)
Metadata	Embedded + optionally obfuscated
Output	Base64-encoded ciphertext
Protection	Throttled decrypt, version headers
