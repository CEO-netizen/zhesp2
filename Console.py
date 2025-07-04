#!/usr/bin/env python3
"""
Z-HESP2 – Zero's Hash Encryption Secure Protocol
Version 2.3  (July 2025)
"""

import os
import base64
import getpass
import shlex
import zlib
import json
import time
import secrets
from datetime import datetime, timezone

from Crypto.Cipher import AES
from argon2.low_level import hash_secret_raw, Type

# ────────────────────────────────── Banner ────────────────────────────────── #
def banner() -> None:
    print(r"""
 ███████╗██╗  ██╗███████╗███████╗███████╗██████╗
 ██╔════╝██║  ██║██╔════╝██╔════╝██╔════╝██╔══██╗
 ███████╗███████║█████╗  █████╗  █████╗  ██████╔╝
 ╚════██║██╔══██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
 ███████║██║  ██║██║     ██║     ███████╗██║  ██║
 ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
        Zero's Hash Encryption Secure Protocol
                  Version 2.3 (Z-HESP2)
    """)

# ──────────────────────────────── KDF ─────────────────────────────────────── #
def derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    """Derive a symmetric key with Argon2id."""
    return hash_secret_raw(
        password.encode(),
        salt,
        time_cost=3,
        memory_cost=65_536,    # 64 MiB
        parallelism=2,
        hash_len=length,
        type=Type.ID,
    )

# ─────────────────────────────── Encrypt ──────────────────────────────────── #
def encrypt(message: str, password: str, metadata: dict | None = None) -> str:
    """Encrypt a message, returning a ZH2:-prefixed token."""
    salt = os.urandom(16)
    iv   = os.urandom(12)
    key  = derive_key(password, salt)

    # metadata
    if metadata is None:
        metadata = {}
    metadata["timestamp"] = datetime.now(timezone.utc).isoformat()

    meta_blob        = zlib.compress(json.dumps(metadata).encode())
    meta_len_bytes   = len(meta_blob).to_bytes(4, "big")
    compressed_msg   = zlib.compress(message.encode())
    plaintext        = meta_blob + compressed_msg          # ← encrypted part
    aad              = meta_len_bytes                      # ← authenticated only

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    payload = salt + iv + tag + aad + ciphertext
    return "ZH2:" + base64.urlsafe_b64encode(payload).decode()

# ─────────────────────────────── Decrypt ──────────────────────────────────── #
def decrypt(token: str, password: str) -> str:
    """Decrypt a ZH2 token with the supplied password."""
    try:
        if not token.startswith("ZH2:"):
            return "[!] Invalid ZHESP2 header."

        raw         = base64.urlsafe_b64decode(token[4:])
        salt        = raw[:16]
        iv          = raw[16:28]
        tag         = raw[28:44]
        aad         = raw[44:48]          # 4-byte meta length
        ciphertext  = raw[48:]

        key    = derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        cipher.update(aad)

        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        meta_len   = int.from_bytes(aad, "big")
        meta_blob  = zlib.decompress(plaintext[:meta_len])
        metadata   = json.loads(meta_blob.decode())
        message    = zlib.decompress(plaintext[meta_len:]).decode()

        return f"[+] Metadata: {metadata}\n[+] Decrypted: {message}"

    except Exception as e:
        return f"[!] Decryption error: {e}"

# ─────────────────────────── Key Generation ──────────────────────────────── #
def generate_key(length: int = 32) -> str:
    raw   = secrets.token_bytes(length)
    b64   = base64.urlsafe_b64encode(raw).decode()
    print(f"[+] Generated Key ({length*8} bits):\nBase64: {b64}\nHex:    {raw.hex()}\n")
    return b64

# ──────────────────────────────── CLI ─────────────────────────────────────── #
def main() -> None:
    banner()
    print("Z-HESP2 ready. Commands: encrypt, decrypt, genkey, exit.")
    failures = 0

    while True:
        try:
            cmd  = input("zhesp2 > ").strip()
            if not cmd:
                continue
            args = shlex.split(cmd)

            match args[0]:
                case "exit" | "quit":
                    print("[*] Goodbye.")
                    break

                case "encrypt":
                    msg = " ".join(args[1:]) or input("Message: ")
                    pwd = getpass.getpass("Passphrase: ")
                    print(encrypt(msg, pwd))

                case "decrypt":
                    token = args[1] if len(args) > 1 else input("Ciphertext: ")
                    pwd   = getpass.getpass("Passphrase: ")

                    if failures >= 3:
                        delay = min(2 ** (failures - 2), 60)
                        print(f"[!] Too many failed attempts. Sleeping {delay}s...")
                        time.sleep(delay)

                    result = decrypt(token, pwd)
                    print(result)

                    failures = failures + 1 if result.startswith("[!]") else 0

                case "genkey":
                    generate_key()

                case _:
                    print("[!] Unknown command.")

        except (KeyboardInterrupt, EOFError):
            print("\n[!] Exiting Z-HESP2.")
            break
        except Exception as err:
            print(f"[!] Error: {err}")

# ───────────────────────────── Unit Test ─────────────────────────────────── #
def _test_roundtrip() -> None:
    msg = "Hello, world!"
    pwd = "hunter2"
    token = encrypt(msg, pwd)
    assert decrypt(token, pwd).endswith(msg)
    print("[✓] Round-trip test passed.")

# Uncomment the next line to run the self-test once:
# _test_roundtrip()

# ────────────────────────────── Entrypoint ───────────────────────────────── #
if __name__ == "__main__":
    main()
