# SPDX-License-Identifier: GPL-3.0-or-later
#This is ZHESP2(Zero's Hash Encryption Secure Protocol v2)
# Copyright (C) 2025  Gage Singleton <zeroday@mail.i2p>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
from datetime import datetime, timezone
import base64
import json
import os
import secrets
import zlib

from Crypto.Cipher import AES
from argon2.low_level import hash_secret_raw, Type

from .config import (
    VERSION,
    VERSIONS_INFO,
    SECURITY_PROFILES,
)

class EncryptionError(Exception):
    """Custom exception for encryption errors."""
    pass

class DecryptionError(Exception):
    """Custom exception for decryption errors."""
    pass

def generate_key(length: int = 32, print_key: bool = True) -> str:
    raw = secrets.token_bytes(length)
    b64 = base64.urlsafe_b64encode(raw).decode()
    if print_key:
        print(f"[+] Generated Key ({length * 8} bits):\nBase64: {b64}\nHex:    {raw.hex()}\n")
    return b64

def derive_key(password: str, salt: bytes, length: int = 32,
               security_profile: str = "secure") -> bytes:
    """Derive key using security profile parameters."""
    if security_profile not in SECURITY_PROFILES:
        raise EncryptionError(f"Invalid security profile: {security_profile}")
    
    profile = SECURITY_PROFILES[security_profile]
    params = profile["argon2_params"]
    
    try:
        return hash_secret_raw(
            password.encode(),
            salt,
            time_cost=params["time_cost"],
            memory_cost=params["memory_cost"],
            parallelism=params["parallelism"],
            hash_len=params["hash_length"],
            type=Type.ID,
        )
    except Exception as e:
        raise EncryptionError(f"Key derivation failed: {e}")

def encrypt(message: str, password: str, metadata: dict | None = None, 
            security_profile: str = "secure") -> str:
    """Encrypt message with specified security profile."""
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = derive_key(password, salt, security_profile=security_profile)

    if metadata is None:
        metadata = {}
    metadata.update({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": VERSION,
        "security_profile": security_profile
    })

    meta_json = json.dumps(metadata).encode()
    meta_nonce = os.urandom(12)
    meta_cipher = AES.new(key, AES.MODE_GCM, nonce=meta_nonce)
    meta_ct, meta_tag = meta_cipher.encrypt_and_digest(meta_json)

    compressed_msg = zlib.compress(message.encode())
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(compressed_msg)

    meta_ct_len = len(meta_ct).to_bytes(4, "big")
    ct_len = len(ciphertext).to_bytes(4, "big")

    payload = (
        VERSION.to_bytes(1, "big") +
        salt + iv + meta_nonce + meta_tag +
        meta_ct_len + meta_ct +
        ct_len + ciphertext + tag
    )
    return "ZH2:" + base64.urlsafe_b64encode(payload).decode()

def decrypt(token: str, password: str) -> str:
    try:
        if not token.startswith("ZH2:"):
            return "[!] Invalid ZHESP2 header."
        raw = base64.urlsafe_b64decode(token[4:])
        version = raw[0]
        payload = raw[1:]

        if version == 2:
            return decrypt_v2(payload, password)
        else:
            return f"[!] Unknown ZHESP2 version: {version}"
    except Exception as e:
        return f"[!] Decryption error: {e}"

def decrypt_v2(payload: bytes, password: str) -> str:
    try:
        salt = payload[:16]
        iv = payload[16:28]
        meta_nonce = payload[28:40]
        meta_tag = payload[40:56]
        meta_len = int.from_bytes(payload[56:60], "big")
        meta_ct = payload[60:60 + meta_len]
        offset = 60 + meta_len

        ct_len = int.from_bytes(payload[offset:offset + 4], "big")
        offset += 4
        ciphertext = payload[offset:offset + ct_len]
        tag = payload[offset + ct_len:offset + ct_len + 16]

        # Try to decrypt with each security profile until one works
        # This handles both old and new encrypted data
        for profile_name in ["secure", "fast", "paranoid"]:
            try:
                key = derive_key(password, salt, security_profile=profile_name)
                meta_cipher = AES.new(key, AES.MODE_GCM, nonce=meta_nonce)
                metadata_json = meta_cipher.decrypt_and_verify(meta_ct, meta_tag)
                metadata = json.loads(metadata_json.decode())
                
                # If we get here, this profile worked
                cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                message = zlib.decompress(plaintext).decode()
                
                return f"[+] Metadata: {json.dumps(metadata, indent=2)}\\n[+] Decrypted: {message}"
            except:
                continue
        
        # If none of the profiles worked, raise an error
        return "[!] Decryption failed: Invalid password or corrupted data"
    except Exception as e:
        return f"[!] Decryption error (v2): {e}"

# New helper functions for filename encryption/decryption

def encrypt_filename(filename: str, password: str, security_profile: str = "secure") -> str:
    """
    Encrypt a filename string using the same encryption scheme but without compression and metadata.
    Returns a URL-safe base64 encoded string.
    """
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = derive_key(password, salt, security_profile=security_profile)

    # Encrypt filename bytes directly
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(filename.encode())

    payload = (
        salt + iv + tag + ciphertext
    )
    # Encode payload as base64 urlsafe string
    return base64.urlsafe_b64encode(payload).decode()

def decrypt_filename(token: str, password: str) -> str:
    """
    Decrypt a filename string encrypted by encrypt_filename.
    """
    try:
        payload = base64.urlsafe_b64decode(token)
        salt = payload[:16]
        iv = payload[16:28]
        tag = payload[28:44]
        ciphertext = payload[44:]

        # Try each security profile for filename decryption
        for profile_name in ["secure", "fast", "paranoid"]:
            try:
                key = derive_key(password, salt, security_profile=profile_name)
                cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                return plaintext.decode()
            except:
                continue
        
        raise ValueError("Filename decryption failed: Invalid password or corrupted data")
    except Exception as e:
        raise ValueError(f"Filename decryption error: {e}")

def resolve_path(path: str) -> str:
    """
    Resolve a file path, expanding ~ to the current user's home directory.
    
    Args:
        path (str): The file path to resolve.
        
    Returns:
        str: The resolved absolute file path.
    """
    if path.startswith("~"):
        return os.path.expanduser(path)
    return path

def shred_file(path: str, passes: int = 3) -> None:
    """
    Securely shred a file by overwriting its content multiple times with random data before deleting it.

    Args:
        path (str): The file path to shred.
        passes (int): Number of overwrite passes. Default is 3.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"File not found: {path}")

    length = os.path.getsize(path)
    with open(path, "ba+", buffering=0) as f:
        for _ in range(passes):
            f.seek(0)
            f.write(os.urandom(length))
            f.flush()
            os.fsync(f.fileno())
    os.remove(path)
