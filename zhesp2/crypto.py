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
    ARGON2_TIME_COST,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_HASH_LENGTH,
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

def derive_key(password: str, salt: bytes, length: int = ARGON2_HASH_LENGTH,
               time_cost=ARGON2_TIME_COST, memory_cost=ARGON2_MEMORY_COST,
               parallelism=ARGON2_PARALLELISM) -> bytes:
    try:
        return hash_secret_raw(
            password.encode(),
            salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=length,
            type=Type.ID,
        )
    except Exception as e:
        raise EncryptionError(f"Key derivation failed: {e}")

def encrypt(message: str, password: str, metadata: dict | None = None) -> str:
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = derive_key(password, salt)

    if metadata is None:
        metadata = {}
    metadata.update({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": VERSION
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

        key = derive_key(password, salt)

        meta_cipher = AES.new(key, AES.MODE_GCM, nonce=meta_nonce)
        metadata_json = meta_cipher.decrypt_and_verify(meta_ct, meta_tag)
        metadata = json.loads(metadata_json.decode())

        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        message = zlib.decompress(plaintext).decode()

        return f"[+] Metadata: {json.dumps(metadata, indent=2)}\\n[+] Decrypted: {message}"
    except Exception as e:
        return f"[!] Decryption error (v2): {e}"

# New helper functions for filename encryption/decryption

def encrypt_filename(filename: str, password: str) -> str:
    """
    Encrypt a filename string using the same encryption scheme but without compression and metadata.
    Returns a URL-safe base64 encoded string.
    """
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = derive_key(password, salt)

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

        key = derive_key(password, salt)

        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()
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
