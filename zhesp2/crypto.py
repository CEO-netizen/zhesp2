import os
import base64
import json
import zlib
import secrets
from datetime import datetime, timezone

from Crypto.Cipher import AES
from argon2.low_level import hash_secret_raw, Type

VERSION = 2

VERSIONS_INFO = {
    1: {
        "name": "ZH1",
        "description": "Initial release - AES-256-CBC encryption, PBKDF2 key derivation",
        "status": "deprecated"
    },
    2: {
        "name": "ZH2",
        "description": "Current stable release - Argon2id KDF, metadata support, base64 & hex output",
        "status": "stable"
    },
    # Add future versions here
}

def generate_key(length: int = 32, print_key: bool = True) -> str:
    raw = secrets.token_bytes(length)
    b64 = base64.urlsafe_b64encode(raw).decode()
    if print_key:
        print(f"[+] Generated Key ({length * 8} bits):\nBase64: {b64}\nHex:    {raw.hex()}\n")
    return b64

def derive_key(password: str, salt: bytes, length: int = 32, time_cost=3, memory_cost=65536, parallelism=2) -> bytes:
    return hash_secret_raw(
        password.encode(),
        salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=length,
        type=Type.ID,
    )

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

        return f"[+] Metadata: {json.dumps(metadata, indent=2)}\n[+] Decrypted: {message}"
    except Exception as e:
        return f"[!] Decryption error (v2): {e}"	
