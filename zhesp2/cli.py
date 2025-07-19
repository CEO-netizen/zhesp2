import shlex
import getpass
import time
import os
from . import __version__
from .crypto import encrypt, decrypt, generate_key, VERSIONS_INFO

INTEGRITY_FLAG_FILE = os.path.expanduser("~/.zhesp2_verified")

def banner() -> None:
    """Print the ASCII art banner with version info."""
    print(rf"""
 ███████╗██╗  ██╗███████╗███████╗███████╗██████╗
 ██╔════╝██║  ██║██╔════╝██╔════╝██╔════╝██╔══██╗
 ███████╗███████║█████╗  █████╗  █████╗  ██████╔╝
 ╚════██║██╔══██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗
 ███████║██║  ██║██║     ██║     ███████╗██║  ██║
 ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝
        Zero's Hash Encryption Secure Protocol
               Version {__version__} (Z-HESP2)
""")

def safe_encrypt_flow(message: str, password: str) -> str:
    """Perform first-time integrity check then encrypt the message."""
    if not os.path.exists(INTEGRITY_FLAG_FILE):
        print("[*] Running first-time encryption integrity check...")
        try:
            test_token = encrypt("test123", password)
            output = decrypt(test_token, password)
            if "test123" not in output:
                raise RuntimeError("[!] Integrity test failed. Got: " + output)
            with open(INTEGRITY_FLAG_FILE, "w") as f:
                f.write("verified")
            print("[✓] Z-HESP2 encryption system verified.")
        except Exception as e:
            raise RuntimeError(f"[!] Integrity test failed: {e}")
    return encrypt(message, password)

def list_versions() -> None:
    """Print supported ZHESP2 versions."""
    try:
        if not VERSIONS_INFO:
            print("[!] No version information found.")
            return
        print("[*] Supported ZHESP2 Versions:")
        for ver, info in VERSIONS_INFO.items():
            print(f"  - Version {ver} ({info.get('name','')}): {info.get('description','')} [{info.get('status','unknown')}]")
    except Exception as e:
        print(f"[!] Error listing versions: {e}")

HELP_SUMMARIES = {
    "encrypt": "Encrypt a plaintext message.",
    "decrypt": "Decrypt an encrypted token.",
    "genkey": "Generate a new encryption key.",
    "listversions": "List supported encryption versions.",
    "encryptfile": "Encrypt a file or directory.",
    "decryptfile": "Decrypt a file or directory.",
    "help": "Show help information.",
    "exit": "Exit the program.",
}

HELP_DETAILS = """
Z-HESP2 Command Line Interface Help

Commands:

encrypt
    Encrypt a plaintext message. You will be prompted for the message and passphrase.

decrypt
    Decrypt an encrypted token. You will be prompted for the token and passphrase.

genkey
    Generate a new encryption key. The key will be displayed in base64 and hex formats.

listversions
    List supported encryption versions with their descriptions and status.

encryptfile
    Encrypt a file or directory. You will be prompted for input path, output path, and passphrase.
    Directories are processed recursively, preserving structure.

decryptfile
    Decrypt a file or directory. You will be prompted for input path, output path, and passphrase.
    Directories are processed recursively, preserving structure.

help
    Show this help message or detailed help for a specific command.
    Usage: help [command]

exit
    Exit the program.
"""

def help(command: str | None = None) -> None:
    """Display help information."""
    if command:
        summary = HELP_SUMMARIES.get(command.lower())
        if summary:
            print(f"{command} - {summary}")
        else:
            print(f"No help available for command: {command}")
    else:
        print(HELP_DETAILS)

import os
import pathlib

def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    """Encrypt the contents of a file or directory and write to output path."""
    try:
        input_path_obj = pathlib.Path(input_path)
        output_path_obj = pathlib.Path(output_path)

        if input_path_obj.is_dir():
            # Recursively encrypt all files in directory
            for file_path in input_path_obj.rglob('*'):
                if file_path.is_file():
                    relative_path = file_path.relative_to(input_path_obj)
                    out_file_path = output_path_obj / relative_path
                    out_file_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(file_path, "rb") as f:
                        data = f.read()
                    token = encrypt(data.decode('latin1'), password)
                    with open(out_file_path.with_suffix(out_file_path.suffix + ".zhesp2"), "w", encoding="utf-8") as f:
                        f.write(token)
                    print(f"[+] Encrypted file: {file_path} -> {out_file_path.with_suffix(out_file_path.suffix + '.zhesp2')}")
        else:
            with open(input_path, "rb") as f:
                data = f.read()
            token = encrypt(data.decode('latin1'), password)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(token)
            print(f"[+] File encrypted successfully: {output_path}")
    except Exception as e:
        print(f"[!] Error encrypting file: {e}")

def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    """Decrypt the contents of a file or directory and write to output path."""
    try:
        input_path_obj = pathlib.Path(input_path)
        output_path_obj = pathlib.Path(output_path)

        if input_path_obj.is_dir():
            # Recursively decrypt all files in directory
            for file_path in input_path_obj.rglob('*.zhesp2'):
                if file_path.is_file():
                    relative_path = file_path.relative_to(input_path_obj)
                    out_file_path = output_path_obj / relative_path.with_suffix('')
                    out_file_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(file_path, "r", encoding="utf-8") as f:
                        token = f.read()
                    result = decrypt(token, password)
                    if result.startswith("[!]"):
                        print(f"[!] Error decrypting file {file_path}: {result}")
                        continue
                    decrypted_message = result.split("\n[+] Decrypted: ", 1)[-1]
                    with open(out_file_path, "wb") as f:
                        f.write(decrypted_message.encode('latin1'))
                    print(f"[+] Decrypted file: {file_path} -> {out_file_path}")
        else:
            with open(input_path, "r", encoding="utf-8") as f:
                token = f.read()
            result = decrypt(token, password)
            if result.startswith("[!]"):
                print(result)
                return
            decrypted_message = result.split("\n[+] Decrypted: ", 1)[-1]
            with open(output_path, "wb") as f:
                f.write(decrypted_message.encode('latin1'))
            print(f"[+] File decrypted successfully: {output_path}")
    except Exception as e:
        print(f"[!] Error decrypting file: {e}")
