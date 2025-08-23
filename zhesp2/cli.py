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
import shlex
import getpass
import time
import os
from . import __version__
from .crypto import encrypt, decrypt, generate_key, VERSIONS_INFO, encrypt_filename, decrypt_filename
from .config import SECURITY_PROFILES, DEFAULT_SECURITY_PROFILE, INTEGRITY_FLAG_FILE

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

def safe_encrypt_flow(message: str, password: str, metadata: dict | None = None) -> str:
    """Perform first-time integrity check then encrypt the message."""
    if not os.path.exists(INTEGRITY_FLAG_FILE):
        print("[*] Running first-time encryption integrity check...")
        try:
            # Prompt user to select security profile
            print("Select a security profile for encryption:")
            for i, (key, profile) in enumerate(SECURITY_PROFILES.items(), 1):
                print(f"  {i}. {profile['name']} - {profile['description']}")
            choice = input(f"Enter choice (1-{len(SECURITY_PROFILES)}) [default {DEFAULT_SECURITY_PROFILE}]: ").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(SECURITY_PROFILES):
                selected_profile = list(SECURITY_PROFILES.keys())[int(choice) - 1]
            else:
                selected_profile = DEFAULT_SECURITY_PROFILE
            print(f"Using security profile: {selected_profile}")

            test_token = encrypt("test123", password, security_profile=selected_profile)
            output = decrypt(test_token, password)
            if "test123" not in output:
                raise RuntimeError("[!] Integrity test failed. Got: " + output)
            with open(INTEGRITY_FLAG_FILE, "w") as f:
                f.write("verified")
            print("[✓] Z-HESP2 encryption system verified.")
        except Exception as e:
            raise RuntimeError(f"[!] Integrity test failed: {e}")
    # Prompt user to select security profile before actual encryption
    print("Select a security profile for encryption:")
    for i, (key, profile) in enumerate(SECURITY_PROFILES.items(), 1):
        print(f"  {i}. {profile['name']} - {profile['description']}")
    choice = input(f"Enter choice (1-{len(SECURITY_PROFILES)}) [default {DEFAULT_SECURITY_PROFILE}]: ").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(SECURITY_PROFILES):
        selected_profile = list(SECURITY_PROFILES.keys())[int(choice) - 1]
    else:
        selected_profile = DEFAULT_SECURITY_PROFILE
    print(f"Using security profile: {selected_profile}")
    return encrypt(message, password, metadata, security_profile=selected_profile)

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
        from .crypto import shred_file

        # Prompt user to select security profile
        print("Select a security profile for file encryption:")
        for i, (key, profile) in enumerate(SECURITY_PROFILES.items(), 1):
            print(f"  {i}. {profile['name']} - {profile['description']}")
        choice = input(f"Enter choice (1-{len(SECURITY_PROFILES)}) [default {DEFAULT_SECURITY_PROFILE}]: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(SECURITY_PROFILES):
            selected_profile = list(SECURITY_PROFILES.keys())[int(choice) - 1]
        else:
            selected_profile = DEFAULT_SECURITY_PROFILE
        print(f"Using security profile: {selected_profile}")

        input_path_obj = pathlib.Path(input_path)
        output_path_obj = pathlib.Path(output_path)

        if input_path_obj.is_dir():
            # Recursively encrypt all files in directory
            for file_path in input_path_obj.rglob('*'):
                if file_path.is_file():
                    relative_path = file_path.relative_to(input_path_obj)
                    # Encrypt the filename
                    encrypted_name = encrypt_filename(str(relative_path.name), password)
                    # Use .zh extension
                    encrypted_name_with_ext = encrypted_name + ".zh"
                    out_file_path = output_path_obj / relative_path.parent / encrypted_name_with_ext
                    # Ensure parent directory exists
                    out_file_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(file_path, "rb") as f:
                        data = f.read()
                    token = encrypt(data.decode('latin1'), password, security_profile=selected_profile)
                    with open(out_file_path, "w", encoding="utf-8") as f:
                        f.write(token)
                    print(f"[+] Encrypted file: {file_path} -> {out_file_path}")
                    # Shred original file after encryption
                    shred_file(str(file_path))
        else:
            # Encrypt single file
            input_name = input_path_obj.name
            encrypted_name = encrypt_filename(input_name, password)
            encrypted_name_with_ext = encrypted_name + ".zh"
            out_file_path = output_path_obj / encrypted_name_with_ext
            with open(input_path, "rb") as f:
                data = f.read()
            token = encrypt(data.decode('latin1'), password, security_profile=selected_profile)
            # Ensure parent directory exists
            out_file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_file_path, "w", encoding="utf-8") as f:
                f.write(token)
            print(f"[+] File encrypted successfully: {out_file_path}")
            # Shred original file after encryption
            shred_file(str(input_path_obj))
    except Exception as e:
        print(f"[!] Error encrypting file: {e}")

def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    """Decrypt the contents of a file or directory and write to output path."""
    try:
        input_path_obj = pathlib.Path(input_path)
        output_path_obj = pathlib.Path(output_path)

        if input_path_obj.is_dir():
            # Recursively decrypt all files in directory
            for file_path in input_path_obj.rglob('*.zh'):
                if file_path.is_file():
                    relative_path = file_path.relative_to(input_path_obj)
                    # Remove .zh extension and decrypt filename
                    encrypted_name = relative_path.name[:-3]
                    try:
                        decrypted_name = decrypt_filename(encrypted_name, password)
                    except Exception as e:
                        print(f"[!] Error decrypting filename {relative_path.name}: {e}")
                        continue
                    out_file_path = output_path_obj / relative_path.parent / decrypted_name
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
            # Decrypt single file
            if input_path_obj.suffix != ".zh":
                print(f"[!] Input file does not have .zh extension: {input_path_obj.name}")
                return
            encrypted_name = input_path_obj.name[:-3]
            try:
                decrypted_name = decrypt_filename(encrypted_name, password)
            except Exception as e:
                print(f"[!] Error decrypting filename {input_path_obj.name}: {e}")
                return
            out_file_path = output_path_obj / decrypted_name
            with open(input_path, "r", encoding="utf-8") as f:
                token = f.read()
            result = decrypt(token, password)
            if result.startswith("[!]"):
                print(result)
                return
            decrypted_message = result.split("\n[+] Decrypted: ", 1)[-1]
            with open(out_file_path, "wb") as f:
                f.write(decrypted_message.encode('latin1'))
            print(f"[+] File decrypted successfully: {out_file_path}")
    except Exception as e:
        print(f"[!] Error decrypting file: {e}")
