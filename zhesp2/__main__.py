import shlex
import getpass
import time
from .cli import banner, safe_encrypt_flow, list_versions
from .crypto import decrypt, generate_key
from typing import List

def handle_encrypt(args: List[str]) -> None:
    msg = " ".join(args) or input("Message: ")
    pwd = getpass.getpass("Passphrase: ")
    token = safe_encrypt_flow(msg, pwd)
    print("[+] Encrypted token:\n" + token)

def handle_decrypt(args: List[str], failures: int) -> int:
    token = args[0] if args else input("Ciphertext: ")
    pwd = getpass.getpass("Passphrase: ")
    if failures >= 3:
        delay = min(2 ** (failures - 2), 60)
        print(f"[!] Too many failed attempts. Sleeping {delay}s...")
        time.sleep(delay)
    result = decrypt(token, pwd)
    print(result)
    return failures + 1 if result.startswith("[!]") else 0

def main() -> None:
    banner()
    print("Z-HESP2 ready. Commands: encrypt, decrypt, encryptfile, decryptfile, genkey, listversions, help, exit.")
    failures = 0

    while True:
        try:
            cmd = input("zhesp2 > ").strip()
            if not cmd:
                continue
            args = shlex.split(cmd)

            match args[0]:
                case "exit" | "quit":
                    print("[*] Goodbye.")
                    break
                case "encrypt":
                    handle_encrypt(args[1:])
                case "decrypt":
                    failures = handle_decrypt(args[1:], failures)
                case "encryptfile":
                    input_path = input("Input file path: ").strip()
                    output_path = input("Output file path: ").strip()
                    pwd = getpass.getpass("Passphrase: ")
                    from .crypto import resolve_path
                    input_path = resolve_path(input_path)
                    output_path = resolve_path(output_path)
                    from .cli import encrypt_file
                    encrypt_file(input_path, output_path, pwd)
                case "decryptfile":
                    input_path = input("Input file path: ").strip()
                    output_path = input("Output file path: ").strip()
                    pwd = getpass.getpass("Passphrase: ")
                    from .crypto import resolve_path
                    input_path = resolve_path(input_path)
                    output_path = resolve_path(output_path)
                    from .cli import decrypt_file
                    decrypt_file(input_path, output_path, pwd)
                case "genkey":
                    generate_key()
                case "listversions" | "versions":
                    list_versions()
                case "help":
                    from .cli import help
                    if len(args) > 1:
                        help(args[1])
                    else:
                        help()
                case _:
                    print("[!] Unknown command.")
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Exiting Z-HESP2.")
            break
        except Exception as err:
            print(f"[!] Error: {err}")

if __name__ == "__main__":
    main()
