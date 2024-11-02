
import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def encrypt_content(plain_text: bytes, key: bytes) -> bytes:
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(plain_text, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return iv + encrypted_data

def decrypt_content(encrypted_data: bytes, key: bytes) -> bytes:
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(encrypted_data)
    plain_text = unpad(padded_data, AES.block_size)
    return plain_text

def read_file(file_path: str) -> bytes:
    with open(file_path, 'rb') as f:
        return f.read()

def write_file(file_path: str, data: bytes):
    with open(file_path, 'wb') as f:
        f.write(data)

def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt a file using AES encryption.")
    parser.add_argument('--mode', choices=['encrypt', 'decrypt'], required=True, help="Mode: 'encrypt' or 'decrypt'")
    parser.add_argument('--input', required=True, help="Path to the input file")
    parser.add_argument('--output', required=True, help="Path to save the output file")
    parser.add_argument('--key', required=True, help="Encryption key (16, 24, or 32 bytes)")

    args = parser.parse_args()

    key = args.key.encode()
    if len(key) not in [16, 24, 32]:
        raise ValueError("Key must be 16, 24, or 32 bytes long.")

    if args.mode == 'encrypt':
        content = read_file(args.input)
        encrypted_content = encrypt_content(content, key)
        write_file(args.output, encrypted_content)
        print("Encryption successful. Encrypted file saved at:", args.output)
    elif args.mode == 'decrypt':
        encrypted_content = read_file(args.input)
        decrypted_content = decrypt_content(encrypted_content, key)
        write_file(args.output, decrypted_content)
        print("Decryption successful. Decrypted file saved at:", args.output)

if __name__ == "__main__":
    main()
