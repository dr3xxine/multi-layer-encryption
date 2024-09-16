import argparse
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes
from secrets import choice
import json
import os
import base64

step = ['fernet', 'aes', 'aes_gcm', 'chacha20', 'blowfish']

# AES Encryption and Decryption
def generate_aes_key():
    return os.urandom(32)  # AES-256 key

def encrypt_aes(data, key):
    iv = os.urandom(16)  # Initialization vector for AES
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()

def decrypt_aes(encrypted_data, key):
    iv = encrypted_data[:16]  # Extract the IV
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

# AES-GCM Encryption and Decryption
def generate_aes_gcm_key():
    return os.urandom(32)  # AES-256 key

def encrypt_aes_gcm(data, key):
    iv = os.urandom(12)  # AES-GCM uses a 12-byte IV
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return iv + encrypted_data + encryptor.tag

def decrypt_aes_gcm(encrypted_data, key):
    iv = encrypted_data[:12]
    tag = encrypted_data[-16:]
    encrypted_data = encrypted_data[12:-16]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

# ChaCha20 Encryption and Decryption
def encrypt_chacha20(data, key):
    cipher = Cipher(algorithms.ChaCha20(key, b'0'*16), mode=None)
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def decrypt_chacha20(encrypted_data, key):
    cipher = Cipher(algorithms.ChaCha20(key, b'0'*16), mode=None)
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

# Blowfish Encryption and Decryption
def generate_blowfish_key():
    return get_random_bytes(16)  # Blowfish key

def encrypt_blowfish(data, key):
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=os.urandom(8))
    padded_data = pad_blowfish(data)
    return cipher.iv + cipher.encrypt(padded_data)

def decrypt_blowfish(encrypted_data, key):
    iv = encrypted_data[:8]
    encrypted_data = encrypted_data[8:]
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
    padded_data = cipher.decrypt(encrypted_data)
    return unpad_blowfish(padded_data)

def pad_blowfish(data):
    padding_len = 8 - len(data) % 8
    return data + bytes([padding_len] * padding_len)

def unpad_blowfish(padded_data):
    padding_len = padded_data[-1]
    return padded_data[:-padding_len]

# Fernet Encryption and Decryption
def encrypt_fernet(data):
    key = Fernet.generate_key()
    fernet = Fernet(key)
    return fernet.encrypt(data), key

def decrypt_fernet(encrypted_data, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data)

def encrypt(input_file, output_file, key_file, times):
    keys_json = []
    
    with open(input_file, 'rb') as fp:
        data = fp.read()
        
    for _ in range(times):
        method = choice(step)
        if method == 'fernet':
            data, key = encrypt_fernet(data)
            keys_json.append({'method': method, 'key': base64.urlsafe_b64encode(key).decode('utf-8')})
        elif method == 'aes':
            key = generate_aes_key()
            data = encrypt_aes(data, key)
            keys_json.append({'method': method, 'key': key.hex()})
        elif method == 'aes_gcm':
            key = generate_aes_gcm_key()
            data = encrypt_aes_gcm(data, key)
            keys_json.append({'method': method, 'key': key.hex()})
        elif method == 'chacha20':
            key = os.urandom(32)
            data = encrypt_chacha20(data, key)
            keys_json.append({'method': method, 'key': key.hex()})
        elif method == 'blowfish':
            key = generate_blowfish_key()
            data = encrypt_blowfish(data, key)
            keys_json.append({'method': method, 'key': key.hex()})
    
    with open(key_file, 'w') as key_file:
        json.dump(keys_json, key_file)
        
    with open(output_file, 'wb') as fp:
        fp.write(data)

def decrypt(input_file, key_file, output_file):
    with open(key_file, 'r') as key_file:
        keys = json.load(key_file)
    
    with open(input_file, 'rb') as fp:
        data = fp.read()
    
    for j in reversed(keys):
        method = j['method']
        key = j['key']
        if method == 'fernet':
            key = base64.urlsafe_b64decode(key)
            data = decrypt_fernet(data, key)
        elif method == 'aes':
            key = bytes.fromhex(key)
            data = decrypt_aes(data, key)
        elif method == 'aes_gcm':
            key = bytes.fromhex(key)
            data = decrypt_aes_gcm(data, key)
        elif method == 'chacha20':
            key = bytes.fromhex(key)
            data = decrypt_chacha20(data, key)
        elif method == 'blowfish':
            key = bytes.fromhex(key)
            data = decrypt_blowfish(data, key)
    
    with open(output_file, 'wb') as fp:
        fp.write(data)

def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt files using multiple methods.")
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Encrypt Command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file.')
    encrypt_parser.add_argument('-i', '--input', required=True, help='Input file path')
    encrypt_parser.add_argument('-o', '--output', required=True, help='Output file path')
    encrypt_parser.add_argument('-k', '--keys', required=True, help='Key file path')
    encrypt_parser.add_argument('-t', '--times', type=int, required=True, help='Number of times to apply encryption')

    # Decrypt Command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file.')
    decrypt_parser.add_argument('-i', '--input', required=True, help='Input file path')
    decrypt_parser.add_argument('-k', '--keys', required=True, help='Key file path')
    decrypt_parser.add_argument('-o', '--output', required=True, help='Output file path')

    args = parser.parse_args()

    if args.command == 'e':
        encrypt(args.input, args.output, args.keys, args.times)
    elif args.command == 'd':
        decrypt(args.input, args.keys, args.output)

if __name__ == '__main__':
    main()
