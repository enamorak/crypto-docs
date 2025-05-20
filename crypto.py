import os
from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad

# === Файловые утилиты ===
def readFile(filename: str) -> bytes:
    with open(filename, 'rb') as file:
        return file.read()

def writeToFile(filename: str, data: bytes):
    with open(filename, 'wb') as file:
        file.write(data)

# === AES ===
def generate_aes_key():
    return os.urandom(32)

def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher.iv + cipher.encrypt(pad(data, AES.block_size))

def aes_decrypt(key, data):
    iv, ct = data[:16], data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

# === RSA ===
def generate_rsa_keys(bits=2048):
    key = RSA.generate(bits)
    return key.export_key(), key.publickey().export_key()

def rsa_encrypt(public_key, data):
    pubkey = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(pubkey)
    return cipher.encrypt(data)

def rsa_decrypt(private_key, data):
    privkey = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(privkey)
    return cipher.decrypt(data)

# === DES ===
def generate_des_key():
    return os.urandom(8)

def des_encrypt(key, data):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(data, DES.block_size))

def des_decrypt(key, data):
    cipher = DES.new(key, DES.MODE_ECB)
    return unpad(cipher.decrypt(data), DES.block_size)

# === Главные функции ===
def Encrypt(filename: str, cipher_name: str):
    data = readFile(filename)
    name_base, ext = os.path.splitext(filename)
    cipher_name = cipher_name.lower()

    if cipher_name == 'aes':
        key = generate_aes_key()
        encrypted = aes_encrypt(key, data)

    elif cipher_name in ['rsa2048', 'rsa4096']:
        bits = 2048 if cipher_name == 'rsa2048' else 4096
        private_key, public_key = generate_rsa_keys(bits=bits)
        aes_key = generate_aes_key()
        encrypted_data = aes_encrypt(aes_key, data)
        encrypted_key = rsa_encrypt(public_key, aes_key)
        encrypted = encrypted_key + encrypted_data
        key = private_key  # сохраняем приватный ключ

    elif cipher_name == 'des':
        key = generate_des_key()
        encrypted = des_encrypt(key, data)

    else:
        raise ValueError(f"Неизвестный шифр: {cipher_name}")

    encrypted_filename = f"{name_base}_enc{ext}"
    writeToFile(encrypted_filename, encrypted)

    key_filename = f"{name_base}_key.txt"
    with open(key_filename, 'wb') as kf:
        kf.write(key)

    return encrypted_filename, key_filename

def Decrypt(filename: str, cipher_name: str, key_path: str):
    data = readFile(filename)
    key = readFile(key_path) 
    name_base, ext = os.path.splitext(filename)
    cipher_name = cipher_name.lower()

    if cipher_name == 'aes':
        decrypted = aes_decrypt(key, data)

    elif cipher_name in ['rsa2048', 'rsa4096']:
        rsa_key_len = 256 if cipher_name == 'rsa2048' else 512  # bytes
        encrypted_key = data[:rsa_key_len]
        encrypted_data = data[rsa_key_len:]
        aes_key = rsa_decrypt(key, encrypted_key)
        decrypted = aes_decrypt(aes_key, encrypted_data)

    elif cipher_name == 'des':
        decrypted = des_decrypt(key, data)

    else:
        raise ValueError(f"Неизвестный шифр: {cipher_name}")

    decrypted_filename = f"{name_base}_dec{ext}"
    writeToFile(decrypted_filename, decrypted)
    return decrypted_filename

