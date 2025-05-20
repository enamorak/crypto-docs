import os
import shutil
from crypto import Encrypt, Decrypt, readFile

# Тестовые данные
TEST_FILES = {
    "test_text.txt": b"Hello, this is a test message.",
    "test_image.jpg": bytes([120] * 1000),  # Псевдо-байты
    "test_pdf.pdf": bytes([37, 80, 68, 70, 45]) + bytes([0] * 995)  # PDF magic + мусор
}

CIPHERS = [
    "aes",
    "rsa2048",
    "rsa4096",
    "des"
]

def setup_test_files():
    os.makedirs("test_data", exist_ok=True)
    for fname, content in TEST_FILES.items():
        with open(os.path.join("test_data", fname), "wb") as f:
            f.write(content)

def cleanup_test_files():
    shutil.rmtree("test_data")
    for f in os.listdir():
        if f.startswith("test_text_enc") or f.startswith("test_image_enc") or f.startswith("test_pdf_enc"):
            os.remove(f)
        if f.endswith("_key.txt") or f.endswith("_dec.txt") or f.endswith("_dec.jpg") or f.endswith("_dec.pdf"):
            os.remove(f)

def test_encrypt_decrypt():
    print("Запуск тестов на все шифры и форматы файлов...")
    for test_file in TEST_FILES:
        test_path = os.path.join("test_data", test_file)
        print(f"  Файл: {test_file}")
        for cipher in CIPHERS:
            try:
                print(f"    -> Шифр: {cipher}")
                encrypted_file, key_file = Encrypt(test_path, cipher)
                with open(key_file, 'rb') as kf:
                    key = kf.read()
                decrypted_file = Decrypt(encrypted_file, cipher, key)
                original_data = readFile(test_path)
                decrypted_data = readFile(decrypted_file)

                assert original_data == decrypted_data, f"FAILED: {cipher} on {test_file}"
                print(f"       OK")
            except Exception as e:
                print(f"       ERROR: {e}")

if __name__ == "__main__":
    setup_test_files()
    try:
        test_encrypt_decrypt()
    finally:
        cleanup_test_files()
