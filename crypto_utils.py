from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512, SHA1
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
import base64

# -------------------- AES --------------------
def pad(data):
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def aes_encrypt(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data))

def aes_decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext))

# -------------------- RSA --------------------
def rsa_encrypt(data, public_key_file):
    with open(public_key_file, "rb") as f:
        public_key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA1)  # ⚠ Dùng SHA1 để tương thích RSA 1024
    return cipher.encrypt(data)

def rsa_decrypt(ciphertext, private_key_file):
    with open(private_key_file, "rb") as f:
        private_key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA1)  # ⚠ Phải giống lúc mã hóa
    return cipher.decrypt(ciphertext)

# -------------------- Ký số --------------------
def sign_data(data, private_key_file):
    h = SHA512.new(data)
    with open(private_key_file, "rb") as f:
        private_key = RSA.import_key(f.read())
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

def verify_signature(data, signature, public_key_file):
    h = SHA512.new(data)
    with open(public_key_file, "rb") as f:
        public_key = RSA.import_key(f.read())
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def verify_signature(data, signature, public_key_file):
    h = SHA512.new(data)
    with open(public_key_file, "rb") as f:
        public_key = RSA.import_key(f.read())
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
