import socket
import json
import base64
import os
import time
from crypto_utils import *
from Crypto.Random import get_random_bytes


receiver_ip = "127.0.0.1"
receiver_port = 12345

session_key = get_random_bytes(16)
iv = get_random_bytes(16)

filename = "cv.pdf"
with open(filename, "rb") as f:
    file_data = f.read()

ciphertext = aes_encrypt(file_data, session_key, iv)

data_hash = SHA512.new(iv + ciphertext).hexdigest()

timestamp = str(int(time.time()))
sender_ip = socket.gethostbyname(socket.gethostname())
metadata = f"{filename}|{timestamp}|{sender_ip}".encode()

signature = sign_data(metadata, "keys/sender_private.pem")
encrypted_key = rsa_encrypt(session_key, "keys/receiver_public.pem")

packet = {
    "iv": base64.b64encode(iv).decode(),
    "cipher": base64.b64encode(ciphertext).decode(),
    "hash": data_hash,
    "sig": base64.b64encode(signature).decode(),
    "metadata": base64.b64encode(metadata).decode(),
    "key": base64.b64encode(encrypted_key).decode()
}

print("📡 Đang kết nối tới receiver...")  # DEBUG
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((receiver_ip, receiver_port))
    print("✅ Đã kết nối tới receiver.")  # DEBUG
    s.sendall(b"Hello!" + sender_ip.encode())
    response = s.recv(1024)
    print("📨 Phản hồi từ receiver:", response)  # DEBUG
    if response == b"Ready!":
        print("🚀 Gửi dữ liệu...")  # DEBUG
        s.sendall(json.dumps(packet).encode())
        result = s.recv(1024).decode()
        print("✅ Kết quả:", result)
    else:
        print("❌ Bị từ chối kết nối do IP không hợp lệ.")
