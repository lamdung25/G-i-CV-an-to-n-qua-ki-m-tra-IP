import socket
import json
import base64
from crypto_utils import *

receiver_port = 12345
allowed_ip = "127.0.0.1"

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(("", receiver_port))
    s.listen(1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print("Chờ người gửi...")
    conn, addr = s.accept()
    with conn:
        hello = conn.recv(1024)
        print("📥 Đã nhận Hello từ sender:", hello)  # <--- Thêm dòng này

        sender_ip = hello[6:].decode()
        print("IP gửi đến:", sender_ip)
        if sender_ip != allowed_ip:
            conn.sendall(b"NACK")
            exit()

        conn.sendall(b"Ready!")
        packet_data = conn.recv(100000).decode()
        packet = json.loads(packet_data)

        iv = base64.b64decode(packet["iv"])
        cipher = base64.b64decode(packet["cipher"])
        hash_received = packet["hash"]
        sig = base64.b64decode(packet["sig"])
        metadata = base64.b64decode(packet["metadata"])
        encrypted_key = base64.b64decode(packet["key"])

        session_key = rsa_decrypt(encrypted_key, "keys/receiver_private.pem")
        if SHA512.new(iv + cipher).hexdigest() != hash_received:
            conn.sendall(b"NACK")
            exit()

        if not verify_signature(metadata, sig, "keys/sender_public.pem"):
            conn.sendall(b"NACK")
            exit()

        plain = aes_decrypt(cipher, session_key, iv)
        with open("received_cv.pdf", "wb") as f:
            f.write(plain)

        print("Lưu file thành công thành: received_cv.pdf")
        conn.sendall(b"ACK")
