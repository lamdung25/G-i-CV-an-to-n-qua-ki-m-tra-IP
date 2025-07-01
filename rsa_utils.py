from Crypto.PublicKey import RSA
import os

os.makedirs("keys", exist_ok=True)

def generate_key_pair(name):
    print(f"🔐 Đang tạo khóa cho: {name}")
    key = RSA.generate(1024)  # Chỉ dùng 1024-bit theo yêu cầu đề tài
    with open(f"keys/{name}_private.pem", "wb") as f:
        f.write(key.export_key())
    with open(f"keys/{name}_public.pem", "wb") as f:
        f.write(key.publickey().export_key())
    print(f"✅ Xong: {name}")

if __name__ == "__main__":
    generate_key_pair("sender")
    generate_key_pair("receiver")
