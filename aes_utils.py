from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def generate_aes_key():
    key = get_random_bytes(32)  # 256-bit
    return key

def encrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        data = f.read()

    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))

    with open(output_file, 'wb') as f:
        f.write(cipher.iv + ct_bytes)  # Lưu IV + dữ liệu đã mã hóa

    print(f"✅ Đã mã hóa {input_file} → {output_file}")

def decrypt_file(encrypted_file, output_file, key):
    with open(encrypted_file, 'rb') as f:
        iv = f.read(16)  # AES block size = 16 bytes
        ct = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)

    with open(output_file, 'wb') as f:
        f.write(pt)

    print(f"✅ Đã giải mã {encrypted_file} → {output_file}")
