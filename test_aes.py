from aes_utils import generate_aes_key, encrypt_file, decrypt_file

key = generate_aes_key()

# File test: bạn có thể tạo file "hello.txt" chứa vài dòng chữ
encrypt_file("hello.txt", "hello_encrypted.bin", key)
decrypt_file("hello_encrypted.bin", "hello_decrypted.txt", key)
