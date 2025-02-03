from Crypto.Random import get_random_bytes 
from Crypto.Protocol.KDF import PBKDF2 

from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad, unpad

Key_Salt = get_random_bytes(32)
print(Key_Salt)

Key_Plaintext = "I Love Cryptography" 

key = PBKDF2(Key_Plaintext, Key_Salt, dkLen=32)

print(key)

message = b"What is going on?" 

ciphertext = AES.new(key, AES.MODE_CBC)

ciphered_data = ciphertext.encrypt(pad(message, AES.block_size)) 

with open('encrypted.bin', 'wb') as f:
    f.write(ciphertext.iv)
    f.write(ciphered_data)
    
with open('encrypted.bin', 'rb') as f:
    iv = f.read(16)
    decrypt_data = f.read()

cipher = AES.new(key, AES.MODE_CBC, iv=iv)
original = unpad(cipher.decrypt(decrypt_data), AES.block_size)
print(original)

with open('key.bin', 'wb') as f:
    f.write(key)

