from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY_SIZE = 256

def encrypt(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    return cipher.encryptor().update(data)
