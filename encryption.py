import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import rsa

class AESCipher:
    def __init__(self, key: bytes) -> None:

        self.key = [key + b'0' * (32)][0]

    def encrypt(self, plaintext: bytes) -> bytes:
        iv = os.urandom(AES.block_size)
        cipher = AES.new(self.key[:32], AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        return iv + ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(self.key[:32], AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
        return plaintext

class RSACipher:
    @staticmethod
    def generate_keys(size: int) -> tuple:
        return rsa.newkeys(size)
    @staticmethod
    def export_public_key(key: rsa.PublicKey) -> bytes:
        return key.save_pkcs1()
    @staticmethod
    def export_private_key(key: rsa.PrivateKey) -> bytes:
        return key.save_pkcs1()
    @staticmethod
    def import_public_key(key: bytes) -> rsa.PublicKey:
        return rsa.PublicKey.load_pkcs1(key)
    @staticmethod
    def import_private_key(key: bytes) -> rsa.PrivateKey:
        return rsa.PrivateKey.load_pkcs1(key)
    
    @staticmethod
    def encrypt(public_key: rsa.PublicKey, plaintext: bytes) -> bytes:
        return rsa.encrypt(plaintext, public_key)
    @staticmethod
    def decrypt(private_key: rsa.PrivateKey, ciphertext: bytes) -> bytes:
        return rsa.decrypt(ciphertext, private_key)
    
class RSAxAES:
    @staticmethod
    def encrypt(public_key: rsa.PublicKey, plaintext: bytes) -> bytes:
        key = os.urandom(32)
        aes = AESCipher(key)
        return RSACipher.encrypt(public_key, key) + aes.encrypt(plaintext)
    @staticmethod
    def decrypt(private_key: rsa.PrivateKey, ciphertext: bytes) -> bytes:
        rsa_key_size = private_key.n.bit_length() // 8
        key = RSACipher.decrypt(private_key, ciphertext[:rsa_key_size])
        aes = AESCipher(key)
        return aes.decrypt(ciphertext[rsa_key_size:])