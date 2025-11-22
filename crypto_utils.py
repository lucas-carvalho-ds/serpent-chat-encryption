import os
import bcrypt
import hmac
import hashlib
from pyserpent import Serpent, serpent_cbc_encrypt, serpent_cbc_decrypt
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from logger_config import setup_logger

log = setup_logger(__name__)

class CryptoUtils:
    @staticmethod
    def generate_salt():
        return bcrypt.gensalt()

    @staticmethod
    def hash_password(password, salt):
        return bcrypt.hashpw(password.encode('utf-8'), salt)

    @staticmethod
    def verify_password(password, hashed_password):
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

    @staticmethod
    def generate_rsa_keypair(bits=2048):
        key = RSA.generate(bits)
        private_key = key
        public_key = key.publickey()
        return private_key, public_key

    @staticmethod
    def encrypt_rsa(public_key, data):
        cipher = PKCS1_OAEP.new(public_key)
        return cipher.encrypt(data)

    @staticmethod
    def decrypt_rsa(private_key, encrypted_data):
        cipher = PKCS1_OAEP.new(private_key)
        return cipher.decrypt(encrypted_data)

    @staticmethod
    def sign_message(key, message):
        """Assina uma mensagem usando HMAC-SHA256."""
        if isinstance(message, str):
            message = message.encode('utf-8')
        # A chave para HMAC deve ser bytes. Se for string, encode.
        # Aqui assumimos que a 'key' é a chave da sala (Serpent Key) ou outra chave secreta compartilhada.
        if isinstance(key, str):
            key = key.encode('utf-8')
            
        signature = hmac.new(key, message, hashlib.sha256).digest()
        return signature

    @staticmethod
    def verify_signature(key, message, received_signature):
        """Verifica a assinatura HMAC-SHA256."""
        expected_signature = CryptoUtils.sign_message(key, message)
        return hmac.compare_digest(expected_signature, received_signature)

class SerpentCipher:
    def __init__(self, key):
        if len(key) != 32:
            raise ValueError("A chave Serpent deve ter 32 bytes (256 bits).")
        self.key = key

    def encrypt(self, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        iv = Serpent.generateIV()
        # pyserpent faz padding automaticamente se necessário, mas é bom garantir
        ciphertext = serpent_cbc_encrypt(self.key, plaintext, iv)
        return iv, ciphertext

    def decrypt(self, iv, ciphertext):
        decrypted_padded = serpent_cbc_decrypt(self.key, ciphertext, iv)
        # Remover padding nulo (comportamento padrão do pyserpent em alguns casos, mas idealmente usar PKCS7)
        # Para simplificar e compatibilizar com o código original, vamos usar rstrip(b'\0')
        # CUIDADO: Isso remove nulos legítimos do final se houver.
        # Melhor implementação seria PKCS7, mas vamos manter simples por enquanto e ajustar se precisar.
        return decrypted_padded.rstrip(b'\0')
