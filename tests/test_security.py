import unittest
import os
import sys
import pyotp

# Adicionar diretório pai ao path para importar módulos
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.common.crypto_utils import CryptoUtils, SerpentCipher
from src.server.auth import AuthManager
from src.server.database import Database

class TestSecurity(unittest.TestCase):
    def setUp(self):
        # Usar arquivo temporário para testes
        self.db_path = "test_chat.db"
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        self.db = Database(self.db_path)
        self.auth = AuthManager(self.db)

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_serpent_encryption(self):
        key = os.urandom(32)
        cipher = SerpentCipher(key)
        plaintext = b"Mensagem Secreta"
        
        iv, ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(iv, ciphertext)
        
        self.assertEqual(plaintext, decrypted)
        self.assertNotEqual(plaintext, ciphertext)

    def test_rsa_encryption(self):
        priv, pub = CryptoUtils.generate_rsa_keypair()
        message = b"Chave da Sala"
        
        encrypted = CryptoUtils.encrypt_rsa(pub, message)
        decrypted = CryptoUtils.decrypt_rsa(priv, encrypted)
        
        self.assertEqual(message, decrypted)

    def test_hmac_integrity(self):
        key = b"secret_key"
        message = b"Dados Importantes"
        
        signature = CryptoUtils.sign_message(key, message)
        self.assertTrue(CryptoUtils.verify_signature(key, message, signature))
        
        # Testar falha
        fake_signature = os.urandom(32)
        self.assertFalse(CryptoUtils.verify_signature(key, message, fake_signature))
        
        # Testar mensagem alterada
        self.assertFalse(CryptoUtils.verify_signature(key, b"Dados Alterados", signature))

    def test_authentication_flow(self):
        username = "alice"
        password = "password123"
        priv, pub = CryptoUtils.generate_rsa_keypair()
        pub_pem = pub.export_key()
        
        # Registro
        success, result = self.auth.register_user(username, password, pub_pem)
        self.assertTrue(success)
        totp_secret = result
        
        # Login Falha (Senha errada)
        success, msg = self.auth.authenticate_user(username, "wrongpass", "000000")
        self.assertFalse(success)
        
        # Login Falha (TOTP errado)
        success, msg = self.auth.authenticate_user(username, password, "000000")
        self.assertFalse(success)
        
        # Login Sucesso
        totp = pyotp.TOTP(totp_secret)
        code = totp.now()
        success, msg = self.auth.authenticate_user(username, password, code)
        self.assertTrue(success)

if __name__ == '__main__':
    unittest.main()
