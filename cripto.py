# cripto.py
import hmac
import hashlib
from pyserpent import Serpent, serpent_cbc_encrypt, serpent_cbc_decrypt
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from logger_config import setup_logger

log = setup_logger(__name__)

class CriptoRSA:
    """Gerencia a geração e uso de chaves RSA."""
    def __init__(self, key_length=2048):
        log.debug(f"Gerando novo par de chaves RSA de {key_length} bits...")
        self._private_key = RSA.generate(key_length)
        self._public_key = self._private_key.publickey()
        self.cipher_rsa_encrypt = PKCS1_OAEP.new(self._public_key)
        self.cipher_rsa_decrypt = PKCS1_OAEP.new(self._private_key)
        log.info("Par de chaves RSA gerado com sucesso.")

    def get_public_key(self):
        return self._public_key

    def get_public_key_pem(self):
        return self._public_key.export_key()

    def decrypt(self, encrypted_data):
        log.debug(f"Tentando descriptografar {len(encrypted_data)} bytes com a chave privada RSA.")
        try:
            decrypted = self.cipher_rsa_decrypt.decrypt(encrypted_data)
            log.debug("Dados descriptografados com RSA com sucesso.")
            return decrypted
        except ValueError as e:
            log.error(f"Falha na descriptografia RSA: {e}")
            return None

def encrypt_with_public_key(public_key, data):
    log.debug(f"Criptografando {len(data)} bytes com uma chave pública RSA fornecida.")
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(data)
    log.debug(f"Dados criptografados com RSA. Tamanho final: {len(encrypted)} bytes.")
    return encrypted

class CriptoSerpent:
    """Gerencia a criptografia simétrica com Serpent."""
    # pyserpent usa chaves de 128, 192 ou 256 bits. Vamos usar 256 bits (32 bytes).
    # O HMAC também usará uma chave de 256 bits (32 bytes).
    # Portanto, a chave de sessão total terá 64 bytes.
    def __init__(self, key):
        if len(key) != 64:
            raise ValueError("A chave de sessão combinada (Serpent + HMAC) deve ter 64 bytes.")
        self.serpent_key = key[:32] # Primeiros 32 bytes para Serpent
        self.hmac_key = key[32:]   # Últimos 32 bytes para HMAC
        log.info(f"Instância de CriptoSerpent inicializada com chave Serpent de 256 bits e chave HMAC de 256 bits.")

    def encrypt(self, plaintext_bytes):
        """Criptografa e autentica dados usando Serpent-CBC e HMAC-SHA256 (Encrypt-then-MAC)."""
        log.debug(f"Criptografando {len(plaintext_bytes)} bytes com Serpent-CBC + HMAC.")
        
        # 1. Gerar um IV (Vetor de Inicialização) aleatório para CBC
        iv = Serpent.generateIV()

        # 2. Criptografar os dados com Serpent-CBC
        ciphertext = serpent_cbc_encrypt(self.serpent_key, plaintext_bytes, iv)

        # 3. Gerar um MAC (código de autenticação) do IV + ciphertext
        mac = hmac.new(self.hmac_key, iv + ciphertext, hashlib.sha256).digest()
        
        log.debug("Criptografia e autenticação concluídas.")
        return {'iv': iv, 'ciphertext': ciphertext, 'mac': mac}

    def decrypt(self, encrypted_package):
        """Verifica a autenticidade e descriptografa dados."""
        iv = encrypted_package['iv']
        ciphertext = encrypted_package['ciphertext']
        received_mac = encrypted_package['mac']
        log.debug(f"Tentando descriptografar {len(ciphertext)} bytes.")

        # 1. Recalcular o MAC com os dados recebidos
        expected_mac = hmac.new(self.hmac_key, iv + ciphertext, hashlib.sha256).digest()

        # 2. Comparar os MACs de forma segura
        if not hmac.compare_digest(received_mac, expected_mac):
            log.error("FALHA NA VERIFICAÇÃO DE AUTENTICIDADE (MAC)! A mensagem pode ter sido adulterada.")
            return None

        # 3. Se o MAC for válido, descriptografar
        decrypted_bytes = serpent_cbc_decrypt(self.serpent_key, ciphertext, iv)
        log.debug("Descriptografia e verificação bem-sucedidas.")
        # O pyserpent pode adicionar padding que precisa ser removido.
        return decrypted_bytes.rstrip(b'\0')