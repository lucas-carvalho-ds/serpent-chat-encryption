# cripto.py
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

    def get_private_key_pem(self):
        return self._private_key.export_key()

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
    def __init__(self, key):
        if len(key) != 32:
            raise ValueError("A chave de sessão Serpent deve ter 32 bytes.")
        self.serpent_key = key
        log.info("Instância de CriptoSerpent inicializada com chave Serpent de 256 bits.")

    def encrypt(self, plaintext_bytes):
        """Criptografa dados usando Serpent-CBC."""
        log.debug(f"Criptografando {len(plaintext_bytes)} bytes com Serpent-CBC.")
        
        # 1. Gerar um IV (Vetor de Inicialização) aleatório para CBC
        iv = Serpent.generateIV()

        # 2. Criptografar os dados com Serpent-CBC
        ciphertext = serpent_cbc_encrypt(self.serpent_key, plaintext_bytes, iv)
        
        log.debug("Criptografia concluída.")
        return {'iv': iv, 'ciphertext': ciphertext}

    def decrypt(self, encrypted_package):
        """Descriptografa dados."""
        iv = encrypted_package['iv']
        ciphertext = encrypted_package['ciphertext']
        log.debug(f"Tentando descriptografar {len(ciphertext)} bytes...")

        # Descriptografa os dados
        decrypted_bytes_with_padding = serpent_cbc_decrypt(self.serpent_key, ciphertext, iv)
        log.debug("Descriptografia bem-sucedida.")
        
        # O pyserpent pode adicionar padding que precisa ser removido.
        # Vamos calcular a quantidade de padding.
        unpadded_message = decrypted_bytes_with_padding.rstrip(b'\0')
        padded_size = len(ciphertext) # O tamanho do bloco é o tamanho do ciphertext recebido.
        unpadded_size = len(unpadded_message)
        padding_bytes_count = padded_size - unpadded_size
        
        #log.debug(f"Removidos {padding_bytes_count} bytes de padding.")
        
        return {
            'plaintext': unpadded_message,
            'padded_size': padded_size,
            'unpadded_size': unpadded_size
        }