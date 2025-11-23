import pyotp
from src.server.database import Database
from src.common.crypto_utils import CryptoUtils
from src.common.logger_config import setup_logger

log = setup_logger(__name__)

class AuthManager:
    def __init__(self, db: Database):
        self.db = db

    def register_user(self, username, password, public_key_pem):
        if self.db.get_user_by_username(username):
            log.warning(f"Tentativa de registro falhou: Usuário {username} já existe.")
            return False, "Usuário já existe."

        salt = CryptoUtils.generate_salt()
        password_hash = CryptoUtils.hash_password(password, salt)
        totp_secret = pyotp.random_base32()
        
        user_id = self.db.add_user(username, password_hash, salt, totp_secret, public_key_pem)
        
        if user_id:
            log.info(f"Usuário {username} registrado com sucesso.")
            return True, totp_secret
        else:
            return False, "Erro ao salvar no banco de dados."

    def authenticate_user(self, username, password, totp_code):
        user = self.db.get_user_by_username(username)
        if not user:
            return False, "Usuário não encontrado."

        # user tuple: (id, username, password_hash, salt, totp_secret, public_key_pem, created_at)
        stored_hash = user[2]
        # salt = user[3] # O bcrypt armazena o salt no hash, mas salvamos separado por redundância/legado do plano
        totp_secret = user[4]

        if CryptoUtils.verify_password(password, stored_hash):
            totp = pyotp.TOTP(totp_secret)
            if totp.verify(totp_code):
                log.info(f"Usuário {username} autenticado com sucesso.")
                return True, "Autenticação bem-sucedida."
            else:
                log.warning(f"Falha de 2FA para usuário {username}.")
                return False, "Código 2FA inválido."
        else:
            log.warning(f"Senha incorreta para usuário {username}.")
            return False, "Senha incorreta."

    def get_user_public_key(self, username):
        user = self.db.get_user_by_username(username)
        if user:
            return user[5] # public_key_pem
        return None

    def update_public_key(self, username, public_key_pem):
        self.db.update_user_public_key(username, public_key_pem)
