"""
Input Validation Module
Contains all validation logic for user inputs.
"""


def validate_username(username):
    """Valida formato de username"""
    username = username.strip()
    if not username:
        return False, "O nome de usuário não pode estar vazio."
    if len(username) < 3:
        return False, "O nome de usuário deve ter pelo menos 3 caracteres."
    if len(username) > 20:
        return False, "O nome de usuário não pode ter mais de 20 caracteres."
    if not username.replace('_', '').isalnum():
        return False, "O nome de usuário pode conter apenas letras, números e underscore (_)."
    return True, ""


def validate_password(password):
    """Valida força de senha"""
    if not password:
        return False, "A senha não pode estar vazia."
    if len(password) < 6:
        return False, "A senha deve ter pelo menos 6 caracteres."
    return True, ""


def validate_registration(username, password, confirm_password):
    """Valida dados de registro"""
    # Validar username
    valid, msg = validate_username(username)
    if not valid:
        return False, msg
    
    # Validar senha
    valid, msg = validate_password(password)
    if not valid:
        return False, msg
    
    # Validar confirmação de senha
    if password != confirm_password:
        return False, "As senhas não coincidem."
    
    return True, ""


def validate_login(username, password, totp_code):
    """Valida dados de login"""
    username = username.strip()
    if not username:
        return False, "O nome de usuário não pode estar vazio."
    if not password:
        return False, "A senha não pode estar vazia."
    if not totp_code:
        return False, "O código 2FA não pode estar vazio."
    if not totp_code.isdigit() or len(totp_code) != 6:
        return False, "O código 2FA deve conter exatamente 6 dígitos."
    return True, ""
