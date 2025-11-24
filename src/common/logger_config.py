# logger_config.py
import logging
import sys
import os

def setup_logger(name, level=logging.DEBUG):
    """Configura e retorna um logger com um formato padronizado."""
    
    # Previne a adição de múltiplos handlers se a função for chamada várias vezes
    logger = logging.getLogger(name)
    if logger.hasHandlers():
        return logger

    logger.setLevel(level)
    
    # Formato do log: [TIMESTAMP] [NÍVEL] [NOME_DO_ARQUIVO] MENSAGEM
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - [%(name)s] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Handler para exibir logs no console
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    
    logger.addHandler(stream_handler)
    
    return logger

def log_security(pillar, component, message, **kwargs):
    """
    Logs a security event to the centralized security_debug.log file.
    
    Args:
        pillar (str): The security pillar (AUTHENTICITY, CONFIDENTIALITY, INTEGRITY, AVAILABILITY).
        component (str): The component generating the log (e.g., 'Client', 'Server', 'Auth').
        message (str): The log message.
        **kwargs: Additional context to format into the message.
    """
    log_file = "security_debug.log"
    
    # Format: [TIMESTAMP] [PILLAR] [COMPONENT] Message
    import datetime
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    formatted_message = f"[{timestamp}] [{pillar.upper()}] [{component}] {message}"
    
    if kwargs:
        formatted_message += f" | Context: {kwargs}"
        
    try:
        with open(log_file, "a", encoding='utf-8') as f:
            f.write(formatted_message + "\n")
    except Exception as e:
        print(f"Failed to write to security log: {e}")