# logger_config.py
import logging
import sys

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