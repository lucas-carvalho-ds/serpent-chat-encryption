# utils.py
import struct
import pickle

HEADER_LENGTH = 4 # Usa 4 bytes para o tamanho da mensagem

def send_message(sock, message_obj):
    """Serializa um objeto com pickle e o envia prefixado com seu tamanho."""
    pickled_message = pickle.dumps(message_obj)
    # Prepara o header com o tamanho da mensagem, em big-endian
    header = struct.pack('>I', len(pickled_message))
    sock.sendall(header + pickled_message)

def receive_message(sock):
    """Recebe uma mensagem prefixada com seu tamanho e a desserializa."""
    # 1. Lê o header para descobrir o tamanho da mensagem
    header_data = sock.recv(HEADER_LENGTH)
    if not header_data:
        return None # Conexão fechada
    
    message_length = struct.unpack('>I', header_data)[0]
    
    # 2. Lê o número exato de bytes da mensagem
    data = b''
    while len(data) < message_length:
        packet = sock.recv(message_length - len(data))
        if not packet:
            return None # Conexão fechada inesperadamente
        data += packet
        
    return pickle.loads(data)