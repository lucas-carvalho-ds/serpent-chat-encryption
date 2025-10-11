# servidor.py
import socket
import threading
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

from logger_config import setup_logger
from utils import send_message, receive_message
from cripto import encrypt_with_public_key

log = setup_logger(__name__)

HOST = '127.0.0.1'
PORT = 65432
SERVER_SECRET = get_random_bytes(32) # Segredo interno para futuras expansões

clients = {} # Dicionário para armazenar {client_socket: {"addr": addr, "public_key": pub_key}}
clients_lock = threading.Lock()

def broadcast_new_group_key():
    """Gera e distribui uma nova chave de sessão Serpent para todos os clientes."""
    with clients_lock:
        log.info("INICIANDO PROCESSO DE REKEYING (TROCA DE CHAVES) DO GRUPO.")
        if not clients:
            log.warning("Nenhum cliente conectado. Abortando rekeying.")
            return
            
        # 1. Gerar uma nova chave de sessão Serpent
        new_serpent_key = get_random_bytes(32) # 32 bytes para Serpent (256 bits)
        log.debug(f"Nova chave de sessão Serpent gerada: {new_serpent_key.hex()}")

        # 2. Distribuir para cada cliente, criptografada com sua chave pública RSA
        for client_socket, client_data in clients.items():
            try:
                log.debug(f"Preparando para enviar nova chave para {client_data['addr']}")
                
                # Criptografa a chave Serpent com a chave pública RSA do cliente
                encrypted_key = encrypt_with_public_key(client_data['public_key'], new_serpent_key)
                
                # Prepara o pacote de controle
                rekey_package = {
                    "type": "control_rekey",
                    "key": encrypted_key
                }
                
                # Serializa e envia
                send_message(client_socket, rekey_package)
                log.info(f"Nova chave de sessão enviada com sucesso para {client_data['addr']}")

            except Exception as e:
                log.error(f"Erro ao enviar nova chave para {client_data['addr']}: {e}")
        
        log.info("PROCESSO DE REKEYING CONCLUÍDO.")

def broadcast_message(message_package, origin_socket):
    """Envia uma mensagem para todos os clientes, exceto a origem."""
    with clients_lock:
        log.debug(f"Retransmitindo mensagem de {clients.get(origin_socket, {}).get('addr')}")
        for client_socket in clients:
            if client_socket != origin_socket:
                try:
                    send_message(client_socket, message_package)
                except Exception as e:
                    log.error(f"Erro ao retransmitir para {clients[client_socket]['addr']}: {e}")

def handle_client(client_socket, addr):
    """Lida com a conexão de um único cliente."""
    log.info(f"Nova conexão de {addr}. Aguardando chave pública RSA.")
    
    try:
        # 1. Receber pacote inicial com a chave pública do cliente
        initial_package = receive_message(client_socket)
        if not initial_package or initial_package.get('type') != 'pubkey':
            log.warning(f"Cliente {addr} desconectou antes de enviar a chave pública.")
            return

        public_key_pem = initial_package['key']
        public_key = RSA.import_key(public_key_pem)
        log.debug(f"Chave pública RSA recebida e importada de {addr}.")

        # 2. Adicionar cliente ao grupo e iniciar rekeying
        with clients_lock:
            clients[client_socket] = {"addr": addr, "public_key": public_key}

        # Informa o novo cliente sobre sua conexão
        info_package = {"type": "server_info", "message": "Conectado com sucesso! Aguardando outros membros para iniciar o chat."}
        send_message(client_socket, info_package)

        broadcast_new_group_key()

        # 3. Loop para receber e retransmitir mensagens
        while True:
            package = receive_message(client_socket)
            if not package:
                log.warning(f"Conexão com {addr} foi fechada pelo cliente.")
                break
            
            # Apenas retransmite, não precisa entender o conteúdo
            log.debug(f"Recebido pacote do tipo '{package.get('type')}' de {addr}. Retransmitindo.")
            broadcast_message(package, client_socket)

    except (ConnectionResetError, EOFError):
        log.warning(f"Conexão com {addr} perdida inesperadamente.")
    except Exception as e:
        log.error(f"Erro inesperado com o cliente {addr}: {e}")
    finally:
        # 4. Remover cliente do grupo e iniciar rekeying para os restantes
        log.info(f"Removendo cliente {addr} do grupo.")
        with clients_lock:
            if client_socket in clients:
                del clients[client_socket]
        
        client_socket.close()
        log.info(f"Conexão com {addr} finalizada.")
        broadcast_new_group_key() # Garante a segurança do grupo restante


def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Permite a reutilização do endereço para evitar o erro "Address already in use" em reinicializações rápidas
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    log.info(f"Servidor iniciado e ouvindo em {HOST}:{PORT}")

    while True:
        client_socket, addr = server_socket.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket, addr))
        thread.daemon = True
        thread.start()

if __name__ == "__main__":
    start_server()