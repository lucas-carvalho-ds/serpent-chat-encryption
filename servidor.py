# servidor.py
import socket
import threading
from Crypto.Random import get_random_bytes

from logger_config import setup_logger
from utils import send_message, receive_message

log = setup_logger(__name__)

HOST = '127.0.0.1'
PORT = 65432
SERVER_SECRET = get_random_bytes(32) # Segredo interno para futuras expansões

clients = {} # Dicionário para armazenar {client_socket: {"addr": addr, "public_key_pem": pem}}
clients_lock = threading.Lock()

def notify_all_clients_of_member_change():
    """Notifica todos os clientes sobre a lista atual de membros e suas chaves públicas."""
    with clients_lock:
        # Só notifica se houver um "grupo" (mais de 1 pessoa)
        if len(clients) <= 1:
            return

        log.info("Notificando clientes sobre mudança na composição do grupo.")
        # Monta a lista de chaves públicas de todos os clientes conectados
        all_public_keys = [client_data['public_key_pem'] for client_data in clients.values()]

        member_update_package = {
            "type": "control_member_update",
            "public_keys": all_public_keys
        }

        for client_socket, client_data in clients.items():
            try:
                log.debug(f"Enviando atualização de membros para {client_data['addr']}")
                send_message(client_socket, member_update_package)
            except Exception as e:
                log.error(f"Erro ao notificar cliente {client_data['addr']}: {e}")

def broadcast_message(message_package, origin_socket):
    """Envia uma mensagem para todos os clientes, exceto a origem."""
    with clients_lock:
        print("")
        log.debug(f"Retransmitindo mensagem de {clients.get(origin_socket, {}).get('addr')}")
        for client_socket in clients:
            if client_socket != origin_socket:
                try:
                    send_message(client_socket, message_package)
                except Exception as e:
                    log.error(f"Erro ao retransmitir para {clients[client_socket]['addr']}: {e}")

def handle_client(client_socket, addr):
    """Lida com a conexão de um único cliente."""
    print("\n")
    log.info(f"Nova conexão de {addr}. Aguardando chave pública RSA.")
    
    try:
        # 1. Receber pacote inicial com a chave pública do cliente
        initial_package = receive_message(client_socket)
        if not initial_package or initial_package.get('type') != 'pubkey':
            log.warning(f"Cliente {addr} desconectou antes de enviar a chave pública.")
            return

        public_key_pem = initial_package['key']
        log.info(f"Chave pública RSA recebida de {addr}.")
        print(f"\n[Servidor] Chave pública recebida de {addr}:\n{public_key_pem.decode('utf-8')}\n")

        # 2. Adicionar cliente ao grupo e iniciar rekeying
        with clients_lock:
            clients[client_socket] = {"addr": addr, "public_key_pem": public_key_pem}

        # Informa o novo cliente sobre sua conexão
        info_package = {"type": "server_info", "message": "Conectado com sucesso! Aguardando outros membros para iniciar o chat."}
        send_message(client_socket, info_package)

        # Notifica todos sobre a nova composição do grupo
        notify_all_clients_of_member_change()

        # 3. Loop para receber e retransmitir mensagens
        while True:
            package = receive_message(client_socket)
            if not package:
                print("")
                log.warning(f"Conexão com {addr} foi fechada pelo cliente.")
                break
            
            log.debug(f"Recebido pacote do tipo '{package.get('type')}' de {addr}. Retransmitindo para todos.")
            # Apenas retransmite, não precisa entender o conteúdo.
            broadcast_message(package, client_socket) # Envia para todos, exceto a origem

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
        notify_all_clients_of_member_change() # Notifica os restantes sobre a saída


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