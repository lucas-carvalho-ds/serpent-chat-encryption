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

clients = {} # Dicionário para armazenar {client_socket: {"addr": addr, "username": str, "public_key_pem": pem}}
clients_lock = threading.RLock()

def get_client_by_username(username):
    """Encontra o socket de um cliente pelo seu nome de usuário."""
    with clients_lock:
        for sock, data in clients.items():
            if data['username'] == username:
                return sock
    return None

def broadcast_message(message_package, origin_socket, group_id):
    """Envia uma mensagem para os membros de um grupo específico, exceto a origem."""
    with clients_lock:
        # O group_id é uma tupla ordenada de nomes de usuário
        group_members_usernames = group_id
        log.debug(f"Retransmitindo mensagem para o grupo {group_id}")
        
        for username in group_members_usernames:
            client_socket = get_client_by_username(username)
            if client_socket and client_socket != origin_socket:
                try:
                    send_message(client_socket, message_package)
                except Exception as e:
                    log.error(f"Erro ao retransmitir para {clients[client_socket]['addr']}: {e}")

def notify_members_of_departure(departed_user, groups):
    """Notifica os membros restantes de uma lista de grupos sobre a saída de um usuário."""
    with clients_lock:
        for group_id in groups:
            remaining_members = [user for user in group_id if user != departed_user]
            
            # Se o grupo ainda pode continuar (2+ membros), inicia um re-keying
            if len(remaining_members) >= 2:
                log.info(f"Iniciando re-keying para o grupo {group_id} após saída de '{departed_user}'.")
                group_sockets_and_keys = {}
                new_group_id = tuple(sorted(remaining_members))

                for member_user in remaining_members:
                    member_sock = get_client_by_username(member_user)
                    if member_sock:
                        group_sockets_and_keys[member_user] = clients[member_sock]['public_key_pem']
                        # Atualiza o estado do grupo para os membros restantes
                        if group_id in clients[member_sock]['active_groups']:
                            clients[member_sock]['active_groups'].remove(group_id)
                        if new_group_id not in clients[member_sock]['active_groups']:
                            clients[member_sock]['active_groups'].append(new_group_id)
                
                notification = {
                    "type": "group_invite", # Reutiliza o fluxo de convite para forçar o re-keying
                    "group_id": new_group_id,
                    "members": group_sockets_and_keys
                }
                for member_user in remaining_members:
                    member_sock = get_client_by_username(member_user)
                    if member_sock:
                        send_message(member_sock, notification)

            # Se o grupo não pode mais continuar (1 membro restante)
            elif len(remaining_members) == 1:
                member_user = remaining_members[0]
                sock = get_client_by_username(member_user)
                if sock:
                    log.info(f"Notificando '{member_user}' sobre o encerramento do grupo {group_id}.")
                    notification = {
                        "type": "control_member_left",
                        "group_id": group_id,
                        "departed_user": departed_user
                    }
                    send_message(sock, notification)
                    # Remove o grupo encerrado da lista do último membro
                    if group_id in clients[sock]['active_groups']:
                        clients[sock]['active_groups'].remove(group_id)

def handle_client(client_socket, addr):
    """Lida com a conexão de um único cliente."""
    username = None
    print("\n")
    log.info(f"Nova conexão de {addr}. Aguardando chave pública RSA.")
    
    try:
        # 1. Receber pacote inicial com a chave pública e nome de usuário
        initial_package = receive_message(client_socket)
        if not initial_package or initial_package.get('type') != 'identity':
            log.warning(f"Cliente {addr} desconectou antes de se identificar.")
            # Envia mensagem de erro antes de retornar
            error_package = {"type": "server_error", "message": "Falha na identificação"}
            send_message(client_socket, error_package)
            return

        public_key_pem = initial_package['key']
        username = initial_package['username']

        log.info(f"Identidade recebida de {addr}: username='{username}'.")
        print(f"\n[Servidor] Cliente '{username}' conectado de {addr}.")
        print(f"[Servidor] Chave pública de '{username}':\n{public_key_pem.decode('utf-8')}\n")

        # 2. Adicionar cliente à lista de clientes
        with clients_lock:
            if get_client_by_username(username):
                log.warning(f"Nome de usuário '{username}' já em uso. Desconectando.")
                info_package = {"type": "server_error", "message": "Nome de usuário já está em uso."}
                send_message(client_socket, info_package)
                return
            
            clients[client_socket] = {
                "addr": addr, 
                "username": username, 
                "public_key_pem": public_key_pem,
                "active_groups": []}
            info_package = {"type": "server_info", "message": "Conectado com sucesso! Use /private ou /group para iniciar conversas."}
            send_message(client_socket, info_package)

        # 3. Loop para receber e retransmitir mensagens
        while True:
            package = receive_message(client_socket)
            if not package:
                print("")
                log.warning(f"Conexão com '{username}' ({addr}) foi fechada.")
                break
            
            pkg_type = package.get('type')
            log.debug(f"Recebido pacote do tipo '{pkg_type}' de '{username}'.")

            if pkg_type == 'chat_message':
                broadcast_message(package, client_socket, package['group_id'])

            elif pkg_type == 'control_rekey':
                # Retransmite a chave para um usuário específico
                target_username = package['target_username']
                target_socket = get_client_by_username(target_username)
                if target_socket:
                    log.info(f"Retransmitindo chave de '{username}' para '{target_username}'.")
                    send_message(target_socket, package)

            elif pkg_type == 'group_init':
                # Um cliente quer iniciar um novo grupo
                group_usernames = tuple(sorted(package['members']))
                log.info(f"'{username}' iniciou um pedido para criar o grupo: {group_usernames}")
                
                group_sockets_and_keys = {}
                missing_users = []
                with clients_lock:
                    for member_user in group_usernames:
                        member_sock = get_client_by_username(member_user)
                        if member_sock:
                            group_sockets_and_keys[member_user] = clients[member_sock]['public_key_pem']
                        else:
                            missing_users.append(member_user)
                
                # Se algum usuário não foi encontrado, notifica o autor do pedido
                if missing_users:
                    log.warning(f"Pedido de grupo de '{username}' falhou. Usuários não encontrados: {missing_users}")
                    error_package = {"type": "command_error", "message": f"Usuário(s) não encontrado(s): {', '.join(missing_users)}"}
                    send_message(client_socket, error_package)
                    continue

                # Notifica todos os membros do novo grupo
                notification = {
                    "type": "group_invite",
                    "group_id": group_usernames,
                    "members": group_sockets_and_keys # {username: pubkey_pem}
                }
                # Adiciona o grupo à lista de grupos ativos de cada membro
                with clients_lock:
                    for member_user in group_usernames:
                        member_sock = get_client_by_username(member_user)
                        if member_sock and group_usernames not in clients[member_sock]['active_groups']:
                            clients[member_sock]['active_groups'].append(group_usernames)

                for member_user in group_usernames:
                    member_sock = get_client_by_username(member_user)
                    if member_sock:
                        log.debug(f"Enviando convite de grupo para '{member_user}'.")
                        send_message(member_sock, notification)

    except (ConnectionResetError, EOFError):
        log.warning(f"Conexão com '{username}' ({addr}) perdida inesperadamente.")
    except Exception as e:
        log.error(f"Erro inesperado com o cliente '{username}' ({addr}): {e}")
    finally:
        # 4. Remover cliente do grupo e iniciar rekeying para os restantes
        if username:
            log.info(f"Removendo cliente '{username}' ({addr}).")
            with clients_lock:
                # Notificar outros membros dos grupos dos quais este usuário fazia parte
                groups_to_notify = []
                # Encontra todos os group_ids que contêm o usuário que está saindo
                # Esta é uma busca ineficiente para muitos grupos, mas funciona para este projeto.
                # Em um sistema real, o servidor manteria um mapa de user -> groups.
                for sock, data in clients.items():
                    if 'active_groups' in data:
                        for group_id in data['active_groups']:
                            if username in group_id and group_id not in groups_to_notify:
                                groups_to_notify.append(group_id)
                
                # Remove o cliente da lista principal
                if client_socket in clients:
                    del clients[client_socket]

                # Envia a notificação para os membros restantes
                notify_members_of_departure(username, groups_to_notify)

        client_socket.close()
        log.info(f"Conexão com '{username}' ({addr}) finalizada.")


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