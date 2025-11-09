# cliente.py
import socket
import threading
import sys
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

from logger_config import setup_logger
from utils import send_message, receive_message
from cripto import CriptoRSA, CriptoSerpent, encrypt_with_public_key

log = setup_logger('cliente')

HOST = '127.0.0.1'
PORT = 65432

# --- Variáveis Globais de Criptografia ---
# O cliente gera seu par de chaves RSA uma vez ao iniciar
crypto_rsa = CriptoRSA() 
# Dicionário para armazenar instâncias de CriptoSerpent por group_id
session_keys = {}
# Lista para mapear IDs numéricos (0, 1, 2...) para group_id de tupla
active_conversations = []
# ---

def generate_and_distribute_group_key(client_socket, group_id, members):
    """Gera uma nova chave de sessão e a distribui para os membros do grupo."""
    global session_keys

    log.info(f"Gerando e distribuindo chave para o grupo {group_id}.")
    # 1. Gerar nova chave de sessão Serpent
    new_session_key = get_random_bytes(32)
    session_keys[group_id] = CriptoSerpent(new_session_key)
    # Adiciona a nova conversa à lista se não estiver lá
    if group_id not in active_conversations:
        active_conversations.append(group_id)
    group_numeric_id = active_conversations.index(group_id)
    print(f"[SISTEMA] Conversa segura estabelecida. ID do Grupo: {group_numeric_id}")
    print(f"\n[AÇÃO] Nova chave de sessão gerada por este cliente: {new_session_key.hex()}")

    # 2. Criptografar e enviar para cada membro do grupo
    my_username = members['my_username']
    for username, pub_key_pem in members['keys'].items():
        if username == my_username:
            continue

        pub_key = RSA.import_key(pub_key_pem)
        encrypted_key = encrypt_with_public_key(pub_key, new_session_key)
        print(f"[AÇÃO] Criptografando chave de sessão para o membro '{username}'.")
        
        rekey_package = {
            "type": "control_rekey",
            "group_id": group_id,
            "key": encrypted_key,
            "target_username": username # Servidor usará isso para rotear
        }
        send_message(client_socket, rekey_package)
        log.info(f"Pacote de chave para o grupo {group_id} enviado para '{username}'.")

def receive_handler(client_socket, initial_setup_complete, my_username):
    """Lida com o recebimento de mensagens do servidor."""
    global session_keys
    
    while True:
        try:
            package = receive_message(client_socket)
            if not package:
                print("\n[SISTEMA] Conexão com o servidor foi fechada. Pressione Enter para sair.")
                break

            print("\n")
            log.debug(f"Pacote recebido do servidor. Tipo: {package.get('type')}")

            # Lógica para tratar diferentes tipos de pacotes
            if package['type'] == 'control_rekey':
                group_id = package['group_id']
                encrypted_key = package['key']
                
                # Descriptografa a nova chave de sessão com a chave privada RSA
                new_session_key = crypto_rsa.decrypt(encrypted_key)
                
                if new_session_key:
                    log.info(f"Recebida chave de sessão para o grupo {group_id}.")
                    print(f"\n[AÇÃO] Chave de sessão para o grupo '{' & '.join(group_id)}' recebida.")
                    print(f"[AÇÃO] Chave de sessão descriptografada com sucesso: {new_session_key.hex()}")
                    # Atualiza a instância de criptografia simétrica com a nova chave
                    session_keys[group_id] = CriptoSerpent(new_session_key)
                    # Adiciona a nova conversa à lista se não estiver lá
                    if group_id not in active_conversations:
                        active_conversations.append(group_id)
                    group_numeric_id = active_conversations.index(group_id)

                    log.info(f"Chave de sessão para o grupo {group_id} estabelecida.")
                    print(f"\r\033[K[SISTEMA] Conversa segura com '{' & '.join(group_id)}' estabelecida. ID do Grupo: {group_numeric_id}\n> ", end="", flush=True)
                else:
                    log.error("Falha ao descriptografar a nova chave de sessão. A comunicação pode estar comprometida.")

            elif package['type'] == 'group_invite':
                group_id = package['group_id']
                members_keys = package['members'] # {username: pubkey_pem}
                log.info(f"Recebido convite para o grupo {group_id}.")
                print(f"\n[SISTEMA] Você foi adicionado à conversa com: {', '.join(group_id)}")
                
                # O "líder" (primeiro na ordem alfabética de usernames) gera a chave
                if my_username == group_id[0]:
                    print("[SISTEMA] Você é o líder deste grupo e irá gerar a chave de sessão.")
                    members_data = {'my_username': my_username, 'keys': members_keys}
                    generate_and_distribute_group_key(client_socket, group_id, members_data)

            elif package['type'] == 'chat_message':
                group_id = package['group_id']
                crypto_serpent_instance = session_keys.get(group_id)
                if crypto_serpent_instance:
                    encrypted_content = package['content']
                    print(f"\n[AÇÃO] Mensagem criptografada recebida (IV: {encrypted_content['iv'].hex()}, Ciphertext: {encrypted_content['ciphertext'].hex()}).")
                    print(f"[AÇÃO] Descriptografando com a chave de sessão atual...")
                    decryption_result = crypto_serpent_instance.decrypt(encrypted_content)
                    decrypted_message = decryption_result['plaintext']                    
                    decrypted_block_size = decryption_result['padded_size'] # Tamanho do bloco descriptografado (e.g., 16)
                    original_message_size = decryption_result['unpadded_size'] # Tamanho da mensagem original (e.g., 9)
                    print(f"[AÇÃO] Mensagem descriptografada. O bloco de {decrypted_block_size} bytes continha {original_message_size} bytes de dados e {decrypted_block_size - original_message_size} bytes de preenchimento.")
                    print(f"\r\033[K[Mensagem de {' & '.join(group_id)}] - {decrypted_message.decode('utf-8')}\n\n> ", end="", flush=True)
                else:
                    log.warning(f"Mensagem de chat recebida para o grupo {group_id}, mas não temos a chave de sessão.")
            
            elif package['type'] == 'server_info':
                # Sinaliza que a configuração inicial foi recebida, liberando o prompt de username
                if not initial_setup_complete.is_set():
                    initial_setup_complete.set() # Apenas sinaliza, não imprime
            
            elif package['type'] == 'server_error':
                print(f"\n[ERRO DO SERVIDOR] {package['message']}")
                client_socket.close()
                break
            
            elif package['type'] == 'command_error':
                print(f"\r\033[K[ERRO] {package['message']}\n> ", end="", flush=True)

            elif package['type'] == 'control_member_left':
                group_id = package['group_id']
                departed_user = package['departed_user']
                
                if group_id in session_keys:
                    log.info(f"Usuário '{departed_user}' saiu do grupo {group_id}. Removendo chave de sessão.")
                    del session_keys[group_id]
                    if group_id in active_conversations:
                        active_conversations.remove(group_id)
                    
                    # Informa o usuário e redesenha o prompt
                    print(f"\r\033[K[SISTEMA] {departed_user} saiu da conversa. A conversa foi encerrada.\n> ", end="", flush=True)

        except (EOFError, ConnectionResetError):
            print("\n[SISTEMA] Conexão com o servidor perdida. Pressione Enter para sair.")
            break
        except Exception as e:
            log.error(f"Erro no handler de recebimento: {e}")
            # Não quebre o loop em erros genéricos, apenas em erros de conexão

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Pede o nome de usuário primeiro, antes de qualquer outra coisa.
    print("\nDigite seu nome de usuário para o chat:")
    username = input("> ")
    if not username:
        print("Nome de usuário não pode ser vazio.")
        return

    try:
        client_socket.connect((HOST, PORT))
        log.info(f"Conectando ao servidor em {HOST}:{PORT} como '{username}'")

        # Imprime as chaves geradas para rastreamento
        print("\n--- Chaves RSA Geradas Localmente ---\n")
        print(f"[CHAVE PÚBLICA]:\n{crypto_rsa.get_public_key_pem().decode('utf-8')}\n")
        print(f"\n[CHAVE PRIVADA (não compartilhada)]:\n{crypto_rsa.get_private_key_pem().decode('utf-8')}\n")

        # Envia a identidade (username + chave pública) para o servidor
        log.info("Enviando identidade para o servidor...")
        identity_package = {
            "type": "identity",
            "username": username,
            "key": crypto_rsa.get_public_key_pem(),
        }
        send_message(client_socket, identity_package)

        # Evento para sincronizar o prompt de username com o recebimento da primeira mensagem do servidor
        initial_setup_complete = threading.Event()

        # Inicia a thread para receber mensagens
        receive_thread = threading.Thread(target=receive_handler, args=(client_socket, initial_setup_complete, username))
        receive_thread.daemon = True
        receive_thread.start()
        
        # Aguarda a thread de recebimento confirmar que a configuração inicial do servidor foi recebida
        print("Aguardando configuração do servidor...")
        initial_setup_complete.wait()

        print("\n[INFO DO SERVIDOR]: Conectado com sucesso! Use /private ou /group para iniciar conversas.")
        print(f"\nOlá, {username}! Comandos disponíveis:")
        print("  /private <username> - Inicia chat entre duas pessoas")
        print("  /group <user1> <user2> <user3>... - Inicia chat em um grupo")
        print("  /msg <group_id> <message> - Envia mensagem para um grupo")
        print("  /sair - Fecha o cliente")

        while True:
            full_command = input("> ")
            if full_command.lower() == '/sair':
                break

            parts = full_command.split()
            command = parts[0]

            if command == '/private' and len(parts) == 2:
                target_user = parts[1]
                group_id = tuple(sorted((username, target_user)))
                
                if group_id in session_keys:
                    print(f"[SISTEMA] Você já tem uma conversa com {target_user}.")
                else:
                    print(f"[SISTEMA] Solicitando início de conversa com {target_user}...")
                    init_package = {"type": "group_init", "members": [username, target_user]}
                    send_message(client_socket, init_package)

            elif command == '/group' and len(parts) >= 2:
                members = list(set([username] + parts[1:]))
                group_id = tuple(sorted(members))
                if group_id in session_keys:
                    print("[SISTEMA] Você já está neste grupo.")
                    continue
                print(f"[SISTEMA] Criando grupo com: {', '.join(members)}")
                init_package = {"type": "group_init", "members": members}
                send_message(client_socket, init_package)

            elif command == '/msg' and len(parts) >= 3:
                try:
                    group_numeric_id = int(parts[1])
                    message_text = ' '.join(parts[2:])

                    if 0 <= group_numeric_id < len(active_conversations):
                        group_id = active_conversations[group_numeric_id]
                        crypto_instance = session_keys.get(group_id)

                        if not crypto_instance:
                            print("[ERRO] A chave para este grupo ainda não foi estabelecida.")
                            continue

                        full_message = f"{username}: {message_text}"
                        encrypted_content = crypto_instance.encrypt(full_message.encode('utf-8'))
                        message_package = {"type": "chat_message", "group_id": group_id, "content": encrypted_content}
                        send_message(client_socket, message_package)
                        print(f"[AÇÃO] Mensagem enviada para o grupo {group_numeric_id}.")
                    else:
                        print("[ERRO] ID de grupo inválido.")
                except (ValueError, IndexError):
                    print("[ERRO] Formato de comando inválido. Use: /msg <id_numerico> <mensagem>")

            else:
                print("[SISTEMA] Comando inválido ou formato incorreto.")
                print("  Formatos: /private <user> | /group <user1> ... | /msg <id> <msg> | /sair")


    except ConnectionRefusedError:
        log.critical("Não foi possível conectar ao servidor. Verifique se ele está em execução.")
    except Exception as e:
        log.critical(f"Um erro crítico ocorreu: {e}")
    finally:
        log.info("Encerrando cliente.")
        client_socket.close()
        sys.exit(0)

if __name__ == "__main__":
    start_client()