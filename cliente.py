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
# A instância de Serpent será substituída toda vez que uma nova chave de grupo for recebida
crypto_serpent = None 
# Armazena as chaves públicas (em formato PEM) dos outros membros do grupo
group_public_keys = []
# ---

def generate_and_distribute_group_key(client_socket):
    """Gera uma nova chave de sessão e a distribui para os membros do grupo."""
    global crypto_serpent, group_public_keys

    if len(group_public_keys) < 2:
        log.info("Não há outros membros no grupo para iniciar uma conversa segura.")
        print("[SISTEMA] Você é o único no chat. Aguardando outros membros...")
        return

    log.info("Iniciando geração e distribuição de uma nova chave de grupo.")
    # 1. Gerar nova chave de sessão Serpent
    new_session_key = get_random_bytes(32)
    crypto_serpent = CriptoSerpent(new_session_key)
    print(f"\n[AÇÃO] Nova chave de sessão gerada por este cliente: {new_session_key.hex()}")

    # 2. Criptografar e enviar para cada membro
    for pub_key_pem in group_public_keys:
        # Não envia para si mesmo
        if pub_key_pem == crypto_rsa.get_public_key_pem():
            continue

        pub_key = RSA.import_key(pub_key_pem)
        encrypted_key = encrypt_with_public_key(pub_key, new_session_key)
        print(f"[AÇÃO] Criptografando chave de sessão para um membro com sua chave pública.")
        
        rekey_package = {"type": "control_rekey", "key": encrypted_key}
        send_message(client_socket, rekey_package)
        log.info("Pacote de rekey enviado para o servidor para distribuição.")

def receive_handler(client_socket, initial_setup_complete):
    """Lida com o recebimento de mensagens do servidor."""
    global crypto_serpent, group_public_keys
    
    while True:
        try:
            package = receive_message(client_socket)
            if not package:
                log.warning("Conexão com o servidor foi fechada.")
                break

            print("\n")
            log.debug(f"Pacote recebido do servidor. Tipo: {package.get('type')}")

            # Lógica para tratar diferentes tipos de pacotes
            if package['type'] == 'control_rekey':
                encrypted_key = package['key']
                
                # Descriptografa a nova chave de sessão com a chave privada RSA
                new_session_key = crypto_rsa.decrypt(encrypted_key)
                
                if new_session_key:
                    is_initial_key = crypto_serpent is None

                    if is_initial_key:
                        log.info("Recebida chave de sessão inicial do grupo.")
                        print("\n[AÇÃO] Chave de sessão inicial recebida de outro membro.")
                    else:
                        log.info("Recebido comando de REKEYING (nova chave de sessão).")
                        print("\n[AÇÃO] Recebida uma nova chave de sessão de outro membro.")

                    print(f"[AÇÃO] Chave de sessão descriptografada com sucesso: {new_session_key.hex()}")
                    # Atualiza a instância de criptografia simétrica com a nova chave
                    crypto_serpent = CriptoSerpent(new_session_key)
                    if is_initial_key:
                        log.info("CHAVE DE SESSÃO INICIAL ESTABELECIDA COM SUCESSO.")
                        print(f"\r\033[K[SISTEMA] A chave de segurança do grupo foi estabelecida.\n> ", end="", flush=True)
                    else:
                        log.info("CHAVE DE SESSÃO DO GRUPO ATUALIZADA COM SUCESSO.")
                        print(f"\r\033[K[SISTEMA] A chave de segurança do grupo foi atualizada.\n> ", end="", flush=True)
                else:
                    log.error("Falha ao descriptografar a nova chave de sessão. A comunicação pode estar comprometida.")

            elif package['type'] == 'control_member_update':
                log.info("Recebida atualização da lista de membros do grupo.")
                new_public_keys = package['public_keys']
                
                # Se o número de membros mudou e agora somos o "primeiro" (decidido por ordem de chave), geramos a chave
                if len(new_public_keys) > 1 and sorted(new_public_keys)[0] == crypto_rsa.get_public_key_pem() and len(new_public_keys) != len(group_public_keys):
                    # Verifica se é a primeira chave ou uma atualização
                    if crypto_serpent is None:
                        print("\n[SISTEMA] Grupo formado. Estabelecendo chave de sessão segura...")
                    else:
                        print("\n[SISTEMA] Um novo membro entrou/saiu. Gerando nova chave de grupo...")
                    group_public_keys = new_public_keys
                    generate_and_distribute_group_key(client_socket)
                else:
                    group_public_keys = new_public_keys

            elif package['type'] == 'chat_message':
                if crypto_serpent:
                    encrypted_content = package['content']
                    print(f"\n[AÇÃO] Mensagem criptografada recebida (IV: {encrypted_content['iv'].hex()}, Ciphertext: {encrypted_content['ciphertext'].hex()}).")
                    print(f"[AÇÃO] Descriptografando com a chave de sessão atual...")
                    decryption_result = crypto_serpent.decrypt(encrypted_content)
                    decrypted_message = decryption_result['plaintext']                    
                    decrypted_block_size = decryption_result['padded_size'] # Tamanho do bloco descriptografado (e.g., 16)
                    original_message_size = decryption_result['unpadded_size'] # Tamanho da mensagem original (e.g., 9)
                    print(f"[AÇÃO] Mensagem descriptografada. O bloco de {decrypted_block_size} bytes continha {original_message_size} bytes de dados e {decrypted_block_size - original_message_size} bytes de preenchimento.")
                    print(f"\r\033[K[Mensagem recebida] - {decrypted_message.decode('utf-8')}\n\n> ", end="", flush=True)
                else:
                    log.warning("Mensagem de chat recebida, mas ainda não temos uma chave de sessão.")
            
            elif package['type'] == 'server_info':
                print(f"\r\033[K[INFO DO SERVIDOR]: {package['message']}", flush=True)
                # Sinaliza que a configuração inicial foi recebida, liberando o prompt de username
                if not initial_setup_complete.is_set():
                    initial_setup_complete.set()

        except (EOFError, ConnectionResetError):
            log.warning("Conexão com o servidor perdida.")
            break
        except Exception as e:
            log.error(f"Erro no handler de recebimento: {e}")
            break

def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((HOST, PORT))
        log.info(f"Conectado ao servidor em {HOST}:{PORT}")

        # Imprime as chaves geradas para rastreamento
        print("\n--- Chaves RSA Geradas Localmente ---\n")
        print(f"[CHAVE PÚBLICA]:\n{crypto_rsa.get_public_key_pem().decode('utf-8')}\n")
        print(f"\n[CHAVE PRIVADA (não compartilhada)]:\n{crypto_rsa.get_private_key_pem().decode('utf-8')}\n")

        # Envia a chave pública RSA para o servidor imediatamente após a conexão
        log.info("Enviando chave pública RSA para o servidor...")
        pubkey_package = {
            "type": "pubkey",
            "key": crypto_rsa.get_public_key_pem()
        }
        send_message(client_socket, pubkey_package)
        print("[AÇÃO] Chave pública enviada ao servidor.")

        # Evento para sincronizar o prompt de username com o recebimento da primeira mensagem do servidor
        initial_setup_complete = threading.Event()

        # Inicia a thread para receber mensagens
        receive_thread = threading.Thread(target=receive_handler, args=(client_socket, initial_setup_complete))
        receive_thread.daemon = True
        receive_thread.start()
        
        # Aguarda a thread de recebimento confirmar que a configuração inicial do servidor foi recebida
        print("Aguardando configuração do servidor...")
        initial_setup_complete.wait()

        # Pede o nome de usuário
        print("\nDigite seu nome de usuário para o chat:")
        username = input("> ")
        print(f"\nOlá, {username}! Você pode começar a enviar mensagens. Digite 'sair' para fechar.")

        while True:
            message_text = input("> ")
            if message_text.lower() == 'sair':
                break

            if not crypto_serpent:
                print("[SISTEMA] Aguardando o servidor estabelecer uma chave de segurança para o grupo...")
                continue
            
            full_message = f"{username}: {message_text}"
            
            print(f"\n[AÇÃO] Criptografando a mensagem '{full_message}' com a chave de sessão atual.")

            # Criptografa a mensagem com a chave de sessão Serpent atual
            encrypted_content = crypto_serpent.encrypt(full_message.encode('utf-8'))
            
            print(f"[AÇÃO] Mensagem criptografada (IV: {encrypted_content['iv'].hex()}, Ciphertext: {encrypted_content['ciphertext'].hex()}). Enviando...\n")
            
            # Empacota para envio
            message_package = {
                "type": "chat_message",
                "content": encrypted_content
            }
            send_message(client_socket, message_package)

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