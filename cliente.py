# cliente.py
import socket
import threading
import pickle
import sys

from logger_config import setup_logger
from cripto import CriptoRSA, CriptoSerpent

log = setup_logger(__name__)

HOST = '127.0.0.1'
PORT = 65432

# --- Variáveis Globais de Criptografia ---
# O cliente gera seu par de chaves RSA uma vez ao iniciar
crypto_rsa = CriptoRSA() 
# A instância de Serpent será substituída toda vez que uma nova chave de grupo for recebida
crypto_serpent = None 
# ---

def receive_handler(client_socket):
    """Lida com o recebimento de mensagens do servidor."""
    global crypto_serpent
    
    while True:
        try:
            data = client_socket.recv(4096)
            if not data:
                log.warning("Conexão com o servidor foi fechada.")
                break

            package = pickle.loads(data)
            log.debug(f"Pacote recebido do servidor. Tipo: {package.get('type')}")

            # Lógica para tratar diferentes tipos de pacotes
            if package['type'] == 'control_rekey':
                log.info("Recebido comando de REKEYING do servidor.")
                encrypted_key = package['key']
                
                # Descriptografa a nova chave de sessão com a chave privada RSA
                new_session_key = crypto_rsa.decrypt(encrypted_key).rstrip(b'\0')
                
                if new_session_key:
                    # Atualiza a instância de criptografia simétrica com a nova chave
                    crypto_serpent = CriptoSerpent(new_session_key)
                    log.info("CHAVE DE SESSÃO DO GRUPO ATUALIZADA COM SUCESSO.")
                    print("\n[SISTEMA] A chave de segurança do grupo foi atualizada.\n> ", end="")
                else:
                    log.error("Falha ao descriptografar a nova chave de sessão. A comunicação pode estar comprometida.")

            elif package['type'] == 'chat_message':
                if crypto_serpent:
                    encrypted_content = package['content']
                    # Descriptografa a mensagem do chat com a chave de sessão atual
                    decrypted_message = crypto_serpent.decrypt(encrypted_content)
                    if decrypted_message:
                        print(f"\n[Mensagem recebida]: {decrypted_message.decode('utf-8')}\n> ", end="")
                else:
                    log.warning("Mensagem de chat recebida, mas ainda não temos uma chave de sessão.")
            
            elif package['type'] == 'server_info':
                print(f"\n[INFO DO SERVIDOR]: {package['message']}\n> ", end="")

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

        # Envia a chave pública RSA para o servidor imediatamente após a conexão
        log.debug("Enviando chave pública RSA para o servidor...")
        client_socket.send(crypto_rsa.get_public_key_pem())
        log.info("Chave pública enviada.")

        # Inicia a thread para receber mensagens
        receive_thread = threading.Thread(target=receive_handler, args=(client_socket,))
        receive_thread.daemon = True
        receive_thread.start()
        
        # Loop principal para enviar mensagens
        print("Digite seu nome de usuário para o chat:")
        username = input("> ")
        print(f"Olá, {username}! Você pode começar a enviar mensagens. Digite 'sair' para fechar.")

        while True:
            message_text = input("> ")
            if message_text.lower() == 'sair':
                break

            if not crypto_serpent:
                print("[SISTEMA] Aguardando o servidor estabelecer uma chave de segurança para o grupo...")
                continue
            
            full_message = f"{username}: {message_text}"
            
            # Criptografa a mensagem com a chave de sessão Serpent atual
            encrypted_content = crypto_serpent.encrypt(full_message.encode('utf-8'))
            
            # Empacota para envio
            message_package = {
                "type": "chat_message",
                "content": encrypted_content
            }
            client_socket.send(pickle.dumps(message_package))

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