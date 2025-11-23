import asyncio
import json
import struct
from database import Database
from auth import AuthManager
from crypto_utils import CryptoUtils
from pyserpent import Serpent
from logger_config import setup_logger

log = setup_logger(__name__)

HOST = '0.0.0.0'
PORT = 8888

class ChatServer:
    def __init__(self):
        self.db = Database()
        self.auth_manager = AuthManager(self.db)
        self.connected_clients = {} # {username: writer}
        self.client_keys = {} # {username: public_key_pem}
        
        # Cache de chaves de sala para envio rápido {room_id: serpent_key_bytes}
        self.active_room_keys = {} 

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        log.info(f"Nova conexão de {addr}")
        username = None

        try:
            while True:
                header = await reader.read(4)
                if not header:
                    break
                
                msg_len = struct.unpack('!I', header)[0]
                data = await reader.read(msg_len)
                
                if not data:
                    break

                try:
                    message = json.loads(data.decode('utf-8'))
                    response = await self.process_message(message, writer, username)
                    
                    if response:
                        await self.send_json(writer, response)
                        
                        if message.get('action') == 'login' and response.get('status') == 'success':
                            username = message.get('username')
                            self.connected_clients[username] = writer
                            
                            user_pub_key_pem = self.auth_manager.get_user_public_key(username)
                            if user_pub_key_pem:
                                from Crypto.PublicKey import RSA
                                pub_key = RSA.import_key(user_pub_key_pem)
                                self.client_keys[username] = pub_key
                                
                                # Enviar lista de usuários e salas
                                await self.broadcast_user_list()
                                await self.send_user_rooms(writer, username)
                            
                except json.JSONDecodeError:
                    log.error("Erro ao decodificar JSON.")
                except Exception as e:
                    log.error(f"Erro ao processar mensagem: {e}")

        except asyncio.CancelledError:
            pass
        except Exception as e:
            log.error(f"Erro na conexão com {addr}: {e}")
        finally:
            log.info(f"Conexão fechada com {addr}")
            if username and username in self.connected_clients:
                del self.connected_clients[username]
                if username in self.client_keys:
                    del self.client_keys[username]
                await self.broadcast_user_list()
            writer.close()
            await writer.wait_closed()

    async def send_json(self, writer, data):
        try:
            msg_bytes = json.dumps(data).encode('utf-8')
            header = struct.pack('!I', len(msg_bytes))
            writer.write(header + msg_bytes)
            await writer.drain()
        except Exception as e:
            log.error(f"Erro ao enviar JSON: {e}")

    async def process_message(self, message, writer, current_user):
        action = message.get('action')
        
        if action == 'register':
            return self.handle_register(message)
        elif action == 'login':
            return self.handle_login(message)
        
        # Ações que requerem autenticação
        if not current_user:
            return {'status': 'error', 'message': 'Não autenticado.'}

        if action == 'create_private_chat':
            target_username = message.get('target_username')
            return await self.create_private_chat(current_user, target_username)
        
        elif action == 'create_group_chat':
            group_name = message.get('group_name')
            members = message.get('members') # Lista de usernames
            return await self.create_group_chat(current_user, group_name, members)
            
        elif action == 'send_message':
            return await self.handle_send_message(current_user, message)
            
        elif action == 'get_room_history':
            room_id = message.get('room_id')
            return self.get_room_history(current_user, room_id)

        elif action == 'leave_room':
            room_id = message.get('room_id')
            return await self.leave_room(current_user, room_id)

        elif action == 'join_room':
            room_id = message.get('room_id')
            return await self.join_room(current_user, room_id)

        elif action == 'get_room_members':
            room_id = message.get('room_id')
            return self.get_room_members(current_user, room_id)

        return {'status': 'error', 'message': 'Ação desconhecida.'}

    def handle_register(self, message):
        username = message.get('username')
        password = message.get('password')
        pub_key_pem = message.get('public_key').encode('utf-8')
        success, result = self.auth_manager.register_user(username, password, pub_key_pem)
        if success:
            return {'status': 'success', 'message': 'Registro realizado.', 'totp_secret': result}
        else:
            return {'status': 'error', 'message': result}

    def handle_login(self, message):
        username = message.get('username')
        password = message.get('password')
        totp_code = message.get('totp_code')
        public_key = message.get('public_key')
        
        if username in self.connected_clients:
             return {'status': 'error', 'message': 'Usuário já está logado.'}

        success, msg = self.auth_manager.authenticate_user(username, password, totp_code)
        if success:
            if public_key:
                self.auth_manager.update_public_key(username, public_key.encode('utf-8'))
            return {'status': 'success', 'message': 'Login realizado.'}
        else:
            return {'status': 'error', 'message': msg}

    async def create_private_chat(self, creator, target_user):
        creator_data = self.db.get_user_by_username(creator)
        target_data = self.db.get_user_by_username(target_user)
        
        if not target_data:
            return {'status': 'error', 'message': 'Usuário alvo não encontrado.'}
            
        creator_id = creator_data[0]
        target_id = target_data[0]
        
        # Verificar se já existe
        existing_room_id = self.db.get_private_chat_id(creator_id, target_id)
        if existing_room_id:
            return {'status': 'success', 'message': 'Chat individual já existe.', 'room_id': existing_room_id}
            
        # Criar nova sala
        room_key = Serpent.generateIV() + Serpent.generateIV()
        room_name = f"{creator}-{target_user}" # Nome interno, UI pode mostrar diferente
        room_id = self.db.create_room(room_name, 'private', room_key)
        
        self.db.add_room_member(room_id, creator_id)
        self.db.add_room_member(room_id, target_id)
        
        # Notificar ambos e enviar chaves
        await self.notify_new_room(room_id, room_name, 'private', [creator, target_user], room_key)
        
        return {'status': 'success', 'message': 'Chat individual criado.', 'room_id': room_id}

    async def create_group_chat(self, creator, group_name, members):
        creator_data = self.db.get_user_by_username(creator)
        creator_id = creator_data[0]
        
        room_key = Serpent.generateIV() + Serpent.generateIV()
        room_id = self.db.create_room(group_name, 'group', room_key)
        
        self.db.add_room_member(room_id, creator_id)
        
        valid_members = [creator]
        
        for member_name in members:
            m_data = self.db.get_user_by_username(member_name)
            if m_data:
                self.db.add_room_member(room_id, m_data[0])
                valid_members.append(member_name)
        
        await self.notify_new_room(room_id, group_name, 'group', valid_members, room_key)
        
        return {'status': 'success', 'message': f'Grupo {group_name} criado.', 'room_id': room_id}

    async def leave_room(self, username, room_id):
        user_data = self.db.get_user_by_username(username)
        user_id = user_data[0]
        
        # Remover do banco
        self.db.remove_room_member(room_id, user_id)
        
        # Notificar sucesso para o cliente remover da UI
        return {'status': 'success', 'message': 'Você saiu da sala.', 'action': 'left_room', 'room_id': room_id}

    async def join_room(self, username, room_id):
        user_data = self.db.get_user_by_username(username)
        user_id = user_data[0]
        
        # Verificar se sala existe
        # Podemos usar get_room_key para verificar existência
        room_key = self.db.get_room_key(room_id)
        if not room_key:
             return {'status': 'error', 'message': 'Sala não encontrada.'}
             
        # Adicionar membro
        success = self.db.add_room_member(room_id, user_id)
        if not success:
             return {'status': 'error', 'message': 'Você já está nesta sala ou erro ao entrar.'}
             
        # Pegar info da sala para enviar ao usuário
        # Precisamos do nome e tipo. Vamos fazer uma query rápida ou adicionar método no DB.
        # Como não temos get_room_info, vamos usar get_user_rooms e filtrar (ineficiente mas funciona sem mudar muito DB agora)
        rooms = self.db.get_user_rooms(user_id)
        target_room = next((r for r in rooms if r[0] == room_id), None)
        
        if target_room:
            r_id, r_name, r_type = target_room
            pub_key = self.client_keys.get(username)
            if pub_key:
                encrypted_key = CryptoUtils.encrypt_rsa(pub_key, room_key)
                # Enviar dados da sala para o usuário
                # Retornamos success, mas também mandamos o evento room_added via socket para garantir consistência
                writer = self.connected_clients.get(username)
                if writer:
                    await self.send_json(writer, {
                        'action': 'room_added',
                        'room_id': r_id,
                        'name': r_name,
                        'type': r_type,
                        'key': encrypted_key.hex()
                    })
        
        return {'status': 'success', 'message': 'Entrou na sala com sucesso.'}

    def get_room_members(self, username, room_id):
        # Verificar permissão
        user_data = self.db.get_user_by_username(username)
        user_id = user_data[0]
        members_ids = self.db.get_room_members(room_id)
        
        if user_id not in members_ids:
            return {'status': 'error', 'message': 'Acesso negado.'}
            
        members_usernames = []
        for m_id in members_ids:
            u = self.db.get_user_by_id(m_id)
            if u:
                members_usernames.append(u[1])
                
        return {'action': 'room_members', 'room_id': room_id, 'members': members_usernames}

    async def notify_new_room(self, room_id, name, r_type, members, room_key):
        for username in members:
            if username in self.connected_clients:
                writer = self.connected_clients[username]
                pub_key = self.client_keys.get(username)
                if pub_key:
                    encrypted_key = CryptoUtils.encrypt_rsa(pub_key, room_key)
                    await self.send_json(writer, {
                        'action': 'room_added',
                        'room_id': room_id,
                        'name': name,
                        'type': r_type,
                        'key': encrypted_key.hex()
                    })

    async def handle_send_message(self, sender, message):
        room_id = message.get('room_id')
        content_hex = message.get('content')
        iv_hex = message.get('iv')
        signature_hex = message.get('signature')
        
        # Verificar se usuário é membro da sala
        sender_data = self.db.get_user_by_username(sender)
        sender_id = sender_data[0]
        members_ids = self.db.get_room_members(room_id)
        
        if sender_id not in members_ids:
            return {'status': 'error', 'message': 'Você não é membro desta sala.'}
            
        # Salvar
        content_bytes = bytes.fromhex(content_hex)
        iv_bytes = bytes.fromhex(iv_hex)
        signature_bytes = bytes.fromhex(signature_hex)
        self.db.save_message(sender_id, room_id, content_bytes, iv_bytes, signature_bytes)
        
        # Broadcast para membros
        await self.broadcast_room_message(room_id, members_ids, sender, content_hex, iv_hex, signature_hex)
        return {'status': 'success'}

    async def broadcast_room_message(self, room_id, members_ids, sender, content, iv, signature):
        msg = {
            'action': 'new_message',
            'room_id': room_id,
            'sender': sender,
            'content': content,
            'iv': iv,
            'signature': signature
        }
        
        for user_id in members_ids:
            user_data = self.db.get_user_by_id(user_id)
            if user_data:
                username = user_data[1]
                if username in self.connected_clients:
                    await self.send_json(self.connected_clients[username], msg)

    def get_room_history(self, username, room_id):
        # Verificar permissão
        user_data = self.db.get_user_by_username(username)
        user_id = user_data[0]
        members = self.db.get_room_members(room_id)
        
        if user_id not in members:
            return {'status': 'error', 'message': 'Acesso negado.'}
            
        msgs = self.db.get_messages_for_room(room_id)
        history = []
        for m in msgs:
             history.append({
                 'sender': m[7],
                 'content': m[3].hex(),
                 'iv': m[4].hex(),
                 'signature': m[5].hex(),
                 'timestamp': m[6]
             })
        return {'status': 'history', 'room_id': room_id, 'data': history}

    async def send_user_rooms(self, writer, username):
        user_data = self.db.get_user_by_username(username)
        user_id = user_data[0]
        rooms = self.db.get_user_rooms(user_id)
        
        pub_key = self.client_keys.get(username)
        
        for r in rooms:
            # r: id, name, type
            r_id, r_name, r_type = r
            key = self.db.get_room_key(r_id)
            if pub_key and key:
                encrypted_key = CryptoUtils.encrypt_rsa(pub_key, key)
                await self.send_json(writer, {
                    'action': 'room_added',
                    'room_id': r_id,
                    'name': r_name,
                    'type': r_type,
                    'key': encrypted_key.hex()
                })

    async def broadcast_user_list(self):
        # Pegar todos os usuários do DB
        all_users = self.db.get_all_users()
        connected_users = set(self.connected_clients.keys())
        
        user_list = []
        for u in all_users:
            user_list.append({
                'username': u,
                'status': 'online' if u in connected_users else 'offline'
            })
            
        msg = {'action': 'user_list', 'users': user_list}
        for writer in self.connected_clients.values():
            await self.send_json(writer, msg)

    async def start(self):
        server = await asyncio.start_server(self.handle_client, HOST, PORT)
        log.info(f"Servidor rodando em {HOST}:{PORT}")
        async with server:
            await server.serve_forever()

if __name__ == '__main__':
    server = ChatServer()
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        log.info("Servidor parado.")
