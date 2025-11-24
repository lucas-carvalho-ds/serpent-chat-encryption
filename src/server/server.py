import asyncio
import json
import struct
from src.server.database import Database
from src.server.auth import AuthManager
from src.common.crypto_utils import CryptoUtils
from pyserpent import Serpent
from src.common.logger_config import setup_logger, log_security
from pyserpent import serpent_cbc_encrypt, serpent_cbc_decrypt

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
        log_security("AVAILABILITY", "Server", f"New connection from {addr}")
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
                                
                                log_security("AVAILABILITY", "Server", f"User {username} connected and authenticated")
                                
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
            log_security("AVAILABILITY", "Server", f"Connection closed with {addr} (User: {username})")
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
            encrypted_keys = message.get('encrypted_keys') # {username: hex_key}
            return await self.create_private_chat(current_user, target_username, encrypted_keys)
        
        elif action == 'create_group_chat':
            group_name = message.get('group_name')
            members = message.get('members') # Lista de usernames
            encrypted_keys = message.get('encrypted_keys') # {username: hex_key}
            return await self.create_group_chat(current_user, group_name, members, encrypted_keys)
            
        elif action == 'send_message':
            return await self.handle_send_message(current_user, message)
            
        elif action == 'get_room_history':
            room_id = message.get('room_id')
            return self.get_room_history(current_user, room_id)

        elif action == 'leave_room':
            room_id = message.get('room_id')
            return await self.leave_room(current_user, room_id)

        elif action == 'invite_to_group':
            room_id = message.get('room_id')
            invitee_username = message.get('invitee_username')
            encrypted_key = message.get('encrypted_key')
            return await self.invite_to_group(current_user, room_id, invitee_username, encrypted_key)

        elif action == 'rotate_room_key':
            room_id = message.get('room_id')
            encrypted_keys = message.get('encrypted_keys')  # {username: hex_key}
            return await self.rotate_room_key(current_user, room_id, encrypted_keys)

        elif action == 'get_room_members':
            room_id = message.get('room_id')
            return self.get_room_members(current_user, room_id)

        elif action == 'logout':
            # Remove user from connected clients
            if current_user in self.connected_clients:
                del self.connected_clients[current_user]
            if current_user in self.client_keys:
                del self.client_keys[current_user]
            await self.broadcast_user_list()
            return {'status': 'success', 'message': 'Logout realizado.'}

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



    async def create_private_chat(self, creator, target_user, encrypted_keys):
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
            
        # Criar nova sala (SEM CHAVE NO SERVIDOR)
        room_name = f"{creator}-{target_user}" # Nome interno
        room_id = self.db.create_room(room_name, 'private')
        
        # Adicionar membros com suas chaves criptografadas
        key_creator = bytes.fromhex(encrypted_keys.get(creator)) if encrypted_keys.get(creator) else None
        key_target = bytes.fromhex(encrypted_keys.get(target_user)) if encrypted_keys.get(target_user) else None
        
        self.db.add_room_member(room_id, creator_id, key_creator)
        self.db.add_room_member(room_id, target_id, key_target)
        
        log_security("CONFIDENTIALITY", "Server", f"Stored encrypted keys for private chat {room_name}")
        
        # Notificar ambos
        await self.notify_new_room(room_id, room_name, 'private', [creator, target_user])
        
        # System Message (Broadcast only, no storage)
        await self.broadcast_system_message(room_id, f"{creator} criou este chat com {target_user}.")
        
        return {'status': 'success', 'message': 'Chat individual criado.', 'room_id': room_id}

    async def create_group_chat(self, creator, group_name, members, encrypted_keys):
        creator_data = self.db.get_user_by_username(creator)
        creator_id = creator_data[0]
        
        # Criar sala
        room_id = self.db.create_room(group_name, 'group')
        
        # Adicionar criador
        key_creator = bytes.fromhex(encrypted_keys.get(creator)) if encrypted_keys.get(creator) else None
        self.db.add_room_member(room_id, creator_id, key_creator)
        
        valid_members = [creator]
        
        for member_name in members:
            m_data = self.db.get_user_by_username(member_name)
            if m_data:
                key_member = bytes.fromhex(encrypted_keys.get(member_name)) if encrypted_keys.get(member_name) else None
                self.db.add_room_member(room_id, m_data[0], key_member)
                valid_members.append(member_name)
        
        log_security("CONFIDENTIALITY", "Server", f"Stored encrypted keys for group chat {group_name}")
        
        await self.notify_new_room(room_id, group_name, 'group', valid_members)
        
        # System Message
        members_str = ", ".join(members)
        await self.broadcast_system_message(room_id, f"{creator} criou o grupo '{group_name}' com: {members_str}.")
        
        return {'status': 'success', 'message': f'Grupo {group_name} criado.', 'room_id': room_id}

    async def leave_room(self, username, room_id):
        user_data = self.db.get_user_by_username(username)
        user_id = user_data[0]
        
        # Get room type before removing member
        room_type = self.db.get_room_type(room_id)
        
        # Get remaining members (before removal)
        members_ids_before = self.db.get_room_members(room_id)
        
        # Remover do banco
        self.db.remove_room_member(room_id, user_id)
        
        # Get remaining members (after removal)
        members_ids_after = self.db.get_room_members(room_id)
        
        # Notificar sucesso para o cliente remover da UI
        await self.broadcast_system_message(room_id, f"{username} saiu do chat.")
        
        # If it's a group and there are remaining members, trigger automatic key rotation
        if room_type == 'group' and len(members_ids_after) > 0:
            # Pick first remaining online member to initiate rotation
            # (In a real system, you might want more sophisticated logic)
            for member_id in members_ids_after:
                member_data = self.db.get_user_by_id(member_id)
                if member_data:
                    member_username = member_data[1]
                    if member_username in self.connected_clients:
                        # Request this member to rotate the key
                        writer = self.connected_clients[member_username]
                        await self.send_json(writer, {
                            'action': 'request_key_rotation',
                            'room_id': room_id,
                            'reason': f'{username} saiu do grupo'
                        })
                        log_security("CONFIDENTIALITY", "Server", f"Requested {member_username} to rotate key for room {room_id} after {username} left")
                        break  # Only ask one member
        
        return {'status': 'success', 'message': 'Você saiu do chat.', 'action': 'left_room', 'room_id': room_id}

    async def invite_to_group(self, inviter, room_id, invitee_username, encrypted_key_hex):
        """Invite a user to a group and share the encrypted key"""
        inviter_data = self.db.get_user_by_username(inviter)
        invitee_data = self.db.get_user_by_username(invitee_username)
        
        if not invitee_data:
            return {'status': 'error', 'message': 'Usuário não encontrado.'}
        
        inviter_id = inviter_data[0]
        invitee_id = invitee_data[0]
        
        # Verify inviter is a member of the room
        members = self.db.get_room_members(room_id)
        if inviter_id not in members:
            return {'status': 'error', 'message': 'Você não é membro deste grupo.'}
        
        # Verify room is a group (not private chat)
        room_type = self.db.get_room_type(room_id)
        if room_type != 'group':
            return {'status': 'error', 'message': 'Apenas grupos permitem convites.'}
        
        # Check if invitee is already a member
        if invitee_id in members:
            return {'status': 'error', 'message': 'Usuário já é membro do grupo.'}
        
        # Add invitee with encrypted key
        encrypted_key = bytes.fromhex(encrypted_key_hex)
        success = self.db.add_room_member(room_id, invitee_id, encrypted_key)
        
        if not success:
            return {'status': 'error', 'message': 'Erro ao adicionar membro.'}
        
        log_security("CONFIDENTIALITY", "Server", f"User {inviter} invited {invitee_username} to room {room_id}")
        
        # Get room info
        rooms = self.db.get_user_rooms(invitee_id)
        target_room = next((r for r in rooms if r[0] == room_id), None)
        
        if target_room:
            r_id, r_name, r_type, seen = target_room
            
            # Notify invitee if online
            if invitee_username in self.connected_clients:
                writer = self.connected_clients[invitee_username]
                self.db.mark_room_seen(r_id, invitee_id)
                
                await self.send_json(writer, {
                    'action': 'room_added',
                    'room_id': r_id,
                    'name': r_name,
                    'type': r_type,
                    'key': encrypted_key_hex,
                    'is_new': True,
                    'notification_text': f"{inviter} convidou você para o grupo: {r_name}"
                })
        
        # Broadcast system message
        await self.broadcast_system_message(room_id, f"{inviter} convidou {invitee_username} para o grupo.")
        
        return {'status': 'success', 'message': f'{invitee_username} foi convidado para o grupo.'}

    async def rotate_room_key(self, initiator, room_id, encrypted_keys):
        """Rotate the encryption key for a room"""
        initiator_data = self.db.get_user_by_username(initiator)
        initiator_id = initiator_data[0]
        
        # Verify initiator is a member
        members_ids = self.db.get_room_members(room_id)
        if initiator_id not in members_ids:
            return {'status': 'error', 'message': 'Você não é membro desta sala.'}
        
        # Update keys for all members
        for member_id in members_ids:
            member_data = self.db.get_user_by_id(member_id)
            if member_data:
                username = member_data[1]
                if username in encrypted_keys:
                    new_encrypted_key = bytes.fromhex(encrypted_keys[username])
                    self.db.update_user_room_key(room_id, member_id, new_encrypted_key)
        
        log_security("CONFIDENTIALITY", "Server", f"User {initiator} rotated key for room {room_id}")
        
        # Broadcast new keys to online members
        for member_id in members_ids:
            member_data = self.db.get_user_by_id(member_id)
            if member_data:
                username = member_data[1]
                if username in self.connected_clients and username in encrypted_keys:
                    writer = self.connected_clients[username]
                    await self.send_json(writer, {
                        'action': 'key_rotated',
                        'room_id': room_id,
                        'new_key': encrypted_keys[username],
                        'reason': f'Rotacionada por {initiator}'
                    })
        
        # Broadcast system message
        await self.broadcast_system_message(room_id, f"{initiator} rotacionou a chave de criptografia.")
        
        return {'status': 'success', 'message': 'Chave rotacionada com sucesso.'}

    async def broadcast_system_message(self, room_id, content):
        """Broadcast a system message to room members (NO DB STORAGE for now)"""
        import datetime
        
        # Broadcast to online members
        msg = {
            'action': 'system_message',
            'room_id': room_id,
            'content': content,
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        members_ids = self.db.get_room_members(room_id)
        for user_id in members_ids:
            user_data = self.db.get_user_by_id(user_id)
            if user_data:
                username = user_data[1]
                if username in self.connected_clients:
                    await self.send_json(self.connected_clients[username], msg)

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

    async def notify_new_room(self, room_id, name, r_type, members):
        for username in members:
            if username in self.connected_clients:
                writer = self.connected_clients[username]
                
                # Obter chave específica do usuário
                user_data = self.db.get_user_by_username(username)
                if user_data:
                    user_id = user_data[0]
                    encrypted_key = self.db.get_user_room_key(room_id, user_id)
                    
                    # Mark as seen immediately if user is online and notified
                    self.db.mark_room_seen(room_id, user_id)
                    
                    key_hex = encrypted_key.hex() if encrypted_key else None
                    
                    log_security("CONFIDENTIALITY", "Server", f"Sending encrypted room key to {username}")
                    
                    await self.send_json(writer, {
                        'action': 'room_added',
                        'room_id': room_id,
                        'name': name,
                        'type': r_type,
                        'key': key_hex,
                        'is_new': True
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
        
        # Get room name for logging
        room_info = self.db.get_room_by_id(room_id)
        room_name = room_info[1] if room_info else f"Room {room_id}"
        
        log_security("CONFIDENTIALITY", "Server", f"User {sender} sending encrypted message to '{room_name}'")
        log_security("CONFIDENTIALITY", "Server", f"Message encrypted with Serpent (CBC mode)")
        log_security("INTEGRITY", "Server", f"Message signed with HMAC by {sender}")
        
        # Salvar
        content_bytes = bytes.fromhex(content_hex)
        iv_bytes = bytes.fromhex(iv_hex)
        signature_bytes = bytes.fromhex(signature_hex)
        msg_id = self.db.save_message(sender_id, room_id, content_bytes, iv_bytes, signature_bytes)
        
        log_security("INTEGRITY", "Database", f"Encrypted message from {sender} saved to DB (ID: {msg_id})")
        
        # Broadcast para membros
        await self.broadcast_room_message(room_id, members_ids, sender, content_hex, iv_hex, signature_hex)
        return {'status': 'success'}

    async def broadcast_room_message(self, room_id, members_ids, sender, content, iv, signature):
        import datetime
        msg = {
            'action': 'new_message',
            'room_id': room_id,
            'sender': sender,
            'content': content,
            'iv': iv,
            'signature': signature,
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
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
            
        # Filtrar mensagens a partir da entrada do usuário
        # join_time = self.db.get_member_join_time(room_id, user_id)
        # Desabilitando filtro temporariamente para garantir que histórico apareça
        msgs = self.db.get_messages_for_room(room_id, min_timestamp=None)
        history = []
        for m in msgs:
            # m[1] is sender_id, m[7] is username
            # If sender_id (m[1]) is None, it's a system message
            sender_name = m[7] if m[1] is not None else 'System'
            
            history.append({
                'sender': sender_name,
                'content': m[3].hex(),
                'iv': m[4].hex(),
                'signature': m[5].hex(),
                'timestamp': m[6]
            })
        return {'status': 'history', 'action': 'room_history', 'room_id': room_id, 'data': history}

    async def send_user_rooms(self, writer, username):
        user_data = self.db.get_user_by_username(username)
        user_id = user_data[0]
        rooms = self.db.get_user_rooms(user_id)
        
        for r in rooms:
            # r: id, name, type, seen
            r_id, r_name, r_type, seen = r
            
            # Obter chave específica do usuário
            encrypted_key = self.db.get_user_room_key(r_id, user_id)
            
            if encrypted_key:
                is_new = False
                if not seen:
                    is_new = True
                    self.db.mark_room_seen(r_id, user_id)
                
                await self.send_json(writer, {
                    'action': 'room_added',
                    'room_id': r_id,
                    'name': r_name,
                    'type': r_type,
                    'key': encrypted_key.hex(),
                    'is_new': is_new
                })

    async def broadcast_user_list(self):
        # Pegar todos os usuários do DB
        all_users = self.db.get_all_users()
        connected_users = set(self.connected_clients.keys())
        
        user_list = []
        for u in all_users:
            # Incluir chave pública
            user_data = self.db.get_user_by_username(u)
            pub_key = user_data[5].decode('utf-8') if user_data else None
            
            user_list.append({
                'username': u,
                'status': 'online' if u in connected_users else 'offline',
                'public_key': pub_key
            })
            
        msg = {'action': 'user_list', 'users': user_list}
        for writer in self.connected_clients.values():
            await self.send_json(writer, msg)

    async def start(self):
        server = await asyncio.start_server(self.handle_client, HOST, PORT)
        log.info(f"Servidor rodando em {HOST}:{PORT}")
        log_security("AVAILABILITY", "Server", f"========== SERVER STARTED ==========")
        log_security("AVAILABILITY", "Server", f"Server listening on {HOST}:{PORT}")
        log_security("AVAILABILITY", "Server", f"Database: chat.db")
        async with server:
            await server.serve_forever()

if __name__ == '__main__':
    server = ChatServer()
    try:
        asyncio.run(server.start())
    except KeyboardInterrupt:
        log.info("Servidor parado.")
        log_security("AVAILABILITY", "Server", "========== SERVER STOPPED ==========")
