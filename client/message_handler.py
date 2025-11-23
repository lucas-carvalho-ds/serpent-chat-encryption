"""
Message Handler Module
Processes incoming messages from the server and updates the application state.
"""

from tkinter import messagebox
from crypto_utils import CryptoUtils, SerpentCipher
from logger_config import setup_logger

log = setup_logger(__name__)


class MessageHandler:
    """Handles processing of incoming server messages"""
    
    @staticmethod
    def process_message(message, context):
        """
        Process incoming message and update application state
        
        Args:
            message: The message dict from server
            context: Dict containing application state and callbacks:
                - 'rooms': dict of room data
                - 'room_keys': dict of room encryption keys
                - 'room_ciphers': dict of SerpentCipher instances
                - 'private_key': RSA private key
                - 'active_room_id': currently active room ID
                - 'on_login_success': callback after successful login
                - 'on_registration_qr': callback to show QR code (username, secret)
                - 'on_room_added': callback when room is added
                - 'on_user_list_updated': callback (users_list)
                - 'on_new_message': callback (room_id, formatted_message)
                - 'on_room_history': callback (room_id, history_list)
        """
        action = message.get('action')
        
        # Handle status messages
        if 'status' in message and action != 'status':
            status = message.get('status')
            text = message.get('message')
            if status == 'error':
                messagebox.showerror("Erro", text)
            elif status == 'success':
                # If login success, switch UI
                if text == 'Login realizado.':
                    context['on_login_success']()
                elif 'totp_secret' in message:
                    # Registration success, show QR
                    context['on_registration_qr'](message['totp_secret'])
        
        # Handle connection status
        if action == 'status':
            print(f"Status: {message.get('message')}")
        
        # Handle room added
        elif action == 'room_added':
            r_id = message.get('room_id')
            r_name = message.get('name')
            r_type = message.get('type')
            enc_key = bytes.fromhex(message.get('key'))
            
            try:
                key = CryptoUtils.decrypt_rsa(context['private_key'], enc_key)
                context['room_keys'][r_id] = key
                context['room_ciphers'][r_id] = SerpentCipher(key)
                
                if r_id not in context['rooms']:
                    context['rooms'][r_id] = {'name': r_name, 'type': r_type, 'history': []}
                    context['on_room_added'](r_id, r_name, r_type)
            except Exception as e:
                log.error(f"Erro ao descriptografar chave da sala {r_name}: {e}")
        
        # Handle user list update
        elif action == 'user_list':
            users = message.get('users')
            context['on_user_list_updated'](users)
        
        # Handle new message
        elif action == 'new_message':
            r_id = message.get('room_id')
            sender = message.get('sender')
            content_hex = message.get('content')
            iv_hex = message.get('iv')
            signature_hex = message.get('signature')
            
            if r_id in context['room_ciphers']:
                try:
                    cipher = context['room_ciphers'][r_id]
                    key = context['room_keys'][r_id]
                    
                    content_bytes = bytes.fromhex(content_hex)
                    iv_bytes = bytes.fromhex(iv_hex)
                    sig_bytes = bytes.fromhex(signature_hex)
                    
                    if CryptoUtils.verify_signature(key, content_bytes, sig_bytes):
                        decrypted = cipher.decrypt(iv_bytes, content_bytes).decode('utf-8')
                        
                        timestamp = message.get('timestamp', '')
                        # Format timestamp to HH:MM if possible, or keep as is
                        try:
                            if ' ' in timestamp:
                                time_part = timestamp.split(' ')[1][:5] # HH:MM
                                formatted_msg = f"[{time_part}] [{sender}]: {decrypted}"
                            else:
                                formatted_msg = f"[{sender}]: {decrypted}"
                        except:
                            formatted_msg = f"[{sender}]: {decrypted}"
                        
                        context['rooms'][r_id]['history'].append(formatted_msg)
                        context['on_new_message'](r_id, formatted_msg)
                except Exception as e:
                    log.error(f"Erro ao ler mensagem: {e}")
        
        # Handle room history
        elif action == 'room_history':
            r_id = message.get('room_id')
            data = message.get('data')
            if r_id in context['rooms'] and r_id in context['room_ciphers']:
                cipher = context['room_ciphers'][r_id]
                key = context['room_keys'][r_id]
                history_text = []
                for m in data:
                    try:
                        content = bytes.fromhex(m['content'])
                        iv = bytes.fromhex(m['iv'])
                        sig = bytes.fromhex(m['signature'])
                        if CryptoUtils.verify_signature(key, content, sig):
                            dec = cipher.decrypt(iv, content).decode('utf-8')
                            
                            timestamp = m.get('timestamp', '')
                            try:
                                if ' ' in timestamp:
                                    time_part = timestamp.split(' ')[1][:5]
                                    history_text.append(f"[{time_part}] [{m['sender']}]: {dec}")
                                else:
                                    history_text.append(f"[{m['sender']}]: {dec}")
                            except:
                                history_text.append(f"[{m['sender']}]: {dec}")
                    except:
                        pass
                context['rooms'][r_id]['history'] = history_text
                context['rooms'][r_id]['history'] = history_text
                context['on_room_history'](r_id, history_text)

        # Handle left room
        elif action == 'left_room':
            r_id = message.get('room_id')
            if 'on_left_room' in context:
                context['on_left_room'](r_id)

        # Handle room members
        elif action == 'room_members':
            r_id = message.get('room_id')
            members = message.get('members')
            if 'on_room_members' in context:
                context['on_room_members'](r_id, members)
