"""
Message Handler Module
Processes incoming messages from the server and updates the application state.
"""

from tkinter import messagebox
from src.common.crypto_utils import CryptoUtils, SerpentCipher
from src.common.logger_config import setup_logger, log_security
from pyserpent import serpent_cbc_decrypt

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
                    is_new = message.get('is_new', False)
                    notification_text = message.get('notification_text')
                    context['on_room_added'](r_id, r_name, r_type, is_new, notification_text)
            except Exception as e:
                log.error(f"Erro ao descriptografar chave da sala {r_name}: {e}")
        
        # Handle user list update
        elif action == 'user_list':
            users = message.get('users')
            context['on_user_list_updated'](users)
        
        # Handle new message
        elif action == 'new_message':
            room_id = message.get('room_id')
            sender = message.get('sender')
            content_hex = message.get('content')
            iv_hex = message.get('iv')
            signature_hex = message.get('signature')
            timestamp = message.get('timestamp')
            
            if room_id in context['room_keys']:
                try:
                    key = context['room_keys'][room_id]
                    content_bytes = bytes.fromhex(content_hex)
                    iv_bytes = bytes.fromhex(iv_hex)
                    signature_bytes = bytes.fromhex(signature_hex)
                    
                    # Get room name for logging (safely)
                    room_name = 'Unknown'
                    if 'rooms' in context and room_id in context['rooms']:
                        room_name = context['rooms'][room_id].get('name', f'Room {room_id}')
                    
                    log_security("INTEGRITY", "Client", f"Verifying message signature from {sender} in '{room_name}'")
                    
                    # Verify Signature
                    if CryptoUtils.verify_signature(key, content_bytes, signature_bytes):
                        log_security("INTEGRITY", "Client", f"Signature VALID for message from {sender}")
                        log_security("CONFIDENTIALITY", "Client", f"Decrypting message from {sender} with Serpent key")
                        
                        # Decrypt using SerpentCipher (handles padding correctly)
                        cipher = context['room_ciphers'][room_id]
                        msg_text = cipher.decrypt(iv_bytes, content_bytes).decode('utf-8')
                        
                        formatted_msg = f"[{timestamp}] {sender}: {msg_text}"
                        
                        log_security("CONFIDENTIALITY", "Client", f"Message decrypted successfully: '{msg_text[:50]}...'" if len(msg_text) > 50 else f"Message decrypted successfully: '{msg_text}'")
                        
                        if context.get('on_new_message'):
                            context['on_new_message'](room_id, formatted_msg)
                    else:
                        log.warning(f"Assinatura inválida de {sender}")
                        log_security("INTEGRITY", "Client", f"Signature INVALID for message from {sender}")
                except Exception as e:
                    log.error(f"Erro ao processar mensagem de {sender}: {e}")
            else:
                log.warning(f"Recebida mensagem para sala {room_id} sem chave.")
        
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
                            sender = m.get('sender', 'Unknown')
                            
                            try:
                                if ' ' in timestamp:
                                    time_part = timestamp.split(' ')[1][:5]
                                    # Format system messages differently
                                    if sender == 'System':
                                        history_text.append(f"[{time_part}] [Sistema]: {dec}")
                                    else:
                                        history_text.append(f"[{time_part}] [{sender}]: {dec}")
                                else:
                                    if sender == 'System':
                                        history_text.append(f"[Sistema]: {dec}")
                                    else:
                                        history_text.append(f"[{sender}]: {dec}")
                            except:
                                if sender == 'System':
                                    history_text.append(f"[Sistema]: {dec}")
                                else:
                                    history_text.append(f"[{sender}]: {dec}")
                    except:
                        pass
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

        # Handle available groups
        elif action == 'available_groups':
            groups = message.get('groups')
            if 'on_available_groups' in context:
                context['on_available_groups'](groups)

        # Handle key rotation
        elif action == 'key_rotated':
            r_id = message.get('room_id')
            new_key_hex = message.get('new_key')
            reason = message.get('reason', 'unknown')
            
            if r_id in context['rooms']:
                try:
                    enc_key = bytes.fromhex(new_key_hex)
                    key = CryptoUtils.decrypt_rsa(context['private_key'], enc_key)
                    context['room_keys'][r_id] = key
                    context['room_ciphers'][r_id] = SerpentCipher(key)
                    
                    if 'on_key_rotated' in context:
                        context['on_key_rotated'](r_id, reason)
                    
                    log.info(f"Chave da sala {r_id} rotacionada. Motivo: {reason}")
                except Exception as e:
                    log.error(f"Falha ao atualizar chave rotacionada: {e}")

        # Handle key rotation request from server
        elif action == 'request_key_rotation':
            room_id = message.get('room_id')
            reason = message.get('reason', 'membro saiu')
            
            if context.get('on_key_rotation_requested'):
                context['on_key_rotation_requested'](room_id, reason)

        # Handle system message
        elif action == 'system_message':
            r_id = message.get('room_id')
            content = message.get('content')
            timestamp = message.get('timestamp', '')
            
            # Format timestamp
            try:
                if ' ' in timestamp:
                    time_part = timestamp.split(' ')[1][:5]
                    formatted_msg = f"[{time_part}] [Sistema]: {content}"
                else:
                    formatted_msg = f"[Sistema]: {content}"
            except:
                formatted_msg = f"[Sistema]: {content}"
            
            if r_id in context['rooms']:
                context['rooms'][r_id]['history'].append(formatted_msg)
                context['on_new_message'](r_id, formatted_msg)
