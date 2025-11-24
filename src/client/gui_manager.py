"""
GUI Manager Module
Main coordinator for the SerpTalk client using modular architecture.
"""

import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
import queue
import os
from Crypto.PublicKey import RSA
from pyserpent import Serpent # Import Serpent for key generation

from src.client.networking import NetworkThread
from src.client.validation import validate_login, validate_registration, validate_username
from src.client.message_handler import MessageHandler
from src.client.ui.auth_screens import AuthScreens
from src.client.ui.main_screen import MainScreen
from src.client.ui.dialogs import MemberSelectionDialog, RoomMembersDialog, JoinGroupDialog
from src.client.ui.qr_dialog import show_qr_code
from src.client.key_logger import KeyLogger
from src.client.ui.key_history_window import KeyHistoryWindow
from src.common.crypto_utils import CryptoUtils, SerpentCipher
from src.common.logger_config import setup_logger

log = setup_logger(__name__)


class ChatGUI:
    """Main GUI coordinator using modular architecture"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("SerpTalk")
        self.root.geometry("900x600")
        
        # Communication queues
        self.incoming_queue = queue.Queue()
        self.outgoing_queue = queue.Queue()
        
        # Key Logger (initialize early)
        self.key_logger = KeyLogger()
        
        # State
        self.username = None
        self.private_key = None
        self.public_key = None
        self.rooms = {}
        self.room_keys = {}
        self.room_ciphers = {}
        self.online_users = set()  # All users currently online
        self.all_users_data = {} # {username: {'status': 'online/offline', 'public_key': 'PEM'}}
        self.room_members = {}  # {room_id: [usernames]}
        self.room_online_members = {}  # {room_id: set(online_usernames)}
        self.active_room_id = None
        
        # UI references
        self.main_screen = None
        
        # Network thread
        self.network_thread = NetworkThread(self.incoming_queue, self.outgoing_queue)
        self.network_thread.start()
        
        # Show welcome screen
        self.build_welcome_ui()
        
        # Start message queue polling
        self.root.after(100, self.check_queue)
    
    def _load_or_generate_rsa_keys(self, username):
        """Load RSA keys from disk or generate new ones"""
        keys_dir = "client_keys"
        os.makedirs(keys_dir, exist_ok=True)
        
        private_key_path = os.path.join(keys_dir, f"{username}_private.pem")
        public_key_path = os.path.join(keys_dir, f"{username}_public.pem")
        
        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            # Load existing keys
            try:
                with open(private_key_path, 'rb') as f:
                    self.private_key = RSA.import_key(f.read())
                with open(public_key_path, 'rb') as f:
                    self.public_key = RSA.import_key(f.read())
                
                log.info(f"Loaded existing RSA keys for {username}")
                from src.common.logger_config import log_security
                log_security("AUTHENTICITY", "Client", f"Loaded existing RSA keys for {username}")
                return
            except Exception as e:
                log.error(f"Failed to load keys: {e}. Generating new ones.")
        
        # Generate new keys
        self.private_key, self.public_key = CryptoUtils.generate_rsa_keypair()
        self._save_rsa_keys(username)
        
        log.info(f"Generated new RSA keys for {username}")
        from src.common.logger_config import log_security
        key_hash = str(hash(self.public_key.export_key()))[:16]
        log_security("AUTHENTICITY", "Client", f"Generated new RSA keys for {username}", key_hash=key_hash)
        
        self.key_logger.log_event(
            'RSA_GENERATION',
            f'RSA keypair generated for {username}',
            key_data={
                'key_size': self.public_key.size_in_bits(),
                'public_key_hash': key_hash
            },
            context={'username': username}
        )
    
    def _save_rsa_keys(self, username):
        """Save RSA keys to disk"""
        keys_dir = "client_keys"
        os.makedirs(keys_dir, exist_ok=True)
        
        private_key_path = os.path.join(keys_dir, f"{username}_private.pem")
        public_key_path = os.path.join(keys_dir, f"{username}_public.pem")
        
        try:
            with open(private_key_path, 'wb') as f:
                f.write(self.private_key.export_key())
            with open(public_key_path, 'wb') as f:
                f.write(self.public_key.export_key())
            
            log.info(f"Saved RSA keys for {username}")
        except Exception as e:
            log.error(f"Failed to save keys: {e}")
    
    def clear_window(self):
        """Clear all widgets from window"""
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def build_welcome_ui(self):
        """Show welcome screen"""
        AuthScreens.build_welcome_ui(
            self.root,
            self.clear_window,
            self.build_login_ui,
            self.build_register_ui
        )
    
    def build_login_ui(self):
        """Show login screen"""
        AuthScreens.build_login_ui(
            self.root,
            self.clear_window,
            self.do_login,
            self.build_welcome_ui
        )
    
    def build_register_ui(self):
        """Show registration screen"""
        AuthScreens.build_register_ui(
            self.root,
            self.clear_window,
            self.do_register,
            self.build_welcome_ui
        )
    
    def build_main_ui(self):
        """Show main chat UI"""
        self.main_screen = MainScreen(self.root, self.username)
        self.main_screen.build_ui(
            on_room_select_callback=self.on_room_select,
            on_send_callback=self.send_message,
            on_create_private_callback=self.create_private_chat,
            on_create_group_callback=self.create_group_chat,
            on_invite_to_group_callback=self.invite_to_group,
            on_leave_room_callback=self.leave_room,
            on_view_members_callback=self.show_room_members,
            on_logout_callback=self.logout,
            on_close_view_callback=self.close_chat_view,
            on_rotate_key_callback=self.rotate_room_key,
            on_view_keys_callback=self.show_key_history
        )
        self.update_rooms_list()
    
    def do_login(self, username, password, totp_code):
        """Handle login submission"""
        valid, msg = validate_login(username, password, totp_code)
        if not valid:
            messagebox.showerror("Erro de Validação", msg)
            return
        
        self.username = username.strip()
        
        # Load or generate RSA keys for this user
        self._load_or_generate_rsa_keys(self.username)
        
        pub_key_pem = self.public_key.export_key().decode('utf-8')
        self.outgoing_queue.put({
            'action': 'login',
            'username': self.username,
            'password': password,
            'totp_code': totp_code,
            'public_key': pub_key_pem
        })
        from src.common.logger_config import log_security
        log_security("AUTHENTICITY", "Client", f"Attempting login for user {self.username}")
    
    def do_register(self, username, password, confirm_password):
        """Handle registration submission"""
        valid, msg = validate_registration(username, password, confirm_password)
        if not valid:
            messagebox.showerror("Erro de Validação", msg)
            return
        
        self.username = username.strip()
        
        # Generate new RSA keys for registration
        self._load_or_generate_rsa_keys(self.username)
        
        pub_key_pem = self.public_key.export_key().decode('utf-8')
        self.outgoing_queue.put({
            'action': 'register',
            'username': self.username,
            'password': password,
            'public_key': pub_key_pem
        })
        from src.common.logger_config import log_security
        log_security("AUTHENTICITY", "Client", f"Attempting registration for user {self.username}")
    
    def create_private_chat(self):
        """Create private chat dialog with user selection"""
        
        all_usernames = list(self.all_users_data.keys())
        online_usernames = {u for u, d in self.all_users_data.items() if d['status'] == 'online'}
        
        if not all_usernames or (len(all_usernames) == 1 and self.username in all_usernames):
            messagebox.showinfo("Info", "Não há outros usuários disponíveis.")
            return

        # Show member selection dialog in single mode
        dialog = MemberSelectionDialog(self.root, all_usernames, self.username, online_usernames, mode='single')
        target = dialog.show()
        
        if target:
            # E2EE: Generate key and encrypt for both
            try:
                # Generate Serpent Key
                serpent_key = Serpent.generateIV() + Serpent.generateIV()
                
                encrypted_keys = {}
                
                # Encrypt for Self
                encrypted_keys[self.username] = CryptoUtils.encrypt_rsa(self.public_key, serpent_key).hex()
                
                # Encrypt for Target
                target_pub_pem = self.all_users_data.get(target, {}).get('public_key')
                if not target_pub_pem:
                    messagebox.showerror("Erro", f"Chave pública de {target} não encontrada.")
                    return
                
                target_pub_key = RSA.import_key(target_pub_pem)
                encrypted_keys[target] = CryptoUtils.encrypt_rsa(target_pub_key, serpent_key).hex()
                
                self.outgoing_queue.put({
                    'action': 'create_private_chat', 
                    'target_username': target,
                    'encrypted_keys': encrypted_keys
                })
                
                # Log Key Generation
                self.key_logger.log_event(
                    'KEY_GENERATION',
                    f'Generated key for private chat with {target}',
                    key_data={'key_hash': str(hash(serpent_key.hex()))[:16]},
                    context={'target': target}
                )
                
            except Exception as e:
                log.error(f"Error creating private chat: {e}")
                messagebox.showerror("Erro", "Falha ao criar chat seguro.")
    
    def create_group_chat(self):
        """Create group chat with checkbox-based member selection"""
        # Get all users
        all_usernames = list(self.all_users_data.keys())
        online_usernames = {u for u, d in self.all_users_data.items() if d['status'] == 'online'}
        
        if not all_usernames or (len(all_usernames) == 1 and self.username in all_usernames):
            messagebox.showinfo("Info", "Não há outros usuários disponíveis para criar um grupo.")
            return
        
        # Show member selection dialog
        dialog = MemberSelectionDialog(self.root, all_usernames, self.username, online_usernames, mode='multiple')
        
        result = dialog.show()
        
        if result:
            group_name, selected_members = result
            
            # E2EE: Generate key and encrypt for all members
            try:
                # Generate Serpent Key
                serpent_key = Serpent.generateIV() + Serpent.generateIV()
                
                encrypted_keys = {}
                
                # Encrypt for Self
                encrypted_keys[self.username] = CryptoUtils.encrypt_rsa(self.public_key, serpent_key).hex()
                
                # Encrypt for Members
                for member in selected_members:
                    member_pub_pem = self.all_users_data.get(member, {}).get('public_key')
                    if member_pub_pem:
                        member_pub_key = RSA.import_key(member_pub_pem)
                        encrypted_keys[member] = CryptoUtils.encrypt_rsa(member_pub_key, serpent_key).hex()
                    else:
                        log.warning(f"Public key for {member} not found. They won't be able to read messages.")
                
                self.outgoing_queue.put({
                    'action': 'create_group_chat',
                    'group_name': group_name,
                    'members': selected_members,
                    'encrypted_keys': encrypted_keys
                })
                
                # Log Key Generation
                self.key_logger.log_event(
                    'KEY_GENERATION',
                    f'Generated key for group chat {group_name}',
                    key_data={'key_hash': str(hash(serpent_key.hex()))[:16]},
                    context={'group_name': group_name, 'members': selected_members}
                )
                
            except Exception as e:
                log.error(f"Error creating group chat: {e}")
                messagebox.showerror("Erro", "Falha ao criar grupo seguro.")

    def invite_to_group(self):
        """Invite a user to the currently selected group"""
        if not self.active_room_id:
            messagebox.showwarning("Aviso", "Por favor, selecione um grupo primeiro.")
            return
        
        # Check if selected room is a group
        if self.active_room_id not in self.rooms:
            return
        
        room_type = self.rooms[self.active_room_id]['type']
        if room_type != 'group':
            messagebox.showwarning("Aviso", "Apenas grupos permitem convites. Selecione um grupo.")
            return
        
        # Check if we have the key for this room
        if self.active_room_id not in self.room_keys:
            messagebox.showerror("Erro", "Você não tem a chave deste grupo.")
            return
        
        # Get list of all users
        all_usernames = list(self.all_users_data.keys())
        online_usernames = {u for u, d in self.all_users_data.items() if d['status'] == 'online'}
        
        # Get current room members
        # We'll request this from server, but for now use a simple dialog
        # TODO: Could enhance to show only non-members
        
        if not all_usernames or (len(all_usernames) == 1 and self.username in all_usernames):
            messagebox.showinfo("Info", "Não há outros usuários disponíveis.")
            return
        
        # Show member selection dialog in single mode
        dialog = MemberSelectionDialog(self.root, all_usernames, self.username, online_usernames, mode='single')
        invitee = dialog.show()
        
        if invitee:
            try:
                # Get the room key
                room_key = self.room_keys[self.active_room_id]
                
                # Get invitee's public key
                invitee_pub_pem = self.all_users_data.get(invitee, {}).get('public_key')
                if not invitee_pub_pem:
                    messagebox.showerror("Erro", f"Chave pública de {invitee} não encontrada.")
                    return
                
                invitee_pub_key = RSA.import_key(invitee_pub_pem)
                
                # Encrypt room key for invitee
                encrypted_key = CryptoUtils.encrypt_rsa(invitee_pub_key, room_key).hex()
                
                self.outgoing_queue.put({
                    'action': 'invite_to_group',
                    'room_id': self.active_room_id,
                    'invitee_username': invitee,
                    'encrypted_key': encrypted_key
                })
                
                from src.common.logger_config import log_security
                log_security("CONFIDENTIALITY", "Client", f"Invited {invitee} to group {self.rooms[self.active_room_id]['name']}")
                
                messagebox.showinfo("Sucesso", f"{invitee} foi convidado para o grupo!")
                
            except Exception as e:
                log.error(f"Error inviting to group: {e}")
                messagebox.showerror("Erro", "Falha ao convidar usuário.")

    def join_room_dialog(self):
        """Request available groups from server"""
        self.outgoing_queue.put({'action': 'get_available_groups'})

    def handle_available_groups(self, groups):
        """Show dialog with available groups"""
        dialog = JoinGroupDialog(self.root, groups)
        r_id = dialog.show()
        
        if r_id:
            self.outgoing_queue.put({'action': 'join_room', 'room_id': r_id})

    def logout(self):
        """Handle logout"""
        if messagebox.askyesno("Sair", "Deseja realmente sair?"):
            # Send logout message to server
            try:
                self.outgoing_queue.put({'action': 'logout'})
            except:
                pass
            
            from src.common.logger_config import log_security
            log_security("AUTHENTICITY", "Client", f"User {self.username} logging out")

            # Clear state (but keep RSA keys for next login)
            self.username = None
            # Do NOT regenerate keys - they persist on disk
            self.private_key = None
            self.public_key = None
            
            self.rooms = {}
            self.room_keys = {}
            self.room_ciphers = {}
            self.active_room_id = None
            self.room_members = {}
            self.room_online_members = {}
            self.all_users_data = {}
            
            # Return to login screen
            self.root.title("SerpTalk")
            self.build_login_ui()

    def close_chat_view(self):
        """Close current chat view without leaving the room"""
        self.active_room_id = None
        if self.main_screen:
            self.main_screen.chat_header.config(text="Selecione um chat")
            self.main_screen.chat_history.config(state='normal')
            self.main_screen.chat_history.delete(1.0, tk.END)
            self.main_screen.chat_history.config(state='disabled')
            self.main_screen.rooms_listbox.selection_clear(0, tk.END)

    def leave_room(self, room_id):
        """Leave a room"""
        if messagebox.askyesno("Sair do Chat", "Tem certeza que deseja sair deste chat?"):
            self.outgoing_queue.put({'action': 'leave_room', 'room_id': room_id})

    def show_room_members(self, room_id):
        """Show members of a room"""
        if room_id not in self.rooms:
            return
            
        self.outgoing_queue.put({'action': 'get_room_members', 'room_id': room_id})
    
    def rotate_room_key(self, room_id):
        """Rotate the encryption key for a room"""
        if room_id not in self.rooms:
            return
        
        # Check if we have the current key
        if room_id not in self.room_keys:
            messagebox.showerror("Erro", "Você não tem a chave deste chat.")
            return
        
        # Confirm action
        room_name = self.rooms[room_id]['name']
        if not messagebox.askyesno("Rotacionar Chave", 
                                   f"Deseja rotacionar a chave de criptografia para '{room_name}'?\n\n"
                                   "Isso irá gerar uma nova chave e compartilhá-la com todos os membros."):
            return
        
        try:
            # Generate new Serpent key
            new_serpent_key = Serpent.generateIV() + Serpent.generateIV()
            
            # Get room members (we need to request this from server first)
            # For now, we'll use a simpler approach: get all users and encrypt for those we know
            # TODO: Could be improved by requesting member list first
            
            encrypted_keys = {}
            
            # Encrypt for self
            encrypted_keys[self.username] = CryptoUtils.encrypt_rsa(self.public_key, new_serpent_key).hex()
            
            # Encrypt for all known users (server will filter to actual members)
            for username, user_data in self.all_users_data.items():
                if username != self.username:
                    pub_key_pem = user_data.get('public_key')
                    if pub_key_pem:
                        try:
                            pub_key = RSA.import_key(pub_key_pem)
                            encrypted_keys[username] = CryptoUtils.encrypt_rsa(pub_key, new_serpent_key).hex()
                        except Exception as e:
                            log.warning(f"Failed to encrypt key for {username}: {e}")
            
            # Send to server
            self.outgoing_queue.put({
                'action': 'rotate_room_key',
                'room_id': room_id,
                'encrypted_keys': encrypted_keys
            })
            
            # Update local key immediately
            self.room_keys[room_id] = new_serpent_key
            self.room_ciphers[room_id] = SerpentCipher(new_serpent_key)
            
            from src.common.logger_config import log_security
            key_hash = str(hash(new_serpent_key.hex()))[:16]
            log_security("CONFIDENTIALITY", "Client", f"Rotated key for room {room_name}", new_key_hash=key_hash)
            
            self.key_logger.log_event(
                'ROOM_KEY_ROTATED',
                f'Rotated key for room: {room_name}',
                key_data={'key_hash': key_hash},
                context={'room_id': room_id, 'room_name': room_name, 'username': self.username}
            )
            
            messagebox.showinfo("Sucesso", "Chave rotacionada com sucesso!")
            
        except Exception as e:
            log.error(f"Error rotating room key: {e}")
            messagebox.showerror("Erro", "Falha ao rotacionar chave.")
    
    def show_key_history(self):
        """Show the Key History window"""
        KeyHistoryWindow(self.root, self.key_logger)
    
    def on_room_select(self, event):
        """Handle room selection"""
        if not self.main_screen:
            return
        
        selection = self.main_screen.rooms_listbox.curselection()
        if selection:
            index = selection[0]
            item_text = self.main_screen.rooms_listbox.get(index)
            r_id = int(item_text.split(':')[0])
            
            self.active_room_id = r_id
            self.main_screen.chat_header.config(text=f"Chat: {self.rooms[r_id]['name']}")
            self.refresh_chat_history()
            
            # Only request history if we haven't loaded it yet
            if not self.rooms[r_id]['history']:
                self.outgoing_queue.put({'action': 'get_room_history', 'room_id': r_id})
    
    def send_message(self):
        """Send message to active room"""
        if not self.main_screen:
            return
        
        text = self.main_screen.msg_entry.get().strip()
        
        if not self.active_room_id:
            messagebox.showwarning("Aviso", "Por favor, selecione um chat antes de enviar mensagens.")
            return
        
        if not text:
            messagebox.showwarning("Aviso", "A mensagem não pode estar vazia.")
            return
        
        # Check if we have the key
        if self.active_room_id not in self.room_ciphers:
            messagebox.showerror("Erro", "Você não tem a chave para este chat (ainda).")
            return

        # Check if there are other online members in the room
        if self.active_room_id in self.room_online_members:
            online_in_room = self.room_online_members[self.active_room_id]
            # Remove self from count
            other_online = online_in_room - {self.username}
            
            if len(other_online) == 0:
                messagebox.showwarning(
                    "Sem destinatários online",
                    "Não há outros usuários online neste chat no momento.\n\n"
                    "Sua mensagem não será recebida por ninguém agora."
                )
                return
        
        cipher = self.room_ciphers[self.active_room_id]
        key = self.room_keys[self.active_room_id]
        
        content_bytes = text.encode('utf-8')
        iv, ciphertext = cipher.encrypt(content_bytes)
        signature = CryptoUtils.sign_message(key, ciphertext)
        
        self.outgoing_queue.put({
            'action': 'send_message',
            'room_id': self.active_room_id,
            'content': ciphertext.hex(),
            'iv': iv.hex(),
            'signature': signature.hex()
        })
        self.main_screen.msg_entry.delete(0, tk.END)
    
    def check_queue(self):
        """Process incoming messages from queue"""
        try:
            for _ in range(10):
                msg = self.incoming_queue.get_nowait()
                self.process_message(msg)
        except queue.Empty:
            pass
        finally:
            self.root.after(200, self.check_queue)
    
    def process_message(self, message):
        """Delegate message processing to MessageHandler"""
        context = {
            'rooms': self.rooms,
            'room_keys': self.room_keys,
            'room_ciphers': self.room_ciphers,
            'private_key': self.private_key,
            'active_room_id': self.active_room_id,
            'on_login_success': self.build_main_ui,
            'on_registration_qr': self.show_qr_with_username,
            'on_room_added': self.handle_room_added,
            'on_user_list_updated': self.update_user_list,
            'on_new_message': self.handle_new_message,
            'on_room_history': self.handle_room_history,
            'on_left_room': self.handle_left_room,
            'on_room_members': self.handle_room_members,
            'on_available_groups': self.handle_available_groups,
            'on_key_rotated': self.handle_key_rotated,
            'on_key_rotation_requested': self.handle_key_rotation_requested
        }
        MessageHandler.process_message(message, context)

    def handle_room_added(self, r_id, name, r_type, is_new=False, notification_text=None):
        """Handle new room added"""
        # Log room key reception
        if r_id in self.room_keys:
            room_key = self.room_keys[r_id]
            self.key_logger.log_event(
                'ROOM_KEY_RECEIVED',
                f'Received and decrypted room key for chat: {name}',
                key_data={
                    'key_length': len(room_key),
                    'key_hash': str(hash(room_key.hex()))[:16]
                },
                context={
                    'room_id': r_id,
                    'room_name': name,
                    'room_type': r_type,
                    'username': self.username
                }
            )
        
        # Add or update room
        if r_id not in self.rooms:
            self.rooms[r_id] = {'name': name, 'type': r_type, 'history': []}
        
        self.update_rooms_list()
        
        # Request history immediately for newly joined/created rooms
        if is_new:
            self.outgoing_queue.put({'action': 'get_room_history', 'room_id': r_id})
        
        # Show notification only for truly new rooms
        if is_new and notification_text:
            messagebox.showinfo("Nova Sala", notification_text)
        elif is_new:
            messagebox.showinfo("Nova Sala", f"Você entrou em: {name}")

    def handle_room_history(self, r_id, history):
        """Handle received room history"""
        if r_id in self.rooms:
            # Replace history with server data
            # System messages broadcast after this will be appended via handle_new_message
            self.rooms[r_id]['history'] = history
            
            # If this is the active room, refresh the display
            if self.active_room_id == r_id and self.main_screen:
                self.main_screen.chat_history.config(state='normal')
                self.main_screen.chat_history.delete(1.0, tk.END)
                for msg in history:
                    self.main_screen.chat_history.insert(tk.END, msg + "\n")
                self.main_screen.chat_history.see(tk.END)
                self.main_screen.chat_history.config(state='disabled')

    def handle_left_room(self, room_id):
        """Handle confirmation of leaving a room"""
        if room_id in self.rooms:
            del self.rooms[room_id]
            if room_id in self.room_keys:
                del self.room_keys[room_id]
            if room_id in self.room_ciphers:
                del self.room_ciphers[room_id]
            
            if self.active_room_id == room_id:
                self.active_room_id = None
                if self.main_screen:
                    self.main_screen.chat_header.config(text="Selecione um chat")
                    self.main_screen.chat_history.config(state='normal')
                    self.main_screen.chat_history.delete(1.0, tk.END)
                    self.main_screen.chat_history.config(state='disabled')
            
            self.update_rooms_list()
            messagebox.showinfo("Sucesso", "Você saiu do chat.")

    def handle_room_members(self, room_id, members):
        """Handle receiving room members list"""
        if room_id not in self.rooms:
            return
            
        room_name = self.rooms[room_id]['name']
        member_usernames = members
        online_members = set()
        
        # Calculate online members based on global status
        for m in member_usernames:
            if self.all_users_data.get(m, {}).get('status') == 'online':
                online_members.add(m)
        
        dialog = RoomMembersDialog(self.root, room_name, member_usernames, online_members)
        dialog.show()
    
    def handle_key_rotated(self, room_id, reason):
        """Handle room key rotation"""
        if room_id in self.rooms:
            room_name = self.rooms[room_id]['name']
            room_key = self.room_keys[room_id]
            key_hash = str(hash(room_key.hex()))[:16]
            
            # Log the key rotation
            self.key_logger.log_event(
                'ROOM_KEY_ROTATED',
                f'Chave rotacionada para: {room_name}',
                key_data={
                    'key_length': len(room_key),
                    'key_hash': key_hash
                },
                context={
                    'room_id': room_id,
                    'room_name': room_name,
                    'reason': reason,
                    'username': self.username
                }
            )
            log_security("CONFIDENTIALITY", "Client", f"Key rotated for room {room_name}", reason=reason, new_key_hash=key_hash)
    
    def handle_key_rotation_requested(self, room_id, reason):
        """Handle automatic key rotation request from server"""
        if room_id not in self.rooms:
            return
        
        # Check if we have the current key
        if room_id not in self.room_keys:
            log.warning(f"Cannot rotate key for room {room_id}: No key available")
            return
        
        room_name = self.rooms[room_id]['name']
        old_key = self.room_keys[room_id]
        old_key_hash = str(hash(old_key.hex()))[:16]
        
        log.info(f"Auto-rotating key for room {room_id}. Reason: {reason}")
        log_security("CONFIDENTIALITY", "Client", f"========== KEY ROTATION INITIATED ==========")
        log_security("CONFIDENTIALITY", "Client", f"Room: '{room_name}' (ID: {room_id})")
        log_security("CONFIDENTIALITY", "Client", f"Reason: {reason}")
        log_security("CONFIDENTIALITY", "Client", f"OLD Key Hash: {old_key_hash}")
        
        try:
            # Generate new Serpent key
            new_serpent_key = Serpent.generateIV() + Serpent.generateIV()
            new_key_hash = str(hash(new_serpent_key.hex()))[:16]
            
            log_security("CONFIDENTIALITY", "Client", f"NEW Key Hash: {new_key_hash}")
            log_security("CONFIDENTIALITY", "Client", f"Generating new Serpent key (32 bytes)")
            
            encrypted_keys = {}
            
            # Encrypt for self
            encrypted_keys[self.username] = CryptoUtils.encrypt_rsa(self.public_key, new_serpent_key).hex()
            log_security("CONFIDENTIALITY", "Client", f"Encrypted new key for self ({self.username}) with RSA")
            
            # Encrypt for all known users (server will filter to actual members)
            member_count = 0
            for username, user_data in self.all_users_data.items():
                if username != self.username:
                    pub_key_pem = user_data.get('public_key')
                    if pub_key_pem:
                        try:
                            pub_key = RSA.import_key(pub_key_pem)
                            encrypted_keys[username] = CryptoUtils.encrypt_rsa(pub_key, new_serpent_key).hex()
                            member_count += 1
                            log_security("CONFIDENTIALITY", "Client", f"Encrypted new key for {username} with RSA")
                        except Exception as e:
                            log.warning(f"Failed to encrypt key for {username}: {e}")
            
            log_security("CONFIDENTIALITY", "Client", f"New key encrypted for {member_count + 1} members")
            
            # Send to server
            self.outgoing_queue.put({
                'action': 'rotate_room_key',
                'room_id': room_id,
                'encrypted_keys': encrypted_keys
            })
            
            # Update local key immediately
            self.room_keys[room_id] = new_serpent_key
            self.room_ciphers[room_id] = SerpentCipher(new_serpent_key)
            
            from src.common.logger_config import log_security
            log_security("CONFIDENTIALITY", "Client", f"Key rotation completed for '{room_name}'")
            log_security("CONFIDENTIALITY", "Client", f"========== KEY ROTATION COMPLETE ==========")
            
            self.key_logger.log_event(
                'ROOM_KEY_ROTATED',
                f'Auto-rotated key for room: {room_name}',
                key_data={'old_key_hash': old_key_hash, 'new_key_hash': new_key_hash},
                context={'room_id': room_id, 'room_name': room_name, 'reason': reason, 'username': self.username}
            )
            
        except Exception as e:
            log.error(f"Error auto-rotating room key: {e}")
    
    def show_qr_with_username(self, secret):
        """Show QR code after registration"""
        show_qr_code(self.root, self.username, secret, self.build_login_ui)
    
    def update_rooms_list(self):
        """Update rooms list in UI"""
        if not self.main_screen:
            return
        
        self.main_screen.rooms_listbox.delete(0, tk.END)
        
        if len(self.rooms) == 0:
            self.main_screen.rooms_listbox.pack_forget()
            self.main_screen.empty_rooms_label.pack(fill="both", expand=True)
        else:
            self.main_screen.empty_rooms_label.pack_forget()
            if not self.main_screen.rooms_listbox.winfo_ismapped():
                self.main_screen.rooms_listbox.pack(fill="both", expand=True)
            
            for r_id, r_data in self.rooms.items():
                self.main_screen.rooms_listbox.insert(tk.END, f"{r_id}: {r_data['name']} ({r_data['type']})")
    
    def update_user_list(self, users_data):
        """Update users list in UI with online status indicators"""
        # users_data is now a list of dicts: [{'username': 'u', 'status': 'online', 'public_key': 'PEM'}, ...]
        
        self.all_users_data = {} # {username: {'status': '...', 'public_key': '...'}}
        self.online_users = set()
        
        for u_data in users_data:
            if isinstance(u_data, dict):
                username = u_data['username']
                status = u_data['status']
                public_key = u_data.get('public_key')
            else:
                # Fallback for old format if any
                username = u_data
                status = 'online'
                public_key = None
                
            self.all_users_data[username] = {'status': status, 'public_key': public_key}
            if status == 'online':
                self.online_users.add(username)
        
        if self.main_screen and hasattr(self.main_screen, 'users_listbox'):
            self.main_screen.users_listbox.delete(0, tk.END)
            for i, username in enumerate(sorted(self.all_users_data.keys())):
                status = self.all_users_data[username]['status']
                # Use standard bullet point
                icon = "●"
                text = f"{icon} {username}"
                
                if status == 'offline':
                    text += " (offline)"
                    color = "#d32f2f" # Red
                else:
                    color = "#2e7d32" # Green
                
                self.main_screen.users_listbox.insert(tk.END, text)
                self.main_screen.users_listbox.itemconfig(i, {'fg': color})
    
    def handle_new_message(self, room_id, formatted_msg):
        """Handle new message"""
        if self.active_room_id == room_id and self.main_screen:
            self.append_chat(formatted_msg)
    
    def append_chat(self, text):
        """Append message to chat"""
        if not self.main_screen:
            return
        self.main_screen.chat_history.config(state='normal')
        self.main_screen.chat_history.insert(tk.END, text + "\n")
        self.main_screen.chat_history.see(tk.END)
        self.main_screen.chat_history.config(state='disabled')
    
    def refresh_chat_history(self):
        """Refresh entire chat history"""
        if not self.main_screen:
            return
        self.main_screen.chat_history.config(state='normal')
        self.main_screen.chat_history.delete(1.0, tk.END)
        if self.active_room_id in self.rooms:
            for msg in self.rooms[self.active_room_id]['history']:
                self.main_screen.chat_history.insert(tk.END, msg + "\n")
        self.main_screen.chat_history.see(tk.END)
        self.main_screen.chat_history.config(state='disabled')
