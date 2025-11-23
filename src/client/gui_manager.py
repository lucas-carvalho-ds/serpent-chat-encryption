"""
GUI Manager Module
Main coordinator for the SerpTalk client using modular architecture.
"""

import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
import queue
from Crypto.PublicKey import RSA

from src.client.networking import NetworkThread
from src.client.validation import validate_login, validate_registration, validate_username
from src.client.message_handler import MessageHandler
from src.client.ui.auth_screens import AuthScreens
from src.client.ui.main_screen import MainScreen
from src.client.ui.dialogs import MemberSelectionDialog, RoomMembersDialog
from src.client.ui.qr_dialog import show_qr_code
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
        
        # State
        self.username = None
        self.private_key, self.public_key = CryptoUtils.generate_rsa_keypair()
        self.rooms = {}
        self.room_keys = {}
        self.room_ciphers = {}
        self.online_users = set()  # All users currently online
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
            on_join_group_callback=self.join_room_dialog,
            on_leave_room_callback=self.leave_room,
            on_view_members_callback=self.show_room_members,
            on_logout_callback=self.logout
        )
        self.update_rooms_list()
    
    def do_login(self, username, password, totp_code):
        """Handle login submission"""
        valid, msg = validate_login(username, password, totp_code)
        if not valid:
            messagebox.showerror("Erro de Validação", msg)
            return
        
        self.username = username.strip()
        pub_key_pem = self.public_key.export_key().decode('utf-8')
        self.outgoing_queue.put({
            'action': 'login',
            'username': self.username,
            'password': password,
            'totp_code': totp_code,
            'public_key': pub_key_pem
        })
    
    def do_register(self, username, password, confirm_password):
        """Handle registration submission"""
        valid, msg = validate_registration(username, password, confirm_password)
        if not valid:
            messagebox.showerror("Erro de Validação", msg)
            return
        
        self.username = username.strip()
        pub_key_pem = self.public_key.export_key().decode('utf-8')
        self.outgoing_queue.put({
            'action': 'register',
            'username': self.username,
            'password': password,
            'public_key': pub_key_pem
        })
    
    def create_private_chat(self):
        """Create private chat dialog with user selection"""
        # Get all users (online and offline)
        # The server now sends all users in user_list, so self.online_users contains all users?
        # No, self.online_users was a set of strings. Now update_user_list receives dicts.
        # We need to store all users and their status.
        
        # Let's check update_user_list implementation below first.
        # Assuming self.all_users_status is available (we will add it)
        
        if not hasattr(self, 'all_users_status'):
             self.all_users_status = {}
             
        all_usernames = list(self.all_users_status.keys())
        online_usernames = {u for u, s in self.all_users_status.items() if s == 'online'}
        
        if not all_usernames or (len(all_usernames) == 1 and self.username in all_usernames):
            messagebox.showinfo("Info", "Não há outros usuários disponíveis.")
            return

        # Show member selection dialog in single mode
        dialog = MemberSelectionDialog(self.root, all_usernames, self.username, online_usernames, mode='single')
        target = dialog.show()
        
        if target:
            self.outgoing_queue.put({'action': 'create_private_chat', 'target_username': target})
    
    def create_group_chat(self):
        """Create group chat with checkbox-based member selection"""
        # Get all users
        if not hasattr(self, 'all_users_status'):
             self.all_users_status = {}
             
        all_usernames = list(self.all_users_status.keys())
        online_usernames = {u for u, s in self.all_users_status.items() if s == 'online'}
        
        if not all_usernames or (len(all_usernames) == 1 and self.username in all_usernames):
            messagebox.showinfo("Info", "Não há outros usuários disponíveis para criar um grupo.")
            return
        
        # Show member selection dialog
        dialog = MemberSelectionDialog(self.root, all_usernames, self.username, online_usernames, mode='multiple')
        

        result = dialog.show()
        
        if result:
            group_name, selected_members = result
            self.outgoing_queue.put({
                'action': 'create_group_chat',
                'group_name': group_name,
                'members': selected_members
            })
    
    def join_room_dialog(self):
        """Join room dialog"""
        r_id = simpledialog.askinteger("Entrar em Chat em Grupo", "ID do Chat:")
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

            # Clear state
            self.username = None
            self.private_key, self.public_key = CryptoUtils.generate_rsa_keypair()
            self.rooms = {}
            self.room_keys = {}
            self.room_ciphers = {}
            self.active_room_id = None
            self.room_members = {}
            self.room_online_members = {}
            
            # Return to login screen
            self.build_login_ui()

    def leave_room(self, room_id):
        """Leave a room"""
        if messagebox.askyesno("Sair do Chat", "Tem certeza que deseja sair deste chat?"):
            self.outgoing_queue.put({'action': 'leave_room', 'room_id': room_id})

    def show_room_members(self, room_id):
        """Show members of a room"""
        if room_id not in self.rooms:
            return
            
        self.outgoing_queue.put({'action': 'get_room_members', 'room_id': room_id})
    
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
            
            # Request history update
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
            'on_room_added': lambda r_id, name, r_type: self.update_rooms_list(),
            'on_user_list_updated': self.update_user_list,
            'on_new_message': self.handle_new_message,
            'on_new_message': self.handle_new_message,
            'on_room_history': self.handle_room_history,
            'on_left_room': self.handle_left_room,
            'on_room_members': self.handle_room_members
        }
        MessageHandler.process_message(message, context)

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
        if hasattr(self, 'all_users_status'):
            for m in member_usernames:
                if self.all_users_status.get(m) == 'online':
                    online_members.add(m)
        
        dialog = RoomMembersDialog(self.root, room_name, member_usernames, online_members)
        dialog.show()
    
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
        # users_data is now a list of dicts: [{'username': 'u', 'status': 'online'}, ...]
        
        self.all_users_status = {} # {username: status}
        self.online_users = set()
        
        for u_data in users_data:
            if isinstance(u_data, dict):
                username = u_data['username']
                status = u_data['status']
            else:
                # Fallback for old format if any
                username = u_data
                status = 'online'
                
            self.all_users_status[username] = status
            if status == 'online':
                self.online_users.add(username)
        
        if self.main_screen and hasattr(self.main_screen, 'users_listbox'):
            self.main_screen.users_listbox.delete(0, tk.END)
            for i, username in enumerate(sorted(self.all_users_status.keys())):
                status = self.all_users_status[username]
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
    
    def handle_room_history(self, room_id, history):
        """Handle room history"""
        if self.active_room_id == room_id:
            self.refresh_chat_history()
    
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
