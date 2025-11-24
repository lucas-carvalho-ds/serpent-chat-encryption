import tkinter as tk
from tkinter import ttk, simpledialog, messagebox, scrolledtext
import asyncio
import threading
import queue
import json
import struct
import time
import qrcode
from PIL import Image, ImageTk
from crypto_utils import CryptoUtils, SerpentCipher
from logger_config import setup_logger

log = setup_logger(__name__)

HOST = '127.0.0.1'
PORT = 8888

class NetworkThread(threading.Thread):
    def __init__(self, incoming_queue, outgoing_queue):
        super().__init__()
        self.incoming_queue = incoming_queue
        self.outgoing_queue = outgoing_queue
        self.loop = None
        self.reader = None
        self.writer = None
        self.running = True
        self.connected = False

    def run(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.main_loop())

    async def main_loop(self):
        try:
            self.reader, self.writer = await asyncio.open_connection(HOST, PORT)
            self.connected = True
            self.incoming_queue.put({'action': 'status', 'status': 'connected', 'message': f'Conectado a {HOST}:{PORT}'})
            
            # Start receive task
            receive_task = asyncio.create_task(self.receive_loop())
            
            # Send loop
            while self.running:
                try:
                    # Non-blocking get from queue
                    msg = self.outgoing_queue.get_nowait()
                    await self.send_json(msg)
                except queue.Empty:
                    await asyncio.sleep(0.05)
                except Exception as e:
                    log.error(f"Erro no loop de envio: {e}")
                    
            receive_task.cancel()
            
        except Exception as e:
            self.incoming_queue.put({'action': 'status', 'status': 'error', 'message': str(e)})
        finally:
            if self.writer:
                self.writer.close()
                await self.writer.wait_closed()

    async def receive_loop(self):
        try:
            while self.running:
                header = await self.reader.read(4)
                if not header: break
                msg_len = struct.unpack('!I', header)[0]
                data = await self.reader.read(msg_len)
                if not data: break
                
                message = json.loads(data.decode('utf-8'))
                self.incoming_queue.put(message)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.incoming_queue.put({'action': 'status', 'status': 'error', 'message': f"Erro de recepção: {e}"})

    async def send_json(self, data):
        if not self.writer: return
        msg_bytes = json.dumps(data).encode('utf-8')
        header = struct.pack('!I', len(msg_bytes))
        self.writer.write(header + msg_bytes)
        await self.writer.drain()

    def stop(self):
        self.running = False

class ChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SerpTalk")
        self.root.geometry("900x600")
        
        self.incoming_queue = queue.Queue()
        self.outgoing_queue = queue.Queue()
        
        self.network = NetworkThread(self.incoming_queue, self.outgoing_queue)
        self.network.start()
        
        # Crypto State
        self.private_key, self.public_key = CryptoUtils.generate_rsa_keypair()
        self.room_keys = {}
        self.room_ciphers = {}
        self.rooms = {} # {id: {name, type, history}}
        self.active_room_id = None
        self.username = None
        
        # Styles
        self.style = ttk.Style()
        self.style.configure("Bold.TLabel", font=('Helvetica', 10, 'bold'))
        
        self.build_welcome_ui()
        
        # Start polling queue
        self.root.after(100, self.check_queue)

    def build_welcome_ui(self):
        """Tela inicial com escolha entre Login e Registro"""
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="40")
        frame.place(relx=0.5, rely=0.5, anchor="center")
        
        ttk.Label(frame, text="SerpTalk", font=('Helvetica', 20, 'bold')).pack(pady=10)
        ttk.Label(frame, text="Sistema de Chat Criptografado", font=('Helvetica', 12)).pack(pady=5)
        
        ttk.Separator(frame, orient='horizontal').pack(fill='x', pady=20)
        
        ttk.Button(frame, text="Fazer Login", command=self.build_login_ui, width=25).pack(pady=10)
        ttk.Button(frame, text="Criar Conta", command=self.build_register_ui, width=25).pack(pady=10)

    def build_login_ui(self):
        """Tela de login com campos de autenticação"""
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="30")
        frame.place(relx=0.5, rely=0.5, anchor="center")
        
        ttk.Label(frame, text="Fazer Login", font=('Helvetica', 16, 'bold')).grid(row=0, column=0, columnspan=2, pady=20)
        
        ttk.Label(frame, text="Usuário:").grid(row=1, column=0, sticky="e", padx=5)
        self.user_entry = ttk.Entry(frame, width=25)
        self.user_entry.grid(row=1, column=1, pady=8)
        self.user_entry.focus()  # Auto-focus
        
        ttk.Label(frame, text="Senha:").grid(row=2, column=0, sticky="e", padx=5)
        self.pass_entry = ttk.Entry(frame, show="*", width=25)
        self.pass_entry.grid(row=2, column=1, pady=8)
        
        ttk.Label(frame, text="Código 2FA:").grid(row=3, column=0, sticky="e", padx=5)
        self.totp_entry = ttk.Entry(frame, width=25)
        self.totp_entry.grid(row=3, column=1, pady=8)
        
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=20)
        
        ttk.Button(btn_frame, text="Entrar", command=self.do_login, width=12).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Voltar", command=self.build_welcome_ui, width=12).pack(side="left", padx=5)

    def build_register_ui(self):
        """Tela de registro para novos usuários"""
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="30")
        frame.place(relx=0.5, rely=0.5, anchor="center")
        
        ttk.Label(frame, text="Criar Nova Conta", font=('Helvetica', 16, 'bold')).grid(row=0, column=0, columnspan=2, pady=20)
        
        ttk.Label(frame, text="Usuário:").grid(row=1, column=0, sticky="e", padx=5)
        self.user_entry = ttk.Entry(frame, width=25)
        self.user_entry.grid(row=1, column=1, pady=8)
        self.user_entry.focus()  # Auto-focus
        
        ttk.Label(frame, text="Senha:").grid(row=2, column=0, sticky="e", padx=5)
        self.pass_entry = ttk.Entry(frame, show="*", width=25)
        self.pass_entry.grid(row=2, column=1, pady=8)
        
        ttk.Label(frame, text="Confirmar Senha:").grid(row=3, column=0, sticky="e", padx=5)
        self.pass_confirm_entry = ttk.Entry(frame, show="*", width=25)
        self.pass_confirm_entry.grid(row=3, column=1, pady=8)
        
        ttk.Label(frame, text="(Você irá configurar 2FA na próxima etapa)", font=('Helvetica', 9, 'italic')).grid(row=4, column=0, columnspan=2, pady=5)
        
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=5, column=0, columnspan=2, pady=20)
        
        ttk.Button(btn_frame, text="Prosseguir", command=self.do_register, width=12).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Voltar", command=self.build_welcome_ui, width=12).pack(side="left", padx=5)

    def build_main_ui(self):
        self.clear_window()
        
        # Update window title with username
        self.root.title(f"SerpTalk - {self.username}")
        
        # Main Layout: Sidebar (Rooms/Users) | Chat Area
        paned = ttk.PanedWindow(self.root, orient="horizontal")
        paned.pack(fill="both", expand=True)
        
        # Sidebar
        sidebar = ttk.Frame(paned, padding="5", width=250)
        paned.add(sidebar, weight=1)
        
        # User info header
        user_header = ttk.Frame(sidebar)
        user_header.pack(fill="x", pady=(0, 10))
        ttk.Label(user_header, text="Logado como:", font=('Helvetica', 9)).pack(anchor="w")
        ttk.Label(user_header, text=f"👤 {self.username}", font=('Helvetica', 11, 'bold'), foreground='#2e7d32').pack(anchor="w")
        ttk.Separator(user_header, orient='horizontal').pack(fill='x', pady=5)
        
        # Rooms List
        ttk.Label(sidebar, text="Seus Chats", style="Bold.TLabel").pack(anchor="w")
        
        # Container for rooms list and empty state
        rooms_container = ttk.Frame(sidebar, height=200)
        rooms_container.pack(fill="x", pady=5)
        rooms_container.pack_propagate(False)  # Maintain fixed height
        
        self.rooms_listbox = tk.Listbox(rooms_container, height=15)
        self.rooms_listbox.pack(fill="both", expand=True)
        self.rooms_listbox.bind('<<ListboxSelect>>', self.on_room_select)
        
        # Empty state label for when no rooms exist
        self.empty_rooms_label = ttk.Label(rooms_container,
                                           text="Você ainda não entrou\nem nenhuma sala.\n\nCrie ou entre em uma conversa\nusando os botões abaixo! 👇",
                                           font=('Helvetica', 9, 'italic'),
                                           foreground='gray',
                                           justify='center',
                                           anchor='center',
                                           background='white',
                                           relief='sunken',
                                           padding=20)
        
        # Buttons
        btn_frame = ttk.Frame(sidebar)
        btn_frame.pack(fill="x", pady=5)
        ttk.Button(btn_frame, text="Novo Chat Individual", command=self.create_private_chat).pack(fill="x", pady=2)
        ttk.Button(btn_frame, text="Novo Chat em Grupo", command=self.create_group_chat).pack(fill="x", pady=2)
        ttk.Button(btn_frame, text="Entrar em Chat em Grupo", command=self.join_room_dialog).pack(fill="x", pady=2)
        
        # Users List
        ttk.Label(sidebar, text="Usuários Online", style="Bold.TLabel").pack(anchor="w", pady=(10,0))
        self.users_listbox = tk.Listbox(sidebar, height=10)
        self.users_listbox.pack(fill="both", expand=True, pady=5)
        
        # Chat Area
        chat_frame = ttk.Frame(paned, padding="5")
        paned.add(chat_frame, weight=4)
        
        self.chat_header = ttk.Label(chat_frame, text="Selecione uma sala", font=('Helvetica', 12, 'bold'))
        self.chat_header.pack(anchor="w", pady=5)
        
        self.chat_history = scrolledtext.ScrolledText(chat_frame, state='disabled', wrap='word')
        self.chat_history.pack(fill="both", expand=True, pady=5)
        
        input_frame = ttk.Frame(chat_frame)
        input_frame.pack(fill="x", pady=5)
        
        self.msg_entry = ttk.Entry(input_frame)
        self.msg_entry.pack(side="left", fill="x", expand=True, padx=(0,5))
        self.msg_entry.bind("<Return>", lambda e: self.send_message())
        
        ttk.Button(input_frame, text="Enviar", command=self.send_message).pack(side="right")
        
        # Initialize rooms list display (will show empty state if no rooms)
        self.update_rooms_list()

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def check_queue(self):
        try:
            # Process up to 10 messages at a time to avoid freezing the GUI
            for _ in range(10):
                msg = self.incoming_queue.get_nowait()
                self.process_message(msg)
        except queue.Empty:
            pass
        finally:
            # Schedule next check in 200ms
            self.root.after(200, self.check_queue)

    def process_message(self, message):
        action = message.get('action')
        
        if 'status' in message and action != 'status':
            # Generic status handling
            status = message.get('status')
            text = message.get('message')
            if status == 'error':
                messagebox.showerror("Erro", text)
            elif status == 'success':
                # If login success, switch UI
                if message.get('message') == 'Login realizado.':
                    self.build_main_ui()
                elif 'totp_secret' in message:
                    self.show_qr_code(self.user_entry.get(), message['totp_secret'])
        
        if action == 'status':
            # Connection status
            print(f"Status: {message.get('message')}")
            
        elif action == 'room_added':
            r_id = message.get('room_id')
            r_name = message.get('name')
            r_type = message.get('type')
            enc_key = bytes.fromhex(message.get('key'))
            
            try:
                key = CryptoUtils.decrypt_rsa(self.private_key, enc_key)
                self.room_keys[r_id] = key
                self.room_ciphers[r_id] = SerpentCipher(key)
                
                if r_id not in self.rooms:
                    self.rooms[r_id] = {'name': r_name, 'type': r_type, 'history': []}
                    self.update_rooms_list()
            except Exception as e:
                log.error(f"Erro ao descriptografar chave da sala {r_name}: {e}")

        elif action == 'user_list':
            users = message.get('users')
            if hasattr(self, 'users_listbox'):
                self.users_listbox.delete(0, tk.END)
                for u in users:
                    self.users_listbox.insert(tk.END, u)

        elif action == 'new_message':
            r_id = message.get('room_id')
            sender = message.get('sender')
            content_hex = message.get('content')
            iv_hex = message.get('iv')
            signature_hex = message.get('signature')
            
            if r_id in self.room_ciphers:
                try:
                    cipher = self.room_ciphers[r_id]
                    key = self.room_keys[r_id]
                    
                    content_bytes = bytes.fromhex(content_hex)
                    iv_bytes = bytes.fromhex(iv_hex)
                    sig_bytes = bytes.fromhex(signature_hex)
                    
                    if CryptoUtils.verify_signature(key, content_bytes, sig_bytes):
                        decrypted = cipher.decrypt(iv_bytes, content_bytes).decode('utf-8')
                        formatted_msg = f"[{sender}]: {decrypted}"
                        
                        self.rooms[r_id]['history'].append(formatted_msg)
                        
                        if self.active_room_id == r_id:
                            self.append_chat(formatted_msg)
                        else:
                            # Mark as unread logic could go here
                            pass
                except Exception as e:
                    log.error(f"Erro ao ler mensagem: {e}")

        elif action == 'room_history':
            r_id = message.get('room_id')
            data = message.get('data')
            if r_id in self.rooms and r_id in self.room_ciphers:
                cipher = self.room_ciphers[r_id]
                key = self.room_keys[r_id]
                history_text = []
                for m in data:
                    try:
                        content = bytes.fromhex(m['content'])
                        iv = bytes.fromhex(m['iv'])
                        sig = bytes.fromhex(m['signature'])
                        if CryptoUtils.verify_signature(key, content, sig):
                            dec = cipher.decrypt(iv, content).decode('utf-8')
                            history_text.append(f"[{m['sender']}]: {dec}")
                    except:
                        pass
                self.rooms[r_id]['history'] = history_text
                if self.active_room_id == r_id:
                    self.refresh_chat_history()

    # --- Validation Methods ---
    
    def validate_username(self, username):
        """Valida formato de username"""
        username = username.strip()
        if not username:
            return False, "O nome de usuário não pode estar vazio."
        if len(username) < 3:
            return False, "O nome de usuário deve ter pelo menos 3 caracteres."
        if len(username) > 20:
            return False, "O nome de usuário não pode ter mais de 20 caracteres."
        if not username.replace('_', '').isalnum():
            return False, "O nome de usuário pode conter apenas letras, números e underscore (_)."
        return True, ""
    
    def validate_password(self, password):
        """Valida força de senha"""
        if not password:
            return False, "A senha não pode estar vazia."
        if len(password) < 6:
            return False, "A senha deve ter pelo menos 6 caracteres."
        return True, ""
    
    def validate_registration(self, username, password, confirm_password):
        """Valida dados de registro"""
        # Validar username
        valid, msg = self.validate_username(username)
        if not valid:
            return False, msg
        
        # Validar senha
        valid, msg = self.validate_password(password)
        if not valid:
            return False, msg
        
        # Validar confirmação de senha
        if password != confirm_password:
            return False, "As senhas não coincidem."
        
        return True, ""
    
    def validate_login(self, username, password, totp_code):
        """Valida dados de login"""
        username = username.strip()
        if not username:
            return False, "O nome de usuário não pode estar vazio."
        if not password:
            return False, "A senha não pode estar vazia."
        if not totp_code:
            return False, "O código 2FA não pode estar vazio."
        if not totp_code.isdigit() or len(totp_code) != 6:
            return False, "O código 2FA deve conter exatamente 6 dígitos."
        return True, ""

    # --- Actions ---

    def do_login(self):
        user = self.user_entry.get()
        pwd = self.pass_entry.get()
        totp = self.totp_entry.get()
        
        # Validate inputs
        valid, msg = self.validate_login(user, pwd, totp)
        if not valid:
            messagebox.showerror("Erro de Validação", msg)
            return
        
        self.username = user.strip()
        pub_key_pem = self.public_key.export_key().decode('utf-8')
        self.outgoing_queue.put({
            'action': 'login',
            'username': self.username,
            'password': pwd,
            'totp_code': totp,
            'public_key': pub_key_pem
        })

    def do_register(self):
        user = self.user_entry.get()
        pwd = self.pass_entry.get()
        confirm_pwd = self.pass_confirm_entry.get()
        
        # Validate inputs
        valid, msg = self.validate_registration(user, pwd, confirm_pwd)
        if not valid:
            messagebox.showerror("Erro de Validação", msg)
            return
        
        pub_key_pem = self.public_key.export_key().decode('utf-8')
        self.outgoing_queue.put({
            'action': 'register',
            'username': user.strip(),
            'password': pwd,
            'public_key': pub_key_pem
        })

    def create_private_chat(self):
        target = simpledialog.askstring("Novo Chat Individual", "Nome do usuário:")
        if not target:
            return
        
        target = target.strip()
        if not target:
            messagebox.showerror("Erro", "O nome do usuário não pode estar vazio.")
            return
        
        if target.lower() == self.username.lower():
            messagebox.showerror("Erro", "Você não pode criar um chat com você mesmo.")
            return
        
        # Validate username format
        valid, msg = self.validate_username(target)
        if not valid:
            messagebox.showerror("Erro de Validação", msg)
            return
        
        self.outgoing_queue.put({'action': 'create_private_chat', 'target_username': target})

    def create_group_chat(self):
        name = simpledialog.askstring("Novo Chat em Grupo", "Nome do Grupo:")
        if not name:
            return
        
        name = name.strip()
        if not name:
            messagebox.showerror("Erro", "O nome do grupo não pode estar vazio.")
            return
        
        if len(name) < 3:
            messagebox.showerror("Erro", "O nome do grupo deve ter pelo menos 3 caracteres.")
            return
        
        if len(name) > 50:
            messagebox.showerror("Erro", "O nome do grupo não pode ter mais de 50 caracteres.")
            return
        
        members = simpledialog.askstring("Membros", "Usuários (separados por vírgula):")
        if not members:
            return
        
        members = members.strip()
        if not members:
            messagebox.showerror("Erro", "Você deve adicionar pelo menos um membro.")
            return
        
        member_list = [m.strip() for m in members.split(',') if m.strip()]
        if not member_list:
            messagebox.showerror("Erro", "Você deve adicionar pelo menos um membro válido.")
            return
        
        # Validate each member username
        for member in member_list:
            valid, msg = self.validate_username(member)
            if not valid:
                messagebox.showerror("Erro de Validação", f"Membro '{member}': {msg}")
                return
        
        self.outgoing_queue.put({
            'action': 'create_group_chat',
            'group_name': name,
            'members': member_list
        })

    def join_room_dialog(self):
        r_id = simpledialog.askinteger("Entrar em Sala em Grupo", "ID da Sala:")
        if r_id:
            # Logic to join? Currently server auto-joins if invited.
            # This might be for public rooms in future.
            pass

    def on_room_select(self, event):
        selection = self.rooms_listbox.curselection()
        if selection:
            index = selection[0]
            # Map index to room_id (simple way: keep ordered list or parse string)
            # String format: "ID: Name (Type)"
            item_text = self.rooms_listbox.get(index)
            r_id = int(item_text.split(':')[0])
            
            self.active_room_id = r_id
            self.chat_header.config(text=f"Chat: {self.rooms[r_id]['name']}")
            self.refresh_chat_history()
            
            # Request history update
            self.outgoing_queue.put({'action': 'get_room_history', 'room_id': r_id})

    def send_message(self):
        text = self.msg_entry.get().strip()
        
        # Validate that there's an active room
        if not self.active_room_id:
            messagebox.showwarning("Aviso", "Por favor, selecione uma sala antes de enviar mensagens.")
            return
        
        # Validate message not empty
        if not text:
            messagebox.showwarning("Aviso", "A mensagem não pode estar vazia.")
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
        self.msg_entry.delete(0, tk.END)

    # --- UI Helpers ---

    def update_rooms_list(self):
        self.rooms_listbox.delete(0, tk.END)
        
        # Show/hide empty state based on rooms count
        if len(self.rooms) == 0 and hasattr(self, 'empty_rooms_label'):
            self.rooms_listbox.pack_forget()
            self.empty_rooms_label.pack(fill="both", expand=True)
        else:
            if hasattr(self, 'empty_rooms_label'):
                self.empty_rooms_label.pack_forget()
            if not self.rooms_listbox.winfo_ismapped():
                self.rooms_listbox.pack(fill="both", expand=True)
            
            for r_id, r_data in self.rooms.items():
                self.rooms_listbox.insert(tk.END, f"{r_id}: {r_data['name']} ({r_data['type']})")

    def append_chat(self, text):
        self.chat_history.config(state='normal')
        self.chat_history.insert(tk.END, text + "\n")
        self.chat_history.see(tk.END)
        self.chat_history.config(state='disabled')

    def refresh_chat_history(self):
        self.chat_history.config(state='normal')
        self.chat_history.delete(1.0, tk.END)
        if self.active_room_id in self.rooms:
            for msg in self.rooms[self.active_room_id]['history']:
                self.chat_history.insert(tk.END, msg + "\n")
        self.chat_history.see(tk.END)
        self.chat_history.config(state='disabled')

    def show_qr_code(self, username, secret):
        """Mostra QR Code em janela maximizada após registro"""
        # Generate Provisioning URI
        uri = f"otpauth://totp/SerpentChat:{username}?secret={secret}&issuer=SerpentChat"
        
        # Generate QR Code (optimized size to fit in window)
        qr = qrcode.QRCode(version=1, box_size=8, border=4)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to ImageTk
        self.qr_image = ImageTk.PhotoImage(img)
        
        # Create fullscreen window
        top = tk.Toplevel(self.root)
        top.title("Configurar Autenticação de Dois Fatores")
        
        # Maximize window
        top.state('zoomed')  # Windows
        # top.attributes('-zoomed', True)  # Linux alternative
        
        # Keep reference to image to prevent Garbage Collection
        top.qr_image = self.qr_image
        
        # Create canvas with scrollbar
        canvas = tk.Canvas(top)
        scrollbar = ttk.Scrollbar(top, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas, padding="20")
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        # Create window centered
        canvas_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="n")
        
        # Center the content horizontally
        def center_window(event):
            canvas_width = event.width
            canvas.itemconfig(canvas_window, width=canvas_width)
        
        canvas.bind('<Configure>', center_window)
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Enable mouse wheel scrolling
        def on_mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        canvas.bind_all("<MouseWheel>", on_mousewheel)
        
        # Unbind when window closes
        def on_close():
            canvas.unbind_all("<MouseWheel>")
            top.destroy()
        
        top.protocol("WM_DELETE_WINDOW", on_close)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Content
        ttk.Label(scrollable_frame, text="Configurar Autenticação de Dois Fatores", font=('Helvetica', 18, 'bold')).pack(pady=10)
        ttk.Label(scrollable_frame, text="Escaneie este código com seu aplicativo autenticador:", font=('Helvetica', 12)).pack(pady=5)
        ttk.Label(scrollable_frame, text="(Google Authenticator, Authy, Microsoft Authenticator, etc.)", font=('Helvetica', 10, 'italic')).pack(pady=3)
        
        # QR Code image
        lbl_img = ttk.Label(scrollable_frame, image=top.qr_image)
        lbl_img.pack(pady=10)
        
        # Secret text
        ttk.Label(scrollable_frame, text="Código Manual (se preferir configurar manualmente):", font=('Helvetica', 10)).pack(pady=5)
        secret_frame = ttk.Frame(scrollable_frame)
        secret_frame.pack(pady=3)
        secret_entry = ttk.Entry(secret_frame, font=('Courier', 12, 'bold'), width=len(secret)+4, justify='center')
        secret_entry.insert(0, secret)
        secret_entry.config(state='readonly')
        secret_entry.pack()
        
        # Instructions
        ttk.Separator(scrollable_frame, orient='horizontal').pack(fill='x', pady=10)
        ttk.Label(scrollable_frame, text="⚠️ Guarde este código em local seguro!", font=('Helvetica', 11, 'bold'), foreground='red').pack(pady=3)
        ttk.Label(scrollable_frame, text="Você precisará do aplicativo autenticador para fazer login.", font=('Helvetica', 10)).pack(pady=3)
        
        # Finish button that redirects to login
        def finish_registration():
            top.destroy()
            self.build_login_ui()
        
        ttk.Button(scrollable_frame, text="Concluir", command=finish_registration, width=20).pack(pady=15)
        
        # Force update to ensure rendering
        top.update()

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatGUI(root)
    
    def on_closing():
        app.network.stop()
        root.destroy()
        
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()
