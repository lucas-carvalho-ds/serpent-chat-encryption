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
        self.root.title("Serpent Chat Seguro")
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
        
        self.build_login_ui()
        
        # Start polling queue
        self.root.after(100, self.check_queue)

    def build_login_ui(self):
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="20")
        frame.place(relx=0.5, rely=0.5, anchor="center")
        
        ttk.Label(frame, text="Serpent Chat Login", font=('Helvetica', 16, 'bold')).grid(row=0, column=0, columnspan=2, pady=20)
        
        ttk.Label(frame, text="Usuário:").grid(row=1, column=0, sticky="e")
        self.user_entry = ttk.Entry(frame)
        self.user_entry.grid(row=1, column=1, pady=5)
        
        ttk.Label(frame, text="Senha:").grid(row=2, column=0, sticky="e")
        self.pass_entry = ttk.Entry(frame, show="*")
        self.pass_entry.grid(row=2, column=1, pady=5)
        
        ttk.Label(frame, text="TOTP (Login):").grid(row=3, column=0, sticky="e")
        self.totp_entry = ttk.Entry(frame)
        self.totp_entry.grid(row=3, column=1, pady=5)
        
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=20)
        
        ttk.Button(btn_frame, text="Login", command=self.do_login).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Registrar", command=self.do_register).pack(side="left", padx=5)

    def build_main_ui(self):
        self.clear_window()
        
        # Main Layout: Sidebar (Rooms/Users) | Chat Area
        paned = ttk.PanedWindow(self.root, orient="horizontal")
        paned.pack(fill="both", expand=True)
        
        # Sidebar
        sidebar = ttk.Frame(paned, padding="5", width=250)
        paned.add(sidebar, weight=1)
        
        # Rooms List
        ttk.Label(sidebar, text="Suas Salas", style="Bold.TLabel").pack(anchor="w")
        self.rooms_listbox = tk.Listbox(sidebar, height=15)
        self.rooms_listbox.pack(fill="x", pady=5)
        self.rooms_listbox.bind('<<ListboxSelect>>', self.on_room_select)
        
        # Buttons
        btn_frame = ttk.Frame(sidebar)
        btn_frame.pack(fill="x", pady=5)
        ttk.Button(btn_frame, text="Novo Privado", command=self.create_private_chat).pack(fill="x", pady=2)
        ttk.Button(btn_frame, text="Novo Grupo", command=self.create_group_chat).pack(fill="x", pady=2)
        ttk.Button(btn_frame, text="Entrar (ID)", command=self.join_room_dialog).pack(fill="x", pady=2)
        
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

    # --- Actions ---

    def do_login(self):
        user = self.user_entry.get()
        pwd = self.pass_entry.get()
        totp = self.totp_entry.get()
        self.username = user
        pub_key_pem = self.public_key.export_key().decode('utf-8')
        self.outgoing_queue.put({
            'action': 'login',
            'username': user,
            'password': pwd,
            'totp_code': totp,
            'public_key': pub_key_pem
        })

    def do_register(self):
        user = self.user_entry.get()
        pwd = self.pass_entry.get()
        pub_key_pem = self.public_key.export_key().decode('utf-8')
        self.outgoing_queue.put({
            'action': 'register',
            'username': user,
            'password': pwd,
            'public_key': pub_key_pem
        })

    def create_private_chat(self):
        target = simpledialog.askstring("Novo Chat Privado", "Nome do usuário:")
        if target:
            self.outgoing_queue.put({'action': 'create_private_chat', 'target_username': target})

    def create_group_chat(self):
        name = simpledialog.askstring("Novo Grupo", "Nome do Grupo:")
        members = simpledialog.askstring("Membros", "Usuários (separados por vírgula):")
        if name and members:
            member_list = [m.strip() for m in members.split(',')]
            self.outgoing_queue.put({
                'action': 'create_group_chat',
                'group_name': name,
                'members': member_list
            })

    def join_room_dialog(self):
        r_id = simpledialog.askinteger("Entrar na Sala", "ID da Sala:")
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
        if not text or not self.active_room_id: return
        
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
        # Generate Provisioning URI
        uri = f"otpauth://totp/SerpentChat:{username}?secret={secret}&issuer=SerpentChat"
        
        # Generate QR Code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to ImageTk
        self.qr_image = ImageTk.PhotoImage(img)
        
        # Show Dialog
        top = tk.Toplevel(self.root)
        top.title("Configurar 2FA")
        top.geometry("400x500")
        
        # Keep reference to image to prevent Garbage Collection
        top.qr_image = self.qr_image
        
        ttk.Label(top, text="Escaneie este QR Code", font=('Helvetica', 14, 'bold')).pack(pady=10)
        
        lbl_img = ttk.Label(top, image=top.qr_image)
        lbl_img.pack(pady=10)
        
        ttk.Label(top, text=f"Segredo Manual: {secret}", font=('Courier', 10)).pack(pady=5)
        ttk.Label(top, text="Use seu app autenticador (Google Auth, Authy, etc)", font=('Helvetica', 9)).pack(pady=5)
        
        ttk.Button(top, text="OK", command=top.destroy).pack(pady=20)
        
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
