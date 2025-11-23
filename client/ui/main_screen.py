"""
Main Screen Module
Contains the main chat UI with rooms list, users list, and chat area.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext


class MainScreen:
    """Manages the main chat interface"""
    
    def __init__(self, root, username):
        self.root = root
        self.username = username
        self.rooms_listbox = None
        self.users_listbox = None
        self.chat_header = None
        self.chat_history = None
        self.msg_entry = None
        self.empty_rooms_label = None
        
    def build_ui(self, on_room_select_callback, on_send_callback, 
                 on_create_private_callback, on_create_group_callback, on_join_group_callback,
                 on_leave_room_callback, on_view_members_callback):
        """Builds the main chat UI"""
        self.on_leave_room = on_leave_room_callback
        self.on_view_members = on_view_members_callback
        # Clear window
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Update window title with username
        self.root.title(f"Serpent Chat - {self.username}")
        
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
        ttk.Label(sidebar, text="Suas Salas", style="Bold.TLabel").pack(anchor="w")
        
        # Container for rooms list and empty state
        rooms_container = ttk.Frame(sidebar, height=200)
        rooms_container.pack(fill="x", pady=5)
        rooms_container.pack_propagate(False)  # Maintain fixed height
        
        self.rooms_listbox = tk.Listbox(rooms_container, height=15)
        self.rooms_listbox.pack(fill="both", expand=True)
        self.rooms_listbox.pack(fill="both", expand=True)
        self.rooms_listbox.bind('<<ListboxSelect>>', on_room_select_callback)
        self.rooms_listbox.bind('<Button-3>', self.show_room_context_menu)
        
        # Context Menu
        self.room_context_menu = tk.Menu(self.root, tearoff=0)
        self.room_context_menu.add_command(label="Ver Participantes", command=self.view_room_members)
        self.room_context_menu.add_separator()
        self.room_context_menu.add_command(label="Sair da Sala", command=self.leave_room)
        
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
        ttk.Button(btn_frame, text="Nova Sala Individual", command=on_create_private_callback).pack(fill="x", pady=2)
        ttk.Button(btn_frame, text="Nova Sala em Grupo", command=on_create_group_callback).pack(fill="x", pady=2)
        ttk.Button(btn_frame, text="Entrar em Sala em Grupo", command=on_join_group_callback).pack(fill="x", pady=2)
        
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
        self.msg_entry.bind("<Return>", lambda e: on_send_callback())
        
        ttk.Button(input_frame, text="Enviar", command=on_send_callback).pack(side="right")

    def show_room_context_menu(self, event):
        """Show context menu for rooms"""
        try:
            index = self.rooms_listbox.nearest(event.y)
            self.rooms_listbox.selection_clear(0, tk.END)
            self.rooms_listbox.selection_set(index)
            self.rooms_listbox.activate(index)
            
            # Trigger selection event manually to update active room
            self.rooms_listbox.event_generate("<<ListboxSelect>>")
            
            self.room_context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.room_context_menu.grab_release()

    def leave_room(self):
        """Callback for leaving room"""
        selection = self.rooms_listbox.curselection()
        if selection:
            index = selection[0]
            item_text = self.rooms_listbox.get(index)
            r_id = int(item_text.split(':')[0])
            if self.on_leave_room:
                self.on_leave_room(r_id)

    def view_room_members(self):
        """Callback for viewing members"""
        selection = self.rooms_listbox.curselection()
        if selection:
            index = selection[0]
            item_text = self.rooms_listbox.get(index)
            r_id = int(item_text.split(':')[0])
            if self.on_view_members:
                self.on_view_members(r_id)
