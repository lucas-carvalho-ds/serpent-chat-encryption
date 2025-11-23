"""
Custom Dialogs Module
Provides custom dialog windows for enhanced user experience.
"""

import tkinter as tk
from tkinter import ttk, messagebox


class MemberSelectionDialog:
    """Dialog for selecting group members with checkboxes"""
    
    def __init__(self, parent, all_users, current_username, online_users, mode='multiple'):
        """
        Args:
            parent: Parent window
            all_users: List of all available usernames
            current_username: Username of current user (excluded from list)
            online_users: Set of currently online usernames
            mode: 'multiple' for group creation, 'single' for private chat
        """
        self.result = None
        self.selected_members = []
        self.mode = mode
        
        # Create dialog
        title = "Criar Grupo" if mode == 'multiple' else "Nova Conversa"
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("400x500")
        self.dialog.attributes('-topmost', True)  # Always on top
        self.dialog.transient(parent)  # Associated with parent
        self.dialog.grab_set()  # Modal
        
        # Center on screen
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (400 // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (500 // 2)
        self.dialog.geometry(f"400x500+{x}+{y}")
        
        # Group name (only for multiple mode)
        if self.mode == 'multiple':
            name_frame = ttk.Frame(self.dialog, padding="10")
            name_frame.pack(fill="x")
            
            ttk.Label(name_frame, text="Nome do Grupo:").pack(anchor="w")
            self.name_entry = ttk.Entry(name_frame, font=('Helvetica', 11))
            self.name_entry.pack(fill="x", pady=5)
            self.name_entry.focus()
            
            ttk.Separator(self.dialog, orient='horizontal').pack(fill='x', pady=5)
        else:
            self.name_entry = None
        
        # Members selection
        members_label_frame = ttk.Frame(self.dialog, padding="10")
        members_label_frame.pack(fill="x")
        
        lbl_text = "Selecione os membros:" if self.mode == 'multiple' else "Selecione o usuário:"
        ttk.Label(members_label_frame, text=lbl_text, 
                 font=('Helvetica', 10, 'bold')).pack(anchor="w")
                 
        if self.mode == 'multiple':
            ttk.Label(members_label_frame, text="(Você será adicionado automaticamente)", 
                     font=('Helvetica', 9, 'italic'), foreground='gray').pack(anchor="w")
        
        # Scrollable frame for checkboxes
        canvas_frame = ttk.Frame(self.dialog)
        canvas_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        canvas = tk.Canvas(canvas_frame, highlightthickness=0)
        scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Create checkboxes for each user (except current user)
        self.checkbox_vars = {}
        available_users = [u for u in all_users if u != current_username]
        
        if not available_users:
            ttk.Label(scrollable_frame, text="Nenhum outro usuário disponível", 
                     foreground='gray', font=('Helvetica', 10, 'italic')).pack(pady=20)
        else:
            for user in sorted(available_users):
                var = tk.BooleanVar()
                self.checkbox_vars[user] = var
                
                # Determine status icon
                if user in online_users:
                    status_icon = "🟢"
                    status_text = ""
                else:
                    status_icon = "⚫"
                    status_text = " (offline)"
                
                if self.mode == 'single':
                     # Use Radiobutton logic with Checkbuttons (manual enforcement) or just Checkbuttons
                     # For simplicity, let's use Checkbuttons but enforce single selection in 'ok' or via trace
                     # Actually, let's just use Checkbuttons and validate count = 1
                     pass

                cb = ttk.Checkbutton(
                    scrollable_frame,
                    text=f"{status_icon} {user}{status_text}",
                    variable=var,
                    command=lambda v=var: self.on_check(v) if self.mode == 'single' else None
                )
                cb.pack(anchor="w", padx=10, pady=2)
        
        # Info label
        info_frame = ttk.Frame(self.dialog, padding="10")
        info_frame.pack(fill="x")
        
        info_text = "💡 Mínimo: você + 1 pessoa" if self.mode == 'multiple' else "Selecione 1 usuário"
        ttk.Label(info_frame, text=info_text, 
                 font=('Helvetica', 9), foreground='#666').pack(anchor="w")
        
        # Buttons
        btn_frame = ttk.Frame(self.dialog, padding="10")
        btn_frame.pack(fill="x")
        
        ttk.Button(btn_frame, text="Cancelar", command=self.cancel, width=15).pack(side="right", padx=5)
        btn_text = "Criar Grupo" if self.mode == 'multiple' else "Criar Conversa"
        ttk.Button(btn_frame, text=btn_text, command=self.ok, width=15).pack(side="right")
        
        # Bind Enter key
        if self.name_entry:
            self.name_entry.bind("<Return>", lambda e: self.ok())

    def on_check(self, current_var):
        """Ensure only one checkbox is selected in single mode"""
        if current_var.get():
            for var in self.checkbox_vars.values():
                if var != current_var:
                    var.set(False)
        
    def ok(self):
        """Validate and accept selection"""
        group_name = ""
        
        if self.mode == 'multiple':
            group_name = self.name_entry.get().strip()
            
            # Validate group name
            if not group_name:
                messagebox.showerror("Erro", "O nome do grupo não pode estar vazio.", parent=self.dialog)
                return
            
            if len(group_name) < 3:
                messagebox.showerror("Erro", "O nome do grupo deve ter pelo menos 3 caracteres.", parent=self.dialog)
                return
            
            if len(group_name) > 50:
                messagebox.showerror("Erro", "O nome do grupo não pode ter mais de 50 caracteres.", parent=self.dialog)
                return
        
        # Get selected members
        self.selected_members = [user for user, var in self.checkbox_vars.items() if var.get()]
        
        # Validate selection
        if self.mode == 'multiple':
            if len(self.selected_members) < 1:
                messagebox.showerror("Erro", "Selecione pelo menos 1 pessoa para o grupo.", parent=self.dialog)
                return
            self.result = (group_name, self.selected_members)
        else:
            if len(self.selected_members) != 1:
                messagebox.showerror("Erro", "Selecione exatamente 1 usuário.", parent=self.dialog)
                return
            self.result = self.selected_members[0] # Return just the username string
            
        self.dialog.destroy()
    
    def cancel(self):
        """Cancel selection"""
        self.result = None
        self.dialog.destroy()
    
    def show(self):
        """Show dialog and wait for result"""
        self.dialog.wait_window()
        return self.result


class RoomMembersDialog:
    """Dialog for viewing room members with online/offline status"""
    
    def __init__(self, parent, room_name, members, online_members):
        """
        Args:
            parent: Parent window
            room_name: Name of the room
            members: List of all member usernames
            online_members: Set of currently online member usernames
        """
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(f"Membros: {room_name}")
        self.dialog.geometry("350x400")
        self.dialog.attributes('-topmost', True)
        self.dialog.transient(parent)
        
        # Center on screen
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (350 // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (400 // 2)
        self.dialog.geometry(f"350x400+{x}+{y}")
        
        # Header
        header_frame = ttk.Frame(self.dialog, padding="15")
        header_frame.pack(fill="x")
        ttk.Label(header_frame, text=f"Participantes de '{room_name}'", 
                 font=('Helvetica', 12, 'bold')).pack(anchor="w")
        
        ttk.Separator(self.dialog, orient='horizontal').pack(fill='x')
        
        # Members list
        list_frame = ttk.Frame(self.dialog, padding="10")
        list_frame.pack(fill="both", expand=True)
        
        # Scrollable listbox
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side="right", fill="y")
        
        listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set, font=('Helvetica', 10))
        listbox.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=listbox.yview)
        
        # Populate list
        online_count = 0
        for member in sorted(members):
            if member in online_members:
                listbox.insert(tk.END, f"🟢 {member}")
                online_count += 1
            else:
                listbox.insert(tk.END, f"⚫ {member} (offline)")
        
        # Status info
        info_frame = ttk.Frame(self.dialog, padding="10")
        info_frame.pack(fill="x")
        ttk.Label(info_frame, text=f"Total: {len(members)} | Online: {online_count}", 
                 font=('Helvetica', 9), foreground='#666').pack(anchor="w")
        
        # Close button
        btn_frame = ttk.Frame(self.dialog, padding="10")
        btn_frame.pack(fill="x")
        ttk.Button(btn_frame, text="Fechar", command=self.dialog.destroy, width=15).pack(side="right")
    
    def show(self):
        """Show dialog"""
        self.dialog.wait_window()
