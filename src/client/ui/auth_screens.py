"""
Authentication Screens Module
Contains Welcome, Login, and Registration UI screens.
"""

from tkinter import ttk


class AuthScreens:
    """Manages authentication-related UI screens"""
    
    @staticmethod
    def build_welcome_ui(root, clear_window_func, on_login_click, on_register_click):
        """Tela inicial com escolha entre Login e Registro"""
        clear_window_func()
        
        frame = ttk.Frame(root, padding="40")
        frame.place(relx=0.5, rely=0.5, anchor="center")
        
        ttk.Label(frame, text="SerpTalk", font=('Helvetica', 20, 'bold')).pack(pady=10)
        ttk.Label(frame, text="Sistema de Chat Criptografado", font=('Helvetica', 12)).pack(pady=5)
        
        ttk.Separator(frame, orient='horizontal').pack(fill='x', pady=20)
        
        ttk.Button(frame, text="Fazer Login", command=on_login_click, width=25).pack(pady=10)
        ttk.Button(frame, text="Criar Conta", command=on_register_click, width=25).pack(pady=10)
    
    @staticmethod
    def build_login_ui(root, clear_window_func, on_submit, on_back):
        """Tela de login com campos de autenticação"""
        clear_window_func()
        
        frame = ttk.Frame(root, padding="30")
        frame.place(relx=0.5, rely=0.5, anchor="center")
        
        ttk.Label(frame, text="Fazer Login", font=('Helvetica', 16, 'bold')).grid(row=0, column=0, columnspan=2, pady=20)
        
        ttk.Label(frame, text="Usuário:").grid(row=1, column=0, sticky="e", padx=5)
        user_entry = ttk.Entry(frame, width=25)
        user_entry.grid(row=1, column=1, pady=8)
        user_entry.focus()  # Auto-focus
        
        ttk.Label(frame, text="Senha:").grid(row=2, column=0, sticky="e", padx=5)
        pass_entry = ttk.Entry(frame, show="*", width=25)
        pass_entry.grid(row=2, column=1, pady=8)
        
        ttk.Label(frame, text="Código 2FA:").grid(row=3, column=0, sticky="e", padx=5)
        totp_entry = ttk.Entry(frame, width=25)
        totp_entry.grid(row=3, column=1, pady=8)
        
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=20)
        
        ttk.Button(btn_frame, text="Entrar", 
                  command=lambda: on_submit(user_entry.get(), pass_entry.get(), totp_entry.get()), 
                  width=12).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Voltar", command=on_back, width=12).pack(side="left", padx=5)
        
        return user_entry, pass_entry, totp_entry
    
    @staticmethod
    def build_register_ui(root, clear_window_func, on_submit, on_back):
        """Tela de registro para novos usuários"""
        clear_window_func()
        
        frame = ttk.Frame(root, padding="30")
        frame.place(relx=0.5, rely=0.5, anchor="center")
        
        ttk.Label(frame, text="Criar Nova Conta", font=('Helvetica', 16, 'bold')).grid(row=0, column=0, columnspan=2, pady=20)
        
        ttk.Label(frame, text="Usuário:").grid(row=1, column=0, sticky="e", padx=5)
        user_entry = ttk.Entry(frame, width=25)
        user_entry.grid(row=1, column=1, pady=8)
        user_entry.focus()  # Auto-focus
        
        ttk.Label(frame, text="Senha:").grid(row=2, column=0, sticky="e", padx=5)
        pass_entry = ttk.Entry(frame, show="*", width=25)
        pass_entry.grid(row=2, column=1, pady=8)
        
        ttk.Label(frame, text="Confirmar Senha:").grid(row=3, column=0, sticky="e", padx=5)
        pass_confirm_entry = ttk.Entry(frame, show="*", width=25)
        pass_confirm_entry.grid(row=3, column=1, pady=8)
        
        ttk.Label(frame, text="(Você irá configurar 2FA na próxima etapa)", 
                 font=('Helvetica', 9, 'italic')).grid(row=4, column=0, columnspan=2, pady=5)
        
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=5, column=0, columnspan=2, pady=20)
        
        ttk.Button(btn_frame, text="Prosseguir", 
                  command=lambda: on_submit(user_entry.get(), pass_entry.get(), pass_confirm_entry.get()), 
                  width=12).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Voltar", command=on_back, width=12).pack(side="left", padx=5)
        
        return user_entry, pass_entry, pass_confirm_entry
