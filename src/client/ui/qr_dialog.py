"""
QR Code Dialog Module
Displays QR code for 2FA setup in a maximized, scrollable window.
"""

import tkinter as tk
from tkinter import ttk
import qrcode
from PIL import ImageTk


def show_qr_code(parent_root, username, secret, on_complete_callback):
    """
    Shows QR Code in maximized window after registration
    
    Args:
        parent_root: Parent Tkinter root window
        username: Username for the QR code
        secret: TOTP secret
        on_complete_callback: Function to call when user clicks "Concluir"
    """
    # Generate Provisioning URI
    uri = f"otpauth://totp/SerpentChat:{username}?secret={secret}&issuer=SerpentChat"
    
    # Generate QR Code (optimized size to fit in window)
    qr = qrcode.QRCode(version=1, box_size=8, border=4)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to ImageTk
    qr_image = ImageTk.PhotoImage(img)
    
    # Create fullscreen window
    top = tk.Toplevel(parent_root)
    top.title("Configurar Autenticação de Dois Fatores")
    
    # Maximize window
    top.state('zoomed')  # Windows
    # top.attributes('-zoomed', True)  # Linux alternative
    
    # Keep reference to image to prevent Garbage Collection
    top.qr_image = qr_image
    
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
    ttk.Label(scrollable_frame, text="Configurar Autenticação de Dois Fatores", 
              font=('Helvetica', 18, 'bold')).pack(pady=10)
    ttk.Label(scrollable_frame, text="Escaneie este código com seu aplicativo autenticador:", 
              font=('Helvetica', 12)).pack(pady=5)
    ttk.Label(scrollable_frame, text="(Google Authenticator, Authy, Microsoft Authenticator, etc.)", 
              font=('Helvetica', 10, 'italic')).pack(pady=3)
    
    # QR Code image
    lbl_img = ttk.Label(scrollable_frame, image=top.qr_image)
    lbl_img.pack(pady=10)
    
    # Secret text
    ttk.Label(scrollable_frame, text="Código Manual (se preferir configurar manualmente):", 
              font=('Helvetica', 10)).pack(pady=5)
    secret_frame = ttk.Frame(scrollable_frame)
    secret_frame.pack(pady=3)
    secret_entry = ttk.Entry(secret_frame, font=('Courier', 12, 'bold'), 
                            width=len(secret)+4, justify='center')
    secret_entry.insert(0, secret)
    secret_entry.config(state='readonly')
    secret_entry.pack()
    
    # Instructions
    ttk.Separator(scrollable_frame, orient='horizontal').pack(fill='x', pady=10)
    ttk.Label(scrollable_frame, text="⚠️ Guarde este código em local seguro!", 
              font=('Helvetica', 11, 'bold'), foreground='red').pack(pady=3)
    ttk.Label(scrollable_frame, text="Você precisará do aplicativo autenticador para fazer login.", 
              font=('Helvetica', 10)).pack(pady=3)
    
    # Finish button that calls callback
    def finish_registration():
        top.destroy()
        on_complete_callback()
    
    ttk.Button(scrollable_frame, text="Concluir", command=finish_registration, width=20).pack(pady=15)
    
    # Force update to ensure rendering
    top.update()
