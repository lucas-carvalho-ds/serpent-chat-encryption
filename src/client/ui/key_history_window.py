"""
Key History Window Module
Displays a window showing the history of key-related events.
"""

import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime


class KeyHistoryWindow:
    """Window to display key event history"""
    
    def __init__(self, parent, key_logger):
        """
        Initialize Key History Window
        
        Args:
            parent: Parent tkinter widget
            key_logger: KeyLogger instance
        """
        self.key_logger = key_logger
        self.window = tk.Toplevel(parent)
        self.window.title("Histórico de Chaves")
        self.window.geometry("900x600")
        self.window.transient(parent)
        
        self._build_ui()
        self._load_logs()
    
    def _build_ui(self):
        """Build the UI components"""
        # Title
        title_frame = tk.Frame(self.window, bg="#2196F3", height=50)
        title_frame.pack(fill="x")
        title_frame.pack_propagate(False)
        
        title_label = tk.Label(
            title_frame,
            text="📋 Histórico de Eventos de Chaves Criptográficas",
            font=("Arial", 14, "bold"),
            bg="#2196F3",
            fg="white"
        )
        title_label.pack(pady=10)
        
        # Button frame
        button_frame = tk.Frame(self.window)
        button_frame.pack(fill="x", padx=10, pady=5)
        
        refresh_btn = tk.Button(
            button_frame,
            text="🔄 Atualizar",
            command=self._load_logs,
            bg="#4CAF50",
            fg="white",
            font=("Arial", 10, "bold"),
            cursor="hand2"
        )
        refresh_btn.pack(side="left", padx=5)
        
        clear_btn = tk.Button(
            button_frame,
            text="🗑️ Limpar Histórico",
            command=self._clear_logs,
            bg="#f44336",
            fg="white",
            font=("Arial", 10, "bold"),
            cursor="hand2"
        )
        clear_btn.pack(side="left", padx=5)
        
        export_btn = tk.Button(
            button_frame,
            text="💾 Exportar",
            command=self._export_logs,
            bg="#2196F3",
            fg="white",
            font=("Arial", 10, "bold"),
            cursor="hand2"
        )
        export_btn.pack(side="left", padx=5)
        
        # Treeview frame
        tree_frame = tk.Frame(self.window)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        
        # Treeview
        self.tree = ttk.Treeview(
            tree_frame,
            columns=("timestamp", "event_type", "description", "details"),
            show="headings",
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set
        )
        
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)
        
        # Column headings
        self.tree.heading("timestamp", text="Data/Hora")
        self.tree.heading("event_type", text="Tipo de Evento")
        self.tree.heading("description", text="Descrição")
        self.tree.heading("details", text="Detalhes")
        
        # Column widths
        self.tree.column("timestamp", width=150)
        self.tree.column("event_type", width=150)
        self.tree.column("description", width=250)
        self.tree.column("details", width=300)
        
        # Grid layout
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Double-click to view details
        self.tree.bind("<Double-1>", self._on_item_double_click)
    
    def _load_logs(self):
        """Load and display logs in the treeview"""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Load logs
        logs = self.key_logger.get_logs()
        
        for log_entry in logs:
            timestamp = log_entry.get('timestamp', '')
            # Format timestamp
            try:
                dt = datetime.fromisoformat(timestamp)
                formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                formatted_time = timestamp
            
            event_type = log_entry.get('event_type', 'UNKNOWN')
            description = log_entry.get('description', '')
            
            # Format details
            key_data = log_entry.get('key_data', {})
            context = log_entry.get('context', {})
            
            details_parts = []
            if context:
                for k, v in context.items():
                    details_parts.append(f"{k}={v}")
            if key_data:
                for k, v in key_data.items():
                    if len(str(v)) > 30:
                        details_parts.append(f"{k}={str(v)[:30]}...")
                    else:
                        details_parts.append(f"{k}={v}")
            
            details = ", ".join(details_parts) if details_parts else "-"
            
            self.tree.insert("", "end", values=(formatted_time, event_type, description, details))
    
    def _clear_logs(self):
        """Clear all logs after confirmation"""
        if messagebox.askyesno("Confirmar", "Tem certeza que deseja limpar todo o histórico de chaves?"):
            self.key_logger.clear_logs()
            self._load_logs()
            messagebox.showinfo("Sucesso", "Histórico de chaves limpo.")
    
    def _export_logs(self):
        """Export logs to a text file"""
        from tkinter import filedialog
        import json
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Exportar Histórico de Chaves"
        )
        
        if filename:
            try:
                logs = self.key_logger.get_logs()
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(logs, f, indent=2, ensure_ascii=False)
                messagebox.showinfo("Sucesso", f"Histórico exportado para {filename}")
            except Exception as e:
                messagebox.showerror("Erro", f"Falha ao exportar: {e}")
    
    def _on_item_double_click(self, event):
        """Show detailed view when an item is double-clicked"""
        selected = self.tree.selection()
        if not selected:
            return
        
        item = selected[0]
        values = self.tree.item(item, "values")
        
        # Get full log entry
        logs = self.key_logger.get_logs()
        # Find the matching log (by timestamp)
        matching_log = None
        for log_entry in logs:
            try:
                dt = datetime.fromisoformat(log_entry.get('timestamp', ''))
                formatted_time = dt.strftime("%Y-%m-%d %H:%M:%S")
                if formatted_time == values[0]:
                    matching_log = log_entry
                    break
            except:
                pass
        
        if matching_log:
            self._show_detail_dialog(matching_log)
    
    def _show_detail_dialog(self, log_entry):
        """Show a dialog with full log entry details"""
        import json
        
        detail_window = tk.Toplevel(self.window)
        detail_window.title("Detalhes do Evento")
        detail_window.geometry("600x400")
        detail_window.transient(self.window)
        
        text_widget = tk.Text(detail_window, wrap="word", font=("Courier", 10))
        text_widget.pack(fill="both", expand=True, padx=10, pady=10)
        
        formatted_json = json.dumps(log_entry, indent=2, ensure_ascii=False)
        text_widget.insert("1.0", formatted_json)
        text_widget.config(state="disabled")
    
    def show(self):
        """Show the window"""
        self.window.grab_set()
        self.window.wait_window()
