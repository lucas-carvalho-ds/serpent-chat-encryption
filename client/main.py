"""
Serpent Chat Client - Main Entry Point
Fully modular architecture with separated concerns.
"""

import tkinter as tk
from client.gui_manager import ChatGUI


def main():
    """Main entry point for the chat client"""
    root = tk.Tk()
    app = ChatGUI(root)
    
    def on_closing():
        if app.network_thread:
            app.network_thread.stop()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()
