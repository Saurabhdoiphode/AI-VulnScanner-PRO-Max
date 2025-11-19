"""
Login Window - User Authentication Interface
"""

import tkinter as tk
from tkinter import messagebox, ttk
import sqlite3
import hashlib
import os
from pathlib import Path


class LoginWindow:
    """
    Login window with user authentication
    """
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("AI-VulnScanner PRO Max - Login")
        self.root.geometry("500x600")
        self.root.resizable(False, False)
        
        # Set dark theme colors
        self.bg_color = "#1e1e1e"
        self.fg_color = "#ffffff"
        self.accent_color = "#007acc"
        self.button_color = "#0e639c"
        
        self.root.configure(bg=self.bg_color)
        
        # Initialize database
        self.init_database()
        
        # Create UI
        self.create_widgets()
        
        # Center window
        self.center_window()
    
    def init_database(self):
        """Initialize SQLite database for users"""
        db_path = Path("database/users.db")
        db_path.parent.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create default admin user if doesn't exist
        default_password = self.hash_password("admin123")
        try:
            cursor.execute(
                "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                ("admin", default_password, "admin@vulnscanner.local")
            )
            conn.commit()
        except sqlite3.IntegrityError:
            pass  # User already exists
        
        conn.close()
    
    def hash_password(self, password: str) -> str:
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def create_widgets(self):
        """Create login UI widgets"""
        
        # Logo/Title Frame
        title_frame = tk.Frame(self.root, bg=self.bg_color)
        title_frame.pack(pady=40)
        
        # Title
        title_label = tk.Label(
            title_frame,
            text="AI-VulnScanner PRO Max",
            font=("Arial", 24, "bold"),
            fg=self.accent_color,
            bg=self.bg_color
        )
        title_label.pack()
        
        subtitle_label = tk.Label(
            title_frame,
            text="Enterprise Cybersecurity Scanner",
            font=("Arial", 12),
            fg=self.fg_color,
            bg=self.bg_color
        )
        subtitle_label.pack(pady=5)
        
        version_label = tk.Label(
            title_frame,
            text="Version 1.0.0 | Powered by Local AI",
            font=("Arial", 9),
            fg="#888888",
            bg=self.bg_color
        )
        version_label.pack()
        
        # Login Form Frame
        form_frame = tk.Frame(self.root, bg=self.bg_color)
        form_frame.pack(pady=20, padx=50)
        
        # Username
        username_label = tk.Label(
            form_frame,
            text="Username:",
            font=("Arial", 11),
            fg=self.fg_color,
            bg=self.bg_color
        )
        username_label.grid(row=0, column=0, sticky="w", pady=10)
        
        self.username_entry = tk.Entry(
            form_frame,
            font=("Arial", 11),
            width=30,
            bg="#2d2d2d",
            fg=self.fg_color,
            insertbackground=self.fg_color,
            relief=tk.FLAT,
            bd=2
        )
        self.username_entry.grid(row=1, column=0, pady=5)
        self.username_entry.insert(0, "admin")  # Default username
        
        # Password
        password_label = tk.Label(
            form_frame,
            text="Password:",
            font=("Arial", 11),
            fg=self.fg_color,
            bg=self.bg_color
        )
        password_label.grid(row=2, column=0, sticky="w", pady=10)
        
        self.password_entry = tk.Entry(
            form_frame,
            font=("Arial", 11),
            width=30,
            show="•",
            bg="#2d2d2d",
            fg=self.fg_color,
            insertbackground=self.fg_color,
            relief=tk.FLAT,
            bd=2
        )
        self.password_entry.grid(row=3, column=0, pady=5)
        
        # Bind Enter key to login
        self.password_entry.bind('<Return>', lambda e: self.login())
        
        # Remember me checkbox
        self.remember_var = tk.BooleanVar()
        remember_check = tk.Checkbutton(
            form_frame,
            text="Remember me",
            variable=self.remember_var,
            font=("Arial", 9),
            fg=self.fg_color,
            bg=self.bg_color,
            selectcolor=self.bg_color,
            activebackground=self.bg_color,
            activeforeground=self.accent_color
        )
        remember_check.grid(row=4, column=0, sticky="w", pady=10)
        
        # Login Button
        login_button = tk.Button(
            form_frame,
            text="LOGIN",
            font=("Arial", 12, "bold"),
            width=28,
            bg=self.button_color,
            fg=self.fg_color,
            relief=tk.FLAT,
            cursor="hand2",
            command=self.login
        )
        login_button.grid(row=5, column=0, pady=20)
        
        # Hover effect
        login_button.bind('<Enter>', lambda e: login_button.config(bg=self.accent_color))
        login_button.bind('<Leave>', lambda e: login_button.config(bg=self.button_color))
        
        # Info Frame
        info_frame = tk.Frame(self.root, bg=self.bg_color)
        info_frame.pack(side=tk.BOTTOM, pady=20)
        
        info_label = tk.Label(
            info_frame,
            text="Default credentials: admin / admin123",
            font=("Arial", 9),
            fg="#888888",
            bg=self.bg_color
        )
        info_label.pack()
    
    def center_window(self):
        """Center window on screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def login(self):
        """Handle login attempt"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return
        
        # Verify credentials
        if self.verify_credentials(username, password):
            messagebox.showinfo("Success", f"Welcome, {username}!")
            self.root.destroy()
            
            # Launch main dashboard
            from gui.dashboard import Dashboard
            dashboard = Dashboard(username)
            dashboard.run()
        else:
            messagebox.showerror("Error", "Invalid username or password")
            self.password_entry.delete(0, tk.END)
    
    def verify_credentials(self, username: str, password: str) -> bool:
        """Verify user credentials against database"""
        db_path = Path("database/users.db")
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        hashed_password = self.hash_password(password)
        
        cursor.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, hashed_password)
        )
        
        user = cursor.fetchone()
        conn.close()
        
        return user is not None
    
    def run(self):
        """Start the login window"""
        self.root.mainloop()


# Example usage
if __name__ == "__main__":
    app = LoginWindow()
    app.run()
