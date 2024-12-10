import json
import bcrypt
import os
import tkinter as tk
from tkinter import messagebox
import string
import random

# Base class for user management
class UserManagement:
    USER_DATA_FILE = 'users.json'
    FORGOTTEN_PASSWORD_FILE = 'users_data.txt'

    def __init__(self):
        self.ensure_files_exist()

    @staticmethod
    def ensure_files_exist():
        if not os.path.exists(UserManagement.USER_DATA_FILE):
            with open(UserManagement.USER_DATA_FILE, 'w') as file:
                json.dump({}, file)
        if not os.path.exists(UserManagement.FORGOTTEN_PASSWORD_FILE):
            with open(UserManagement.FORGOTTEN_PASSWORD_FILE, 'w') as file:
                pass

    @staticmethod
    def load_user_data():
        try:
            with open(UserManagement.USER_DATA_FILE, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            return {}

    @staticmethod
    def save_user_data(user_data):
        with open(UserManagement.USER_DATA_FILE, 'w') as file:
            json.dump(user_data, file, indent=4)

    @staticmethod
    def is_password_used(password):
        user_data = UserManagement.load_user_data()
        for hashed_password in user_data.values():
            if bcrypt.checkpw(password.encode(), hashed_password.encode()):
                return True
        return False


# Derived class for registration
class Registration(UserManagement):
    @staticmethod
    def register_user(username, password):
        if not username or not password:
            messagebox.showwarning("Input Error", "Please fill in both fields.")
            return

        user_data = UserManagement.load_user_data()
        if username in user_data:
            messagebox.showerror("Error", "Username already exists.")
            return
        if UserManagement.is_password_used(password):
            messagebox.showerror("Error", "This password is already in use. Please choose a different password.")
            return

        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        user_data[username] = hashed_password.decode()
        UserManagement.save_user_data(user_data)
        messagebox.showinfo("Success", "User registered successfully!")


# Derived class for login
class Login(UserManagement):
    @staticmethod
    def login_user(username, password):
        if not username or not password:
            messagebox.showwarning("Input Error", "Please fill in both fields.")
            return

        user_data = UserManagement.load_user_data()
        if username not in user_data:
            messagebox.showerror("Error", "Username not found.")
            return

        hashed_password = user_data[username].encode()
        if bcrypt.checkpw(password.encode(), hashed_password):
            messagebox.showinfo("Success", "Login successful!")
        else:
            messagebox.showerror("Error", "Incorrect password.")


# Derived class for password management
class PasswordManagement(UserManagement):
    @staticmethod
    def generate_random_password():
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choices(characters, k=10))

    @staticmethod
    def forgot_password(username):
        if not username:
            messagebox.showwarning("Input Error", "Please enter your username.")
            return

        user_data = UserManagement.load_user_data()
        if username not in user_data:
            messagebox.showerror("Error", "Username not found.")
            return

        new_password = PasswordManagement.generate_random_password()
        messagebox.showinfo("New Password", f"Your new password is: {new_password}")

        with open(UserManagement.FORGOTTEN_PASSWORD_FILE, 'a') as file:
            file.write(f"{username}: {new_password}\n")

        hashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
        user_data[username] = hashed_password.decode()
        UserManagement.save_user_data(user_data)


# GUI Application
class UserAuthApp(tk.Tk, Registration, Login, PasswordManagement):
    def __init__(self):
        super().__init__()
        self.title("User Authentication System")
        self.geometry("400x500")
        self.configure(bg="#f0f0f0")
        self.create_widgets()

    def create_widgets(self):
        # Header Label
        header_label = tk.Label(
            self,
            text="Welcome to Stay Safe System",
            bg="#4CAF50",
            fg="white",
            font=("Arial", 14, "bold"),
            pady=10
        )
        header_label.pack(fill=tk.X)

        # Username label and entry
        label_username = tk.Label(self, text="Username:", bg="#f0f0f0", font=("Arial", 12))
        label_username.pack(pady=(20, 5))
        self.entry_username = tk.Entry(self, font=("Arial", 12), bd=2, relief="groove")
        self.entry_username.pack(pady=5)

        # Password label and entry
        label_password = tk.Label(self, text="Password:", bg="#f0f0f0", font=("Arial", 12))
        label_password.pack(pady=(10, 5))
        self.entry_password = tk.Entry(self, show="*", font=("Arial", 12), bd=2, relief="groove")
        self.entry_password.pack(pady=5)

        # Buttons
        button_register = tk.Button(
            self, text="Register", command=self.handle_register,
            bg="#008CBA", fg="white", font=("Arial", 12, "bold"), width=15, pady=5
        )
        button_register.pack(pady=(20, 10))

        button_login = tk.Button(
            self, text="Login", command=self.handle_login,
            bg="#4CAF50", fg="white", font=("Arial", 12, "bold"), width=15, pady=5
        )
        button_login.pack(pady=10)

        button_forgot_password = tk.Button(
            self, text="Forgot Password", command=self.handle_forgot_password,
            bg="#f44336", fg="white", font=("Arial", 12, "bold"), width=15, pady=5
        )
        button_forgot_password.pack(pady=10)

        # Footer Label
        footer_label = tk.Label(
            self,
            text="Secure Your Data with Us",
            bg="#4CAF50",
            fg="white",
            font=("Arial", 10),
            pady=5
        )
        footer_label.pack(side=tk.BOTTOM, fill=tk.X)

    def handle_register(self):
        username = self.entry_username.get()
        password = self.entry_password.get()
        self.register_user(username, password)

    def handle_login(self):
        username = self.entry_username.get()
        password = self.entry_password.get()
        self.login_user(username, password)

    def handle_forgot_password(self):
        username = self.entry_username.get()
        self.forgot_password(username)


