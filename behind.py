import tkinter as tk
from tkinter import messagebox
import string
import bcrypt
import json
import os
import random

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
        else:
            with open(UserManagement.USER_DATA_FILE, 'r+') as file:
                content = file.read().strip()
                if not content:
                    file.seek(0)
                    json.dump({}, file)
                    file.truncate()

        if not os.path.exists(UserManagement.FORGOTTEN_PASSWORD_FILE):
            with open(UserManagement.FORGOTTEN_PASSWORD_FILE, 'w') as file:
                pass

    @staticmethod
    def load_user_data():
        try:
            with open(UserManagement.USER_DATA_FILE, 'r') as file:
                content = file.read().strip()
                if not content:
                    return {}
                return json.loads(content)
        except (FileNotFoundError, json.JSONDecodeError):
            with open(UserManagement.USER_DATA_FILE, 'w') as file:
                json.dump({}, file)
            return {}

    @staticmethod
    def save_user_data(user_data):
        with open(UserManagement.USER_DATA_FILE, 'w') as file:
            json.dump(user_data, file, indent=4)

    @staticmethod
    def hash_password(password):
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    def save_unencrypted_data(self, username, password):
        with open(self.FORGOTTEN_PASSWORD_FILE, 'a') as file:
            file.write(f"{username}|{password}\n")

class Dashboard(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg="#e8f5e9")
        self.controller = controller
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="Welcome to Dashboard", bg="#388e3c", fg="white", 
                font=("Arial", 16, "bold"), pady=15).pack(fill=tk.X)
        
        tk.Label(self, text="You have successfully logged in!", bg="#e8f5e9",
                font=("Arial", 12), pady=20).pack()
        
        tk.Button(self, text="Logout", command=lambda: self.controller.show_frame("LoginPage"),
                 bg="#757575", fg="white", font=("Arial", 12), width=20, pady=5).pack(pady=20)

class Registration(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg="#e8f5e9")
        self.controller = controller
        self.user_manager = UserManagement()
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="Create Your Account", bg="#388e3c", fg="white", 
                font=("Arial", 16, "bold"), pady=15).pack(fill=tk.X)

        self.entry_username = self.create_input_field("Username:")
        self.entry_password = self.create_input_field("Password:", show="*")
        self.entry_confirm_password = self.create_input_field("Confirm Password:", show="*")

        tk.Button(self, text="Register", command=self.handle_register,
                 bg="#4CAF50", fg="white", font=("Arial", 12, "bold"),
                 width=20, pady=5).pack(pady=(30, 10))
        tk.Button(self, text="Back to Login",
                 command=lambda: self.controller.show_frame("LoginPage"),
                 bg="#757575", fg="white", font=("Arial", 12),
                 width=20, pady=5).pack(pady=(10, 20))

    def create_input_field(self, label_text, **kwargs):
        tk.Label(self, text=label_text, bg="#e8f5e9",
                font=("Arial", 12)).pack(pady=(10, 5))
        entry = tk.Entry(self, font=("Arial", 12), bd=2, relief="groove", **kwargs)
        entry.pack(pady=5, ipadx=5, ipady=3)
        return entry

    def handle_register(self):
        username = self.entry_username.get()
        password = self.entry_password.get()
        confirm_password = self.entry_confirm_password.get()

        if not username or not password or not confirm_password:
            messagebox.showwarning("Input Error", "All fields are required.")
            return

        if len(username) < 5 or not username.isalnum():
            messagebox.showwarning("Username Error",
                                 "Username must be at least 5 characters and alphanumeric.")
            return

        if len(password) < 8 or not any(char.isdigit() for char in password) or \
           not any(char.isupper() for char in password) or \
           not any(char.islower() for char in password) or \
           not any(char in string.punctuation for char in password) or \
           username in password:
            messagebox.showerror("Password Error",
                                "Password must meet all security requirements.")
            return

        if password != confirm_password:
            messagebox.showerror("Password Error", "Passwords do not match.")
            return

        user_data = self.user_manager.load_user_data()
        if username in user_data:
            messagebox.showerror("Error", "Username already exists.")
            return

        hashed_password = self.user_manager.hash_password(password)
        user_data[username] = hashed_password
        self.user_manager.save_user_data(user_data)
        self.user_manager.save_unencrypted_data(username, password)

        messagebox.showinfo("Success", "Account registered successfully!")
        self.controller.show_frame("LoginPage")

class Login(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg="#e8f5e9")
        self.controller = controller
        self.user_manager = UserManagement()
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self, text="Login", bg="#388e3c", fg="white",
                font=("Arial", 16, "bold"), pady=15).pack(fill=tk.X)

        self.entry_username = self.create_input_field("Username:")
        self.entry_password = self.create_input_field("Password:", show="*")

        tk.Button(self, text="Login", command=self.handle_login,
                 bg="#4CAF50", fg="white", font=("Arial", 12, "bold"),
                 width=20, pady=5).pack(pady=(30, 10))
        tk.Button(self, text="Forgot Password", command=self.handle_forgot_password,
                 bg="#757575", fg="white", font=("Arial", 12),
                 width=20, pady=5).pack(pady=(10, 10))
        tk.Button(self, text="Register",
                 command=lambda: self.controller.show_frame("RegistrationPage"),
                 bg="#4CAF50", fg="white", font=("Arial", 12),
                 width=20, pady=5).pack(pady=(10, 20))

    def create_input_field(self, label_text, **kwargs):
        tk.Label(self, text=label_text, bg="#e8f5e9",
                font=("Arial", 12)).pack(pady=(10, 5))
        entry = tk.Entry(self, font=("Arial", 12), bd=2, relief="groove", **kwargs)
        entry.pack(pady=5, ipadx=5, ipady=3)
        return entry

    def handle_login(self):
        username = self.entry_username.get()
        password = self.entry_password.get()

        if not username or not password:
            messagebox.showwarning("Input Error", "Please fill in both fields.")
            return

        user_data = self.user_manager.load_user_data()
        if username not in user_data:
            messagebox.showerror("Error", "Username not found.")
            return

        if bcrypt.checkpw(password.encode(), user_data[username].encode()):
            messagebox.showinfo("Success", "Login successful!")
            self.controller.show_frame("DashboardPage")
        else:
            messagebox.showerror("Error", "Incorrect password.")

    def handle_forgot_password(self):
        username = self.entry_username.get()

        if not username:
            messagebox.showwarning("Input Error", "Please enter your username.")
            return

        user_data = self.user_manager.load_user_data()
        if username not in user_data:
            messagebox.showerror("Error", "Username not found.")
            return

        new_password = self.generate_random_password()
        messagebox.showinfo("New Password", f"Your new password is: {new_password}")
        user_data[username] = self.user_manager.hash_password(new_password)
        self.user_manager.save_user_data(user_data)

    @staticmethod
    def generate_random_password():
        characters = string.ascii_letters + string.digits + "@#$%^&*"
        return ''.join(random.choice(characters) for _ in range(12))

class UserAuthApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("User Authentication System")
        self.geometry("400x500")
        self.frames = {}
        self.show_frame("LoginPage")

    def show_frame(self, page_name):
        if page_name not in self.frames:
            frame = None
            if page_name == "LoginPage":
                frame = Login(self, self)
            elif page_name == "RegistrationPage":
                frame = Registration(self, self)
            elif page_name == "DashboardPage":
                frame = Dashboard(self, self)
            self.frames[page_name] = frame
            frame.pack(fill=tk.BOTH, expand=True)
        for frame in self.frames.values():
            frame.pack_forget()
        self.frames[page_name].pack(fill=tk.BOTH, expand=True)

#if __name__ == "__main__":
#   app = UserAuthApp()
#   app.mainloop()




















"""
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
"""




