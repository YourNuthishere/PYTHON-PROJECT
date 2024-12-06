import json
import bcrypt
import os
import tkinter as tk
from tkinter import messagebox

# File to store user data
USER_DATA_FILE = 'users.json'

# Ensure the data file exists
def ensure_file_exists():
    if not os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, 'w') as file:
            json.dump({}, file)

# Load user data from file
def load_user_data():
    try:
        with open(USER_DATA_FILE, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

# Save user data to file
def save_user_data(user_data):
    with open(USER_DATA_FILE, 'w') as file:
        json.dump(user_data, file, indent=4)

# Check if a password is already used
def is_password_used(password):
    user_data = load_user_data()
    for hashed_password in user_data.values():
        if bcrypt.checkpw(password.encode(), hashed_password.encode()):
            return True
    return False

# Register a new user
def register_user(username, password):
    user_data = load_user_data()
    if username in user_data:
        messagebox.showerror("Error", "Username already exists.")
        return
    if is_password_used(password):
        messagebox.showerror("Error", "This password is already in use. Please choose a different password.")
        return
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    user_data[username] = hashed_password.decode()
    save_user_data(user_data)
    messagebox.showinfo("Success", "User registered successfully!")

# Authenticate a user
def login_user(username, password):
    user_data = load_user_data()
    if username not in user_data:
        messagebox.showerror("Error", "Username not found.")
        return
    hashed_password = user_data[username].encode()
    if bcrypt.checkpw(password.encode(), hashed_password):
        messagebox.showinfo("Success", "Login successful!")
        return
    messagebox.showerror("Error", "Incorrect password.")

# GUI Functions
def register():
    username = entry_username.get()
    password = entry_password.get()
    if username and password:
        register_user(username, password)
    else:
        messagebox.showwarning("Input Error", "Please fill in both fields.")

def login():
    username = entry_username.get()
    password = entry_password.get()
    if username and password:
        login_user(username, password)
    else:
        messagebox.showwarning("Input Error", "Please fill in both fields.")

# Ensure the data file exists
ensure_file_exists()

# Create the GUI application
app = tk.Tk()
app.title("User Authentication System")
app.geometry("400x300")

# Username label and entry
label_username = tk.Label(app, text="Username:")
label_username.pack(pady=5)
entry_username = tk.Entry(app)
entry_username.pack(pady=5)

# Password label and entry
label_password = tk.Label(app, text="Password:")
label_password.pack(pady=5)
entry_password = tk.Entry(app, show="*")
entry_password.pack(pady=5)

# Register and Login buttons
button_register = tk.Button(app, text="Register", command=register)
button_register.pack(pady=5)
button_login = tk.Button(app, text="Login", command=login)
button_login.pack(pady=5)

# Run the application
app.mainloop()
