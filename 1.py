"""
import json
import bcrypt
import os
import tkinter as tk
from tkinter import messagebox
import string
import random
# Files for data storage
USER_DATA_FILE = 'users.json'
FORGOTTEN_PASSWORD_FILE = 'user_data.txt'

# Ensure the necessary files exist
def ensure_files_exist():
    if not os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, 'w') as file:
            json.dump({}, file)
    if not os.path.exists(FORGOTTEN_PASSWORD_FILE):
        with open(FORGOTTEN_PASSWORD_FILE, 'w') as file:
            pass

# Load user data from JSON file
def load_user_data():
    try:
        with open(USER_DATA_FILE, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

# Save user data to JSON file
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
def register_user():
    username = entry_username.get()
    password = entry_password.get()
    
    if not username or not password:
        messagebox.showwarning("Input Error", "Please fill in both fields.")
        return
    
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
def login_user():
    username = entry_username.get()
    password = entry_password.get()
    
    if not username or not password:
        messagebox.showwarning("Input Error", "Please fill in both fields.")
        return
    
    user_data = load_user_data()
    if username not in user_data:
        messagebox.showerror("Error", "Username not found.")
        return
    
    hashed_password = user_data[username].encode()
    if bcrypt.checkpw(password.encode(), hashed_password):
        messagebox.showinfo("Success", "Login successful!")
    else:
        messagebox.showerror("Error", "Incorrect password.")

# Generate a random password
def generate_random_password():
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choices(characters, k=10))

# Forgot password functionality
def forgot_password():
    username = entry_username.get()
    
    if not username:
        messagebox.showwarning("Input Error", "Please enter your username.")
        return
    
    user_data = load_user_data()
    if username not in user_data:
        messagebox.showerror("Error", "Username not found.")
        return
    
    # Generate and display a new password
    new_password = generate_random_password()
    messagebox.showinfo("New Password", f"Your new password is: {new_password}")
    
    # Store the new password in user_data.txt
    with open(FORGOTTEN_PASSWORD_FILE, 'a') as file:
        file.write(f"{username}: {new_password}\n")
    
    # Update the password in users.json
    hashed_password = bcrypt.hashpw(new_password.encode().gensalt())
    user_data[username] = hashed_password.decode()
    save_user_data(user_data)

# Ensure the data files exist
ensure_files_exist()

# Create the GUI application
app = tk.Tk()
app.title("User Authentication System")
app.geometry("400x500")
app.configure(bg="#f0f0f0")

# Header Label
header_label = tk.Label(
    app,
    text="Welcome to Stay Safe System",
    bg="#4CAF50",
    fg="white",
    font=("Arial", 14, "bold"),
    pady=10
)
header_label.pack(fill=tk.X)

# Username label and entry
label_username = tk.Label(app, text="Username:", bg="#f0f0f0", font=("Arial", 12))
label_username.pack(pady=(20, 5))
entry_username = tk.Entry(app, font=("Arial", 12), bd=2, relief="groove")
entry_username.pack(pady=5)

# Password label and entry
label_password = tk.Label(app, text="Password:", bg="#f0f0f0", font=("Arial", 12))
label_password.pack(pady=(10, 5))
entry_password = tk.Entry(app, show="*", font=("Arial", 12), bd=2, relief="groove")
entry_password.pack(pady=5)

# Buttons
button_register = tk.Button(
    app, text="Register", command=register_user,
    bg="#008CBA", fg="white", font=("Arial", 12, "bold"), width=15, pady=5
)
button_register.pack(pady=(20, 10))

button_login = tk.Button(
    app, text="Login", command=login_user,
    bg="#4CAF50", fg="white", font=("Arial", 12, "bold"), width=15, pady=5
)
button_login.pack(pady=10)

button_forgot_password = tk.Button(
    app, text="Forgot Password", command=forgot_password,
    bg="#f44336", fg="white", font=("Arial", 12, "bold"), width=15, pady=5
)
button_forgot_password.pack(pady=10)

# Footer Label
footer_label = tk.Label(
    app,
    text="Secure Your Data with Us",
    bg="#4CAF50",
    fg="white",
    font=("Arial", 10),
    pady=5
)
footer_label.pack(side=tk.BOTTOM, fill=tk.X)

# Run the application
app.mainloop()
"""