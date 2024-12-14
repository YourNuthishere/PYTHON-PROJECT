"""
import tkinter as tk
from tkinter import messagebox
import random
import string
import os

# Ensure the data file exists
def ensure_file_exists():
    if not os.path.exists("user_data.txt"):
        with open("user_data.txt", "w") as file:
            pass  # Create an empty file

# Save user data
def register_user():
    username = entry_username.get()
    password = entry_password.get()
    if username and password:
        with open("user_data.txt", "a") as file:
            file.write(f"{username}:{password}\n")
        messagebox.showinfo("Success", "Account created successfully!")
    else:
        messagebox.showwarning("Input Error", "Please fill in both fields.")

# Verify user credentials
def login_user():
    username = entry_username.get()
    password = entry_password.get()
    if username and password:
        with open("user_data.txt", "r") as file:
            users = file.readlines()
            for user in users:
                stored_username, stored_password = user.strip().split(":")
                if stored_username == username and stored_password == password:
                    messagebox.showinfo("Login Success", "You have successfully logged in!")
                    return
        messagebox.showerror("Login Failed", "Invalid username or password.")
    else:
        messagebox.showwarning("Input Error", "Please fill in both fields.")

# Generate a random password
def generate_random_password():
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choices(characters, k=10))

# Forgot password functionality
def forgot_password():
    username = entry_username.get()
    if username:
        with open("user_data.txt", "r") as file:
            users = file.readlines()
            for user in users:
                stored_username, _ = user.strip().split(":")
                if stored_username == username:
                    new_password = generate_random_password()
                    messagebox.showinfo("New Password", f"Your new password is: {new_password}")
                    update_password(username, new_password)
                    return
        messagebox.showerror("Error", "Username not found.")
    else:
        messagebox.showwarning("Input Error", "Please enter your username.")

# Update the password in the data file
def update_password(username, new_password):
    with open("user_data.txt", "r") as file:
        users = file.readlines()
    with open("user_data.txt", "w") as file:
        for user in users:
            stored_username, stored_password = user.strip().split(":")
            if stored_username == username:
                file.write(f"{stored_username}:{new_password}\n")
            else:
                file.write(f"{stored_username}:{stored_password}\n")

# Ensure the data file exists
ensure_file_exists()

# Create the GUI application
app = tk.Tk()
app.title("User Authentication System")
app.geometry("400x500")
app.configure(bg="#f0f0f0")

# Header Label
header_label = tk.Label(
    app,
    text="Welcome to User Authentication System",
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