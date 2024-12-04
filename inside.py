# we should code the backend here
"""
def create_account():
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    confirm_password = input("Confirm your password: ")






def read_login():
    with open('login.txt', 'r') as f:
        contents = f.readlines()
        new_contents = []
        for line in contents:
            fields = line.split(',')
            fields[1] = fields[1].rstrip()  # Remove newline character from password
            new_contents.append(fields)
    return new_contents

# Read the login data from the file
login_data = read_login()

def user_login():
    username = input("Username: ")
    password = input("Password: ")

    logged_in = False

    for line in login_data:
        if line[0] == username and not logged_in:
            if line[1] == password:
                logged_in = True



    if logged_in:
        print("Logged in successfully")
    else:
        print("Username / Password is incorrect.")
        user_login()  # Call the function again for another attempt


user_login()
"""


"""
def create_account():
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    confirm_password = input("Confirm your password: ")

    if password == confirm_password:
        # Write the new account to the file
        with open('login.txt', 'a') as f:
            f.write(f"{username},{password}\n")
        print("Account created successfully!")
    else:
        print("Passwords do not match. Please try again.")
        create_account()  # Call the function again for another attempt

def read_login():
    try:
        with open('login.txt', 'r') as f:
            contents = f.readlines()
            new_contents = []
            for line in contents:
                fields = line.strip().split(',')
                new_contents.append(fields)
            return new_contents
    except FileNotFoundError:
        return []  # Return an empty list if the file does not exist

def user_login():
    username = input("Username: ")
    password = input("Password: ")

    login_data = read_login()

    logged_in = False

    for line in login_data:
        if line[0] == username:
            if line[1] == password:
                logged_in = True
                break  # Exit the loop if logged in

    if logged_in:
        print("Logged in successfully")
    else:
        print("Username / Password is incorrect.")
        user_login()  # Call the function again for another attempt

# Main program flow
while True:
    action = input("Do you want to (1) Create an account or (2) Login? (Enter 1 or 2): ")
    if action == '1':
        create_account()
    elif action == '2':
        user_login()
    else:
        print("Invalid option. Please enter 1 or 2.")
"""



""" creat repeat
def create_account():
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    confirm_password = input("Confirm your password: ")

    if password == confirm_password:
        # Write the new account to the file
        with open('login.txt', 'a') as f:
            f.write(f"{username},{password}\n")
        print("Account created successfully!")
    else:
        print("Passwords do not match. Please try again.")
        create_account()  # Call the function again for another attempt

def read_login():
    try:
        with open('login.txt', 'r') as f:
            contents = f.readlines()
            new_contents = []
            for line in contents:
                fields = line.strip().split(',')
                new_contents.append(fields)
            return new_contents
    except FileNotFoundError:
        return []  # Return an empty list if the file does not exist

def user_login():
    username = input("Username: ")
    password = input("Password: ")

    login_data = read_login()

    logged_in = False

    for line in login_data:
        if line[0] == username:
            if line[1] == password:
                logged_in = True
                break  # Exit the loop if logged in

    if logged_in:
        print("Logged in successfully")
    else:
        print("Username / Password is incorrect.")
        user_login()  # Call the function again for another attempt

# Automatically create an account first, then allow login
create_account()  # Prompt the user to create an account first
user_login()      # After account creation, prompt for login
"""



