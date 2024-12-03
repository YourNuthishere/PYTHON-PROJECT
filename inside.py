# we should code the backend here

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

# Start the login process
user_login()


