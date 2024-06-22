import sys, time, os
import hashlib
import pyfiglet
from termcolor import colored
from cryptography.fernet import Fernet
from string import punctuation, ascii_letters, digits
import pyperclip
import random
import signal
import tkinter as tk
from tkinter import simpledialog, messagebox, filedialog

def signal_handler(sig, frame):
    print()
    exit_program()

signal.signal(signal.SIGINT, signal_handler)

def encrypt_pwd(passwd):
    key = Fernet.generate_key()
    fernet = Fernet(key)
    encrypt = fernet.encrypt(passwd.encode())
    return encrypt.decode(), key.decode()

def exists_list(file_path, keyword):
    lines = []
    line_number = 1
    with open(file_path, 'r') as file:
        for line in file:
            line_number += 1
            if keyword in line:
                lines.append(line_number)
    return lines

def delete_lines(file_path, lines_to_delete):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
        with open(file_path, 'w') as file:
            for index, line in enumerate(lines, start=1):
                if index not in lines_to_delete:
                    file.write(line)
    except FileNotFoundError:
        print(f"File not found at path: {file_path}")
    except Exception as e:
        print(f"An error occurred: {e}")

def extract_pwd(user):
    url = simpledialog.askstring("Extract Password", "Enter website URL:")
    if url:
        line_no = uname_exists('passman.txt', url)
        if line_no is None:
            messagebox.showinfo("Error", "No such entry exists! Try again.")
        else:
            with open('passman.txt') as file:
                content = file.readlines()
                if user + "\n" == content[line_no - 2]:
                    username = content[line_no]
                    decrypt = Fernet(content[line_no - 3]).decrypt(content[line_no + 1]).decode()
                    messagebox.showinfo("Extracted Password", f"Username: {username}\nPassword: {decrypt}")
                    pyperclip.copy(decrypt)
                    messagebox.showinfo("Clipboard", "PASSWORD COPIED TO CLIPBOARD...")
                else:
                    messagebox.showinfo("Error", "No website found! Try again")

def delete_account(user):
    inp = messagebox.askyesno("Delete Account", "You are going to lose your entire data. Continue?")
    if inp:
        linn = exists_list('accounts.txt', user)
        y = []
        for i in linn:
            y.append(i - 1)
            y.append(i)
        delete_lines('accounts.txt', y)
        comp = exists_list('passman.txt', user)
        x = []
        for i in comp:
            x.append(i - 2)
            x.append(i - 1)
            x.append(i)
            x.append(i + 1)
            x.append(i + 2)
        delete_lines('passman.txt', x)
        messagebox.showinfo("Success", "Account has been successfully deleted.")
        exit_program()
    else:
        password_interface(user)

def store_pwd(user):
    url = simpledialog.askstring("Store Password", "Website URL:")
    uname = simpledialog.askstring("Store Password", "Username:")
    passwd = simpledialog.askstring("Store Password", "Password:", show='*')
    if url and uname and passwd:
        encrypt, key = encrypt_pwd(passwd)
        with open("passman.txt", 'a+') as f:
            f.write(key + "\n")
            f.write(user + "\n")
            f.write(url + "\n")
            f.write(uname + "\n")
            f.write(encrypt + "\n")
        messagebox.showinfo("Success", "Password has been successfully added")

def delete_entry(user):
    url = simpledialog.askstring("Delete Entry", "Enter the website URL to delete:")
    if url:
        line_no = uname_exists('passman.txt', url)
        if line_no is None:
            messagebox.showinfo("Error", "No such entry exists!")
        else:
            liss = [line_no - 2, line_no - 1, line_no, line_no + 1, line_no + 2]
            delete_lines('passman.txt', liss)
            messagebox.showinfo("Success", "Entry has been successfully deleted.")

def modify_pwd(user):
    url = simpledialog.askstring("Modify Password", "Enter website:")
    uname = simpledialog.askstring("Modify Password", "Enter username:")
    if url and uname:
        url_list = exists_list('passman.txt', url)
        uname_list = exists_list('passman.txt', uname)
        with open('passman.txt', 'r') as file:
            data = file.readlines()
        line_no = float('inf')
        for i in url_list:
            for j in uname_list:
                if i + 1 == j and data[i - 3] == user + "\n":
                    line_no = i
                    break
        if line_no == float('inf'):
            messagebox.showinfo("Error", "No such entry exists!")
            return
        passwd = simpledialog.askstring("Modify Password", "Enter your modified password:", show='*')
        if passwd:
            pwd, key = encrypt_pwd(passwd)
            data[line_no] = pwd + "\n"
            data[line_no - 4] = key + "\n"
            with open('passman.txt', 'w') as file:
                file.writelines(data)
            messagebox.showinfo("Success", "Password has been successfully modified.")

def modify_uname(user):
    ch = messagebox.askyesno("Modify Username", "Modifying a username removes the previous username data and you need to enter the password again. Continue?")
    if ch:
        delete_entry(user)
        store_pwd(user)

def password_interface(user):
    root = tk.Tk()
    root.title("SavePass Password Manager")

    label = tk.Label(root, text=f"Welcome {user.upper()}, SavePass is an open-source project to generate and store passwords")
    label.pack()

    options = [
        ("Store a Password", lambda: store_pwd(user)),
        ("Extract a Password", lambda: extract_pwd(user)),
        ("Delete an Entry", lambda: delete_entry(user)),
        ("Modify a Username", lambda: modify_uname(user)),
        ("Modify Password", lambda: modify_pwd(user)),
        ("Exit the Application", exit_program)
    ]

    for (text, command) in options:
        button = tk.Button(root, text=text, command=command)
        button.pack(fill='x')

    root.mainloop()

count = 3
count1 = 3

def chg_pwd(uname):
    line_no = uname_exists('accounts.txt', uname)
    if line_no is not None:
        with open('accounts.txt', 'r') as file:
            data = file.readlines()
        curr_pwd = simpledialog.askstring("Change Password", "Enter your current password:", show='*')
        if hash_pwd(curr_pwd) + "\n" == data[line_no]:
            pwd1 = simpledialog.askstring("Change Password", "Enter your new password:", show='*')
            pwd2 = simpledialog.askstring("Change Password", "Re-enter your new password:", show='*')
            if pwd1 == pwd2:
                data[line_no] = hash_pwd(pwd1) + "\n"
                with open('accounts.txt', 'w') as file:
                    file.writelines(data)
                messagebox.showinfo("Success", "Password has been successfully changed.")
                exit_program()
            else:
                messagebox.showinfo("Error", "Passwords don't match. Try again.")

def login_account():
    uname = simpledialog.askstring("Login", "Username:")
    if uname:
        if not os.path.exists('accounts.txt'):
            messagebox.showinfo("Error", "No accounts found. Please signup first!")
            exit_program()
        line_no = uname_exists('accounts.txt', uname)
        if line_no is not None:
            passwd = simpledialog.askstring("Login", "Password:", show='*')
            if passwd:
                hashedpwd = hash_pwd(passwd)
                with open('accounts.txt') as file:
                    content = file.readlines()
                if content[line_no] == hashedpwd + "\n":
                    messagebox.showinfo("Success", f"Login Successful at {time.strftime('%X')}")
                    while True:
                        user_options = tk.Tk()
                        user_options.title("User Options")

                        tk.Button(user_options, text="Change Account Password", command=lambda: chg_pwd(uname)).pack(fill='x')
                        tk.Button(user_options, text="Delete Account", command=lambda: delete_account(uname)).pack(fill='x')
                        tk.Button(user_options, text="Exit Program", command=exit_program).pack(fill='x')

                        user_options.mainloop()
                else:
                    global count
                    count -= 1
                    if count == 0:
                        exit_program()
                    messagebox.showinfo("Error", f"Incorrect password. You have {count} chances remaining.")
                    login_account()
        else:
            global count1
            count1 -= 1
            if count1 == 0:
                messagebox.showinfo("Error", "No user found. Please signup!")
                choice = messagebox.askyesno("Signup", "Press Yes to Signup or No to exit program:")
                if choice:
                    signup_account()
                    return
                else:
                    exit_program()
            messagebox.showinfo("Error", "Username doesn't exist!")
            login_account()

def uname_exists(file_path, keyword):
    line_number = 0
    with open(file_path, 'r') as file:
        for line in file:
            line_number += 1
            if keyword in line:
                return line_number
    return None

def hash_pwd(passwd):
    passwd_bytes = passwd.encode('utf-8')
    hash_obj = hashlib.sha256(passwd_bytes)
    return hash_obj.hexdigest()

def signup_account():
    username = simpledialog.askstring("Signup", "Enter a username:")
    if username:
        if ' ' in username:
            messagebox.showinfo("Error", "Spaces are not allowed in the username.")
            main()
        if not os.path.exists('accounts.txt'):
            open('accounts.txt', 'a').close()
        exists = uname_exists('accounts.txt', username)
        if exists is None:
            passwd = simpledialog.askstring("Signup", "Choose a password:", show='*')
            if passwd:
                hashed_pwd = hash_pwd(passwd)
                with open('accounts.txt', 'a+') as f:
                    f.write(username + "\n")
                    f.write(hashed_pwd + "\n")
                messagebox.showinfo("Success", "Account has been successfully created.")
        else:
            messagebox.showinfo("Error", "Username already exists! Please try again.")
            main()

def generate_pwd():
    x = simpledialog.askinteger("Generate Password", "No. of characters in password:")
    if x:
        symbols = punctuation + ascii_letters + digits
        secure_rand = random.SystemRandom()
        password = "".join(secure_rand.choice(symbols) for i in range(x))
        pyperclip.copy(password)
        messagebox.showinfo("Generated Password", f"Generated password: {password}")
        messagebox.showinfo("Clipboard", "PASSWORD COPIED TO CLIPBOARD...")

def exit_program():
    messagebox.showinfo("Exit", f"Exiting the program at {time.strftime('%X')}...")
    sys.exit(0)

def main():
    root = tk.Tk()
    root.title("SavePass")

    options = [
        ("Sign Up", signup_account),
        ("Login", login_account),
        ("Generate Password", generate_pwd),
        ("Exit", exit_program)
    ]

    for (text, command) in options:
        button = tk.Button(root, text=text, command=command)
        button.pack(fill='x')

    root.mainloop()

if __name__ == "__main__":
    main()
