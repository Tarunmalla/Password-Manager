import sys
import time
import random
import hashlib
import os
import sqlite3
import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
from string import punctuation, ascii_letters, digits
import pyperclip

def encrypt_pwd(passwd):
    key = Fernet.generate_key()
    fernet = Fernet(key)
    encrypt = fernet.encrypt(passwd.encode())
    return encrypt.decode(), key.decode()

def store_pwd(user, url, uname, pwd):
    encrypt, key = encrypt_pwd(pwd)
    conn = sqlite3.connect('accounts.db')
    c = conn.cursor()
    c.execute(f"INSERT INTO {user} (website, uname, password, key) VALUES (?, ?, ?, ?)", (url, uname, encrypt, key,))
    conn.commit()
    conn.close()
    messagebox.showinfo("Success", "Password has been successfully stored!")

def retrieve_pwd(user, url):
    conn = sqlite3.connect('accounts.db')
    c = conn.cursor()
    c.execute(f"SELECT * FROM {user} WHERE website = ?", (url,))
    result = c.fetchone()
    if result is None:
        messagebox.showerror("Error", "No such record found!")
    else:
        uname = result[1]
        pwd = result[2]
        key = result[3]
        decrypted_pwd = Fernet(key).decrypt(pwd.encode()).decode()
        pyperclip.copy(decrypted_pwd)
        messagebox.showinfo("Password Retrieved", f"Username: {uname}\nPassword: {decrypted_pwd}\nPassword copied to clipboard!")

def delete_entry(user, url):
    conn = sqlite3.connect('accounts.db')
    c = conn.cursor()
    c.execute(f"DELETE FROM {user} WHERE website = ?", (url,))
    conn.commit()
    conn.close()
    messagebox.showinfo("Success", "Entry has been successfully deleted!")

def modify_pwd(user, url, uname, new_pwd):
    pwd, key = encrypt_pwd(new_pwd)
    conn = sqlite3.connect('accounts.db')
    c = conn.cursor()
    c.execute(f"UPDATE {user} SET password = ?, key = ? WHERE website = ? AND uname = ?", (pwd, key, url, uname,))
    conn.commit()
    conn.close()
    messagebox.showinfo("Success", "Password has been successfully modified!")

def check_user(uname):
    conn = sqlite3.connect('accounts.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)''')
    c.execute("SELECT username FROM users WHERE username = ?", (uname,))
    return c.fetchone()

def change_pwd(user, current_pwd, new_pwd):
    conn = sqlite3.connect('accounts.db')
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username = ?", (user,))
    if hash_pwd(current_pwd) == c.fetchone()[0]:
        c.execute(f"UPDATE users SET password = ? WHERE username = ?", (hash_pwd(new_pwd), user,))
        conn.commit()
        conn.close()
        messagebox.showinfo("Success", "Password has been successfully modified!")
    else:
        messagebox.showerror("Error", "Current password is incorrect!")

def hash_pwd(passwd):
    passwd_bytes = passwd.encode('utf-8')
    hash_obj = hashlib.sha256(passwd_bytes)
    return hash_obj.hexdigest()

def signup_account(username, password):
    if check_user(username) is None:
        hashed_pwd = hash_pwd(password)
        conn = sqlite3.connect('accounts.db')
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pwd))
        c.execute(f'''CREATE TABLE IF NOT EXISTS {username} (website TEXT, uname TEXT, password TEXT, key TEXT)''')
        conn.commit()
        conn.close()
        messagebox.showinfo("Success", "Account has been successfully created!")
    else:
        messagebox.showerror("Error", "Username already exists!")

def login_account(username, password):
    if check_user(username) is None:
        messagebox.showerror("Error", "No such user found!")
    else:
        hashed_pwd = hash_pwd(password)
        conn = sqlite3.connect('accounts.db')
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        if c.fetchone()[0] == hashed_pwd:
            messagebox.showinfo("Success", f"Login Successful at {time.strftime('%X')}")
            password_interface(username)
        else:
            messagebox.showerror("Error", "Incorrect password!")

def generate_pwd(length):
    symbols = punctuation + ascii_letters + digits
    secure_rand = random.SystemRandom()
    password = "".join(secure_rand.choice(symbols) for i in range(length))
    pyperclip.copy(password)
    messagebox.showinfo("Generated Password", f"Generated password: {password}\nPassword copied to clipboard!")

def password_interface(user):
    interface = tk.Tk()
    interface.title("SavePass")

    def store():
        url = url_entry.get()
        uname = uname_entry.get()
        pwd = pwd_entry.get()
        store_pwd(user, url, uname, pwd)

    def retrieve():
        url = url_entry.get()
        retrieve_pwd(user, url)

    def delete():
        url = url_entry.get()
        delete_entry(user, url)

    def modify():
        url = url_entry.get()
        uname = uname_entry.get()
        new_pwd = pwd_entry.get()
        modify_pwd(user, url, uname, new_pwd)

    tk.Label(interface, text="Website URL:").grid(row=0, column=0)
    tk.Label(interface, text="Username:").grid(row=1, column=0)
    tk.Label(interface, text="Password:").grid(row=2, column=0)

    url_entry = tk.Entry(interface)
    uname_entry = tk.Entry(interface)
    pwd_entry = tk.Entry(interface, show='*')

    url_entry.grid(row=0, column=1)
    uname_entry.grid(row=1, column=1)
    pwd_entry.grid(row=2, column=1)

    tk.Button(interface, text="Store Password", command=store).grid(row=3, column=0)
    tk.Button(interface, text="Retrieve Password", command=retrieve).grid(row=3, column=1)
    tk.Button(interface, text="Delete Entry", command=delete).grid(row=4, column=0)
    tk.Button(interface, text="Modify Password", command=modify).grid(row=4, column=1)
    tk.Button(interface, text="Exit", command=interface.destroy).grid(row=5, column=0, columnspan=2)

    interface.mainloop()

def main():
    root = tk.Tk()
    root.title("SavePass")

    def signup():
        username = username_entry.get()
        password = password_entry.get()
        signup_account(username, password)

    def login():
        username = username_entry.get()
        password = password_entry.get()
        login_account(username, password)

    def generate():
        length = int(password_length_entry.get())
        generate_pwd(length)

    tk.Label(root, text="Username:").grid(row=0, column=0)
    tk.Label(root, text="Password:").grid(row=1, column=0)

    username_entry = tk.Entry(root)
    password_entry = tk.Entry(root, show='*')

    username_entry.grid(row=0, column=1)
    password_entry.grid(row=1, column=1)

    tk.Button(root, text="Sign Up", command=signup).grid(row=2, column=0)
    tk.Button(root, text="Login", command=login).grid(row=2, column=1)
    
    tk.Label(root, text="Password Length:").grid(row=3, column=0)
    password_length_entry = tk.Entry(root)
    password_length_entry.grid(row=3, column=1)
    
    tk.Button(root, text="Generate Password", command=generate).grid(row=4, column=0, columnspan=2)
    tk.Button(root, text="Exit", command=root.destroy).grid(row=5, column=0, columnspan=2)

    root.mainloop()

if __name__ == "__main__":
    main()
