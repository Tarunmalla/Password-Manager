import sys
import time
import hashlib
import pyfiglet
import os
import sqlite3
from termcolor import colored
from cryptography.fernet import Fernet

count= count1= 3
def encrypt_pwd(user,passwd):
    key=Fernet.generate_key()
    fernet = Fernet(key)
    encrypt=fernet.encrypt(passwd.encode())
    return encrypt.decode(),key.decode() #,fernet.decrypt(encrypt).decode()

def  store_pwd(user):
    url=input("Enter website url:")
    uname=input("Enter username:")
    pwd=input("Enter Password:")
    encrypt,key=encrypt_pwd(user,pwd)
    conn=sqlite3.connect('accounts.db')
    c=conn.cursor()
    c.execute(f"INSERT INTO {user} (website,uname,password,key) VALUES (?,?,?,?)", (url,uname,encrypt,key,))
    conn.commit()
    conn.close()
    print("---------------------------------------------------------------------------")

def retrieve_pwd(user):
    print("----------------------------------------------------------------------------")
    print()
    url=input("Enter website url:")
    conn=sqlite3.connect('accounts.db')
    c=conn.cursor()
    c.execute(f"SELECT * FROM {user} WHERE website = ?", (url,))
    result=c.fetchone()
    if result is None :
        print("No such record found!!")
    else:
        print(f"username:{result[1]}")
        pwd=result[2]
        key=result[3]
        print(f"password:{Fernet(key).decrypt(pwd).decode()}")
        print()
        print("-----------------------------------------------------------------")
def password_interface(user):
    print(colored(pyfiglet.figlet_format("SavePass"),'red'))
    print(f"Welcome {user},SavePass is open-source project to generate and store passwords using sqlite3")
    while True:
        
        print("1.Store a Password")
        print("2.Retrieve a Password")
        print("3.To Exit the Application")
        choice=input("Enter your Choice:")
        if choice == '1':
            store_pwd(user)
        elif choice == '2':
            retrieve_pwd(user)
        elif choice == '3':
            exit_program()
        else:
            print("Please choose a correct option to continue...")

def check_user(uname):
    conn = sqlite3.connect('accounts.db')
    c = conn.cursor()
    c.execute("SELECT username FROM users where username= ?",(uname,))
    for row in c:
        return row

def login_account():
    username=input("Username:")
    Passwd=input("Password:")
    if check_user(username) is None :
        print("No Such User Found!!")
        print("Please Try again!!")
        print("---------------------------------------------------------------------")
        login_account()
    else:
        hashed_pwd = hash_pwd(Passwd)
        conn = sqlite3.connect('accounts.db')
        c = conn.cursor()
        c.execute("SELECT password FROM users where username= ?",(username,))
        if c.fetchone()[0] == hashed_pwd:
            print("Login Successful")
            print("Entering into the Application....")
            password_interface(username)
        else:
            global count1
            count1=count1-1
            if count1<0:
                print("No More chances left...")
                exit_program()
            else:
                print("Incorrect Password!! Try again....")
                print(f"You have {count1} chances remaining")
                login_account()

def hash_pwd(passwd):
    passwd_bytes=passwd.encode('utf-8')
    hash_obj=hashlib.sha256(passwd_bytes)
    return hash_obj.hexdigest()  

def signup_account():
    username = input("Enter a username: ")
    conn = sqlite3.connect('accounts.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                (username TEXT, password TEXT)''')
    conn.commit()
    conn.close()
    c=check_user(username)
    if c is None:
        passwd = input("Choose a password: ")
        hashed_pwd = hash_pwd(passwd)
        conn = sqlite3.connect('accounts.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users
                    (username TEXT, password TEXT)''')
        
        c.execute(f'''CREATE TABLE IF NOT EXISTS {username}
                    (website TEXT, uname TEXT, password TEXT,key TEXT)''')
        c.execute("INSERT INTO users VALUES (?, ?)", (username, hashed_pwd))
        conn.commit()
        conn.close()
    else :
        global count
        count=count-1
        if count < 0:
            exit_program() 
        print("UserName Already Exists !!")
        print("Please Try Again...")
        signup_account()

def exit_program():
    print(colored(f"exiting the program at {time.strftime('%X')}.....",'yellow'))
    sys.exit(0)

def main():
    
    while(1):
        print(colored('1.Sign Up','red'))
        print(colored('2.Login','red'))
        print(colored('3.exit','red'))
        choice = (input(colored("select a choice:",'blue')))
        if choice == '1' :
            signup_account()
            break
        elif choice == '2' :
            login_account()
            break
        elif choice == '3' :
            exit_program()
            break
        else:
            print("---------------------------------------------------------------------")
            print()
            print("Please select a proper choice to continue !!")
            print()
            print("---------------------------------------------------------------------")

main()