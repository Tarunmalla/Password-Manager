import sys,time,random
import hashlib,pyfiglet,os
import sqlite3
from termcolor import colored
from cryptography.fernet import Fernet
from string import punctuation,ascii_letters,digits
import pyperclip
import signal

def signal_handler(sig,frame):
    exit_program()

signal.signal(signal.SIGINT,signal_handler)
count= count1=count2= 3
def encrypt_pwd(passwd):
    key=Fernet.generate_key()
    fernet = Fernet(key)
    encrypt=fernet.encrypt(passwd.encode())
    return encrypt.decode(),key.decode() #,fernet.decrypt(encrypt).decode()

def  store_pwd(user):
    url=input("Enter website url:")
    uname=input("Enter username:")
    pwd=input("Enter Password:")
    encrypt,key=encrypt_pwd(pwd)
    conn=sqlite3.connect('accounts.db')
    c=conn.cursor()
    c.execute(f"INSERT INTO {user} (website,uname,password,key) VALUES (?,?,?,?)", (url,uname,encrypt,key,))
    conn.commit()
    conn.close()
    time.sleep(1)
    print("Hurray!!Password has been successfully stored...")
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
        pyperclip.copy(Fernet(key).decrypt(pwd).decode())
        print(colored("PASSWORD COPIED TO CLIPBOARD...","green",attrs=['bold']))
        print()
        print("-----------------------------------------------------------------")

def delete_usr(user):
    inp=input("You are going to lose your entire data?[Y/N]:")
    if inp.upper() == 'Y':
        conn=sqlite3.connect('accounts.db')
        c=conn.cursor()
        c.execute("DELETE FROM users where username =?",(user,))
        c.execute(f"DROP TABLE IF EXISTS {user}")
        conn.commit()
        conn.close()
        print(colored("Account has been successfully deleted",'white'))
        exit_program()
    else:
        exit_program()

def delete_entry(user):
    inp=input("Enter your website url:")
    conn=sqlite3.connect('accounts.db')
    c=conn.cursor()
    c.execute(f"DELETE FROM {user} where website =?",(inp,))
    conn.commit()
    conn.close()
    print(colored("Entry has been successfully deleted...",'white'))
    print()

def modify_uname(user):
    print("Modifying a username removes the previous username data and you need to enter the password again!!")
    ch=input("Do you want to continue...[Y/N]:")
    if ch.upper() == 'Y':
        delete_entry(user)
        print()
        print("---------------------Enter Your New Account Details--------------------------")
        store_pwd(user)
    
def modify_pwd(user):
    url=input("Enter website :")
    uname=input("Enter username:")
    pwd=input("Enter the Modified password:")
    pwd1,key1=encrypt_pwd(pwd)
    conn=sqlite3.connect('accounts.db')
    c=conn.cursor()
    c.execute(f"UPDATE {user} SET password=?,key=? WHERE website=? and uname =?",(pwd1,key1,url,uname,))
    conn.commit()
    conn.close()
    print(colored("Password has been successfully modified...",'white'))
    print()

def password_interface(user):
    print(colored(pyfiglet.figlet_format("SavePass"),'red'))
    print(f"Welcome {user},SavePass is open-source project to generate and store passwords using sqlite3")
    while True:
        
        print("1.Store a Password")
        print("2.Retrieve a Password")
        #print("3.Delete Account")
        print("3.Delete an Entry")
        print("4.Modify Password")
        print("5.Modify username")
        print("6.To Exit the Application")
        choice=input("Enter your Choice:")
        if choice == '1':
            store_pwd(user)
        elif choice == '2':
            retrieve_pwd(user)
        elif choice == '3':
            delete_entry(user)
        elif choice == '4':
            modify_pwd(user)
        elif choice == '5':
            modify_uname(user)
        elif choice == '6':
            exit_program()
        else:
            print("Please choose a correct option to continue...")

def check_user(uname):
    
    conn = sqlite3.connect('accounts.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                (username TEXT, password TEXT)''')
    c.execute("SELECT username FROM users where username= ?",(uname,))
    for row in c:
        return row

def change_pwd(user):
    conn=sqlite3.connect('accounts.db')
    c=conn.cursor()
    present=input("Enter your current password:")
    c.execute("SELECT password FROM users where username= ?",(user,))
    if hash_pwd(present) == c.fetchone()[0]:
        while True:
            new=input("Enter your New password:")
            new1=input("Re-enter your New password:")   
            if new == new1:
                c.execute(f"UPDATE users SET password = ? WHERE username=?",(hash_pwd(new),user,))
                print("Password has been successfully modified....")
                conn.commit()
                conn.close()
                exit_program()
            else:
                print("passwords doesn't match!!")
                print("Please Try again...")

def login_account():
    username=input("Username:")
    Passwd=input("Password:")
    if check_user(username) is None :
        global count2
        count2=count2-1
        if count2==0:
            print("No More chances left...")
            exit_program()
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
            print(colored(f"Login Successful at {time.strftime('%X')}.....",'yellow'))
            print()
            while True:
                print("--------------------------------------------------------------------------")
                print("1.Main Menu")
                print("2.Enter into application")
                print("3.Exit application")
                ch=input("Enter your choice:")
                if ch == '1':
                    while True:
                        print("--------------------------------------------------------------------")
                        print("1.Change Password")
                        print("2.Delete Account")
                        print("3.Exit program")
                        ch1=input("Enter your choice:")
                        if ch1 == '1':
                            change_pwd(username)
                        elif ch1 == '2':
                            delete_usr(username)
                        elif ch1 == '3':
                            exit_program()
                        else :
                            print("Enter a proper choice to continue...")
                elif ch == '2':
                    print("Entering into the Application....")
                    time.sleep(1)
                    password_interface(username)
                elif ch == '3':
                    exit_program()
                else :
                    print("Enter a proper choice to continue....")
        else:
            global count1
            count1=count1-1
            if count1==0:
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

def generate_pwd():
    x=int(input("No. of characters in password:"))
    symbols = punctuation + ascii_letters + digits
    secure_rand = random.SystemRandom()
    password = "".join(secure_rand.choice(symbols) for i in range(x))
    pyperclip.copy(password)
    print(f"generated password: {password}")
    print(colored("PASSWORD COPIED TO CLIPBOARD...","green",attrs=['bold']))

def main():
    while(1):
        print(colored('1.Sign Up','red'))
        print(colored('2.Login','red'))
        print(colored('3.Generate Password','red'))
        print(colored('4.exit','red'))
        choice = (input(colored("select a choice:",'blue')))
        if choice == '1' :
            signup_account()
        elif choice == '2' :
            login_account()
            break
        elif choice == '3' :
            generate_pwd()
            break
        elif choice == '4' :
            exit_program()
            break
        else:
            print("---------------------------------------------------------------------")
            print()
            print("Please select a proper choice to continue !!")
            print()
            print("---------------------------------------------------------------------")

if __name__ == "__main__":
    main()