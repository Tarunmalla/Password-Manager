import sys
import time
import hashlib
import pyfiglet
import os
from termcolor import colored
from cryptography.fernet import Fernet

def encrypt_pwd(passwd):
    key=Fernet.generate_key()
    fernet = Fernet(key)
    with open('passman.txt','a+') as f:
        f.write(key.decode()+"\n")
    # with open ('keys.txt','a+') as f:
    #     f.write(key.decode())
    encrypt=fernet.encrypt(passwd.encode())
    return encrypt.decode() #,fernet.decrypt(encrypt).decode()

def password_interface(user):
    print(colored(pyfiglet.figlet_format("SavePass"),'red'))
    print(f"Welcome {user},SavePass is open-source project to generate and store passwords ")
    while True:
        print("1.Store a Password")
        print("2.Extract a password")
        print("3.Exit the Application")
        choice=int(input("enter your choice:"))
        if choice == 1 :
            print("-------------------------------------------------------")
            print()
            url=input("Website URL:")
            uname=input("Username:")
            passwd=input("Password:")
            encrypt=encrypt_pwd(passwd)
            with open ("passman.txt",'a+') as f:
                f.write(user+"\n")
                f.write(url+"\n")
                f.write(uname+"\n")
                f.write(encrypt+"\n")
            #for seperate files for each one
            # with open('websites.txt','a+') as f1:
            #     f1.write(url+"\n")
            # with open('unames.txt','a+') as f2:
            #     f2.write(uname+"\n")
            # with open('passwd.txt','a+') as f3:
            #     f3.write(encrypt+"\n")
                # f3.write(decrypt)
            
            print("Password has been successfully added")
            print()
            print("-------------------------------------------------------")
        
        if choice == 2 :
            print("----------------------------------------------------------")
            print()
            url=input("enter website url:")
            print()
            line_no=uname_exists('passman.txt',url)
            if line_no is None :
                print("No such entry exists !! Try again")
            else :
                # file1=open('unames.txt')
                # file2=open('passwd.txt')
                # file3=open('keys.txt')
                # content1=file1.readlines()
                # print(f"username:{content1[line_no-1]}")
                # content2=file2.readlines()
                # content3=file3.readlines()
                # decrypt=Fernet(content3[line_no-1]).decrypt(content2[line_no-1]).decode()
                # print(f"Password:{decrypt}")
                file=open('passman.txt')
                content=file.readlines()
                if user == content[line_no-2]:
                    print(f"Username:{content[line_no]}")
                    decrypt=Fernet(content[line_no-3]).decrypt(content[line_no+1]).decode()
                    print(f"Password:{decrypt}")
                else:
                    print("No website found!! Try again")
                print()
                print("--------------------------------------------------------------------")    
        if choice == 3 :
            exit_program()
count=3
count1=3
def login_account():
    print("--------------------------------------------------------------")
    uname=input("Username:")
    if not os.path.exists('accounts.txt') :
        print("Please Signup First!!")
        exit_program()
    line_no = uname_exists('accounts.txt',uname)
    if  line_no is not None :
        passwd=input("Password:")
        hashedpwd=hash_pwd(passwd)
        file=open('passwords.txt')
        content=file.readlines()
        if content[line_no-1] == hashedpwd + "\n" :
            print(f"Login Successful at {time.strftime('%X')}")
            print("entering into the application....")
            time.sleep(1)
            password_interface(uname)
        else :
            global count
            count=count-1
            print(f"You have {count} chances remaining....")
            if count == 0:
                exit_program()
            login_account()
    else :
        global count1
        count1=count1-1
        if count1==0 :
            print("No user Found.Please Signup!!")
            print("------------------------------------------------------------------------")
            while(1):
                choice=input("Press 1 to Signup or 3 to exit Program:")
                if choice == 1:
                    signup_account()
                    break
                elif choice == 3:
                    exit_program()
                else:
                    print("Please enter a proper choice to continue!!")
                    print("------------------------------------------------------------------------")
        print("username doesn't exists!!")
        login_account()



def uname_exists(file_path,keyword):
    line_number=0

    with open(file_path,'r') as file:
        for line in file:
            line_number += 1
            if keyword in line:
                return line_number
    return None


def hash_pwd(passwd):
    passwd_bytes=passwd.encode('utf-8')
    hash_obj=hashlib.sha256(passwd_bytes)
    return hash_obj.hexdigest()  

def signup_account():
    username=input("enter a username:")
    if ' ' in username:
        print("spaces not allowed!!")
        main()
    with open ('accounts.txt','a+'):
        pass
    exists=uname_exists('accounts.txt',username)
    if exists is None :
        passwd = input("choose a password:")
        hashed_pwd=hash_pwd(passwd)
        with open ('accounts.txt','a+') as f:
            f.write(username+"\n")
        with open ('passwords.txt','a+') as ff:
            ff.write(hashed_pwd+"\n")
            print("Account has been successfully created !!")
            exit_program()
    else :
        print("username already exists!!")
        print("Please try again")
        main()
               


def exit_program():
    print(f"exiting the program at {time.strftime('%X')}")
    sys.exit(0)

def main():
    
    while(1):
        print("1.Sign Up")
        print("2.Login")
        print("3.exit")
        choice = (input("select a choice:"))
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