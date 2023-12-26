import sys,time,os
import hashlib
import pyfiglet
from termcolor import colored
from cryptography.fernet import Fernet
from string import punctuation,ascii_letters,digits
import pyperclip
import random

def encrypt_pwd(passwd):
    key=Fernet.generate_key()
    fernet = Fernet(key)
    with open('passman.txt','a+') as f:
        f.write(key.decode()+"\n")
    # with open ('keys.txt','a+') as f:
    #     f.write(key.decode())
    encrypt=fernet.encrypt(passwd.encode())
    return encrypt.decode() #,fernet.decrypt(encrypt).decode()

def exists_list(file_path,keyword):
    lines=[]
    line_number=1
    with open(file_path,'r') as file:
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


def password_interface(user):
    print(colored(pyfiglet.figlet_format("SavePass"),'red'))
    print(f"Welcome {user.upper()},SavePass is open-source project to generate and store passwords ")
    print()
    while True:
        print("1.Store a Password")
        print("2.Extract a password")
        print("3.Delete an Account")
        print("4.Exit the Application")
        print("--------------------------------------------------------------------")  
        choice=input("enter your choice:")
        if choice == '1' :
            url=input("Website URL:")
            uname=input("Username:")
            passwd=input("Password:")
            encrypt=encrypt_pwd(passwd)
            with open ("passman.txt",'a+') as f:
                f.write(user+"\n")
                f.write(url+"\n")
                f.write(uname+"\n")
                f.write(encrypt+"\n")       
            print("Password has been successfully added")
            print()
            print("--------------------------------------------------------------------")
        
        elif choice == '2' :
            print("--------------------------------------------------------------------")
            print()
            url=input("enter website url:")
            print()
            line_no=uname_exists('passman.txt',url)
            if line_no is None :
                print("No such entry exists !! Try again")
            else :
                file=open('passman.txt')
                content=file.readlines()
                if user +"\n" == content[line_no-2]:
                    print(f"Username:{content[line_no]}")
                    decrypt=Fernet(content[line_no-3]).decrypt(content[line_no+1]).decode()
                    print(f"Password:{decrypt}")
                    pyperclip.copy(decrypt)
                    print(colored("PASSWORD COPIED TO CLIPBOARD...","green",attrs=['bold']))
                else:
                    print("No website found!! Try again")
                print()
                print("--------------------------------------------------------------------")   

        elif choice == '3':
            inp=input("You are going to lose your entire data[Y/N]:")
            if inp.upper() == 'Y':
                linn=exists_list('accounts.txt',user)
                y=[]
                for i in linn:
                   y.append(i-1)
                   y.append(i)
                delete_lines('accounts.txt',y)
                comp=exists_list('passman.txt',user)
                print(comp)
                x=[]
                for i in comp : 
                   x.append(i-2)#removing key
                   x.append(i-1)#removing user
                   x.append(i)#removing url
                   x.append(i+1)#removing uname
                   x.append(i+2)#removing pwd
                print(x)
                delete_lines('passman.txt',x)
                print("Your Account has been successfully deleted!!")
                exit_program()
        elif choice == '4' :
            exit_program()
        else:
            print("Please Choose a proper option to continue...")
            print("--------------------------------------------------------------------")  
        
count=3
count1=3
def login_account():
    uname=input("Username:")
    if not os.path.exists('accounts.txt') :
        print("Please Signup First!!")
        exit_program()
    line_no = uname_exists('accounts.txt',uname)
    if  line_no is not None :
        passwd=input("Password:")
        hashedpwd=hash_pwd(passwd)
        file=open('accounts.txt')
        content=file.readlines()
        if content[line_no] == hashedpwd + "\n" :
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
            f.write(hashed_pwd+"\n")
            print("Account has been successfully created !!")
            print("--------------------------------------------------------------------")  
    else :
        print("username already exists!!")
        print("Please try again")
        main()
               
def generate_pwd():
    x=int(input("No. of characters in password:"))
    symbols = punctuation + ascii_letters + digits
    secure_rand = random.SystemRandom()
    password = "".join(secure_rand.choice(symbols) for i in range(x))
    pyperclip.copy(password)
    print(f"generated password;{password}")
    print(colored("PASSWORD COPIED TO CLIPBOARD...","green",attrs=['bold']))

def exit_program():
    print(colored(f"exiting the program at {time.strftime('%X')}.....",'yellow'))
    sys.exit(0)

def main():
    while(1):
        print(colored('1.Sign Up','red'))
        print(colored('2.Login','red'))
        print(colored('3.Generate Password','red'))
        print(colored('4.exit','red'))
        print("--------------------------------------------------------------------")  
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