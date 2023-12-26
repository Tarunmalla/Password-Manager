# Savepass

This is a simple multiuser password manager in Python allows you to store,generate and retrieve passwords using file handling and `SQlite3` where main_db.py uses database and main_file uses file handling.
Here,Password is encrypted using `Fernet` storing in the file or the database.Master Password is hashed before storing into the file or database using `SHA256`
The Password is copied to the clipboard while generating a new password or retrieving a password for a simpler usage which is done using `pyperclip`

## Features

- Encrypts the password before storing
- stores the keys securely
- you can use in windows,linux,macos

## run locally

Clone the project

```bash
git clone https://github.com/Tarunmalla/Password-Manager
```

Go to Project directory

```bash
cd Password-Manager
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run the file

```bash
python main_file.py
```
or 

```bash
python main_db.py
```