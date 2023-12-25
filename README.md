# Savepass

This is a simple multiuser password manager in Python allows you to store passwords using file handling and sqlite3 where main_db.py uses database and main_file uses file handling.

Here,Password is encrypted before storing in the file or the database.

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