import sqlite3

import os

DB_PATH = "data/vault.db"

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL UNIQUE,
            encrypted_password BLOB NOT NULL,
            iv BLOB NOT NULL,
            tag BLOB NOT NULL
            )
        ''')
        conn.commit()

def add_entry(service, encrypted_password, iv, tag):
    try:
        with sqlite3.connect(DB_PATH, timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO passwords (service, encrypted_password, iv, tag)
                VALUES (?, ?, ?, ?)
            ''', (service, encrypted_password, iv, tag))
            conn.commit()
            return True, f"Password for '{service}' added successfully."
    except sqlite3.IntegrityError:
        return False, f"Service '{service}' already exists."

def get_all_entries():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT service, encrypted_password, iv, tag FROM passwords')
        entries = cursor.fetchall()
        return entries

def delete_entry(service):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM passwords WHERE service = ?', (service,))
        if cursor.rowcount == 0:
            return False, f"Service '{service}' not found."
        conn.commit()
        return True, f"Password for '{service}' deleted successfully."

def update_entry(service, encrypted_password, iv, tag):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE passwords
            SET encrypted_password = ?, iv = ?, tag = ?
            WHERE service = ?
        ''', (encrypted_password, iv, tag, service))
        if cursor.rowcount == 0:
            return False, f"Service '{service}' not found."
        conn.commit()
        return True, f"Password for '{service}' updated successfully."


