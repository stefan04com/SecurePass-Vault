import utils.crypto_utils as crypto_utils
import utils.storage_utils as storage_utils
import os
import getpass
import json
import hashlib

def set_up_profile():
    
    while True:
        initial_password = getpass.getpass("Please type your new password: ")
        confirm_password = getpass.getpass("Please confirm your password: ")
        if initial_password != confirm_password:
            print("Passwords do not match. Please try again.")
        else:
            break
    salt = os.urandom(16)
    key = crypto_utils.key_derivation(initial_password, salt)
    key_hash = hashlib.sha256(key).digest()
    profile_data = {
        "salt": salt.hex(),
        "key": key_hash.hex()
    }
    os.makedirs(os.path.dirname("data/profile.json"), exist_ok=True)
    with open("data/profile.json", "w") as f:
        json.dump(profile_data, f)
    return key

def login():
    with open("data/profile.json", "r") as f:
        profile_data = json.load(f)
    salt = bytes.fromhex(profile_data["salt"])
    key = bytes.fromhex(profile_data["key"])
    count = 3
    while count > 0:
        password = getpass.getpass("Please enter your password to log in: ")
        derived_key = crypto_utils.key_derivation(password, salt)
        derived_key_hash = hashlib.sha256(derived_key).digest()
        if derived_key_hash == key:
            print("Login successful!")
            return derived_key
        else:
            print("Incorrect password. Please try again.")
            count -= 1
    print("Too many failed attempts. Exiting.")
    exit(1)

def add_password(master_key):
    print("Add a new password")
    service = input("Enter the service name: ")
    service_password = getpass.getpass(f"Enter the password for '{service}': ")
    encrypted_password, IV, tag = crypto_utils.crypt(service_password, master_key)
    entry_data = {
        "service": service,
        "password": encrypted_password.hex(),
        "IV": IV.hex(),
        "tag": tag.hex()
    }
    password_file = "data/passwords.json"
    entries = storage_utils.load_entries(password_file)
    for entry in entries:
        if entry["service"] == service:
            print(f"Password for '{service}' already exists. Updating the password.")
            entries.remove(entry)
            entries.append(entry_data)
            storage_utils.save_entries(password_file, entries)
            print(f"Password for '{service}' updated successfully.")
            break
    else:
        entries.append(entry_data)
        storage_utils.save_entries(password_file, entries)
        print(f"Password for '{service}' added successfully.")

def view_passwords(master_key):
    password_file = "data/passwords.json"
    entries = storage_utils.load_entries(password_file)
    if not entries:
        print("No passwords stored.")
        return
    print("\nStored Passwords:")
    for entry in entries:
        service = entry["service"]
        encrypted_password = bytes.fromhex(entry["password"])
        IV = bytes.fromhex(entry["IV"])
        tag = bytes.fromhex(entry["tag"])
        decrypted_password = crypto_utils.decrypt(encrypted_password, IV, master_key, tag)
        if decrypted_password:
            print(f"Service: {service}, Password: {decrypted_password}")
        else:
            print(f"Service: {service}, Password: [Decryption failed]")

def main_loop(key):
    while True:
        print("\nPassword Manager Menu:")
        print("1. Add a new password")
        print("2. View stored passwords")
        print("3. Exit")
        choice = input("Please choose an option: ")

        if choice == "1":
            add_password(key)
        elif choice == "2":
            view_passwords(key)
        elif choice == "3":
            print("Exiting the Password Manager. Goodbye!")
            break
        else:
            print("Invalid choice. Please select 1, 2 or 3.")
        

if __name__ == "__main__":
    if not os.path.isfile("data/profile.json"):
        key = set_up_profile()
        main_loop(key)
    else:
        key = login()
        main_loop(key)
