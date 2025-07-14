import FreeSimpleGUIQt as sg
import utils.crypto_utils as crypto_utils
import utils.storage_utils as storage_utils
import gui.layouts as layouts
import utils.database as db_utils
import os
import pyperclip
import time
import threading
import json
import hashlib
import secrets
import string

count = 3
key = None
profile_path = "data/profile.json"
INACTIVITY_LIMIT = 60 * 5
last_activity_time = time.time()

# Button actions and logic
###############################################################################
def set_up_profile(window):
    password = values["password"]
    confirm_password = values["confirm_password"]
    if not password or not confirm_password:
        sg.popup_error("Please enter a password and confirm it.")
        return None, window
    if password != confirm_password:
        sg.popup_error("Passwords do not match! Please try again.")
        window["password"].update('')
        window["confirm_password"].update('')
        return None, window
    else:
        salt = os.urandom(16)
        key = crypto_utils.key_derivation(password, salt)
        key_hash = hashlib.sha256(key).digest()
        profile_data = {
            "salt": salt.hex(),
            "key": key_hash.hex()
        }
        os.makedirs(os.path.dirname(profile_path), exist_ok=True)
        with open(profile_path, "w") as f:
            json.dump(profile_data, f)
        return key, window


def login(window):
    global count
    with open(profile_path, "r") as f:
        profile_data = json.load(f)
    salt = bytes.fromhex(profile_data["salt"])
    key = bytes.fromhex(profile_data["key"])

    password = values["password"]
    derived_key = crypto_utils.key_derivation(password, salt)
    derived_key_hash = hashlib.sha256(derived_key).digest()

    if derived_key_hash == key:
        sg.popup("Login successful!")
        window.close()
        new_window = sg.Window("Password Manager", layouts.layout_password_manager(), size=(300, 200))
        return derived_key, new_window, "password_manager"
    else:
        count -= 1
        if count > 0:
            sg.popup_error(f"Incorrect password. {count} attempts left.")
            window["password"].update('')
        else:
            sg.popup_error("Too many failed attempts. Exiting.")
            exit(1)
        return None, window, "login"

def save_password(window, values, key):
    service = values.get("service", "").strip()
    password = values.get("password", "").strip()

    if not service:
        sg.popup_error("Please enter a service name.")
        return window, "add_password"

    if not password:
        sg.popup_error("Please enter a password.")
        return window, "add_password"

    encrypted_password, IV, tag = crypto_utils.crypt(password, key)
    success, message = db_utils.add_entry(service, encrypted_password, IV, tag)
    
    if not success:
        sg.popup_error(message)
        return window, "add_password"

    sg.popup(message)
    window.close()
    return sg.Window("Password Manager", layouts.layout_password_manager(), size=(300, 200)), "password_manager"

def save_generated_password(window, values, key):
    service = values.get("service", "").strip()
    
    if not service:
        sg.popup_error("Please enter a service name.")
        return window, "add_password"

    password = generate_strong_password()
    encrypted_password, IV, tag = crypto_utils.crypt(password, key)
    success, message = db_utils.add_entry(service, encrypted_password, IV, tag)

    if not success:
        sg.popup_error(message)
        return window, "add_password"

    sg.popup(message)
    window.close()
    return sg.Window("Password Manager", layouts.layout_password_manager(), size=(300, 200)), "password_manager"

def handle_copy_password(entries, events):
    index = int(events.split("_")[1])
    service, enc_password, iv, tag = entries[index]

    decrypted_password = crypto_utils.decrypt(enc_password, iv, key, tag)
    pyperclip.copy(decrypted_password)
    sg.popup("Password copied to clipboard. It will be cleared in 30 seconds.")

    threading.Thread(target=clear_clipboard_after_delay, args=(30,), daemon=True).start()

def handle_change_password(window, values, key):
    service = values.get("service", "").strip()
    new_password = values.get("password", "").strip()
    confirm_password = values.get("confirm_password", "").strip()

    if not new_password or not confirm_password:
        sg.popup_error("Please enter a new password and confirm it.")
        return window, "change_password"
    
    if new_password != confirm_password:
        sg.popup_error("Passwords do not match! Please try again.")
        window["password"].update('')
        window["confirm_password"].update('')
        return window, "change_password"
    
    encrypted_password, IV, tag = crypto_utils.crypt(new_password, key)
    success, message = db_utils.update_entry(service, encrypted_password, IV, tag)

    if success:
        sg.popup(message)
        window.close()
        window = sg.Window("Password Manager", layouts.layout_password_manager(), size=(300, 200))
        return window, "password_manager"
    else:
        sg.popup_error(message)
        return window, "change_password"
    
def handle_delete_password(window, values):
    service = values.get("service", "").strip()
    state = "delete_password"

    if not service:
        sg.popup_error("Please enter a service name to delete.")
        return window, state
    
    success, message = db_utils.delete_entry(service)
    if success:
        sg.popup(message)
        window.close()
        window = sg.Window("Password Manager", layouts.layout_password_manager(), size=(300, 200))
        state = "password_manager"
        storage_utils.log_event(f"User deleted password for service '{service}'.")
    else:
        storage_utils.log_event(f"Failed to delete password for service '{service}': {message}")
        sg.popup_error(message)
    
    
    
    return window, state

def clear_clipboard_after_delay(delay=30):
    time.sleep(delay)
    pyperclip.copy("")

def generate_strong_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

# Main application loop
###############################################################################
if __name__ == "__main__":
    db_utils.init_db()
    if not os.path.isfile(profile_path):
        window = sg.Window("Password Manager", layouts.layout_set_up_profile, size=(300, 200))
        state = "set_up_profile"
    else:
        window = sg.Window("Password Manager", layouts.layout_login, size=(300, 200))
        state = "login"

    while True:
        events, values = window.read(timeout=1000)
        if events == sg.WIN_CLOSED:
            storage_utils.log_event("Application closed by user.")
            break

        match events:
            case "Exit":
                storage_utils.log_event("Application exited.")
                break

            case "Create Profile":
                key, window = set_up_profile(window)
                if key:
                    window.close()
                    window = sg.Window("Password Manager", layouts.layout_password_manager(), size=(300, 200))
                    storage_utils.log_event("Profile created successfully.")
                    state = "password_manager"

            case "Login":
                key, window, new_state = login(window)
                storage_utils.log_event("User attempted to log in.")
                if key:
                    storage_utils.log_event("Login successful.")
                state = new_state

            case "Add a new password":
                window.close()
                window = sg.Window("Add New Password", layouts.layout_add_password(), size=(300, 200))
                state = "add_password"

            case "Generate Strong Password":
                window, state = save_generated_password(window, values, key)
                storage_utils.log_event("User generated a strong password.")

            case "Save Password":
                window, state = save_password(window, values, key)
                storage_utils.log_event(f"User saved a new password for {values['service']}.")

            case "Back":
                window.close()
                window = sg.Window("Password Manager", layouts.layout_password_manager(), size=(300, 200))
                state = "password_manager"

            case "View stored passwords":
                entries = db_utils.get_all_entries()
                window.close()
                window = sg.Window("View Stored Passwords", layouts.layout_view_passwords(entries, key), size=(300, 200))
                storage_utils.log_event("User viewed stored passwords.")
                state = "view_passwords"

            case "Delete Password":
                window.close()
                window = sg.Window("Delete Password", layouts.layout_delete_password(), size=(300, 200))
                state = "delete_password"

            case "Delete":
                window, state = handle_delete_password(window, values)

            case "Change Password":
                window.close()
                window = sg.Window("Change Password", layouts.layout_change_password(), size=(300, 200))
                state = "change_password"

            case "Update Password":
                window, state = handle_change_password(window, values, key)
                storage_utils.log_event(f"User changed a password for {values['service']}.")

        if events.startswith("Copy_"):
            entries = db_utils.get_all_entries()
            handle_copy_password(entries, events)
            storage_utils.log_event(f"User copied password for service '{entries[int(events.split('_')[1])][0]}'.")

        if events != "__TIMEOUT__":
            last_activity_time = time.time()
        if time.time() - last_activity_time > INACTIVITY_LIMIT:
            sg.popup("You have been inactive for too long. Please restart the application.")
            storage_utils.log_event("Application closed due to inactivity.")
            break

    window.close()