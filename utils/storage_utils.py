import json
import os
import time

LOG_FILE = "data/logs.txt"

def load_entries(file_path):
    if not os.path.isfile(file_path):
        return []
    else:
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
                if isinstance(data, list):
                    return data
                else:
                    print(f"Error: The data in {file_path} is not a list.")
                    return []
        except json.JSONDecodeError:
            print(f"Error reading {file_path}. The file may be corrupted or not in JSON format.")
            return []
        
def save_entries(file_path, entries):
    dir = os.path.dirname(file_path)
    if dir:
        os.makedirs(dir, exist_ok=True)
    try:
        with open(file_path, 'w', encoding='utf-8') as file:
            json.dump(entries, file, indent=4)
    except IOError as e:
        print(f"Error writing to {file_path}: {e}")

def log_event(msg):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    with open(LOG_FILE, 'a', encoding='utf-8') as log_file:
        log_file.write(f"{timestamp} - {msg}\n")