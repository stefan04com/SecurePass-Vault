import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import cryptography
import getpass
import hashlib



def key_derivation(password, salt):
    password = password.encode('utf-8')

    key = hashlib.pbkdf2_hmac(
        hash_name='sha256',
        password=password,
        salt=salt,
        iterations=600_000
    )

    return key

def crypt(password, key):
    IVector = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.GCM(IVector))
    encryptor = cipher.encryptor()

    ct = encryptor.update(password.encode('utf-8')) + encryptor.finalize()
    return ct, IVector, encryptor.tag

def decrypt(c_text, IV, key, tag):
    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(IV, tag))
        decryptor = cipher.decryptor()

        dt = decryptor.update(c_text) + decryptor.finalize()

        dt = dt.decode('utf-8')
        return dt
    except cryptography.exceptions.InvalidTag:
        print('Data has been corrupted or wrong key used')
        return None

if __name__ == "__main__":
    initial_password = getpass.getpass("Type password: ")
    salt = os.urandom(16)
    with open("data/salt.txt", "w") as f:
        f.write(salt.hex()) 

    key = key_derivation(initial_password, salt)
    print("\n--- Criptare ---")
    ciphertext, iv, tag = crypt(initial_password, key)
    print("Ciphertext (hex):", ciphertext.hex())
    print("IV (hex):", iv.hex())

    print("\n--- Decriptare ---")
    decrypted_password = decrypt(ciphertext, iv, key, tag)
    print("Parola decriptată:", decrypted_password)
