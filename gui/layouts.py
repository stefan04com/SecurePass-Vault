import FreeSimpleGUIQt as sg
import utils.crypto_utils as crypto_utils

layout_set_up_profile = [
    [sg.Text("Set Up Your Profile")],
    [sg.Text("Password:"), sg.InputText(key="password", password_char='*')],
    [sg.Text("Confirm Password:"), sg.InputText(key="confirm_password", password_char='*')],
    [sg.Button("Create Profile", size=(10, 1), pad=(0, 10))],
    [sg.Text('', size=(1, 4))],
    [sg.Button("Exit", size=(10, 1), pad=(0, 10))]
]

layout_login = [
    [sg.Text("Password:"), sg.InputText(key="password", password_char='*')],
    [sg.Button("Login", size=(10, 1), pad=(0, 10))],
    [sg.Text('', size=(1, 4))],
    [sg.Button("Exit", size=(10, 1), pad=(0, 10))]
]

def layout_password_manager():
    return [
        [sg.Text("Password Manager Menu")],
        [sg.Button("Add a new password", size=(20, 1))],
        [sg.Button("View stored passwords", size=(20, 1))],
        [sg.Button("Delete Password", size=(20, 1))],
        [sg.Button("Change Password", size=(20, 1))],
        [sg.Button("Exit", size=(20, 1))]
    ]


def layout_add_password():
    return [
        [sg.Text("Add New Password")],
        [sg.Text("Service:"), sg.InputText(key="service")],
        [sg.Button("Generate Strong Password", size=(20, 1), pad=(0, 10))],
        [sg.Text("Password:"), sg.InputText(key="password", password_char='*')],
        [sg.Button("Save Password", size=(10, 1), pad=(0, 10))],
        [sg.Button("Back", size=(10, 1), pad=(0, 10))],
        [sg.Text('', size=(1, 4))],
        [sg.Button("Exit", size=(10, 1), pad=(0, 10))]
    ]

def layout_view_passwords(entries, key):
    layout = []

    for i, entry in enumerate(entries):
        service = entry[0]
        enc_password = entry[1]
        IV = entry[2]
        tag = entry[3]

        decrypted_password = crypto_utils.decrypt(enc_password, IV, key, tag)

        layout.append([
            sg.Text(f"Service: {service}", size=(15, 1)),
            sg.Text(f"Password: {decrypted_password}", size=(25, 1)),
            sg.Button("Copy", key=f"Copy_{i}", size=(6, 1))
        ])

    layout.append([sg.Button("Back")])
    return layout


def layout_delete_password():
    return [
        [sg.Text("Delete Password")],
        [sg.Text("Service:"), sg.InputText(key="service")],
        [sg.Button("Delete", size=(10, 1), pad=(0, 10))],
        [sg.Button("Back", size=(10, 1), pad=(0, 10))],
        [sg.Text('', size=(1, 4))],
        [sg.Button("Exit", size=(10, 1), pad=(0, 10))]
    ]

def layout_change_password():
    return [
        [sg.Text("Change Password")],
        [sg.Text("Service:"), sg.InputText(key="service")],
        [sg.Text("New Password:"), sg.InputText(key="password", password_char='*')],
        [sg.Text("Confirm New Password:"), sg.InputText(key="confirm_password", password_char='*')],
        [sg.Button("Update Password", size=(10, 1), pad=(0, 10))],
        [sg.Button("Back", size=(10, 1), pad=(0, 10))],
        [sg.Text('', size=(1, 4))],
        [sg.Button("Exit", size=(10, 1), pad=(0, 10))]
    ]
