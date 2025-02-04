import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet # type: ignore

# Generate and save a key (Run only once)
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

# Load the encryption key
def load_key():
    return open("secret.key", "rb").read()

# Encrypt the selected file
def encrypt_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    key = load_key()
    fernet = Fernet(key)

    with open(file_path, "rb") as file:
        file_data = file.read()

    encrypted_data = fernet.encrypt(file_data)
    
    encrypted_filename = file_path + ".enc"
    with open(encrypted_filename, "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)

    messagebox.showinfo("Success", f"File encrypted successfully!\nSaved as {encrypted_filename}")

# Decrypt the selected file
def decrypt_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    if not file_path.endswith(".enc"):
        messagebox.showerror("Error", "Please select an encrypted (.enc) file!")
        return

    key = load_key()
    fernet = Fernet(key)

    with open(file_path, "rb") as encrypted_file:
        encrypted_data = encrypted_file.read()

    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except:
        messagebox.showerror("Error", "Decryption failed! Wrong key?")
        return

    original_filename = file_path.replace(".enc", "")
    with open(original_filename, "wb") as decrypted_file:
        decrypted_file.write(decrypted_data)

    messagebox.showinfo("Success", f"File decrypted successfully!\nRestored as {original_filename}")

# GUI Setup
root = tk.Tk()
root.title("File Encryptor & Decryptor")
root.geometry("400x300")

tk.Label(root, text="File Encryptor & Decryptor", font=("Arial", 14, "bold")).pack(pady=10)

encrypt_btn = tk.Button(root, text="Encrypt File", command=encrypt_file, width=20, bg="lightblue")
encrypt_btn.pack(pady=10)

decrypt_btn = tk.Button(root, text="Decrypt File", command=decrypt_file, width=20, bg="lightgreen")
decrypt_btn.pack(pady=10)

root.mainloop()
