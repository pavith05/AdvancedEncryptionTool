# AES-256 File Encryption & Decryption Tool
# User-friendly desktop application using Python and Tkinter

import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import secrets

# ---------- CRYPTO FUNCTIONS ----------

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=salt,
        iterations=200000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        data = f.read()

    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)

    encrypted = aesgcm.encrypt(nonce, data, None)

    output_file = file_path + ".enc"
    with open(output_file, 'wb') as f:
        f.write(salt + nonce + encrypted)

    return output_file

def decrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        data = f.read()

    salt = data[:16]
    nonce = data[16:28]
    encrypted = data[28:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    decrypted = aesgcm.decrypt(nonce, encrypted, None)

    output_file = file_path.replace(".enc", "")
    with open(output_file, 'wb') as f:
        f.write(decrypted)

    return output_file

# ---------- GUI ----------

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Encryption Tool (AES-256)")
        self.root.geometry("420x260")
        self.file_path = ""

        tk.Label(root, text="AES-256 File Encryption Tool",
                 font=("Arial", 14, "bold")).pack(pady=10)

        tk.Button(root, text="Select File", width=20,
                  command=self.select_file).pack(pady=5)

        self.file_label = tk.Label(root, text="No file selected", wraplength=380)
        self.file_label.pack(pady=5)

        tk.Label(root, text="Password:").pack()
        self.password_entry = tk.Entry(root, show="*", width=30)
        self.password_entry.pack(pady=5)

        tk.Button(root, text="Encrypt", width=15,
                  command=self.encrypt).pack(pady=5)

        tk.Button(root, text="Decrypt", width=15,
                  command=self.decrypt).pack(pady=5)

    def select_file(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            self.file_label.config(text=self.file_path)

    def encrypt(self):
        if not self.file_path or not self.password_entry.get():
            messagebox.showwarning("Error", "Select a file and enter password")
            return
        try:
            output = encrypt_file(self.file_path, self.password_entry.get())
            messagebox.showinfo("Success", f"Encrypted file:\n{output}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt(self):
        if not self.file_path or not self.password_entry.get():
            messagebox.showwarning("Error", "Select a file and enter password")
            return
        try:
            output = decrypt_file(self.file_path, self.password_entry.get())
            messagebox.showinfo("Success", f"Decrypted file:\n{output}")
        except Exception:
            messagebox.showerror("Error", "Wrong password or corrupted file")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
