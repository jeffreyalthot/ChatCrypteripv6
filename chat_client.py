import socket
import threading
import customtkinter as ctk
from tkinter import messagebox
from cryptography.fernet import Fernet
import base64
import hashlib

# Convertir la clé personnalisée en une clé Fernet valide
def generate_fernet_key_from_custom_key(custom_key: str) -> bytes:
    hash_object = hashlib.sha256(custom_key.encode())
    key = base64.urlsafe_b64encode(hash_object.digest())
    return key

# Clé personnalisée
custom_key = "ELIT21"
key = generate_fernet_key_from_custom_key(custom_key)
cipher_suite = Fernet(key)

# Variables globales
client_socket = None
username = ""

def connect_to_server(ipv6_address):
    global client_socket
    client_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    client_socket.connect((ipv6_address, 5555))

def register_user():
    global client_socket
    username = reg_user_entry.get()
    password = reg_pass_entry.get()
    if username and password:
        message = f"REGISTER {username} {password}"
        encrypted_message = cipher_suite.encrypt(message.encode("utf-8"))
        client_socket.send(encrypted_message)
        response = client_socket.recv(1024)
        decrypted_response = cipher_suite.decrypt(response).decode("utf-8")
        messagebox.showinfo("Réponse du serveur", decrypted_response)
        if "Inscription réussie" in decrypted_response:
            show_login_screen()
    else:
        messagebox.showerror("Erreur", "Veuillez entrer un nom d'utilisateur et un mot de passe.")

def login_user():
    global client_socket, username
    username = login_user_entry.get()
    password = login_pass_entry.get()
    if username and password:
        message = f"LOGIN {username} {password}"
        encrypted_message = cipher_suite.encrypt(message.encode("utf-8"))
        client_socket.send(encrypted_message)
        response = client_socket.recv(1024)
        decrypted_response = cipher_suite.decrypt(response).decode("utf-8")
        if "Connexion réussie" in decrypted_response:
            messagebox.showinfo("Réponse du serveur", decrypted_response)
            show_chat_interface()
            threading.Thread(target=receive_messages, daemon=True).start()  # Daemon thread
        else:
            messagebox.showerror("Erreur", decrypted_response)
    else:
        messagebox.showerror("Erreur", "Veuillez entrer un nom d'utilisateur et un mot de passe.")

def send_message():
    global client_socket
    message = entry_box.get()
    if message:
        encrypted_message = cipher_suite.encrypt(f"MESSAGE {message}".encode("utf-8"))
        client_socket.send(encrypted_message)
        entry_box.delete(0, ctk.END)

def receive_messages():
    global client_socket
    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            if encrypted_message:
                message = cipher_suite.decrypt(encrypted_message).decode("utf-8")
                window.after(0, update_chat_box, message)  # Planifie la mise à jour du chat_box
        except ConnectionResetError:
            break

def update_chat_box(message):
    chat_box.configure(state=ctk.NORMAL)
    chat_box.insert(ctk.END, message + "\n")
    chat_box.configure(state=ctk.DISABLED)

def show_login_screen():
    reg_frame.pack_forget()
    login_frame.pack(fill="both", expand=True)

def show_register_screen():
    login_frame.pack_forget()
    reg_frame.pack(fill="both", expand=True)

def show_chat_interface():
    login_frame.pack_forget()
    chat_frame.pack(fill="both", expand=True)
    update_user_list()

def update_user_list():
    global client_socket, user_frame
    client_socket.send(cipher_suite.encrypt(b"GET_USERS"))
    response = client_socket.recv(1024)
    decrypted_response = cipher_suite.decrypt(response).decode("utf-8")
    
    # Effacer les anciens utilisateurs
    for widget in user_frame.winfo_children():
        widget.destroy()

    # Ajouter les utilisateurs connectés sous forme d'étiquettes
    users = decrypted_response.split()
    for user in users:
        user_label = ctk.CTkLabel(user_frame, text=user, fg_color="black")
        user_label.pack(side=ctk.LEFT, padx=5)

def create_window():
    global login_frame, reg_frame, chat_frame, user_frame
    global login_user_entry, login_pass_entry
    global reg_user_entry, reg_pass_entry
    global chat_box, entry_box

    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("green")

    global window  # Définit la fenêtre globale pour pouvoir l'utiliser dans receive_messages
    window = ctk.CTk()  # Utiliser CTk au lieu de Tk
    window.title("Chat Interface")

    # Dimensions de la fenêtre
    width = 500
    height = 300

    # Frame pour la connexion
    login_frame = ctk.CTkFrame(window, width=width, height=height)
    login_frame.pack_propagate(False)

    ctk.CTkLabel(login_frame, text="Connexion", font=("Arial", 14, "bold")).pack(pady=10)
    ctk.CTkLabel(login_frame, text="Nom d'utilisateur").pack(pady=5)
    login_user_entry = ctk.CTkEntry(login_frame)
    login_user_entry.pack(pady=5)
    ctk.CTkLabel(login_frame, text="Mot de passe").pack(pady=5)
    login_pass_entry = ctk.CTkEntry(login_frame, show="*")
    login_pass_entry.pack(pady=5)

    ctk.CTkButton(login_frame, text="Se connecter", command=login_user).pack(pady=10)
    ctk.CTkButton(login_frame, text="S'inscrire", command=show_register_screen).pack(pady=5)

    login_frame.pack(fill="both", expand=True)

    # Frame pour l'inscription
    reg_frame = ctk.CTkFrame(window, width=width, height=height)
    reg_frame.pack_propagate(False)

    ctk.CTkLabel(reg_frame, text="Inscription", font=("Arial", 14, "bold")).pack(pady=10)
    ctk.CTkLabel(reg_frame, text="Nom d'utilisateur").pack(pady=5)
    reg_user_entry = ctk.CTkEntry(reg_frame)
    reg_user_entry.pack(pady=5)
    ctk.CTkLabel(reg_frame, text="Mot de passe").pack(pady=5)
    reg_pass_entry = ctk.CTkEntry(reg_frame, show="*")
    reg_pass_entry.pack(pady=5)

    ctk.CTkButton(reg_frame, text="S'inscrire", command=register_user).pack(pady=10)
    ctk.CTkButton(reg_frame, text="Retour à la connexion", command=show_login_screen).pack(pady=5)

    # Frame pour le chat
    chat_frame = ctk.CTkFrame(window, fg_color="black", width=width, height=height)  # Correction ici
    chat_frame.pack_propagate(False)

    # Zone de chat
    chat_box = ctk.CTkTextbox(chat_frame, state=ctk.DISABLED, wrap=ctk.WORD)
    chat_box.pack(padx=10, pady=10, fill="both", expand=True, side=ctk.LEFT)

    # Zone pour écrire les messages
    entry_box = ctk.CTkEntry(chat_frame)
    entry_box.pack(padx=10, pady=(0, 10), fill="x", side=ctk.BOTTOM)

    # Zone pour afficher les noms des utilisateurs connectés
    user_frame = ctk.CTkFrame(chat_frame)
    user_frame.pack(padx=(0, 10), pady=10, fill="x", side=ctk.RIGHT)

    # Lier la touche 'Entrée' à l'envoi de messages
    entry_box.bind("<Return>", lambda event: send_message())

    window.protocol("WM_DELETE_WINDOW", window.quit)
    window.mainloop()

if __name__ == "__main__":
    # Demander l'IPv6 à utiliser
    ipv6_address = input("Veuillez entrer l'adresse IPv6 à utiliser : ")
    connect_to_server(ipv6_address)
    create_window()
