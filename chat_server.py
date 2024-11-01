import socket
from cryptography.fernet import Fernet
import threading
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

def load_users():
    users = {}
    try:
        with open("user.txt", "r") as user_file:
            for line in user_file:
                username, password = line.strip().split(" ", 1)
                users[username] = password
    except FileNotFoundError:
        pass
    return users

def save_user(username, password):
    with open("user.txt", "a") as user_file:
        user_file.write(f"{username} {password}\n")

def broadcast_message(message, clients):
    encrypted_message = cipher_suite.encrypt(message.encode("utf-8"))
    for client in clients:
        try:
            client.send(encrypted_message)
        except (ConnectionResetError, BrokenPipeError):
            clients.remove(client)

def handle_client_connection(client_socket, username, clients, users_db):
    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                break
            message = cipher_suite.decrypt(encrypted_message).decode("utf-8")
            print(f"Message reçu de {username}: {message}")

            if message.startswith("MESSAGE"):
                broadcast_message(f"{username}: {message[8:]}", clients)

        except (ConnectionResetError, BrokenPipeError):
            break

    print(f"{username} s'est déconnecté.")
    clients.remove(client_socket)
    broadcast_message(f"{username} s'est déconnecté.", clients)
    client_socket.close()

def start_server(ipv6_address):
    users_db = load_users()
    clients = []

    server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    server_socket.bind((ipv6_address, 5555))
    server_socket.listen(5)
    print("Serveur démarré, en attente de connexions...")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connexion établie avec {addr}")

        # Gestion des requêtes d'inscription ou de connexion
        try:
            encrypted_message = client_socket.recv(1024)
            message = cipher_suite.decrypt(encrypted_message).decode("utf-8")
            parts = message.split(" ", 2)
            command = parts[0]
            if command == "REGISTER":
                username, password = parts[1], parts[2]
                if username in users_db:
                    response = "REGISTER Nom d'utilisateur déjà pris."
                else:
                    users_db[username] = password
                    save_user(username, password)
                    response = "REGISTER Inscription réussie!"
                client_socket.send(cipher_suite.encrypt(response.encode("utf-8")))

            elif command == "LOGIN":
                username, password = parts[1], parts[2]
                if users_db.get(username) == password:
                    clients.append(client_socket)
                    response = "LOGIN Connexion réussie!"
                    client_socket.send(cipher_suite.encrypt(response.encode("utf-8")))
                    broadcast_message(f"{username} est connecté.", clients)
                    threading.Thread(target=handle_client_connection, args=(client_socket, username, clients, users_db)).start()
                else:
                    response = "LOGIN Nom d'utilisateur ou mot de passe incorrect."
                    client_socket.send(cipher_suite.encrypt(response.encode("utf-8")))
        except (ConnectionResetError, BrokenPipeError):
            client_socket.close()

def get_ipv6_address():
    ipv6_address = input("Veuillez entrer l'adresse IPv6 que vous souhaitez utiliser (ou appuyez sur Entrée pour utiliser 2001:56b:de7e:1800:a9bc:bda1:4efa:f7f7 par défaut): ")
    if not ipv6_address:
        ipv6_address = "2001:56b:de7e:1800:a9bc:bda1:4efa:f7f7"  # Adresse par défaut
    return ipv6_address

if __name__ == "__main__":
    ipv6_address = get_ipv6_address()
    start_server(ipv6_address)
