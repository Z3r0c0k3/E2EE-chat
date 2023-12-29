import socket
import json
import threading
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os
import base64

KEY_FILE = "client_key.pem"

def generate_keys():
    if not os.path.exists(KEY_FILE):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

def load_private_key():
    with open(KEY_FILE, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

def encrypt_message(public_key_pem, message):
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        backend=default_backend()
    )
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_message(private_key, encrypted_message):
    decrypted = private_key.decrypt(
        base64.b64decode(encrypted_message),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

def receive_messages(client_socket, private_key):
    while True:
        try:
            message_data = json.loads(client_socket.recv(1024).decode('utf-8'))
            encrypted_message = message_data.get("message")
            if encrypted_message is not None:
                decrypted_message = decrypt_message(private_key, encrypted_message)
                print(f"\nMessage from {message_data['from']}: {decrypted_message}\nWrite your message: ", end='')
            else:
                print("\nReceived an invalid message.")
            sys.stdout.flush()
        except ConnectionResetError:
            break
        except json.JSONDecodeError:
            print("\nReceived an invalid JSON format.")
            break

def request_public_key(client, target_user):
    client.send(json.dumps({"action": "get_public_key", "target_user": target_user}).encode('utf-8'))
    response = json.loads(client.recv(1024).decode('utf-8'))
    if response["status"] == "success":
        return response["public_key"]
    else:
        print(f"Error: {response.get('message', 'Unknown error')}")
        return None

def start_client():
    generate_keys()
    private_key = load_private_key()
    public_key = private_key.public_key()

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('localhost', 12345))

    action = input("Do you want to login or register? (login/register): ")
    user_id = input("Enter your ID: ")
    password = input("Enter your password: ")

    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    request = {"status": "success", "id": user_id, "password": password, "action": action, "public_key": pem_public_key}
    client.send(json.dumps(request).encode('utf-8'))

    response = json.loads(client.recv(1024).decode('utf-8'))
    if response["status"] in ["success", "registration_success"]:
        print(f"{action.capitalize()} successful!")
        if action == "login":
            target_user = input("Enter the ID of the user you want to message: ")
            target_public_key = request_public_key(client, target_user)

            if target_public_key:
                threading.Thread(target=receive_messages, args=(client, private_key), daemon=True).start()

                while True:
                    message = input("Write your message: ")
                    if message == "/exit":
                        break
                    encrypted_message = encrypt_message(target_public_key, message)
                    client.send(json.dumps({"action":"send_message", "target": target_user, "message": encrypted_message}).encode('utf-8'))
            else:
                print(f"Could not retrieve public key for {target_user}.")
    else:
        print(f"{action.capitalize()} failed: {response['status']}")

start_client()
