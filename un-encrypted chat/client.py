import socket
import json
import threading
import sys

def receive_messages(client_socket):
    while True:
        try:
            message = json.loads(client_socket.recv(1024).decode('utf-8'))
            print(f"\nMessage from {message['from']}: {message['message']}\nWrite your message: ", end='')
            sys.stdout.flush()  # 현재 버퍼에 있는 내용을 출력
        except ConnectionResetError:
            break

def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('localhost', 12345))

    action = input("Do you want to login or register? (login/register): ")
    user_id = input("Enter your ID: ")
    password = input("Enter your password: ")

    request = {"id": user_id, "password": password, "action": action}
    client.send(json.dumps(request).encode('utf-8'))

    response = json.loads(client.recv(1024).decode('utf-8'))
    if response["status"] in ["success", "registration_success"]:
        print(f"{action.capitalize()} successful!")
        if action == "login":
            threading.Thread(target=receive_messages, args=(client,), daemon=True).start()
            
            target = input("Enter the ID of the user you want to message: ")
            while True:
                message = input("Write your message: ")
                if message == "/exit":
                    break
                message_data = json.dumps({"target": target, "message": message})
                client.send(message_data.encode('utf-8'))
    else:
        print(f"{action.capitalize()} failed: {response['status']}")

start_client()
