import socket
import threading
import json

# 가상의 사용자 데이터베이스
users_db = {
    "user1": "password1",
    "user2": "password2"
}

# 현재 연결된 클라이언트
connected_clients = {}

def handle_client(client_socket, client_address):
    user_id = None
    try:
        while True:
            request = json.loads(client_socket.recv(1024).decode('utf-8'))
            action = request.get("action")

            if action == "login":
                user_id = request.get("id")
                password = request.get("password")

                # 사용자 인증
                if users_db.get(user_id) == password:
                    connected_clients[user_id] = client_socket
                    client_socket.send(json.dumps({"status": "success"}).encode('utf-8'))
                    break
                else:
                    client_socket.send(json.dumps({"status": "failure"}).encode('utf-8'))
                    return

            elif action == "register":
                user_id = request.get("id")
                password = request.get("password")

                # 사용자 등록
                if user_id in users_db:
                    client_socket.send(json.dumps({"status": "user_exists"}).encode('utf-8'))
                else:
                    users_db[user_id] = password
                    client_socket.send(json.dumps({"status": "registration_success"}).encode('utf-8'))
                    return

        # 메시지 수신 및 전달
        while True:
            message_data = json.loads(client_socket.recv(1024).decode('utf-8'))
            target_user = message_data.get("target")
            message = message_data.get("message")

            if target_user in connected_clients:
                target_client = connected_clients[target_user]
                target_client.send(json.dumps({"from": user_id, "message": message}).encode('utf-8'))

    except ConnectionResetError:
        pass
    finally:
        if user_id and user_id in connected_clients:
            del connected_clients[user_id]

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 12345))
    server.listen()

    while True:
        client_socket, addr = server.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_socket, addr))
        client_handler.start()

start_server()
