import socket
import threading
import json
import logging
import datetime
import os

# 로깅 및 데이터 파일 설정
logging.basicConfig(level=logging.INFO, filename='chat_server.log', filemode='a',
                    format='%(asctime)s - %(levelname)s - %(message)s')
USERS_DB_FILE = "users_db.json"
PUBLIC_KEYS_FILE = "public_keys.json"

# 데이터 로드 및 저장 함수
def load_data(filename, default):
    if os.path.exists(filename):
        with open(filename, 'r') as file:
            return json.load(file)
    return default

def save_data(filename, data):
    with open(filename, 'w') as file:
        json.dump(data, file, indent=4)

# 데이터 로드
users_db = load_data(USERS_DB_FILE, {})
public_keys = load_data(PUBLIC_KEYS_FILE, {})

def log_message(sender, recipient, message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} | From: {sender} | To: {recipient} | Message: {message}"
    logging.info(log_entry)

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
                public_key = request.get("public_key")

                # 사용자 등록 및 공개 키 저장
                if user_id in users_db:
                    client_socket.send(json.dumps({"status": "user_exists"}).encode('utf-8'))
                else:
                    users_db[user_id] = password
                    public_keys[user_id] = public_key
                    save_data(USERS_DB_FILE, users_db)
                    save_data(PUBLIC_KEYS_FILE, public_keys)
                    client_socket.send(json.dumps({"status": "registration_success"}).encode('utf-8'))
                    return

            elif action == "get_public_key":
                target_user = request.get("target_user")
                if target_user in public_keys:
                    client_socket.send(json.dumps({"public_key": public_keys[target_user]}).encode('utf-8'))

        # 메시지 수신 및 전달
        while True:
            message_data = json.loads(client_socket.recv(1024).decode('utf-8'))
            target_user = message_data.get("target")
            message = message_data.get("message")

            if target_user in connected_clients:
                target_client = connected_clients[target_user]
                target_client.send(json.dumps({"from": user_id, "message": message}).encode('utf-8'))
                log_message(user_id, target_user, message)

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
