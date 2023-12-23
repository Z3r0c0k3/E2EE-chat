# 서버 코드 시작
import socket
import threading
import json
import logging
import datetime
import os

# 로깅 및 데이터 파일 설정
logging.basicConfig(level=logging.INFO, filename='chat_server.log', filemode='a', format='%(asctime)s - %(levelname)s - %(message)s')
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

# 현재 연결된 클라이언트
connected_clients = {}

# 메시지 로깅 함수
def log_message(sender, recipient, message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} | From: {sender} | To: {recipient} | Message: {message}"
    logging.info(log_entry)

# 클라이언트 핸들링 함수
def handle_client(client_socket, client_address):
    user_id = None
    try:
        while True:
            request_data = client_socket.recv(1024).decode('utf-8')
            if not request_data:
                break

            request = json.loads(request_data)
            action = request.get("action")

            if action == "login":
                user_id = request.get("id")
                password = request.get("password")

                if users_db.get(user_id) == password:
                    connected_clients[user_id] = client_socket
                    response = {"status": "success"}
                    logging.info(f"User {user_id} logged in successfully.")
                else:
                    response = {"status": "failure", "message": "Invalid credentials"}
                    logging.info(f"Login attempt failed for {user_id}.")

                client_socket.send(json.dumps(response).encode('utf-8'))

            elif action == "register":
                user_id = request.get("id")
                password = request.get("password")
                public_key = request.get("public_key")

                if user_id in users_db:
                    response = {"status": "error", "message": "User already exists"}
                    logging.info(f"Registration attempt failed for {user_id}: User already exists.")
                else:
                    users_db[user_id] = password
                    public_keys[user_id] = public_key
                    save_data(USERS_DB_FILE, users_db)
                    save_data(PUBLIC_KEYS_FILE, public_keys)
                    response = {"status": "success", "message": "User registered successfully"}
                    logging.info(f"User {user_id} registered successfully.")

                client_socket.send(json.dumps(response).encode('utf-8'))

            elif action == "get_public_key":
                target_user = request.get("target_user")
                if target_user in public_keys:
                    response = {"status": "success", "public_key": public_keys[target_user]}
                    logging.info(f"Public key sent for {target_user}.")
                else:
                    response = {"status": "error", "message": "User not found"}
                    logging.error(f"Public key request failed: {target_user} not found.")

                client_socket.send(json.dumps(response).encode('utf-8'))

            elif action == "send_message":
                target_user = request.get("target")
                message = request.get("message")

                if target_user in connected_clients:
                    connected_clients[target_user].send(json.dumps({"from": user_id, "message": message}).encode('utf-8'))
                    response = {"status": "success", "message": "Message sent"}
                    log_message(user_id, target_user, message)
                else:
                    response = {"status": "error", "message": "Target user not connected"}

                client_socket.send(json.dumps(response).encode('utf-8'))

    except ConnectionResetError:
        logging.info(f"Connection reset by {client_address}")
    finally:
        if user_id and user_id in connected_clients:
            del connected_clients[user_id]
            logging.info(f"Disconnected client {user_id}")

# 서버 시작 함수
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 12345))
    server.listen()

    logging.info("Server started. Listening for connections...")

    while True:
        client_socket, addr = server.accept()
        logging.info(f"Accepted connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket, addr))
        client_handler.start()

start_server()
# 서버 코드 종료
