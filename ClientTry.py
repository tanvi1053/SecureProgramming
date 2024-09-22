import asyncio
import websockets
import json
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import hashlib
import time


class Client:
    def __init__(self, uri):
        self.uri = uri
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.counter = 0

    def export_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def get_fingerprint(self):
        public_key_pem = self.export_public_key()
        return base64.b64encode(hashlib.sha256(public_key_pem).digest()).decode()

    async def request_client_list(self, websocket):
        message = {"data": {
                    "type": "client_list_request"
                    }
                   }
        await self.send_message(websocket, message)

    async def send_disconnect(self, websocket):
        message = {
            "data": {
                "type": "disconnect",
                "username": "your_username",  # You could use the actual username here
            }
        }
        await self.send_message(websocket, message)

    async def send_hello(self, websocket, username):
        message = {
            "data": {
                "type": "hello",
                "public_key": self.export_public_key().decode(),
                "username": username,
            }
        }
        await self.send_message(websocket, message)

    async def send_chat(self, websocket, chat, destination_server):
        message = {
            "data": {
                "type": "chat",
                "destination_servers": [destination_server],
                "iv": "<Base64 encoded AES initialisation vector>",
                "symm_keys": [
                    "<Base64 encoded AES key, encrypted with each recipient's public RSA key>",
                ],
                "chat": {
                    "participants": [
                        "<Base64 encoded list of fingerprints of participants, starting with sender>",
                    ],
                    "message": chat,
                },
            }
        }
        await self.send_message(websocket, message)

    async def send_public_chat(self, websocket, chat_message):
        fingerprint = self.get_fingerprint()  # Get the client's fingerprint
        message = {
            "data": {
                "type": "public_chat",
                "sender": fingerprint,
                "message": chat_message,
            }
        }
        await self.send_message(websocket, message)

    async def send_message(self, websocket, data):
        self.counter += 1
        signature = self.sign_data(data)
        message = {
            "type": "signed_data",
            "data": data,
            "counter": self.counter,
            "signature": signature,
        }
        # print("Sent message: ", message["data"])
        await websocket.send(json.dumps(message))

    def sign_data(self, data):
        data_bytes = json.dumps(data).encode()
        signature = self.private_key.sign(
            data_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
        return base64.b64encode(signature).decode()

    async def receive_messages(self, websocket):
        # print("Listening for messages...")
        async for message in websocket:
            # print(f"Message: {message}")
            message = json.loads(message)
            if message["type"] == "signed_data":
                if message["data"]["data"]["type"] == "chat":
                    await self.handle_message(message)
            elif message["type"] == "client_list":
                await self.handle_client_list(message)
            elif message["data"]["type"] == "public_chat":
                await self.handle_public_chat(message)

    async def handle_client_list(self, message):
        # Display list of clients
        servers = message["servers"]
        # print("RAW MESSAGE")
        # print(message)        
        print("Online users:")
        for server in servers:
            print(f"Server: {server['address']}")
            for client in server["clients"]:
                print(f"- {client}")

    async def handle_public_chat(self, message):
        sender = message["data"]["data"]["sender"]
        chat_message = message["data"]["data"]["message"]
        print(f"\nPublic message from {sender}: {chat_message}")


    async def handle_message(self, message):
        # Handle incoming messages (simplified)
        chat = message["data"]["data"]["chat"]["message"]
        print(f"\nReceived message: {chat}")

    async def run(self):
        async with websockets.connect(self.uri) as websocket:
            print("Joining chat server...")
            # time.sleep(3)     # UNCOMMENT WHEN FINISHED
            username = await asyncio.to_thread(input, "Welcome! Enter username: ")
            await self.send_hello(websocket, username)
            asyncio.create_task(self.receive_messages(websocket))

            while True:
                start_message = await asyncio.to_thread(
                    input,
                    "What would you like to do? (chat, public chat, list online users, exit): ",
                )
                if start_message in ["chat", "Chat", "CHAT"]:
                    destination_server = await asyncio.to_thread(
                        input, "Who do you want to send the message to?: "
                    )
                    chat_message = await asyncio.to_thread(input, "Enter message: ")
                    await self.send_chat(websocket, chat_message, destination_server)
                elif start_message in ["public chat", "Public Chat", "PUBLIC CHAT", "public", "Public", "PUBLIC"]:
                    chat_message = await asyncio.to_thread(input, "Enter message: ")
                    await self.send_public_chat(websocket, chat_message)
                elif start_message in [
                    "list online users",
                    "list",
                    "List",
                    "LIST",
                    "List online users",
                    "List Online Users",
                    "LIST ONLINE USERS"
                ]:
                    # list
                    # print("Online users: ")
                    await self.request_client_list(websocket)
                elif start_message in ["exit", "Exit", "EXIT", "quit", "q", "Quit"]:
                    print("Goodbye!")
                    await self.send_disconnect(websocket)  # Send the disconnect message to the server
                    await websocket.close()
                    exit(1)
                else:
                    print("Not a valid command, enter again")


if __name__ == "__main__":
    client = Client("ws://localhost:8001")
    try:
        asyncio.run(client.run())
    except KeyboardInterrupt:
        print("Goodbye!")
        exit(1)
