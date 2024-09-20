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

class Client:
    def __init__(self, uri):
        self.uri = uri
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.counter = 0

    def export_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def get_fingerprint(self):
        public_key_pem = self.export_public_key()
        return base64.b64encode(hashlib.sha256(public_key_pem).digest()).decode()

    async def send_hello(self, websocket):
        message = {
            "data": {
                "type": "hello",
                "public_key": self.export_public_key().decode()
            }
        }
        await self.send_message(websocket, message)

    async def send_chat(self, websocket, chat,destination_server):
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
                    "message": chat

                }
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
            "signature": signature
        }
        print("Sent message: ", message["data"])
        await websocket.send(json.dumps(message))

    def sign_data(self, data):
        data_bytes = json.dumps(data).encode()
        signature = self.private_key.sign(
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()

    async def receive_messages(self, websocket):
        print("Listening for messages...")
        async for message in websocket:
            await self.handle_message(json.loads(message))

    async def handle_message(self, message):
        # Handle incoming messages (simplified)
        chat = message["data"]["data"]["chat"]["message"]
        print(f"Received message: {chat}")

    async def get_input(self, websocket):
            while True:
                chat_message = input("Enter message: ")
                destination_server = input("Enter destination server address: ")
                await self.send_chat(websocket, chat_message, destination_server)

    async def run(self):
        async with websockets.connect(self.uri) as websocket:
            await self.send_hello(websocket)
            asyncio.create_task(self.receive_messages(websocket))

            while True:
                chat_message = await asyncio.to_thread(input, "Enter message: ")
                destination_server = await asyncio.to_thread(input, "Enter destination server address: ")
                await self.send_chat(websocket, chat_message, destination_server)


if __name__ == "__main__":
    client = Client("ws://localhost:8001")
    asyncio.run(client.run())