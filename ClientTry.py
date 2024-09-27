import asyncio
import websockets
import json
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import os
import hashlib
import time


class Client:
    def __init__(self, uri):
        self.uri = uri
        self.public_key, self.private_key = self.generate_rsa_keys()
        self.username = "User"
        self.counter = 0
        self.public_keys_storage = {}
        self.client_list_received = (
            asyncio.Event()
        )  # Flag for waiting for client list response
        self.verification_event = asyncio.Event()
        self.user_valid = False

    def generate_rsa_keys(self):
        # Generate a new RSA key pair
        rsa_key = RSA.generate(2048)
        # Export the public key in PEM format
        public_key = rsa_key.publickey().export_key(format="PEM", pkcs=8)
        # Export the private key in PEM format
        private_key = rsa_key.export_key(format="PEM", pkcs=8)
        return public_key, private_key

    def save_to_pem(self, key, filename):
        with open(filename, "wb") as file:
            file.write(key)

    def export_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def get_fingerprint(self):
        public_key_pem = self.export_public_key()
        return base64.b64encode(hashlib.sha256(public_key_pem).digest()).decode()

    async def request_client_list(self, websocket):
        message = {"data": {"type": "client_list_request"}}
        await self.send_message(websocket, message)
        await self.client_list_received.wait()  # Wait until client list response is handled

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
            }
        }
        await self.send_message(websocket, message)

        # Function to encrypt a message using AES and RSA, importing the public key from a .pem file

    def encrypt_message(message, public_key_pem_file):
        # Import the public key from the .pem file
        with open(public_key_pem_file, "rb") as file:
            public_key = RSA.import_key(file.read())

        # Generate a random AES key
        aes_key = get_random_bytes(32)
        # Generate a random initialization vector (IV)
        iv = get_random_bytes(16)
        # Create an AES cipher object with the AES key and IV
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        # Encrypt the message and generate the authentication tag
        ciphertext, tag = cipher.encrypt_and_digest(message.encode("utf-8"))

        # Create an RSA cipher object with the public key
        cipher_rsa = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        # Encrypt the AES key with the RSA public key
        # print(f"AES Key Length: {len(aes_key)}")

        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        # print(f"Encrypted AES Key Length: {len(encrypted_aes_key)}")
        # print(
        #     f"Base64 Encoded Encrypted AES Key Length: {len(base64.b64encode(encrypted_aes_key))}"
        # )

        # Export the RSA public key
        exported_public_key = public_key.export_key(format="PEM", pkcs=8)

        # Return the IV, ciphertext, encrypted AES key, and exported RSA public key, all base64-encoded
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
        print(f"Key: {users_public_key}")
        # iv, ciphertext, encrypted_AES_key, RSA_public_key = self.encrypt_message(
        #     chat,
        # )
        message = {
            "data": {
                "type": "chat",
                "destination_servers": [destination],
                "iv": "<Base64 encoded AES initialisation vector>",
                "symm_keys": [
                    "<Base64 encoded AES key, encrypted with each recipient's public RSA key>",
                ],
                "chat": {
                    "sender": self.username,
                    "message": chat,
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
        # Import the private key from the .pem file
        with open(private_key, "rb") as file:
            private_key = RSA.import_key(file.read())

        # Create a SHA-256 hash of the message
        h = SHA256.new(message.encode("utf-8"))
        # Create a PSS signer object with the private key and a specified salt length
        signer = pss.new(private_key, salt_bytes=32)
        # Sign the hash and return the signature, base64-encoded
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
        # print("Sent message: ", message["data"])
        await websocket.send(json.dumps(message))

    async def receive_messages(self, websocket):
        # print("Listening for messages...")
        async for message in websocket:
            # print(f"Message: {message}")
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

    async def set_public_key(self, message):
        public_key = message["public_key"]
        user = message["user"]
        self.public_keys_storage[user] = public_key
        # print(f"Public keys: {self.public_keys_storage}")
        self.user_valid = True
        self.verification_event.set()

    async def handle_chat_fail(self):
        print(f"That user is not online/does not exist")
        self.user_valid = False
        self.verification_event.set()

    async def handle_client_list(self, message):
        # Display list of clients
        servers = message["servers"]
        print("Online users:")
        for server in servers:
            print(f"Server: {server['address']}")
            for client in server["clients"]:
                if server["address"] == client:  # FIX THIS!!
                    print(f"- {client}  YOU!")
                else:
                    print(f"- {client}")
        self.client_list_received.set()

    async def handle_public_chat(self, message):
        sender = message["data"]["data"]["sender"]
        chat_message = message["data"]["data"]["message"]
        print(f"\nPublic message from {sender}: {chat_message}")

    async def handle_message(self, message):
        # Handle incoming messages (simplified)
        chat = message["data"]["data"]["chat"]["message"]
        sender = message["data"]["data"]["chat"]["sender"]
        print(f"\nPrivate message from {sender}: {chat}")

    async def run(self):
        async with websockets.connect(self.uri) as websocket:
            print("Joining chat server...")
            # time.sleep(3)     UNCOMMENT WHEN FINISHED
            self.save_to_pem(self.public_key, "public_key.pem")
            self.save_to_pem(self.private_key, "private_key.pem")
            self.username = await asyncio.to_thread(input, "Welcome! Enter username: ")
            await self.send_hello(websocket)
            asyncio.create_task(self.receive_messages(websocket))

            while True:
                start_message = await asyncio.to_thread(
                    input,
                    "What would you like to do? (chat, public chat, list online users, exit): ",
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
                elif start_message.lower() in ["exit", "quit", "q"]:
                    print("Goodbye!")
                    await self.send_disconnect(
                        websocket
                    )  # Send the disconnect message to the server
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
