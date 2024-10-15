# Vulnerable client script of group 16
# Tanvi Srivastava / a1860959
# Kirsten Pope / a1860519
# Leona Heng / a1791093

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
import random
import aiohttp
import aiofiles
import sys

# Configuration Constants
HTTP_ADDRESS = "localhost"
HTTP_PORT = 8080


class Client:
    def __init__(self):
        self.uri = self.get_random_server()
        self.public_key, self.private_key = self.generate_rsa_keys()
        self.username = "User"
        self.counter = 0
        self.public_keys_storage = {}
        self.verification_event = asyncio.Event()
        self.user_valid = False
        self.client_list_received = asyncio.Event()
        self.no_user = asyncio.Event()

    ##############################################################################################################3
    # SERVER CONNECTION
    ##############################################################################################################3
    def get_random_server(self):
        # Load neighboring servers from the file
        NEIGHBOUR_FILE = "neighbouring_servers.txt"
        if os.path.exists(NEIGHBOUR_FILE):
            with open(NEIGHBOUR_FILE, "r") as f:
                servers = [line.strip() for line in f.readlines()]
            if servers:
                # Select a random server and ensure it has the ws:// scheme
                random_server = random.choice(servers)
                if not random_server.startswith("ws://"):
                    random_server = "ws://" + random_server
                return random_server
        print("No servers are running right now")
        exit(1)  # Exit if no servers are found

    ##############################################################################################################3
    # CRYPTOGRAPHY
    ##############################################################################################################3
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

    async def verify_user_and_get_key(self, websocket, destination):
        message = {
            "data": {
                "type": "get_key",
                "destination_server": destination,
                "sender": self.username,
            }
        }
        await self.send_message(websocket, message)
        await self.verification_event.wait()

    # Function to encrypt a message using AES and RSA, importing the public key from a .pem file
    def encrypt_message(self, message, public_key):
        # Import the public key
        public_key = RSA.import_key(public_key)

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

        encrypted_aes_key = cipher_rsa.encrypt(aes_key)
        # Export the RSA public key
        exported_public_key = public_key.export_key(format="PEM", pkcs=8)

        # Return the IV, ciphertext, encrypted AES key, and exported RSA public key, all base64-encoded
        return (
            base64.b64encode(iv).decode("utf-8"),
            base64.b64encode(ciphertext).decode("utf-8"),
            base64.b64encode(encrypted_aes_key).decode("utf-8"),
            base64.b64encode(exported_public_key).decode("utf-8"),
        )

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

    async def set_public_key(self, message):
        public_key = message["public_key"]
        user = message["user"]
        self.public_keys_storage[user] = public_key
        self.user_valid = True
        self.verification_event.set()
        if debug_mode:
            print(f"Key added! {self.public_keys_storage}")

    # Function to decrypt an encrypted message using AES and RSA, importing the private key from a .pem file
    def decrypt_message(self, iv, ciphertext, encrypted_aes_key, private_key_pem_file):
        # Import the private key from the .pem file
        private_key = RSA.import_key(private_key_pem_file)

        # Create an RSA cipher object with the private key
        cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        # Decrypt the AES key with the RSA private key

        aes_key = cipher_rsa.decrypt(base64.b64decode(encrypted_aes_key))

        # Create an AES cipher object with the decrypted AES key and IV
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=base64.b64decode(iv))
        # Decrypt the ciphertext
        decrypted_message = cipher.decrypt(base64.b64decode(ciphertext))

        # Return the decrypted message as a string
        return decrypted_message.decode("utf-8")

    ##############################################################################################################3
    # LIST FUNCTIONALITY
    ##############################################################################################################3

    async def request_client_list(self, websocket):
        message = {"data": {"type": "client_list_request"}}
        await self.send_message(websocket, message)
        await self.client_list_received.wait()  # Wait until client list response is handled

    async def handle_client_list(self, message):
        # Display the message for debugging
        # print("Received client list:", message)

        # Extract the list of servers from the message
        servers = message.get("servers", [])

        # Display the list of online users, grouped by server
        print("\nOnline users:")
        for server in servers:
            server_address = server.get("address", "Unknown address")
            print(f"Server: {server_address}")

            # Get the list of clients from the server
            clients = server.get("clients", [])

            # Print each client and their associated address
            for client in clients:
                username = client.get("username", "Unknown user")
                print(f"- {username}")

        # Signal that the client list has been successfully received
        self.client_list_received.set()

    ##############################################################################################################3
    # CONNECT AND DISCONNECT FROM SERVER
    ##############################################################################################################3
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

    ##############################################################################################################3
    # PRIVATE AND PUBLIC CHATTING
    ##############################################################################################################3
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
                "destination_server": destination,
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
        if debug_mode:
            print(f"SENDING MESSAGE: {message}")
        await websocket.send(json.dumps(message))

    async def receive_messages(self, websocket):
        try:
            async for message in websocket:
                message = json.loads(message)
                if debug_mode:
                    print(f"RECEIVED MESSAGE: {message}")
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
            exit(0)  # Exit the client application

    async def handle_chat_fail(self):
        print("That user is not online/does not exist")
        self.user_valid = False
        self.verification_event.set()

    async def handle_public_chat(self, message):
        sender = message["data"]["data"]["sender"]
        chat_message = message["data"]["data"]["message"]
        print(f"\n[Public message] {sender}: {chat_message}")

    async def handle_message(self, message):
        # Handle incoming messages (simplified)
        ciphertext = message["data"]["data"]["chat"]["message"]
        sender = message["data"]["data"]["chat"]["sender"]
        iv = message["data"]["data"]["iv"]
        encrypted_aes_key = message["data"]["data"]["symm_keys"][0]

        plaintext = self.decrypt_message(
            iv, ciphertext, encrypted_aes_key, self.private_key
        )
        print(f"\n[Private message] {sender}: {plaintext}")

    ##############################################################################################################3
    # FILE UPLOAD
    ##############################################################################################################3
    async def upload_file(self, file_path):
        recipient = input("Enter the recipient's username: ")
        try:
            async with aiohttp.ClientSession() as session:
                async with aiofiles.open(file_path, "rb") as f:
                    file_data = await f.read()
                    payload = {
                        "METHOD": "POST",
                        "body": file_data.decode("latin1"),
                        "recipient": recipient,
                    }
                    async with session.post(
                        f"http://{HTTP_ADDRESS}:{HTTP_PORT}/api/upload", json=payload
                    ) as resp:
                        response = await resp.json()
                        print("File uploaded.")
        except FileNotFoundError:
            print("File does not exist. Try Again!")

    async def link_request(self):
        username = self.username
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://{HTTP_ADDRESS}:{HTTP_PORT}/api/links?username={username}"
            ) as resp:
                if resp.status == 200:
                    response = await resp.json()
                    if response.get("success"):
                        print("Uploaded Files:")
                        available_links = response["uploaded_files"]
                        for link in available_links:
                            print(link)

                        while True:
                            url = await asyncio.to_thread(input, "Enter url: ")
                            if url in available_links:
                                await self.retrieve_file(url)
                                break
                            else:
                                print(
                                    "Invalid URL. Please enter a valid URL from the list above."
                                )
                    else:
                        print("There is no file available.")
                else:
                    print("Failed to retrieve file links.")

    async def retrieve_file(self, file_url):
        username = self.username
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{file_url}?username={username}") as resp:
                if resp.status == 200:
                    file_data = await resp.read()
                    with open("downloaded_file", "wb") as f:
                        f.write(file_data)
                    print("File downloaded successfully.")
                else:
                    print("Failed to retrieve file.")

    ##############################################################################################################3
    # INTERFACE
    ##############################################################################################################3
    async def run(self):
        try:
            async with websockets.connect(self.uri) as websocket:
                print("Joining chat server...")
                # time.sleep(3)     UNCOMMENT WHEN FINISHED
                if debug_mode:
                    print(f"Public key: {self.public_key}")
                    print(f"Private key: {self.private_key}")
                self.save_to_pem(self.public_key, "public_key.pem")
                self.save_to_pem(self.private_key, "private_key.pem")
                self.username = await asyncio.to_thread(input, "\nEnter username: ")
                print(f"\nWelcome {self.username}!")
                await self.send_hello(websocket)
                asyncio.create_task(self.receive_messages(websocket))

                while True:
                    start_message = await asyncio.to_thread(
                        input,
                        "\nChoose action:\n1. Send Private Message\n2. Send Public Message\n3. List Online Users\n4. File Upload\n5. File Download\n6. Exit\n",
                    )
                    if start_message.lower() in [
                        "send private message",
                        "send message",
                        "private",
                        "1",
                    ]:
                        destination = await asyncio.to_thread(
                            input,
                            "\nWho do you want to send the message to? (type 'back' to go back): ",
                        )

                        if destination.lower() != "back":
                            self.verification_event.clear()
                            await self.verify_user_and_get_key(websocket, destination)
                            if not self.user_valid:
                                continue
                            chat_message = await asyncio.to_thread(
                                input, "Enter message: "
                            )
                            await self.send_chat(websocket, chat_message, destination)

                    elif start_message.lower() in [
                        "send public message",
                        "public message",
                        "public",
                        "2",
                    ]:
                        chat_message = await asyncio.to_thread(
                            input, "\nEnter message: "
                        )
                        await self.send_public_chat(websocket, chat_message)
                    elif start_message.lower() in ["list online users", "list", "3"]:
                        self.client_list_received.clear()
                        await self.request_client_list(websocket)
                    elif start_message.lower() in [
                        "upload file",
                        "upload",
                        "4",
                        "file upload",
                    ]:
                        file_path = input("\nEnter the path of the file to upload: ")
                        await self.upload_file(file_path)
                    elif start_message.lower() in [
                        "download",
                        "download file",
                        "file download",
                        "5",
                    ]:
                        await self.link_request()
                    elif start_message.lower() in ["exit", "quit", "q", "6"]:
                        print("\nGoodbye!")
                        await self.send_disconnect(
                            websocket
                        )  # Send the disconnect message to the server
                        await websocket.close()
                        exit(1)
                    else:
                        print("\nNot a valid command, enter again")
        except Exception as e:
            print(f"An error occurred: {e}")


if __name__ == "__main__":
    client = Client()
    try:
        debug_mode = False
        if len(sys.argv) > 1 and sys.argv[1] == "debug":
            debug_mode = True
        asyncio.get_event_loop().run_until_complete(client.run())
    except KeyboardInterrupt:
        print("\nGoodbye!")
        exit(1)
