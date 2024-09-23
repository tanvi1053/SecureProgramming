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


class Client:
    def __init__(self, uri):
        self.uri = uri
        self.public_key, self.private_key = self.generate_rsa_keys()
        self.counter = 0

    # Function to generate RSA public and private keys
    def generate_rsa_keys(self):
        # Generate a new RSA key pair
        rsa_key = RSA.generate(2048)
        # Export the public key in PEM format
        public_key = rsa_key.publickey().export_key(format="PEM", pkcs=8)
        # Export the private key in PEM format
        private_key = rsa_key.export_key(format="PEM", pkcs=8)
        return public_key, private_key

    # def export_public_key(self):
    #     return self.public_key.public_bytes(
    #         encoding=serialization.Encoding.PEM,
    #         format=serialization.PublicFormat.SubjectPublicKeyInfo,
    #     )

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

    async def send_hello(self, websocket, username):
        message = {
            "data": {
                "type": "hello",
                "public_key": self.public_key.decode(),
                "username": username,
            }
        }
        await self.send_message(websocket, message)

    async def send_chat(self, websocket, chat, destination_server):
        iv, ciphertext, encrypted_AES_key, RSA_public_key = self.encrypt_message(
            chat, self.public_key
        )
        message = {
            "data": {
                "type": "chat",
                "destination_servers": [destination_server],
                "iv": iv,
                "symm_keys": encrypted_AES_key,
                "chat": {
                    "participants": [
                        "<Base64 encoded list of fingerprints of participants, starting with sender>",
                    ],
                    "message": ciphertext,
                },
            }
        }
        await self.send_message(websocket, message)

    async def get_list(self, websocket):
        message = {"type": "client_list_request"}
        await websocket.send(json.dumps(message))

    async def send_message(self, websocket, data):
        self.counter += 1
        if data["data"]["type"] == "chat":
            signature = self.sign_message(
                data["data"]["chat"]["message"], self.private_key
            )
        elif data["data"]["type"] == "hello":
            signature = self.sign_message(data["data"]["type"], self.private_key)
        message = {
            "type": "signed_data",
            "data": data,
            "counter": self.counter,
            "signature": signature,
        }
        # print("Sent message: ", message["data"])
        await websocket.send(json.dumps(message))

    # Function to sign a message using RSA and PSS, importing the private key from a .pem file
    def sign_message(self, message, private_key):
        # Import the private key from the .pem file
        # with open(private_key_pem_file, 'rb') as file:
        #     private_key = RSA.import_key(file.read())

        # Create a SHA-256 hash of the message
        h = SHA256.new(message.encode("utf-8"))
        # Create a PSS signer object with the private key and a specified salt length
        signer = pss.new(private_key, salt_bytes=32)
        # Sign the hash and return the signature, base64-encoded
        signature = signer.sign(h)
        return base64.b64encode(signature).decode("utf-8")

    async def receive_messages(self, websocket):
        # print("Listening for messages...")
        async for message in websocket:
            # print(f"Message: {message}")
            message = json.loads(message)
            if message["type"] == "signed_data":
                if message["data"]["data"]["type"] == "chat":
                    await self.handle_message(message)

    # Function to decrypt an encrypted message using AES and RSA, importing the private key from a .pem file
    def decrypt_message(iv, ciphertext, encrypted_aes_key, private_key_pem_file):
        # Import the private key from the .pem file
        with open(private_key_pem_file, "rb") as file:
            private_key = RSA.import_key(file.read())

        # Create an RSA cipher object with the private key
        cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        # Decrypt the AES key with the RSA private key
        print(
            f"Base64 Decoded Encrypted AES Key Length: {len(base64.b64decode(encrypted_aes_key))}"
        )

        aes_key = cipher_rsa.decrypt(base64.b64decode(encrypted_aes_key))

        # Create an AES cipher object with the decrypted AES key and IV
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=base64.b64decode(iv))
        # Decrypt the ciphertext
        decrypted_message = cipher.decrypt(base64.b64decode(ciphertext))

        # Return the decrypted message as a string
        return decrypted_message.decode("utf-8")

    async def handle_message(self, message):
        # Handle incoming messages (simplified)
        iv = message["data"]["data"]["iv"]
        encrypted_AES_key = message["data"]["data"]["symm_keys"]
        ciphertext = message["data"]["data"]["chat"]["message"]
        decrypted_message = self.decrypt_message(
            iv, ciphertext, encrypted_AES_key, self.private_key
        )
        print(f"\nReceived message: {decrypted_message}")

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
                    "What would you like to do? (chat, list online users, exit): ",
                )
                if start_message in ["chat", "Chat", "CHAT"]:
                    destination_server = await asyncio.to_thread(
                        input, "Who do you want to send the message to?: "
                    )
                    chat_message = await asyncio.to_thread(input, "Enter message: ")
                    await self.send_chat(websocket, chat_message, destination_server)
                elif start_message in [
                    "list online users",
                    "list",
                    "List",
                    "LIST",
                    "List online users",
                    "List Online Users",
                ]:
                    await self.get_list(websocket)
                    print("Online users: ")
                elif start_message in ["exit", "Exit", "EXIT", "quit", "q", "Quit"]:
                    print("Goodbye!")
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
