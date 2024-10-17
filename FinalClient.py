# Final/non-vulnerable client script of group 16
# Tanvi Srivastava / a1860959
# Kirsten Pope / a1860519
# Leona Heng / a1791093

import asyncio
import os
import json
import sys
import random
from Cryptography import *
import websockets
import aiohttp
import aiofiles

def read_port(file_path):
    """Reads the last used port from http_port.txt specified file."""
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            first_line = file.readline().strip()
            if first_line:
                return int(first_line)
            else:
                raise ValueError("The file is empty")

# Configuration Constants
HTTP_ADDRESS = "localhost"
HTTP_PORT = read_port("http_port.txt")

class Client:
    """Client class to handle connections and interactions with chat server."""

    def __init__(self):
        self.uri = self.get_random_server()  # Get a random server URI
        self.public_key, self.private_key = (
            generate_rsa_keys()
        )  # Generate RSA keys
        self.username = "User"  # Default username
        self.counter = 0  # Message counter
        self.public_keys_storage = {}  # Storage for public keys of other users
        self.verification_event = asyncio.Event()  # Event for user verification
        self.user_valid = False  # Flag for user validation
        self.client_list_received = asyncio.Event()  # Event for client list reception
        self.no_user = asyncio.Event()  # Event for non-existing user handling

    ##############################################################################################################3
    # SERVER CONNECTION
    ##############################################################################################################3
    def get_random_server(self):
        """Loads neighbouring servers from a file and selects one at random."""
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
    async def verify_user_and_get_key(self, websocket, destination):
        """Sends a message to verify the user and get their public key."""
        message = {
            "data": {
                "type": "get_key",
                "destination_server": destination,
                "sender": self.username,
            }
        }
        await self.send_message(websocket, message)
        await self.verification_event.wait()

    async def set_public_key(self, message):
        """Stores the public key of a user upon receiving it."""
        public_key = message["public_key"]
        user = message["user"]
        self.public_keys_storage[user] = public_key
        self.user_valid = True
        self.verification_event.set()

    ##############################################################################################################3
    # LIST FUNCTIONALITY
    ##############################################################################################################3
    async def request_client_list(self, websocket):
        """Requests a list of connected clients from the server."""
        message = {"data": {"type": "client_list_request"}}
        await self.send_message(websocket, message)  # Send client list request
        await self.client_list_received.wait()  # Wait until the response is received

    async def handle_client_list(self, message):
        """Handles the client list received from the server."""
        servers = message.get("servers", [])  # Extract list of servers

        print("\nOnline users:")
        for server in servers:
            server_address = server.get(
                "address", "Unknown address"
            )  # Get server address
            print(f"Server: {server_address}")

            clients = server.get("clients", [])  # Get list of clients from the server
            for client in clients:
                username = client.get("username", "Unknown user")  # Get client username
                print(f"- {username}")  # Print each client

        self.client_list_received.set()  # Signal that client list has been received

    ##############################################################################################################3
    # CONNECT AND DISCONNECT FROM SERVER
    ##############################################################################################################3
    async def send_disconnect(self, websocket):
        """Sends a disconnect message to the server."""
        message = {
            "data": {
                "type": "disconnect",
                "username": self.username,
            }
        }
        await self.send_message(websocket, message)  # Send disconnect message

    async def send_hello(self, websocket):
        """Sends a connection message to the server."""
        message = {
            "data": {
                "type": "hello",
                "public_key": self.public_key.decode(),
                "username": self.username,
            }
        }
        await self.send_message(websocket, message)  # Send connection message

    ##############################################################################################################3
    # SEND/RECEIVE MESSAGES
    ##############################################################################################################3
    async def send_message(self, websocket, data):
        """Signs the message and sends to the server."""
        signature = sign_message(json.dumps(data), read_key_pem("private_key.pem"))
        message = {
            "type": "signed_data",
            "data": data,
            "counter": self.counter,
            "signature": signature,
        }
        self.counter += 1
        await websocket.send(json.dumps(message))   # Send the JSON-encoded as string message

    async def send_chat(self, websocket, chat_message, destination):
        """Sends a private chat message to a specific user."""
        for key in self.public_keys_storage:
            if key == destination:
                users_public_key = self.public_keys_storage[key]  # Retrieve user's public key
        chat_content = {
            "sender": self.username,
            "message": chat_message,
        }
        chat_content_str = json.dumps(chat_content)  # Convert dictionary to JSON string
        iv, encrypted_AES_key, ciphertext = encrypt_message(chat_content_str, users_public_key)
        message = {
            "data": {
                "type": "chat",
                "destination_server": destination,
                "iv": iv,
                "symm_keys": [encrypted_AES_key],  # Ensure this is a list of strings
                "chat": ciphertext,
            }
        }
        await self.send_message(websocket, message)  # Send the encrypted message through the websocket

    async def send_public_chat(self, websocket, chat_message):
        """Create a message structure for sending a public chat message."""
        message = {
            "data": {
                "type": "public_chat",
                "sender": self.username,  # generate_fingerprint(self.public_key),
                "message": chat_message,
            }
        }
        await self.send_message(websocket, message)  # Send the message through the websocket

    async def receive_messages(self, websocket):
        """Continuously receive messages from the websocket."""
        try:
            async for message in websocket:
                message = json.loads(message)  # Decode the JSON message
                if message["type"] == "signed_data":
                    await self.handle_message(message)
                elif message["type"] == "client_list":
                    await self.handle_client_list(message)  # Handle client list updates
                elif message["type"] == "user_not_found":
                    await self.handle_chat_fail()  # Handle user not found scenarios
                elif message["type"] == "public_key":
                    await self.set_public_key(
                        message
                    )  # Set public key from received message
        except websockets.exceptions.ConnectionClosedError:
            print("Server shut down. Messages no longer possible.")
            sys.exit(0)  # Exit the client application

    async def handle_chat_fail(self):
        """Notify the user that the user they prompted is not online or does not exist."""
        print("That user is not online/does not exist")
        self.user_valid = False
        self.verification_event.set()  # Trigger the verification event
    
    async def handle_chat(self, message):
        """Handle incoming private messages."""
        senders_private_key = read_key_pem("private_key.pem")
        iv = message["data"]["data"]["iv"]
        encrypted_aes_key = message["data"]["data"]["symm_keys"][0]
        ciphertext = message["data"]["data"]["chat"]

        # Decrypt the message using the provided information
        decrypted_chat_data = decrypt_message(iv, encrypted_aes_key, ciphertext, self.private_key)
        decrypted_chat_data = json.loads(decrypted_chat_data)  # Convert JSON string back to dictionary

        sender = decrypted_chat_data["sender"]
        plaintext = decrypted_chat_data["message"]
        print(f"\n[Private message] {sender}: {plaintext}")

    async def handle_public_chat(self, message):
        """Handle incoming public chat messages."""
        sender = message["data"]["data"]["sender"]
        chat_message = message["data"]["data"]["message"]
        print(f"\n[Public message] {sender}: {chat_message}")

    async def handle_message(self, message):
        if message["data"]["data"]["type"] == "chat":
            await self.handle_chat(message)
        elif message["data"]["data"]["type"] == "public_chat":
            await self.handle_public_chat(message)

    ##############################################################################################################3
    # FILE TRANSFER
    ##############################################################################################################3
    async def upload_file(self, file_path):
        """Upload file to server for specific recipient to access."""
        recipient = input("Enter the recipient's username: ")
        file_name = os.path.basename(file_path)  # Extract the base name of the file
        try:
            async with aiohttp.ClientSession() as session:  # Create HTTP session
                async with aiofiles.open(file_path, "rb") as f:
                    file_data = await f.read()  # Read file data
                    payload = {
                        "METHOD": "POST",  # HTTP method
                        "body": file_data.decode(
                            "latin1"
                        ),  # file data encoded using Latin-1
                        "recipient": recipient,
                        "file_name": file_name,
                    }
                    async with session.post(  # send file data to the server
                        f"http://{HTTP_ADDRESS}:{HTTP_PORT}/api/upload", json=payload
                    ) as resp:
                        response = await resp.json()
                        print("File uploaded.")
        except FileNotFoundError:
            print("File does not exist. Try Again!")

    async def link_request(self):
        """Request links to uploaded files for the current user."""
        username = self.username
        async with aiohttp.ClientSession() as session:  # Create an HTTP session
            async with session.get(
                f"http://{HTTP_ADDRESS}:{HTTP_PORT}/api/links?username={username}"
            ) as resp:
                if resp.status == 200:  # If successful request
                    links = await resp.json()
                    if links["uploaded_files"]:
                        print("Uploaded Files:")
                        for idx, file in enumerate(links["uploaded_files"], start=1):
                            print(
                                f"{idx}. {file['file_name']}: {file['file_url']}"
                            )  # List uploaded file URLLs

                        file_url = input("Enter url of the file you want to retrieve: ")
                        await self.retrieve_file(file_url)  # retrieve selected file
                    else:
                        print("No files found for this user.")
                else:
                    print("Failed to retrieve file links.")

    async def retrieve_file(self, file_url):
        """Retrieve a file from the provided URL."""
        username = self.username
        dangerous_extensions = [  # List of potentially dangerous file extensions
            ".exe", ".bat", ".cmd", ".js", ".vbs", ".dll", ".sys", ".lnk",
        ]

        # Validate input
        if not file_url or not username:
            print("Invalid input: file_url and username are required.")
            return

        try:
            async with aiohttp.ClientSession() as session:  # Create HTTP session
                async with session.get(f"{file_url}?username={username}") as resp:
                    if resp.status == 200:
                        file_data = await resp.read()
                        # Extract the original file name from the response headers
                        content_disposition = resp.headers.get("Content-Disposition")
                        if content_disposition:
                            file_name = content_disposition.split("filename=")[-1].strip('"')
                        else:
                            file_name = "downloaded_file"  # Fallback name

                        # Check if the file already exists and modify the name if necessary
                        base_name, extension = os.path.splitext(file_name)
                        counter = 1
                        new_file_name = file_name
                        while os.path.exists(new_file_name):
                            new_file_name = f"{base_name}({counter}){extension}"
                            counter += 1

                        # Check for potentially dangerous file formats
                        if extension.lower() in dangerous_extensions:
                            user_input = input(
                                f"Warning: The file '{file_name}' may be harmful. Do you wish to continue the download? (yes/no): "
                            )
                            if user_input.lower() != "yes":
                                print("Download aborted.")
                                return

                        with open(new_file_name, "wb") as f:  # Write file data to disk
                            f.write(file_data)
                        print(f"File downloaded successfully as {new_file_name}.")
                    else:
                        print(f"Failed to retrieve file. HTTP status code: {resp.status}")
        except aiohttp.ClientError as e:
            print(f"An error occurred: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    ##############################################################################################################3
    # INTERFACE
    ##############################################################################################################3
    async def run(self):
        """Main function to run client."""
        try:
            async with websockets.connect(
                self.uri
            ) as websocket:  # Connect to websocket server
                print("Joining chat server...")
                # Save keys to PEM files
                save_key_pem(self.public_key, "public_key.pem")
                save_key_pem(self.private_key, "private_key.pem")

                while True:
                    self.username = await asyncio.to_thread(input, "\nEnter username: ")
                    await self.send_hello(websocket)  # Send connection message
                    # Wait for a response from the server to check if the username is valid
                    response = await websocket.recv()
                    response_data = json.loads(response)

                    if response_data.get("type") == "error":
                        print(response_data.get("message"))
                        continue  # Ask for a new username if the current one is taken
                    else:
                        print(f"\nWelcome {self.username}!")
                        break

                asyncio.create_task(
                    self.receive_messages(websocket)
                )  # Start listening for incoming messages from the server

                while True:
                    start_message = await asyncio.to_thread(
                        input,
                        "\nChoose action:\n1. Send Private Message\n2. Send Public Message\n3. List Online Users\n4. File Upload\n5. File Download\n6. Exit\n",
                    )
                    # Handle private messages
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
                            await self.verify_user_and_get_key(
                                websocket, destination
                            )  # Verify user and get key
                            if not self.user_valid:
                                continue
                            chat_message = await asyncio.to_thread(
                                input, "Enter message: "
                            )
                            await self.send_chat(websocket, chat_message, destination)

                    # Handle public messages
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

                    # Handle listing online users
                    elif start_message.lower() in ["list online users", "list", "3"]:
                        self.client_list_received.clear()
                        await self.request_client_list(websocket)

                    # Handle file upload
                    elif start_message.lower() in [
                        "upload file",
                        "upload",
                        "4",
                        "file upload",
                    ]:
                        file_path = input("\nEnter the path of the file to upload: ")
                        await self.upload_file(file_path)

                    # Handle file download
                    elif start_message.lower() in [
                        "download",
                        "download file",
                        "file download",
                        "5",
                    ]:
                        await self.link_request()

                    # Handle application exit
                    elif start_message.lower() in ["exit", "quit", "q", "6"]:
                        print("\nGoodbye!")
                        await self.send_disconnect(
                            websocket
                        )  # Send the disconnect message to the server
                        await websocket.close()  # Close the websocket
                        sys.exit(1)
                    else:
                        print("\nNot a valid command, enter again")
        except Exception as e:
            print(f"An error occurred: {e}")


if __name__ == "__main__":
    client = Client()  # Instantiate the client
    try:
        # Run until completion
        asyncio.get_event_loop().run_until_complete(client.run())
    except KeyboardInterrupt:
        print("\nGoodbye!")
        sys.exit(1)