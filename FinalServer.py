# Final/non-vulnerable server script of group 16
# Tanvi Srivastava / a1860959
# Kirsten Pope / a1860519
# Leona Heng / a1791093

import asyncio
import json
import os
import uuid
from collections import defaultdict
import websockets
import aiofiles
from aiohttp import web
from Cryptography import *

# Constants for server configuration.
SERVER_ADDRESS = "127.0.0.1"  # Localhost address for server
NEIGHBOUR_FILE = "neighbouring_servers.txt"  # File to store neighboring servers
PORT_FILE = "http_port.txt"  # File to store ports
HTTP_ADDRESS = "127.0.0.1"  # HTTP address for server communication
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB limit


class Server:
    """Sever class to handle connections and interactions with clients and other servers."""

    def __init__(self):
        self.connected_clients = defaultdict(
            str
        )  # initialise a dictionary to store connected clients
        self.client_key = {}  # Maps usernames to client addresses
        self.public_keys = {}  # Maps usernames to public keys of connected clients
        self.uploaded_files = {}  # Stores uploaded files
        self.neighboring_servers = []  # List of neighboring servers
        self.current_address = "127.0.0.1:8001"
        self.client_updates = (
            {}
        )  # Dictionary to store client lists from neighboring servers
        self.processed_messages = set()  # Track processed message IDs to avoid loops
        self.public_key, self.private_key = generate_rsa_keys()  # Generate RSA keys
        self.counter = 0

    ##############################################################################################################
    # SERVER HANDLING
    ##############################################################################################################
    async def handler(self, websocket):
        """Handle incoming websocket connections and messages."""
        try:
            async for message in websocket:
                await self.handle_message(websocket, json.loads(message))
        except websockets.ConnectionClosed:
            await self.remove_client(websocket)  # Handle client disconnection

    async def handle_message(self, websocket, message):
        """Process different types of incoming messages from clients."""
        if message["type"] == "client_update":
            await self.handle_client_update(message)  # Handle client update
        if message["type"] == "signed_data":  # Process signed data
            await self.process_signed_data(websocket, message)
            if message["data"]["data"]["type"] == "client_list_request":
                await self.send_client_list(websocket)  # Handle client list request
            elif message["data"]["data"]["type"] == "disconnect":
                await self.remove_client(websocket)  # Handle client disconnection
            elif message["data"]["data"]["type"] == "server_disconnect":
                await self.handle_server_disconnect(
                    websocket, message
                )  # Handle server disconnection
            elif message["data"]["data"]["type"] == "get_key":
                await self.send_public_key(
                    websocket, message
                )  # Send public key of specific client to other client

    async def is_username_taken(self, username):
        """Check if username is taken across both the current server and neighboring servers."""
        # Check in the current server's client list
        if username in self.client_key:
            return True

        # Check in neighboring servers' client lists
        for server_clients in self.client_updates.values():
            for client in server_clients:
                if client["username"] == username:
                    return True
        return False


    async def process_signed_data(self, websocket, message):
        """Process signed data messages from clients."""
        public_key = read_key_pem("public_key.pem")

        if message["data"]["data"]["type"] == "hello":
            username = message["data"]["data"]["username"]
            client_address = websocket.remote_address  # Get client's address (IP, port)

            # Check if username already exists.
            if await self.is_username_taken(username):
                error_message = {
                    "type": "error",
                    "message": "Username already taken. Please choose another one.",
                }  # Send an error message back to the client
                await websocket.send(json.dumps(error_message))
                print(f"Username {username} already exists, rejecting connection.")
                return  # Do not proceed further if the username is already taken
                

                # If username is unique, proceed with adding the client.
            self.client_key[username] = f"{client_address}:{client_address}"
            self.connected_clients[f"{client_address}:{client_address}"] = websocket
            self.public_keys[username] = message["data"]["data"]["public_key"]

            await self.send_client_update()

        elif message["data"]["data"]["type"] == "server_hello":
            await self.handle_server_hello(
                websocket, message
            )  # Handle new server connection

        elif message["data"]["data"]["type"] == "chat":
            await self.forward_chat(
                websocket, message
            )  # Forward chat message to intended recipient

        elif message["data"]["data"]["type"] == "public_chat":
            await self.broadcast_public_chat(websocket, message)  # Handle public chat

    async def send_public_key(self, websocket, message):
        """Send the public key of a user to the requesting client."""
        destination_users = message["data"]["data"]["destination_server"]
        sender = message["data"]["data"]["sender"]

        public_key = next(
            (
                user["public_key"]
                for users in self.client_updates.values()
                for user in users
                if user["username"] == destination_users
            ),
            None,  # Default value if no match is found
        )  # Get public key of destination user

        if destination_users in self.public_keys:
            # Client is in current server.
            key = {
                "type": "public_key",
                "user": destination_users,
                "public_key": self.public_keys[destination_users],
            }
            await websocket.send(json.dumps(key))

        elif public_key is not None:
            # Client is in other server.
            key = {
                "type": "public_key",
                "user": destination_users,
                "public_key": public_key,
            }
            await websocket.send(json.dumps(key))

        else:
            # User could not be found.
            fail_message = {"type": "user_not_found"}
            print("User does not exist!")
            await self.connected_clients[self.client_key[sender]].send(
                json.dumps(fail_message)
            )

    ##############################################################################################################3
    # SERVER TO SERVER CONNECTION ESTABLISHMENT
    ##############################################################################################################3
    async def send_client_update(self):
        """Notify all clients and neighboring servers of the current client list."""
        clients_info = [
            {
                "username": username,
                "address": address,
                "public_key": self.public_keys.get(username),
            }
            for username, address in self.client_key.items()
        ]
        update_message = {
            "type": "client_update",
            "sender": self.current_address,
            "clients": clients_info,  # Send the list of dictionaries
        }
        update_message_json = json.dumps(update_message)

        for (
            websocket
        ) in self.connected_clients.values():  # Notify all connected clients
            await websocket.send(update_message_json)

        for server_address in self.neighboring_servers:  # Notify neighboring servers
            try:
                async with websockets.connect(
                    f"ws://{server_address}"
                ) as server_websocket:
                    await server_websocket.send(update_message_json)
            except Exception as e:
                print(f"Failed to send client update to {server_address}: {e}")

    async def handle_server_hello(self, websocket, message):
        """Process connections from neighboring servers."""
        new_server = message["data"]["data"]["sender"]
        if new_server not in self.neighboring_servers:
            self.neighboring_servers.append(new_server)
            print(f"New neighboring server added: {new_server}")
        await self.send_client_update()

    async def handle_client_update(self, message):
        """Handle client update messages from neighboring servers."""
        sender_address = message["sender"]
        clients = message["clients"]
        self.client_updates[sender_address] = (
            clients  # Save the client list from the sender server
        )

    ##############################################################################################################3
    # PRIVATE AND PUBLIC CHATTING
    ##############################################################################################################3
    async def broadcast_public_chat(self, websocket, message):
        """Sends chat message to all online clients."""
        if "message_id" not in message["data"]["data"]:
            message["data"]["data"]["message_id"] = str(
                uuid.uuid4()
            )  # Generate a unique message ID if it doesn't exist

        message_id = message["data"]["data"]["message_id"]

        if message_id in self.processed_messages:
            return  # If we've already processed this message, skip broadcasting it

        self.processed_messages.add(
            message_id
        )  # Add the message ID to the set of processed messages

        message_json = json.dumps(message)  # Convert the message to JSON format
        # Broadcast to all local clients (excluding the sender).#
        for client_websocket in self.connected_clients.values():
            if client_websocket != websocket:
                await client_websocket.send(message_json)

        # Broadcast to neighboring servers.
        for server_address in self.neighboring_servers:
            try:
                async with websockets.connect(
                    f"ws://{server_address}"  # Establish a WebSocket connection with the neighboring server
                ) as server_websocket:
                    await server_websocket.send(
                        message_json
                    )  # Send the public chat message to the neighboring server
            except Exception as e:
                print(f"Failed to broadcast public chat to {server_address}: {e}")

    async def forward_chat(self, websocket, message):
        """Forward the chat to the correct server and client."""
        destination_users = message["data"]["data"]["destination_server"]
        client_address = websocket.remote_address  # Get the IP address of the sender
        sender = next(
            (
                username
                for username, address in self.client_key.items()
                if address == f"{client_address}:{client_address}"
            ),
            None,
        )
        server_key = next(
            (
                key
                for key, users in self.client_updates.items()
                if any(user["username"] == destination_users for user in users)
            ),
            None,
        )  # Find the key for the server that contains the destination user

        if destination_users in self.client_key.keys():
            await self.connected_clients[self.client_key[destination_users]].send(
                json.dumps(message)
            )  # User is in current server
        elif server_key is not None:
            async with websockets.connect(
                f"ws://{server_key}"
            ) as server_websocket:  # User is in another existing server
                await server_websocket.send(
                    json.dumps(message)
                )  # Establish a WebSocket connection with the neighboring server
        else:
            fail_message = {"type": "user_not_found"}
            await self.connected_clients[self.client_key[sender]].send(
                json.dumps(fail_message)
            )  # User could not be found

    ##############################################################################################################3
    # LIST FUNCTIONALITY
    ##############################################################################################################3
    async def send_client_list(self, websocket):
        """Sends the client list to a specific client."""
        servers_list = []  # Initialize the list of servers for the response

        local_server_info = {
            "address": self.current_address,
            "clients": [
                {"username": username, "address": self.current_address}
                for username in self.client_key
            ],
        }
        servers_list.append(local_server_info)  # Add local server's clients

        for (
            server_address,
            clients,
        ) in self.client_updates.items():  # Add clients from neighboring servers
            server_info = {
                "address": server_address,
                "clients": clients,  # clients from neighboring servers are already in the correct format
            }
            servers_list.append(server_info)

        client_list_response = {
            "type": "client_list",
            "servers": servers_list,
        }  # Prepare the response with the structure you requested
        await websocket.send(
            json.dumps(client_list_response)
        )  # Send the response to the requesting client

    ##############################################################################################################3
    # SERVER NEIGHBOURHOOD CONNECTION
    ##############################################################################################################3
    def save_to_file(self, address):
        """Save server address to neighboring_servers.txt"""
        with open(NEIGHBOUR_FILE, "a") as f:
            f.write(address + "\n")

    def load_neighbors(self):
        """Load neighboring servers from file"""
        if os.path.exists(NEIGHBOUR_FILE):
            with open(NEIGHBOUR_FILE, "r") as f:
                self.neighboring_servers = [line.strip() for line in f.readlines()]

    async def connect_to_neighbors(self, actual_port):
        """Connect to all neighboring servers and notify them of this server's presence."""
        private_key = read_key_pem("private_key.pem")
        for neighbor in self.neighboring_servers:
            try:
                async with websockets.connect(f"ws://{neighbor}") as websocket:
                    data = {
                        "data": {
                            "type": "server_hello",
                            "sender": f"{SERVER_ADDRESS}:{actual_port}",
                        }
                    }
                    server_hello = {
                        "type": "signed_data",
                        "data": data,
                        "counter": self.counter,
                        "signature": sign_message(json.dumps(data), private_key),
                    }
                    self.counter += 1
                    await websocket.send(json.dumps(server_hello))
                    print(f"Connected to neighboring server {neighbor}")
            except Exception as e:
                print(f"Failed to connect to {neighbor}: {e}")

    ##############################################################################################################3
    # FILE TRANSFER
    ##############################################################################################################3
    async def handle_file_upload(self, request):
        data = await request.json()
        if (
            "METHOD" not in data
            or data["METHOD"] != "POST"
            or "body" not in data
            or "recipient" not in data
            or "file_name" not in data
        ):
            return web.Response(status=400, text="Invalid request format")

        file_data = data["body"].encode("latin1")
        if len(file_data) > MAX_FILE_SIZE:
            return web.Response(status=413, text="File too large")

        recipient = data["recipient"]
        original_file_name = data["file_name"]
        file_id = str(uuid.uuid4())
        temp_file_path = f"uploads/{recipient}_{file_id}_{original_file_name}"
        os.makedirs("uploads", exist_ok=True)

        async with aiofiles.open(temp_file_path, "wb") as f:
            await f.write(file_data)

        response_body = {
            "body": {
                "file_name": original_file_name,
                "file_url": f"http://{HTTP_ADDRESS}:{self.http_port}/api/files/{file_id}",
                "recipient": recipient,
            }
        }
        print(f"File uploaded: {file_id} for {recipient}")

        # Store the file path with the ID and recipient.
        if recipient not in self.uploaded_files:
            self.uploaded_files[recipient] = {}
        self.uploaded_files[recipient][file_id] = {
            "path": temp_file_path,
            "name": original_file_name,
        }

        return web.json_response(response_body)

    async def handle_link_request(self, request):
        username = request.query.get("username")
        file_links = {"uploaded_files": [], "has_files": False}

        if username in self.uploaded_files:
            file_links["has_files"] = True
            for file_id, file_info in self.uploaded_files[username].items():
                file_links["uploaded_files"].append(
                    {
                        "file_name": file_info["name"],
                        "file_url": f"http://{HTTP_ADDRESS}:{self.http_port}/api/files/{file_id}",
                    }
                )
        return web.json_response(file_links)

    async def handle_file_retrieval(self, request):
        file_id = request.match_info.get("file_id")
        username = request.query.get("username")

        if not file_id or not username:
            return web.Response(
                status=400, text="Invalid input: file_id and username are required."
            )  # Validate input

        file_info = None

        # Check all recipients for the file_id.
        for recipient, files in self.uploaded_files.items():
            if file_id in files:
                if recipient != username:  # Compare recipient with username
                    return web.Response(
                        status=403, text="Access denied: You are not the recipient."
                    )
                file_info = files[file_id]
                break

        if not file_info or not os.path.exists(file_info["path"]):
            return web.Response(status=404, text="File not found")

        print(f"File retrieved: {file_id}")
        headers = {"Content-Disposition": f'attachment; filename="{file_info["name"]}"'}
        return web.FileResponse(file_info["path"], headers=headers)

    ##############################################################################################################3
    # SERVER DISCONNECT AND SHUT DOWN
    ##############################################################################################################3
    def remove_from_file(self, address):
        """Remove server address from neighbouring_servers.txt"""
        if os.path.exists(NEIGHBOUR_FILE):
            with open(NEIGHBOUR_FILE, "r") as f:
                lines = f.readlines()

            with open(NEIGHBOUR_FILE, "w") as f:
                remaining_lines = [line for line in lines if line.strip() != address]
                f.writelines(remaining_lines)

            # Check if the file is now empty
            if not remaining_lines:
                if os.path.exists(PORT_FILE):
                    os.remove(PORT_FILE)
                else:
                    print(f"{PORT_FILE} does not exist.")
            else:
                print(f"Removed {address} from {NEIGHBOUR_FILE}.")

    async def send_server_disconnect(self):
        """Notifies all neighbours about disconnection."""
        disconnect_message = {
            "type": "signed_data",
            "data": {
                "data": {"type": "server_disconnect", "sender": self.current_address}
            },
            "counter": self.counter,
        }
        # Sign the message after it's fully constructed
        disconnect_message["signature"] = sign_message(
            json.dumps(disconnect_message["data"]), read_key_pem("private_key.pem")
        )
        self.counter += 1

        # Notify neighboring servers about the disconnection.
        for neighbor in self.neighboring_servers:
            try:
                async with websockets.connect(f"ws://{neighbor}") as websocket:
                    await websocket.send(json.dumps(disconnect_message))
                    print(f"Notified {neighbor} of disconnection.")
            except Exception as e:
                print(f"Failed to notify {neighbor}: {e}")

    async def handle_server_disconnect(self, websocket, message):
        """Removes disconnected server from neighbouring servers list."""
        remove_server = message["data"]["data"]["sender"]
        if remove_server in self.neighboring_servers:
            self.neighboring_servers.remove(remove_server)

    async def remove_client(self, websocket):
        """Removes client from all storage dictionaries."""
        client_address = websocket.remote_address
        client_key = f"{client_address}:{client_address}"

        if client_key in self.connected_clients:
            del self.connected_clients[
                client_key
            ]  # Remove client from connected_clients

        for username, address in list(self.client_key.items()):
            if address == client_key:
                print(f"Removing client key for: {username}")
                del self.client_key[
                    username
                ]  # Remove the client from client_key dictionary
                break

        if username in self.public_keys:
            del self.public_keys[
                username
            ]  # Remove the client from public_key dictionary

        # Check if websocket is open before sending the update
        if websocket.open:
            await self.send_client_update()  # Notify all clients of the updated list

    async def exit_command_listener(self):
        """Continuously listen for the 'exit' command from the console."""
        while True:
            command = await asyncio.to_thread(
                input, "Type 'exit' to shut down the server\n"
            )
            if command.lower() == "exit":
                print("Shutting down server...")
                await self.send_server_disconnect()  # Notify neighbors before shutdown
                self.remove_from_file(self.current_address)  # Remove from file
                for task in asyncio.all_tasks():
                    task.cancel()  # Cancel all running tasks
                break

    ##############################################################################################################3
    # INTERFACE
    ##############################################################################################################3
    async def run(self, host=SERVER_ADDRESS, ws_port=0, http_port=0):
        """Main function to run server."""
        save_key_pem(self.public_key, "public_key.pem")
        save_key_pem(self.private_key, "private_key.pem")
        ws_server = await websockets.serve(self.handler, host, ws_port)
        actual_ws_port = ws_server.sockets[0].getsockname()[1]  # Get the assigned port

        self.current_address = f"{host}:{actual_ws_port}"
        self.load_neighbors()
        self.save_to_file(self.current_address)

        print(f"Neighboring servers: {self.neighboring_servers}")
        print(f"WebSocket server running on {host}:{actual_ws_port}")

        if os.path.exists(PORT_FILE):
            print("")  # Check if HTTP file needs to be created
        else:
            # Set up the HTTP server with specified routes for file handling.
            app = web.Application()
            app.router.add_post("/api/upload", self.handle_file_upload)
            app.router.add_get("/api/files/{file_id}", self.handle_file_retrieval)
            app.router.add_get("/api/links", self.handle_link_request)
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(
                runner, HTTP_ADDRESS, http_port
            )  # Use port=0 to select a random port

            await site.start()
            self.http_port = site._server.sockets[0].getsockname()[
                1
            ]  # Retrieve the dynamically assigned port
            print(f"HTTP server running on http://{HTTP_ADDRESS}:{self.http_port}")

            async with aiofiles.open(PORT_FILE, "a") as f:
                await f.write(f"{self.http_port}\n")

        await self.connect_to_neighbors(
            actual_ws_port
        )  # Connect to neighbouring servers to establish communication
        await asyncio.gather(
            ws_server.wait_closed(), self.exit_command_listener()
        )  # Wait for the WebSocket server to close or an exit command


if __name__ == "__main__":
    server = Server()
    try:
        asyncio.run(server.run())
    except asyncio.CancelledError:
        print("Server has been shut down.")
