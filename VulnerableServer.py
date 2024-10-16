# Vulnerable server script of group 16
# Tanvi Srivastava / a1860959
# Kirsten Pope / a1860519
# Leona Heng / a1791093

import asyncio
import websockets
import json
import sys
from aiohttp import web
import aiofiles
import os
import uuid
from collections import defaultdict
import time

SERVER_ADDRESS = "127.0.0.1"
NEIGHBOUR_FILE = "neighbouring_servers.txt"
PORT_FILE = "http_port.txt"
HTTP_ADDRESS = "localhost"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB limit

class Server:
    def __init__(self):
        self.connected_clients = defaultdict(str)
        self.client_key = {}
        self.public_keys = {}
        self.uploaded_files = {}
        self.neighboring_servers = []  # List of neighboring servers
        self.current_address = "127.0.0.1:8001"
        self.client_updates = (
            {}
        )  # Dictionary to store client lists from neighboring servers
        self.processed_messages = set()  # Track processed message IDs to avoid loops

    ##############################################################################################################3
    # SERVER HANDLING
    ##############################################################################################################3
    async def handler(self, websocket, path):
        try:
            async for message in websocket:
                if debug_mode:
                    print(
                        f"Received raw message: {message}"
                    )  # Log the raw message for debugging
                await self.handle_message(websocket, json.loads(message))
        except websockets.ConnectionClosed:
            # Handle client disconnection
            await self.remove_client(websocket)

    async def handle_message(self, websocket, message):
        if debug_mode:
            print(f"INCOMING MESSAGE: {message}")
        if message["type"] == "client_update":
            await self.handle_client_update(message)  # Handle client update
        if message["type"] == "signed_data":
            if (
                message["data"]["data"]["type"] == "hello"
                or message["data"]["data"]["type"] == "chat"
            ):
                await self.process_signed_data(websocket, message)
            elif message["data"]["data"]["type"] == "client_list_request":
                await self.send_client_list(websocket)  # Handle client list request
            elif message["data"]["data"]["type"] == "disconnect":
                await self.remove_client(websocket)  # Handle client disconnection
            elif message["data"]["data"]["type"] == "public_chat":
                await self.broadcast_public_chat(
                    websocket, message
                )  # Handle public chat
            elif message["data"]["data"]["type"] == "server_hello":
                await self.handle_server_hello(websocket, message)
            elif message["data"]["data"]["type"] == "server_disconnect":
                await self.handle_server_disconnect(websocket, message)
            elif message["data"]["data"]["type"] == "get_key":
                await self.send_public_key(websocket, message)

    async def process_signed_data(self, websocket, message):
        if message["data"]["data"]["type"] == "hello":
            username = message["data"]["data"]["username"]
            client_address = websocket.remote_address  # This gives (IP, port)
            self.client_key[username] = f"{client_address[0]}:{client_address[1]}"
            self.connected_clients[f"{client_address[0]}:{client_address[1]}"] = (
                websocket
            )
            self.public_keys[username] = message["data"]["data"]["public_key"]
            if debug_mode:
                print(f"Connected Clients: {self.connected_clients}")
                print(f"Client key: {self.client_key}")
                print(f"public_keys: {self.public_keys}")
            await self.send_client_update()
        elif message["data"]["data"]["type"] == "chat":
            # Forward chat message to intended recipient
            await self.forward_chat(message)

    async def send_public_key(self, websocket, message):
        destination_users = message["data"]["data"]["destination_server"]
        sender = message["data"]["data"]["sender"]
        if debug_mode:
            print(f"Public keys: {self.public_keys}")
            print(f"Destination: {destination_users}")
            print(f"CLIENT UPDATES: {self.client_updates}")
        public_key = next(
            (
                user["public_key"]
                for users in self.client_updates.values()
                for user in users
                if user["username"] == destination_users
            ),
            None,  # Default value if no match is found
        )

        if destination_users in self.public_keys:
            if debug_mode:
                print("Key is in server!")

            key = {
                "type": "public_key",
                "user": destination_users,
                "public_key": self.public_keys[destination_users],
            }
            await websocket.send(json.dumps(key))

        elif public_key is not None:
            if debug_mode:
                print("Key is in another server!")
            key = {
                "type": "public_key",
                "user": destination_users,
                "public_key": public_key,
            }
            await websocket.send(json.dumps(key))

        else:
            fail_message = {"type": "user_not_found"}
            if debug_mode:
                print("User does not exist!")
                print(f"Sending to... {self.client_key[sender]}")
            await self.connected_clients[self.client_key[sender]].send(
                json.dumps(fail_message)
            )

    ##############################################################################################################3
    # SERVER TO SERVER CONNECTION ESTABLISHMENT
    ##############################################################################################################3
    async def send_client_update(self):
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
        # Notify all connected clients
        for websocket in self.connected_clients.values():
            await websocket.send(update_message_json)
        # Notify neighboring servers
        for server_address in self.neighboring_servers:
            try:
                async with websockets.connect(
                    f"ws://{server_address}"
                ) as server_websocket:
                    await server_websocket.send(update_message_json)
            except Exception as e:
                print(f"Failed to send client update to {server_address}: {e}")

    async def handle_server_hello(self, websocket, message):
        new_server = message["data"]["data"]["sender"]
        if new_server not in self.neighboring_servers:
            self.neighboring_servers.append(new_server)
            if debug_mode:
                print(f"New neighboring server added: {new_server}")
        await self.send_client_update()

    async def handle_client_update(self, message):
        sender_address = message["sender"]
        clients = message["clients"]
        if debug_mode:
            print(f"clients: {clients}")
            print("CLIENT_UPDATES ARRAY")
            print(self.client_updates)
            print(f"Updated client list from {sender_address}: {clients}")

        # Save the client list from the sender server
        self.client_updates[sender_address] = clients

    ##############################################################################################################3
    # PRIVATE AND PUBLIC CHATTING
    ##############################################################################################################3
    async def broadcast_public_chat(self, websocket, message):
        # Generate a unique message ID if it doesn't exist
        if "message_id" not in message["data"]["data"]:
            message["data"]["data"]["message_id"] = str(uuid.uuid4())

        message_id = message["data"]["data"]["message_id"]

        # If we've already processed this message, skip broadcasting it
        if message_id in self.processed_messages:
            return
        # Add the message ID to the set of processed messages
        self.processed_messages.add(message_id)
        # Convert the message to JSON format
        message_json = json.dumps(message)
        # Broadcast to all local clients (excluding the sender)
        for client_websocket in self.connected_clients.values():
            if client_websocket != websocket:
                await client_websocket.send(message_json)
        # Broadcast to neighboring servers
        for server_address in self.neighboring_servers:
            try:
                # Establish a WebSocket connection with the neighboring server
                async with websockets.connect(
                    f"ws://{server_address}"
                ) as server_websocket:
                    # Send the public chat message to the neighboring server
                    await server_websocket.send(message_json)
            except Exception as e:
                print(f"Failed to broadcast public chat to {server_address}: {e}")

    async def forward_chat(self, message):
        destination_users = message["data"]["data"]["destination_server"]
        sender = message["data"]["data"]["chat"]["sender"]
        if debug_mode:
            print(f"Destination: {destination_users}")
            print(f"Keys: {self.client_key.keys()}")
        server_key = next(
            (
                key
                for key, users in self.client_updates.items()
                if any(user["username"] == "Brad" for user in users)
            ),
            None,
        )
        if debug_mode:
            print(f"Server Key: {server_key}")

        if destination_users in self.client_key.keys():
            if debug_mode:
                print(
                    f"Sending to: {self.client_key[destination_users]} at {self.connected_clients[self.client_key[destination_users]]}"
                )
            await self.connected_clients[self.client_key[destination_users]].send(
                json.dumps(message)
            )
        elif server_key is not None:
            if debug_mode:
                print("Client is in existing server")
            # Establish a WebSocket connection with the neighboring server
            async with websockets.connect(f"ws://{server_key}") as server_websocket:
                await server_websocket.send(json.dumps(message))
        else:
            fail_message = {"type": "user_not_found"}
            if debug_mode:
                print(f"Sending to... {self.client_key[sender]}")
            await self.connected_clients[self.client_key[sender]].send(
                json.dumps(fail_message)
            )

    ##############################################################################################################3
    # LIST FUNCTIONALITY
    ##############################################################################################################3
    async def send_client_list(self, websocket):
        # Initialize the list of servers for the response
        servers_list = []
        # Add local server's clients
        local_server_info = {
            "address": self.current_address,
            "clients": [
                {"username": username, "address": self.current_address}
                for username in self.client_key
            ],
        }
        servers_list.append(local_server_info)
        # Add clients from neighboring servers
        for server_address, clients in self.client_updates.items():
            server_info = {
                "address": server_address,
                "clients": clients,  # clients from neighboring servers are already in the correct format
            }
            servers_list.append(server_info)

        # Prepare the response with the structure you requested
        client_list_response = {"type": "client_list", "servers": servers_list}

        # Send the response to the requesting client
        while debug_mode:
            await websocket.send(json.dumps(client_list_response))
        await websocket.send(json.dumps(client_list_response))

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
        for neighbor in self.neighboring_servers:
            try:
                async with websockets.connect(f"ws://{neighbor}") as websocket:
                    server_hello = {
                        "type": "signed_data",
                        "data": {
                            "data": {
                                "type": "server_hello",
                                "sender": f"{SERVER_ADDRESS}:{actual_port}",
                            }
                        },
                        "counter": 1,
                        "signature": 1234,
                    }
                    await websocket.send(json.dumps(server_hello))
                    if debug_mode:
                        print(f"Connected to neighboring server {neighbor}")
            except Exception as e:
                print(f"Failed to connect to {neighbor}: {e}")

    ##############################################################################################################3
    # FILE UPLOAD
    ##############################################################################################################3
    async def handle_file_upload(self, request):
        data = await request.json()
        if "METHOD" not in data or data["METHOD"] != "POST" or "body" not in data or "recipient" not in data or "file_name" not in data:
            return web.Response(status=400, text="Invalid request format")

        file_data = data["body"].encode('latin1')
        if len(file_data) > MAX_FILE_SIZE:
            return web.Response(status=413, text="File too large")

        recipient = data["recipient"]
        original_file_name = data["file_name"]
        file_id = str(uuid.uuid4())
        temp_file_path = f"uploads/{file_id}_{original_file_name}"
        os.makedirs("uploads", exist_ok=True)

        async with aiofiles.open(temp_file_path, 'wb') as f:
            await f.write(file_data)

        response_body = {
            "body": {
                "file_name": original_file_name,
                "file_url": f"http://{HTTP_ADDRESS}:{self.http_port}/api/files/{file_id}",
                "recipient": recipient
            }
        }
        print(f'File uploaded: {file_id} for {recipient}')
        
        # Store the file path with the ID and recipient
        if recipient not in self.uploaded_files:
            self.uploaded_files[recipient] = {}
        self.uploaded_files[recipient][file_id] = {
            "path": temp_file_path,
            "name": original_file_name
        }

        return web.json_response(response_body)

    async def handle_link_request(self, request):
        username = request.query.get('username')
        file_links = {
            "uploaded_files": [],
            "has_files": False
        } 
        
        if username in self.uploaded_files:
            file_links["has_files"] = True
            for file_id, file_info in self.uploaded_files[username].items():
                file_links["uploaded_files"].append({
                    "file_name": file_info["name"],
                    "file_url": f"http://{HTTP_ADDRESS}:{self.http_port}/api/files/{file_id}"
                })
        return web.json_response(file_links)

    async def handle_file_retrieval(self, request):
        file_id = request.match_info['file_id']
        username = request.query.get('username')
        file_info = None

        # Check all recipients for the file_id
        for recipient, files in self.uploaded_files.items():
            if file_id in files:
                if recipient != username:  # Compare recipient with username
                    return web.Response(status=403, text="Access denied: You are not the recipient.")
                file_info = files[file_id]
                break

        if not file_info or not os.path.exists(file_info["path"]):
            return web.Response(status=404, text="File not found")

        print(f'File retrieved: {file_id}')
        headers = {
            'Content-Disposition': f'attachment; filename="{file_info["name"]}"'
        }
        return web.FileResponse(file_info["path"], headers=headers)

    ##############################################################################################################3
    # SERVER DISCONNECT AND SHUT DOWN
    ##############################################################################################################3
    def remove_from_file(self, address):
        # """Remove server address from neighbouring_servers.txt"""
        if os.path.exists(NEIGHBOUR_FILE):
            with open(NEIGHBOUR_FILE, "r") as f:
                lines = f.readlines()
            with open(NEIGHBOUR_FILE, "w") as f:
                for line in lines:
                    if (
                        line.strip() != address
                    ):  # Write back all lines except the one to remove
                        f.write(line)

    async def send_server_disconnect(self):
        disconnect_message = {
            "type": "signed_data",
            "data": {
                "data": {"type": "server_disconnect", "sender": self.current_address}
            },
            "counter": 1,
            "signature": 1234,
        }
        # Notify neighboring servers about the disconnection
        for neighbor in self.neighboring_servers:
            try:
                async with websockets.connect(f"ws://{neighbor}") as websocket:
                    await websocket.send(json.dumps(disconnect_message))
                    if debug_mode:
                        print(f"Notified {neighbor} of disconnection.")
            except Exception as e:
                print(f"Failed to notify {neighbor}: {e}")

    async def handle_server_disconnect(self, websocket, message):
        remove_server = message["data"]["data"]["sender"]
        if remove_server in self.neighboring_servers:
            self.neighboring_servers.remove(remove_server)
            if debug_mode:
                print(f"handle_server_disconnect: {remove_server}")
                print(self.neighboring_servers)

    async def remove_client(self, websocket):
        client_address = websocket.remote_address
        client_key = f"{client_address[0]}:{client_address[1]}"

        # Remove client from connected_clients
        if client_key in self.connected_clients:
            print(f"Removing client: {client_key}")
            del self.connected_clients[client_key]

        # Remove the client from client_key dictionary
        for username, address in list(self.client_key.items()):
            if address == client_key:
                print(f"Removing client key for: {username}")
                del self.client_key[username]
                break
        if username in self.public_keys:
            print(f"Removing public key for: {username}")
            del self.public_keys[username]

        # Remove the client from public_key dictionary

        # Notify all clients of the updated list
        await self.send_client_update()
        print(f"Client {client_key} removed.")

    async def exit_command_listener(self):
        while True:
            command = await asyncio.to_thread(
                input, "Type 'exit' to shut down the server\n"
            )
            if command.lower() == "exit":
                print("Shutting down server...")
                await self.send_server_disconnect()  # Notify neighbors before shutdown
                self.remove_from_file(self.current_address)  # Remove from file
                # time.sleep(2)  UNCOMMENT WHEN FINISHED
                for task in asyncio.all_tasks():
                    task.cancel()  # Cancel all running tasks
                break

    ##############################################################################################################3
    # INTERFACE
    ##############################################################################################################3
    async def run(self, host=SERVER_ADDRESS, ws_port=0, http_port=0):
        print(f"Starting WebSocket server on {host}...")
        ws_server = await websockets.serve(self.handler, host, ws_port)
        actual_ws_port = ws_server.sockets[0].getsockname()[1]

        self.current_address = f"{host}:{actual_ws_port}"
        self.load_neighbors()
        self.save_to_file(self.current_address)

        print(f"Neighboring servers: {self.neighboring_servers}")
        print(f"WebSocket server running on {host}:{actual_ws_port}")

        if os.path.exists(PORT_FILE):
            print("Skipping HTTP server creation.")
        else:
            app = web.Application()
            app.router.add_post("/api/upload", self.handle_file_upload)
            app.router.add_get("/api/files/{file_id}", self.handle_file_retrieval)
            app.router.add_get("/api/links", self.handle_link_request)
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, HTTP_ADDRESS, http_port)  # Use port=0 to select a random port
            await site.start()
            self.http_port = site._server.sockets[0].getsockname()[1]  # Retrieve the dynamically assigned port
            print(f"HTTP server running on http://{HTTP_ADDRESS}:{self.http_port}")
            async with aiofiles.open(PORT_FILE, 'a') as f:
                await f.write(f"{self.http_port}\n")

        await self.connect_to_neighbors(actual_ws_port)
        await asyncio.gather(ws_server.wait_closed(), self.exit_command_listener())

if __name__ == "__main__":
    server = Server()
    try:
        debug_mode = False
        if len(sys.argv) > 1 and sys.argv[1] == "debug":
            print(f"Running in debug")
            debug_mode = True
        asyncio.run(server.run())
    except asyncio.CancelledError:
        print("Server has been shut down.")