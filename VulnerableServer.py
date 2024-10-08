import asyncio
import websockets
import json
import time
from collections import defaultdict
import os

SERVER_ADDRESS = "127.0.0.1"
SERVER_PORT = 8001
NEIGHBOUR_FILE = "neighbouring_servers.txt"

class Server:
    def __init__(self):
        self.connected_clients = defaultdict(str)
        self.client_key = {}
        self.neighboring_servers = []  # List of neighboring servers
        self.current_address = "127.0.0.1:8001"
        self.client_updates = {}  # Dictionary to store client lists from neighboring servers

    async def handler(self, websocket, path):
        try:
            async for message in websocket:
                print(f"Received raw message: {message}")  # Log the raw message for debugging
                await self.handle_message(websocket, json.loads(message))
        except websockets.ConnectionClosed:
            # Handle client disconnection
            await self.remove_client(websocket)

    async def handle_message(self, websocket, message):
        # print(f"HANDLE_MESSAGE raw message: {message}")  # Log the raw message for debugging 
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
                await self.broadcast_public_chat(websocket, message)  # Handle public chat
            elif message["data"]["data"]["type"] == "server_hello":
                await self.handle_server_hello(websocket, message)
    
    async def handle_server_hello(self, websocket, message):
        new_server = message["data"]["data"]["sender"]
        if new_server not in self.neighboring_servers:
            self.neighboring_servers.append(new_server)
            print(f"New neighboring server added: {new_server}")
        await self.send_client_update()

    async def handle_client_update(self, message):
        sender_address = message["sender"]
        print(sender_address)
        clients = message["clients"]
        print(clients)
        # Save the client list from the sender server
        self.client_updates[sender_address] = clients
        print(f"Updated client list from {sender_address}: {clients}")

    async def process_signed_data(self, websocket, message):
        if message["data"]["data"]["type"] == "hello":
            username = message["data"]["data"]["username"]
            client_address = websocket.remote_address  # This gives (IP, port)
            self.client_key[username] = f"{client_address[0]}:{client_address[1]}"
            self.connected_clients[f"{client_address[0]}:{client_address[1]}"] = (
                websocket
            )
            print(f"Connected Clients: {self.connected_clients}")
            print(f"Client key: {self.client_key}")
            await self.send_client_update()
        elif message["data"]["data"]["type"] == "chat":
            # Forward chat message to intended recipient
            await self.forward_chat(message)

    async def broadcast_public_chat(self, websocket, message):
        message_json = json.dumps(message)
        for client_websocket in self.connected_clients.values():
            if client_websocket != websocket:
                await client_websocket.send(message_json)


    async def send_client_update(self):
        clients_info = [
            {"username": username, "address": address}
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
                async with websockets.connect(f"ws://{server_address}") as server_websocket:
                    await server_websocket.send(update_message_json)
            except Exception as e:
                print(f"Failed to send client update to {server_address}: {e}")
     
    async def send_client_list(self, websocket):
        # Combine local clients and clients from neighboring servers
        combined_clients = []
        
        # Add local clients
        for username, address in self.client_key.items():
            combined_clients.append({"username": username, "address": address})

        # Add clients from neighboring servers
        for server_address, clients in self.client_updates.items():
            for client in clients:
                combined_clients.append({"username": client["username"], "address": server_address})

        # Send combined client list to the requesting client
        client_list_response = {
            "type": "client_list",
            "servers": [
                {
                    "address": f"{websocket.remote_address[0]}:{websocket.remote_address[1]}",
                    "clients": combined_clients,
                }
            ],
        }
        await websocket.send(json.dumps(client_list_response))

    async def forward_chat(self, message):
        destination_users = message["data"]["data"]["destination_servers"]
        sender = message["data"]["data"]["chat"]["sender"]
        # print(f"SENDER: {sender}")
        for server in destination_users:
            # print(f"RECEIVER: {server}")
            # print(f"CLIENT KEY: {self.client_key.values()}")
            if server in self.client_key.keys():
                print(
                    f"Sending to... {self.connected_clients[self.client_key[server]]}"
                )
                await self.connected_clients[self.client_key[server]].send(
                    json.dumps(message)
                )
            else:
                fail_message = {"type": "user_not_found"}
                print(
                    f"Sending to... {self.connected_clients[self.client_key[sender]]}"
                )
                await self.connected_clients[self.client_key[sender]].send(
                    json.dumps(fail_message)
                )

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

        # Notify all clients of the updated list
        await self.send_client_update()
        print(f"Client {client_key} removed.")

    def save_to_file(self, address):
        # """Save server address to neighboring_servers.txt"""
        with open(NEIGHBOUR_FILE, "a") as f:
            f.write(address + "\n")

    def load_neighbors(self):
        # """Load neighboring servers from file"""
        if os.path.exists(NEIGHBOUR_FILE):
            with open(NEIGHBOUR_FILE, "r") as f:
                self.neighboring_servers = [line.strip() for line in f.readlines()]

    async def connect_to_neighbors(self, actual_port):
        for neighbor in self.neighboring_servers:
            try:
                async with websockets.connect(f"ws://{neighbor}") as websocket:
                    server_hello = {"type": "signed_data",
                        "data": {
                        "data": {
                            "type": "server_hello",
                            "sender": f"{SERVER_ADDRESS}:{actual_port}"
                        }
                    },
                        "counter": 1,
                        "signature": 1234 ,
                        }
                    await websocket.send(json.dumps(server_hello))
                    print(f"Connected to neighboring server {neighbor}")
            except Exception as e:
                print(f"Failed to connect to {neighbor}: {e}")

    def remove_from_file(self, address):
        # """Remove server address from neighbouring_servers.txt"""
        if os.path.exists(NEIGHBOUR_FILE):
            with open(NEIGHBOUR_FILE, "r") as f:
                lines = f.readlines()
            with open(NEIGHBOUR_FILE, "w") as f:
                for line in lines:
                    if line.strip() != address:  # Write back all lines except the one to remove
                        f.write(line)

    async def exit_command_listener(self):
        while True:
            command = await asyncio.to_thread(
                input, "Type 'exit' to shut down the server\n"
            )
            if command.lower() == "exit":
                print("Shutting down server...")
                self.remove_from_file(self.current_address)  # Remove from file
                # time.sleep(2)  UNCOMMENT WHEN FINISHED
                for task in asyncio.all_tasks():
                    task.cancel()  # Cancel all running tasks
                break

    async def run(self, host=SERVER_ADDRESS, port=0):  # Use port=0 to select a random port
        print(f"Starting server on {host}...")
        server = await websockets.serve(self.handler, host, port)
        actual_port = server.sockets[0].getsockname()[1]
        
        # Properly assign the address to neighboring_servers
        self.current_address = f"{host}:{actual_port}"
        self.load_neighbors()
        self.save_to_file(self.current_address)
       
        print(f"Neighboring servers: {self.neighboring_servers}")
        print(f"Server running on {host}:{actual_port}")
        
        # Pass the actual_port to connect_to_neighbors
        await self.connect_to_neighbors(actual_port)
        await asyncio.gather(server.wait_closed(), self.exit_command_listener())


if __name__ == "__main__":
    server = Server()
    try:
        asyncio.run(server.run())
    except asyncio.CancelledError:
        print("Server has been shut down.")
