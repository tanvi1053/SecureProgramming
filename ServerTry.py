<<<<<<< HEAD
import asyncio
import websockets
import json
import time
from collections import defaultdict

SERVER_ADDRESS = "127.0.0.1"
SERVER_PORT = 8001


class Server:
    def __init__(self):
        self.connected_clients = defaultdict(str)
        self.client_key = {}

    async def handler(self, websocket, path):
        try:
            async for message in websocket:
                await self.handle_message(websocket, json.loads(message))
        except websockets.ConnectionClosed:
            # Handle client disconnection
            await self.remove_client(websocket)

    async def handle_message(self, websocket, message):
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

    async def send_client_update(self):
        update_message = {
            "type": "client_update",
            "clients": list(self.connected_clients.keys()),
        }
        update_message_json = json.dumps(update_message)
        for websocket in self.connected_clients.values():
            await websocket.send(update_message_json)

    async def send_client_list(self, websocket):
        # Send list of clients to the requesting client
        client_list_response = {
            "type": "client_list",
            "servers": [
                {
                    "address": f"{websocket.remote_address[0]}:{websocket.remote_address[1]}",
                    "clients": list(self.client_key.keys()),
                }
            ],
        }
        await websocket.send(json.dumps(client_list_response))

    async def forward_chat(self, message):
        destination_users = message["data"]["data"]["destination_servers"]
        for server in destination_users:
            # print(f"SERVER: {server}")
            # print(f"CLIENT KEY: {self.client_key.values()}")
            if server in self.client_key.keys():
                print(
                    f"Sending to... {self.connected_clients[self.client_key[server]]}"
                )
                await self.connected_clients[self.client_key[server]].send(
                    json.dumps(message)
                )

    async def remove_client(self, websocket):
        client_address = websocket.remote_address
        client_key = f"{client_address[0]}:{client_address[1]}"
        if client_key in self.connected_clients:
            del self.connected_clients[client_key]
            await self.send_client_update()  # Notify all clients about the disconnected client
            print(f"Client {client_key} removed.")

    async def exit_command_listener(self):
        while True:
            command = await asyncio.to_thread(
                input, "Type 'exit' to shut down the server\n"
            )
            if command.lower() == "exit":
                print("Shutting down server...")
                # time.sleep(2)  UNCOMMENT WHEN FINISHED
                for task in asyncio.all_tasks():
                    task.cancel()  # Cancel all running tasks
                break

    async def run(self, host=SERVER_ADDRESS, port=SERVER_PORT):
        print(f"Server running on {host}:{port}")
        server = await websockets.serve(self.handler, host, port)
        await asyncio.gather(server.wait_closed(), self.exit_command_listener())


if __name__ == "__main__":
    server = Server()
    try:
        asyncio.run(server.run())
    except asyncio.CancelledError:
        print("Server has been shut down.")
=======
import asyncio
import websockets
import json
import time
from collections import defaultdict

SERVER_ADDRESS = "127.0.0.1"
SERVER_PORT = 8001


class Server:
    def __init__(self):
        self.connected_clients = defaultdict(str)

    async def handler(self, websocket, path):
        try:
            async for message in websocket:
                await self.handle_message(websocket, json.loads(message))
        except websockets.ConnectionClosed:
            # Handle client disconnection
            await self.remove_client(websocket)

    async def handle_message(self, websocket, message):
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
                await self.broadcast_public_chat(websocket, message)  # Handle client disconnection

    async def process_signed_data(self, websocket, message):
        if message["data"]["data"]["type"] == "hello":
            # username = message["data"]["data"]["username"]
            client_address = websocket.remote_address  # This gives (IP, port)
            self.connected_clients[f"{client_address[0]}:{client_address[1]}"] = (
                websocket
            )
            print(f"Connected Clients: {self.connected_clients}")
        elif message["data"]["data"]["type"] == "chat":
            # Forward chat message to intended recipient
            await self.forward_chat(message)

    async def broadcast_public_chat(self, websocket, message):
        # Broadcast the public chat message to all clients
        public_chat_message = {
            "type": "signed_data",  # Ensure this is present
            "data": {
                "type": "public_chat",
                "sender": message["data"]["data"]["sender"],
                "message": message["data"]["data"]["message"]
            }
        }
        message_json = json.dumps(public_chat_message)

        for client_websocket in self.connected_clients.values():
            if client_websocket != websocket:
                await client_websocket.send(message_json)

    async def send_client_list(self, websocket):
        # Send list of clients to the requesting client
        client_list_response = {
            "type": "client_list",
            "servers": [
                {
                    "address": f"{websocket.remote_address[0]}:{websocket.remote_address[1]}",
                    "clients": list(self.connected_clients.keys()),
                }
            ],
        }
        await websocket.send(json.dumps(client_list_response))

    async def forward_chat(self, message):
        destination_servers = message["data"]["data"]["destination_servers"]
        for server in destination_servers:
            if server in self.connected_clients:
                print(f"Sending to... {self.connected_clients[server]}")
                await self.connected_clients[server].send(json.dumps(message))

    async def remove_client(self, websocket):
        client_address = websocket.remote_address
        client_key = f"{client_address[0]}:{client_address[1]}"
        if client_key in self.connected_clients:
            del self.connected_clients[client_key]
            print(f"Client {client_key} disconnected.")

    async def exit_command_listener(self):
        while True:
            command = await asyncio.to_thread(
                input, "Type 'exit' to shut down the server\n"
            )
            if command.lower() == "exit":
                print("Shutting down server...")
                # time.sleep(2)  UNCOMMENT WHEN FINISHED
                for task in asyncio.all_tasks():
                    task.cancel()  # Cancel all running tasks
                break

    async def run(self, host=SERVER_ADDRESS, port=SERVER_PORT):
        print(f"Server running on {host}:{port}")
        server = await websockets.serve(self.handler, host, port)
        await asyncio.gather(server.wait_closed(), self.exit_command_listener())


if __name__ == "__main__":
    server = Server()
    try:
        asyncio.run(server.run())
    except asyncio.CancelledError:
        print("Server has been shut down.")
>>>>>>> main
