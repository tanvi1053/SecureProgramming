import asyncio
import websockets
import json
import sys
import time
from collections import defaultdict

SERVER_ADDRESS = "127.0.0.1"
SERVER_PORT = 8001


class Server:
    def __init__(self):
        self.connected_clients = defaultdict(str)
        self.client_key = {}
        self.public_keys = {}

    async def handler(self, websocket, path):
        try:
            async for message in websocket:
                await self.handle_message(websocket, json.loads(message))
        except websockets.ConnectionClosed:
            # Handle client disconnection
            await self.remove_client(websocket)

    async def handle_message(self, websocket, message):
        if debug_mode:
            print(f"INCOMING MESSAGE: {message}")
        if message["type"] == "signed_data":
            if (
                message["data"]["data"]["type"] == "hello"
                or message["data"]["data"]["type"] == "chat"
            ):
                await self.process_signed_data(websocket, message)
            elif message["data"]["data"]["type"] == "client_list_request":
                await self.send_client_list(websocket)  # Handle client list request
                while debug_mode:
                    await self.send_client_list(websocket)  # Handle client list request
            elif message["data"]["data"]["type"] == "disconnect":
                await self.remove_client(websocket)  # Handle client disconnection
            elif message["data"]["data"]["type"] == "public_chat":
                await self.broadcast_public_chat(
                    websocket, message
                )  # Handle public chat
            elif message["data"]["data"]["type"] == "get_key":
                await self.send_public_key(websocket, message)

    async def send_public_key(self, websocket, message):
        destination_users = message["data"]["data"]["destination_servers"]
        sender = message["data"]["data"]["sender"]
        for server in destination_users:
            if server in self.client_key.keys():
                if debug_mode:
                    print(f"Sending to... {self.client_key[sender]}")

                # get public key of destination
                key = {
                    "type": "public_key",
                    "public_key": self.public_keys[server],
                    "user": server,
                }

                await self.connected_clients[self.client_key[sender]].send(
                    json.dumps(key)
                )
            else:
                fail_message = {"type": "user_not_found"}
                if debug_mode:
                    print(f"Sending to... {self.client_key[sender]}")
                await self.connected_clients[self.client_key[sender]].send(
                    json.dumps(fail_message)
                )

    async def process_signed_data(self, websocket, message):
        if message["data"]["data"]["type"] == "hello":
            username = message["data"]["data"]["username"]
            client_address = websocket.remote_address  # This gives (IP, port)
            self.public_keys[username] = message["data"]["data"]["public_key"]
            self.client_key[username] = f"{client_address[0]}:{client_address[1]}"
            self.connected_clients[f"{client_address[0]}:{client_address[1]}"] = (
                websocket
            )
            if debug_mode:
                print(f"Connected Clients: {self.connected_clients}")
                print(f"Client key: {self.client_key}")
                print(f"public_keys: {self.public_keys}")
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
        # print(f"MESSAGE: {message}")
        for server in destination_users:
            if server in self.client_key.keys():
                print(f"Sending to... {self.client_key[server]}")
                await self.connected_clients[self.client_key[server]].send(
                    json.dumps(message)
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
                remove_client = username
                print(f"Removing client key for: {username}")
                del self.client_key[username]
                break

        # Remove the client from public_key dictionary
        for username in self.public_keys:
            if username == remove_client:
                print(f"Removing public key for: {username}")
                del self.public_keys[username]
                break

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
        debug_mode = False
        if len(sys.argv) > 1 and sys.argv[1] == "debug":
            print(f"Running in debug")
            debug_mode = True
        asyncio.run(server.run())
    except asyncio.CancelledError:
        print("Server has been shut down.")
