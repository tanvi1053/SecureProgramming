import asyncio
import websockets
import json
import time
from collections import defaultdict


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
            await self.process_signed_data(websocket, message)
        elif message["type"] == "client_list_request":
            await self.send_client_list(websocket)
    
    async def send_client_list(self, websocket):
        list = {
            "type": "client_list",
            "servers": [
                {
                    "address": "Address",
                    "clients": ["Exported list of clients"],
                }
            ]
        }

    async def process_signed_data(self, websocket, message):
        if message["data"]["data"]["type"] == "hello":
            # username = message["data"]["data"]["username"]
            client_address = websocket.remote_address  # This gives (IP, port)
            self.connected_clients[f"{client_address[0]}:{client_address[1]}"] = websocket
            print(f"Connected Clients: {self.connected_clients}")
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
                    "clients": list(self.connected_clients.keys())
                }
            ]
        }
        await websocket.send(json.dumps(client_list_response))

    # async def send_client_list(self, websocket):
    #     # Send the list of online users to the specific client requesting it
    #     update_message = {
    #         "type": "client_update",
    #         "clients": list(self.connected_clients.keys()),
    #     }
    #     await websocket.send(json.dumps(update_message))

    async def forward_chat(self, message):
        destination_servers = message["data"]["data"]["destination_servers"]
        for server in destination_servers:
            if server in self.connected_clients:
                print(f"Sending to... {self.connected_clients[server]}")
                await self.connected_clients[server].send(json.dumps(message))

    async def remove_client(self, websocket):
        public_key_to_remove = None
        for public_key, client_socket in self.connected_clients.items():
            if client_socket == websocket:
                public_key_to_remove = public_key
                break
        if public_key_to_remove:
            del self.connected_clients[public_key_to_remove]
            await self.send_client_update()  # Notify all clients about the disconnected client

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

    async def run(self, host="localhost", port=8001):
        print(f"Server running on {host}:{port}")
        server = await websockets.serve(self.handler, host, port)
        await asyncio.gather(server.wait_closed(), self.exit_command_listener())


if __name__ == "__main__":
    server = Server()
    try:
        asyncio.run(server.run())
    except asyncio.CancelledError:
        print("Server has been shut down.")
