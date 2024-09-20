import asyncio
import websockets
import json
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

    async def process_signed_data(self, websocket, message):
        # Example handling        
        if message["data"]["data"]["type"] == "hello":
            client_address = websocket.remote_address  # This gives (IP, port)
            self.connected_clients[f"{client_address[0]}:{client_address[1]}"] = websocket           
            print(f"Connected Clients: {self.connected_clients}")
            await self.send_client_update()
        elif message["data"]["data"]["type"] == "chat":
            # Forward chat message to intended recipient
            await self.forward_chat(message)

    async def send_client_update(self):
        # Notify other servers/clients about connected users
        update_message = {
            "type": "client_update",
            "clients": list(self.connected_clients.keys())
        }
        # Logic to send this to all clients (omitted for simplicity)

    async def forward_chat(self, message):
        destination_servers = message["data"]["data"]["destination_servers"]
        for server in destination_servers:
            if server in self.connected_clients:
                print(f"Sending to... {self.connected_clients[server]}")
                await self.connected_clients[server].send(json.dumps(message))
    
    async def remove_client(self, websocket):
        # Remove the client associated with the given WebSocket
        public_key_to_remove = None
        for public_key, client_socket in self.connected_clients.items():
            if client_socket == websocket:
                public_key_to_remove = public_key
                break
        if public_key_to_remove:
            del self.connected_clients[public_key_to_remove]
            await self.send_client_update()  # Notify all clients about the disconnected client


    async def run(self, host='localhost', port=8001):
        print(f"Server running on {host}:{port}")
        server = await websockets.serve(self.handler, host, port)
        await server.wait_closed()

if __name__ == "__main__":
    server = Server()
    asyncio.run(server.run())