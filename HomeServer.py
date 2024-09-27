import asyncio
import websockets
import json
from collections import defaultdict

HOME_SERVER_ADDRESS = "127.0.0.1"
HOME_SERVER_PORT = 8001  # Choose a port for the home server

class HomeServer:
    def __init__(self):
        self.connected_servers = set()  # Track connected servers

    async def handler(self, websocket, path):
        # Add the newly connected server to the set
        self.connected_servers.add(websocket)
        try:
            async for message in websocket:
                await self.handle_message(websocket, json.loads(message))
        except websockets.ConnectionClosed:
            print("Server disconnected.")
        finally:
            # Remove server on disconnect
            self.connected_servers.remove(websocket)

    async def handle_message(self, websocket, message):
        # Handle messages from connected servers
        print(f"Received from server: {message}")
        # You can add additional processing logic here

    async def run(self):
        print(f"Starting home server on {HOME_SERVER_ADDRESS}:{HOME_SERVER_PORT}...")
        server = await websockets.serve(self.handler, HOME_SERVER_ADDRESS, HOME_SERVER_PORT)
        await server.wait_closed()  # Keep the server running until closed

if __name__ == "__main__":
    home_server = HomeServer()
    asyncio.run(home_server.run())
