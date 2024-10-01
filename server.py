import asyncio
import websockets
import json
from aiohttp import web
import aiofiles
import os
import uuid
from collections import defaultdict

# Configuration Constants
WEBSOCKET_ADDRESS = "localhost"
WEBSOCKET_PORT = 8001
HTTP_ADDRESS = "localhost"
HTTP_PORT = 8080

class Server:
    def __init__(self):
        self.connected_clients = defaultdict(str)
        self.client_key = {}
        self.public_keys = {}
        self.uploaded_files = {}

    async def handler(self, websocket, path):
        try:
            async for message in websocket:
                await self.handle_message(websocket, json.loads(message))
        except websockets.ConnectionClosed:
            # Handle client disconnection
            await self.remove_client(websocket)

    async def handle_message(self, websocket, message):
        if message["type"] == "signed_data":
            if message["data"]["data"]["type"] in ["hello", "chat"]:
                await self.process_signed_data(websocket, message)
            elif message["data"]["data"]["type"] == "client_list_request":
                await self.send_client_list(websocket)
            elif message["data"]["data"]["type"] == "disconnect":
                await self.remove_client(websocket)
            elif message["data"]["data"]["type"] == "public_chat":
                await self.broadcast_public_chat(websocket, message)
            elif message["data"]["data"]["type"] == "get_key":
                await self.send_public_key(websocket, message)

    async def send_public_key(self, websocket, message):
        destination_users = message["data"]["data"]["destination_servers"]
        sender = message["data"]["data"]["sender"]
        for server in destination_users:
            if server in self.client_key.keys():
                print(
                    f"Sending to... {self.connected_clients[self.client_key[server]]}"
                )

                # get public key of destination
                key = {
                    "type": "public_key",
                    "public_key": self.public_keys[server],
                    "user": server,
                }
                await self.connected_clients[self.client_key[sender]].send(json.dumps(key))
            else:
                fail_message = {"type": "user_not_found"}
                await self.connected_clients[self.client_key[sender]].send(json.dumps(fail_message))

    async def process_signed_data(self, websocket, message):
        if message["data"]["data"]["type"] == "hello":
            username = message["data"]["data"]["username"]
            client_address = websocket.remote_address
            self.public_keys[username] = message["data"]["data"]["public_key"]
            self.client_key[username] = f"{client_address[0]}:{client_address[1]}"
            self.connected_clients[f"{client_address[0]}:{client_address[1]}"] = websocket
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
        print(f"MESSAGE: {message}")
        for server in destination_users:

            if server in self.client_key.keys():
                await self.connected_clients[self.client_key[server]].send(json.dumps(message))

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

    async def handle_file_upload(self, request):
        data = await request.json()
        if "METHOD" not in data or data["METHOD"] != "POST" or "body" not in data or "recipient" not in data or "file_name" not in data:
            return web.Response(status=400, text="Invalid request format")

        file_data = data["body"].encode('latin1')
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
                "file_url": f"http://{HTTP_ADDRESS}:{HTTP_PORT}/api/files/{file_id}",
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
                    "file_url": f"http://{HTTP_ADDRESS}:{HTTP_PORT}/api/files/{file_id}"
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
        return web.FileResponse(file_info["path"])

    async def run(self):
        print(f"WebSocket server running on ws://{WEBSOCKET_ADDRESS}:{WEBSOCKET_PORT}")
        websocket_server = await websockets.serve(self.handler, WEBSOCKET_ADDRESS, WEBSOCKET_PORT)
        app = web.Application()
        app.router.add_post('/api/upload', self.handle_file_upload)
        app.router.add_get('/api/files/{file_id}', self.handle_file_retrieval)
        app.router.add_get('/api/links', self.handle_link_request)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, HTTP_ADDRESS, HTTP_PORT)
        await site.start()
        print(f"HTTP server running on http://{HTTP_ADDRESS}:{HTTP_PORT}")
        await asyncio.gather(websocket_server.wait_closed(), self.exit_command_listener())

if __name__ == "__main__":
    server = Server()
    try:
        asyncio.run(server.run())
    except asyncio.CancelledError:
        print("Server has been shut down.")