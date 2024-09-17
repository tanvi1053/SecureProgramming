import asyncio
import websockets
import json

# Global variables for simplicity
connected_clients = {}
neighbour_servers = set()
server_address = "localhost:8001"  # Replace with your server address and port

# Asynchronous client handler
async def handle_client(websocket, path):
    try:
        async for message in websocket:
            data = json.loads(message)
            msg_type = data.get("data", {}).get("type", "")

            # Handle client hello (initial connection)
            if msg_type == "hello":
                client_id = data["data"]["client_id"]
                connected_clients[websocket] = client_id
                await broadcast_client_update()
                print(f"Client connected: {client_id}")

            # Handle chat message forwarding
            elif msg_type == "chat":
                await handle_chat_message(data)

    except websockets.ConnectionClosed:
        print("Client disconnected")
        if websocket in connected_clients:
            del connected_clients[websocket]
            await broadcast_client_update()

# Broadcast client updates to all servers
async def broadcast_client_update():
    update_message = {
        "type": "client_update",
        "clients": list(connected_clients.values())
    }
    for server in neighbour_servers:
        await server.send(json.dumps(update_message))

# Handle incoming chat messages
async def handle_chat_message(data):
    # In this basic example, we're assuming the message is broadcast to all clients
    for client in connected_clients.keys():
        await client.send(json.dumps(data))

# Periodically request client updates from other servers
async def request_client_updates():
    while True:
        for server in neighbour_servers:
            update_request = {"type": "client_update_request"}
            await server.send(json.dumps(update_request))
        await asyncio.sleep(30)  # Request every 30 seconds

# Handle incoming connections from other servers
async def handle_server_connection(websocket, path):
    neighbour_servers.add(websocket)
    async for message in websocket:
        data = json.loads(message)
        msg_type = data.get("type", "")
        
        if msg_type == "client_update":
            print("Received client update from another server")
            # Process client update...
        
        elif msg_type == "client_update_request":
            print("Received client update request from another server")
            await websocket.send(json.dumps({
                "type": "client_update",
                "clients": list(connected_clients.values())
            }))

# Main function to start the servers
async def main():
    # Start client handler WebSocket server
    client_server = await websockets.serve(handle_client, "localhost", 8001)
    
    # Start server handler WebSocket server
    server_handler = await websockets.serve(handle_server_connection, "localhost", 8002)

    print(f"Server started at {server_address}")
    await asyncio.gather(client_server.wait_closed(), server_handler.wait_closed())

# Start the server
if __name__ == "__main__":
    asyncio.run(main())
