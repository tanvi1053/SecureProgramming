import asyncio
import websockets
import json

async def test_client():
    uri = "ws://localhost:8001"  # Connect to the server's WebSocket
    
    async with websockets.connect(uri) as websocket:
        # Simulate client hello (client_id exchange)
        hello_message = {
            "data": {
                "type": "hello",
                "client_id": "client_1"  # Unique identifier for the client
            }
        }
        await websocket.send(json.dumps(hello_message))
        print("Sent hello message to the server")

        # Send a chat message after connecting
        chat_message = {
            "data": {
                "type": "chat",
                "message": "Hello from client_1!"
            }
        }
        await websocket.send(json.dumps(chat_message))
        print("Sent chat message to the server")

        # Listen for updates from the server
        while True:
            message = await websocket.recv()
            print(f"Received message from server: {message}")

# Run the test client
asyncio.get_event_loop().run_until_complete(test_client())
