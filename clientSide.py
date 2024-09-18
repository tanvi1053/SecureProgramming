import asyncio
import websockets
import json
import base64

# run in async to improve efficiency, asyncio is ideal for handling multiple clients concurrently

async def send_hello(websocket, public_key, private_key):
    hello_message = {
        "type": "signed_data",
        "data": {
            "type": "hello",
            "public_key": public_key
        },
        "counter": 1,
        "signature": # function to sign message
    }
    await websocket.send(json.dumps(hello_message))

async def send_chat(websocket, destination_server, public_key, private_key, message, recipient_public_key):
    # Generate AES key and IV
    # Encrypt the message
    # Encrypt AES key with recipient's public key

    chat_message = {
        "type": "signed_data",
        "data": {
            "type": "chat",
            "destination_servers": [destination_server],
            "iv": # encode iv
            "symm_keys": [],
            "chat": # encrypted message
        },
        "counter": 2,  # Increment as necessary
        "signature": # function to sign message
    }
    await websocket.send(json.dumps(chat_message))

async def receive_messages(websocket, private_key):
    async for message in websocket:
        data = json.loads(message)
        if data['data']['type'] == 'chat':
            # Decrypt the message
            # Decrypt AES key with private key
            # Decrypt message

async def main():
    uri = "ws://localhost:8000"
    public_key, private_key = # generate key pair

    async with websockets.connect(uri) as websocket:
        await send_hello(websocket, public_key)
        # Optionally, wait or prompt for input to send a message
        await send_chat(websocket, "server_address", public_key, private_key, "Hello, World!", recipient_public_key)
        await receive_messages(websocket, private_key)

asyncio.run(main())
