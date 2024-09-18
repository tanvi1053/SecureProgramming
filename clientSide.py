import asyncio
import websockets
import json
import base64
from Cryptography import *

# run in async to improve efficiency, asyncio is ideal for handling multiple clients concurrently
async def send_hello(websocket, public_key, private_key):
    hello_message = {
        "type": "signed_data",
        "data": {
            "type": "hello",
            "public_key": public_key.decode()
        },
        "counter": 1,
        "signature": sign_message("hello", private_key) # function to sign message
    }

    await websocket.send(json.dumps(hello_message))

async def send_chat(websocket, destination_server, public_key, private_key, message, recipient_public_key):
    # Encrypt the message
    global iv
    global encrypted_aes_key
    iv, encrypted_message, encrypted_aes_key = encrypt_message(message,public_key)

    chat_message = {
        "type": "signed_data",
        "data": {
            "type": "chat",
            "destination_servers": [destination_server],
            "iv": iv,
            "symm_keys": [encrypted_aes_key],
            "chat": encrypted_message
        },
        "counter": 2,  # Increment as necessary
        "signature": sign_message(encrypted_message, private_key)
    }
    print(f"Sent Message: {chat_message}")
    await websocket.send(json.dumps(chat_message))

async def receive_messages(websocket, private_key):
    async for message in websocket:
        decrypted_message= decrypt_message(iv,message,encrypted_aes_key,private_key)
        data = json.loads(decrypted_message)
        if data['data']['type'] == 'chat':
            print(f"Received Message: {data}")


async def main():
    uri = "ws://localhost:8001"
    public_key, private_key = generate_rsa_keys()
    save_to_pem(public_key, "public_key.pem")
    save_to_pem(private_key, "private_key.pem")

    async with websockets.connect(uri) as websocket:
        await send_hello(websocket, public_key,private_key)
        # Optionally, wait or prompt for input to send a message
        await send_chat(websocket, "localhost:8001", public_key, private_key, "Hello, World!", "recipient_public_key")
        await receive_messages(websocket, private_key)

asyncio.run(main())
