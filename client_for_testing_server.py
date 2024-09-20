import asyncio
import websockets
import json
from Cryptography import *  # Assuming this is your module for cryptographic functions

async def test_client():
    uri = "ws://localhost:8001"  # Connect to the server's WebSocket

    # Generate RSA key pair for the client
    client_public_key, client_private_key = generate_rsa_keys()

    # Save the keys to files (optional)
    save_to_pem(client_private_key, 'client_private_key.pem')
    save_to_pem(client_public_key, 'client_public_key.pem')

    # Load server's public key from file (the server's public key must be shared beforehand)
    server_public_key_file = 'server_public_key.pem'  # Assume this file is provided by the server

    async with websockets.connect(uri) as websocket:
        # Simulate client hello (client_id exchange)
        hello_message = {
            "data": {
                "type": "hello",
                "client_id": "client_1",  # Unique identifier for the client
                "public_key": client_public_key.decode('utf-8')  # Send public key to the server
            }
        }

        # Encrypt and send the hello message
        iv, encrypted_message, encrypted_aes_key = encrypt_message(
            json.dumps(hello_message), server_public_key_file
        )

        encrypted_hello_message = {
            "iv": iv,
            "ciphertext": encrypted_message,
            "encrypted_aes_key": encrypted_aes_key
        }
        await websocket.send(json.dumps(encrypted_hello_message))
        print("Sent encrypted hello message to the server")

        # Send a chat message
        chat_message = {
            "data": {
                "type": "chat",
                "message": "TEST!"
            }
        }

        # Encrypt the chat message
        iv, encrypted_chat_message, encrypted_aes_key, export_rsa_public_key = encrypt_message(
            json.dumps(chat_message), server_public_key_file
        )

        # Send the encrypted chat message
        encrypted_chat_payload = {
            "iv": iv,
            "ciphertext": encrypted_chat_message,
            "encrypted_aes_key": encrypted_aes_key
        }
        await websocket.send(json.dumps(encrypted_chat_payload))
        print("Sent encrypted chat message to the server")

        # Listen for messages from the server
        try:
            while True:
                message = await websocket.recv()
                print(f"Received message from server: {message}")
        except websockets.ConnectionClosed:
            print("Connection closed by server or client")

# Run the client and disconnect after a timeout (example: 5 seconds)
async def run_and_disconnect():
    await test_client()

    # Simulate some work, then disconnect after 5 seconds
    await asyncio.sleep(5)
    print("Client is disconnecting now...")

# Start the client and disconnect logic
asyncio.get_event_loop().run_until_complete(run_and_disconnect())
