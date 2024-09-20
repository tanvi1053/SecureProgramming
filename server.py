import asyncio
import websockets
import json
from Cryptography import *  

# Global variables for simplicity
connected_clients = {}
neighbour_servers = set()
server_address = "localhost:8001"  

# Generate new RSA keys for the server (or load existing ones)
public_key, private_key = generate_rsa_keys()
save_to_pem(public_key, 'server_public_key.pem')
save_to_pem(private_key, 'server_private_key.pem')

# Asynchronous client handler
async def handle_client(websocket, path):
    try:
        async for message in websocket:
            data = json.loads(message)

            # Decrypt the incoming message
            iv = data.get('iv', '')
            ciphertext = data.get('ciphertext', '')
            encrypted_aes_key = data.get('encrypted_aes_key', '')

            decrypted_message = decrypt_message(iv, ciphertext, encrypted_aes_key, 'server_private_key.pem')
            decrypted_data = json.loads(decrypted_message)

            msg_type = decrypted_data.get("data", {}).get("type", "")

            # Handle client hello (initial connection)
            if msg_type == "hello":
                client_id = decrypted_data["data"]["client_id"]
                connected_clients[websocket] = client_id
                await broadcast_client_update()
                print(f"Client connected: {client_id}")

            # Handle chat message forwarding
            elif msg_type == "chat":
                message = decrypted_data["data"]["message"]
                print(f"Decrypted chat message: {message}")
                await handle_chat_message({'message': message})
                                
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

    # Convert the message to a string and sign it
    message_str = json.dumps(update_message)
    signature = sign_message(message_str, 'server_private_key.pem')

    # Send the message and signature
    signed_message = {
        "message": update_message,
        "signature": signature
    }

    for server in neighbour_servers:
        await server.send(json.dumps(signed_message))

# Handle incoming chat messages
async def handle_chat_message(data):
    message = data.get('message', '')

    # Encrypt the message before broadcasting (load public key from .pem)
    iv, ciphertext, encrypted_aes_key = encrypt_message(message, 'server_public_key.pem')

    encrypted_data = {
        'type': 'chat',
        'iv': iv,
        'ciphertext': ciphertext,
        'encrypted_aes_key': encrypted_aes_key
    }

    # Broadcast encrypted data to all clients
    for client in connected_clients.keys():
        await client.send(json.dumps(encrypted_data))

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

        # Extract the signed message and signature
        signed_message = data.get("message", {})
        signature = data.get("signature", "")

        # Verify the signature
        if verify_signature(json.dumps(signed_message), signature, 'server_public_key.pem'):
            print("Signature is valid, processing message.")
            msg_type = signed_message.get("type", "")

            if msg_type == "client_update":
                print("Received valid client update from another server")
            elif msg_type == "client_update_request":
                print("Received client update request from another server")
                await websocket.send(json.dumps({
                    "type": "client_update",
                    "clients": list(connected_clients.values())
                }))
        else:
            print("Invalid signature, message rejected.")

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
