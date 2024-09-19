import socket
import threading
from Cryptography_t import *

# Server configuration
SERVER_ADDRESS = '127.0.0.1'  # Use localhost
SERVER_PORT = 8001
BUFFER_SIZE = 4096  # Increased buffer size

# Stored state
clients = []
servers = []
client_counters = {}  # Dictionary to store the last counter value for each client
client_ports = {}  # Dictionary to store the port information for each client

def handle_message(message, client_address):
    message_type = message.get('type')
    
    if message_type == 'signed_data':
        handle_signed_data(message, client_address)
    elif message_type == 'client_list_request':
        handle_client_list_request(client_address)
    elif message_type == 'client_update':
        handle_client_update(client_address)
    elif message_type == 'client_list':
        handle_client_list(client_address)
    elif message_type == 'client_update_request':
        handle_client_update_request()
    else:
        print(f"Unknown message type: {message_type}")

def handle_signed_data(message_data, client_address):
    # Debug print to check the type of message_data
    print(f"Type of message_data: {type(message_data)}")
    
    # Ensure message_data is a dictionary
    if isinstance(message_data, str):
        try:
            message_data = json.loads(message_data)
            print(f"Decoded JSON message_data: {message_data}")
        except json.JSONDecodeError as e:
            print(f"Failed to decode JSON message from {client_address}: {e}")
            return
    
    # Extract the signature_with_counter, data, and counter
    signature_with_counter = message_data.get('signature')
    data = message_data.get('data')
    counter = message_data.get('counter')
    
    # Convert counter to string before using len()
    counter_str = str(counter)
    
    # Extract the signature
    signature = signature_with_counter[:-len(counter_str)]
    
    # Verify the signature
    public_key_pem_file = 'public_key.pem'  # Path to the public key file
    if verify_signature(json.dumps(data), signature, public_key_pem_file):
        print(f"Signature verified successfully for data from {client_address}")
        
        # Decrypt the data
        private_key_pem_file = 'private_key.pem'  # Path to the private key file
        decrypted_data = decrypt_message(data, private_key_pem_file)
        
        # Process the decrypted data
        process_decrypted_data(decrypted_data, client_address)
        
        # Check the type of the decrypted data
        if decrypted_data.get('type') == 'chat':
            relay_chat_message(decrypted_data)
    else:
        print(f"Signature verification failed for data from {client_address}")

def process_decrypted_data(decrypted_data, client_address):
    data_type = decrypted_data.get('type')
    
    if data_type == 'chat':
        relay_chat_message(decrypted_data)
    elif data_type == 'hello':
        relay_hello_message()
    elif data_type == 'public_chat':
        relay_public_chat_message(decrypted_data)
    elif data_type == 'server_hello':
        relay_server_hello_message(client_address)
    else:
        print(f"Unknown data type: {data_type} from {client_address}")

def relay_chat_message(decrypted_data):
    chat_data = decrypted_data.get('chat')
    if chat_data:
        # Decrypt the chat message using decrypt_message from Cryptography.py
        private_key_pem_file = 'private_key.pem'  # Path to the private key file
        encrypted_chat_data = {
            'iv': decrypted_data['iv'],
            'encrypted_aes_key': decrypted_data['symm_keys'][0],  # Assuming the first key is for this server
            'ciphertext': chat_data  # Use chat_data directly as the ciphertext
        }
        decrypted_chat = decrypt_message(encrypted_chat_data, private_key_pem_file)
        
        # Construct the JSON object for chat
        chat_message = {
            "data": {
                "type": "chat",
                "destination_servers": decrypted_data.get('destination_servers', []),
                "iv": base64.b64encode(get_random_bytes(16)).decode('utf-8'),
                "symm_keys": decrypted_data.get('symm_keys', []),
                "chat": decrypted_chat  # Use decrypted_chat directly
            }
        }
        print(f"Relaying chat message: {chat_message}")
        relay_message(json.dumps(chat_message))

def relay_hello_message():
    with open('public_key.pem', 'rb') as file:
        public_key = file.read().decode('utf-8')
    hello_message = {
        'type': 'signed_data',
        'data': {
            'type': 'hello',
            'public_key': public_key
        }
    }
    print(f"Relaying hello message: {hello_message}")
    relay_message(json.dumps(hello_message))

def relay_public_chat_message(decrypted_data):
    with open('public_key.pem', 'rb') as file:
        public_key = RSA.import_key(file.read())
    fingerprint = base64.b64encode(SHA256.new(public_key.export_key()).digest()).decode('utf-8')
    public_chat_message = {
        'type': 'signed_data',
        'data': {
            'type': 'public_chat',
            'sender': fingerprint,
            'message': decrypted_data['message']
        }
    }
    print(f"Relaying public chat message: {public_chat_message}")
    relay_message(json.dumps(public_chat_message))

def relay_server_hello_message(client_address):
    server_hello_message = {
        'type': 'signed_data',
        'data': {
            'type': 'server_hello',
            'sender': client_address[0]
        }
    }
    print(f"Relaying server hello message: {server_hello_message}")
    relay_message(json.dumps(server_hello_message))

def handle_client_list_request(client_address):
    send_message(client_address, json.dumps({'type': 'client_list_request'}))

def handle_client_update(client_address):
    with open('public_key.pem', 'rb') as file:
        public_key = file.read().decode('utf-8')
    clients[:] = [client for client in clients if is_client_connected(client)]
    if public_key not in clients:
        clients.append(public_key)
    send_message(client_address, json.dumps({'type': 'client_update', 'clients': [public_key]}))

def handle_client_list(client_address):
    with open('public_key.pem', 'rb') as file:
        public_key = file.read().decode('utf-8')
    send_message(client_address, json.dumps({
        'type': 'client_list',
        'servers': [{'address': SERVER_ADDRESS, 'clients': [public_key]}]
    }))

def handle_client_update_request():
    for server in servers:
        send_message(server, json.dumps({'type': 'client_update_request'}))

def is_client_connected(client):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(client)
            return True
    except:
        return False

def relay_message(message_data):
    for client in clients:
        client_port = client_ports.get(client)
        if client_port:
            send_message((client[0], client_port), message_data)
    for server in servers:
        send_message(server, message_data)

def send_message(address, message_data):
    try:
        if isinstance(message_data, dict):
            message_data = json.dumps(message_data)  # Convert dict to JSON string
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(address)
            s.sendall(message_data.encode('utf-8'))  # Ensure message is encoded as bytes
    except Exception as e:
        print(f"Failed to send message to {address}: {e}")

def client_handler(client_socket, client_address):
    with client_socket:
        print(f"Connected by {client_address}")
        try:
            message_buffer = ""
            while True:
                chunk = client_socket.recv(BUFFER_SIZE).decode('utf-8')
                if not chunk:
                    break
                message_buffer += chunk
                try:
                    # Attempt to decode the JSON message
                    while message_buffer:
                        message, index = json.JSONDecoder().raw_decode(message_buffer)
                        if isinstance(message, dict):
                            handle_message(message, client_address)
                        else:
                            print(f"Received non-dictionary message: {message}")
                        message_buffer = message_buffer[index:].lstrip()
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            print(f"Error receiving message from {client_address}: {e}")
        finally:
            print(f"Client {client_address} disconnected.")
            handle_client_update(client_address)

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((SERVER_ADDRESS, SERVER_PORT))
        server_socket.listen()
        print(f"Server listening on {SERVER_ADDRESS}:{SERVER_PORT}")
        
        while True:
            client_socket, client_address = server_socket.accept()
            threading.Thread(target=client_handler, args=(client_socket, client_address)).start()

if __name__ == "__main__":
    start_server()