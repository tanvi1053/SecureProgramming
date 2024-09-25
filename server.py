import socket
import threading
from CryptographyTry import *

# Server configuration
SERVER_ADDRESS = '127.0.0.1'
SERVER_PORT = 8001
BUFFER_SIZE = 4096

clients = []
servers = []
client_ports = {}
client_counters = {}  # Dictionary to store the last counter value for each client

def handle_message(message, client_address):
    handlers = {
        'signed_data': handle_signed_data,
        'client_list_request': handle_client_list_request,
        'client_update': handle_client_update,
        'client_list': handle_client_list,
        'client_update_request': handle_client_update_request
    }
    handler = handlers.get(message.get('type'))
    if handler:
        handler(message, client_address)
    else:
        print(f"Unknown message type: {message.get('type')}")

def handle_signed_data(message_data, client_address):
    signature_with_counter = message_data.get('signature')
    data = message_data.get('data')
    counter = message_data.get('counter')
    signature = signature_with_counter[:-len(str(counter))]
    
    client_id = client_address[0]  # Use client IP address as identifier
    last_counter = client_counters.get(client_id, -1)
    
    if counter <= last_counter:
        print(f"Received out-of-order message from {client_address}. Ignoring.")
        return
    
    if verify_signature(json.dumps(data), signature, 'public_key.pem'):
        print(f"Signature verified for data from {client_address}")
        decrypted_data = decrypt_message(data, 'private_key.pem')
        process_decrypted_data(decrypted_data, client_address)
        client_counters[client_id] = counter  # Update the counter for the client
        send_message(client_address, {"status": "success", "message": "Data processed successfully"})  # Send response
    else:
        print(f"Signature verification failed for data from {client_address}")
        send_message(client_address, {"status": "failure", "message": "Signature verification failed"})  # Send response

def process_decrypted_data(decrypted_data, client_address):
    handlers = {
        'chat': relay_chat_message,
        'hello': relay_hello_message,
        'public_chat': relay_public_chat_message,
        'server_hello': relay_server_hello_message
    }
    handler = handlers.get(decrypted_data.get('type'))
    if handler:
        handler(decrypted_data, client_address)
    else:
        print(f"Unknown data type: {decrypted_data.get('type')} from {client_address}")

def relay_chat_message(decrypted_data, _):
    encrypted_chat_data = {
        'iv': decrypted_data['iv'],
        'encrypted_aes_key': decrypted_data['symm_keys'][0],
        'ciphertext': decrypted_data['chat']
    }
    decrypted_chat = decrypt_message(encrypted_chat_data, 'private_key.pem')
    chat_message = {
        "data": {
            "type": "chat",
            "destination_servers": decrypted_data.get('destination_servers', []),
            "iv": base64.b64encode(get_random_bytes(16)).decode('utf-8'),
            "symm_keys": decrypted_data.get('symm_keys', []),
            "chat": decrypted_chat
        }
    }
    relay_message(chat_message)

def relay_hello_message(_, __):
    with open('public_key.pem', 'rb') as file:
        public_key = file.read().decode('utf-8')
    relay_message({'type': 'signed_data', 'data': {'type': 'hello', 'public_key': public_key}})

def relay_public_chat_message(decrypted_data, _):
    with open('public_key.pem', 'rb') as file:
        public_key = RSA.import_key(file.read())
    fingerprint = base64.b64encode(SHA256.new(public_key.export_key()).digest()).decode('utf-8')
    relay_message({'type': 'signed_data', 'data': {'type': 'public_chat', 'sender': fingerprint, 'message': decrypted_data.get('message')}})

def relay_server_hello_message(_, client_address):
    relay_message({'type': 'signed_data', 'data': {'type': 'server_hello', 'sender': client_address[0]}})

def handle_client_list_request(client_address):
    send_message(client_address, {'type': 'client_list_request'})

def handle_client_update(client_address):
    with open('public_key.pem', 'rb') as file:
        public_key = file.read().decode('utf-8')
    clients[:] = [client for client in clients if is_client_connected(client)]
    if public_key not in clients:
        clients.append(public_key)
    send_message(client_address, {'type': 'client_update', 'clients': [public_key]})

def handle_client_list(client_address):
    with open('public_key.pem', 'rb') as file:
        public_key = file.read().decode('utf-8')
    send_message(client_address, {'type': 'client_list', 'servers': [{'address': SERVER_ADDRESS, 'clients': [public_key]}]})

def handle_client_update_request(_, __):
    for server in servers:
        send_message(server, {'type': 'client_update_request'})

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
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(address)
            s.sendall(json.dumps(message_data).encode('utf-8'))
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
                    while message_buffer:
                        message, _ = json.JSONDecoder().raw_decode(message_buffer)
                        if isinstance(message, dict):
                            handle_message(message, client_address)
                        else:
                            print(f"Received non-dictionary message: {message}")
                        message_buffer = message_buffer[len(json.dumps(message)):]
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    print(f"Error processing message buffer: {e}")
                    break
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