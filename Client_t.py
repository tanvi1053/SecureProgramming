import socket
from Cryptography_t import *

# Server configuration
SERVER_ADDRESS = '127.0.0.1'  # Use localhost
SERVER_PORT = 8001
BUFFER_SIZE = 4096  # Increased buffer size

# Generate RSA keys for the client
public_key, private_key = generate_rsa_keys()

# Save the keys to .pem files
save_key_pem(public_key, 'public_key.pem')
save_key_pem(private_key, 'private_key.pem')

counter = 0  # Initialize counter

def send_message_to_server(message):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((SERVER_ADDRESS, SERVER_PORT))
            s.sendall(message.encode('utf-8'))  # Ensure message is encoded as bytes
            response = s.recv(BUFFER_SIZE).decode('utf-8')
            print(f"Response from server: {response}")
    except Exception as e:
        print(f"Failed to send message to server: {e}")

def main():
    global counter
    while True:
        user_input = input("Enter message to encrypt and send to server (or 'exit' to quit): ")
        if user_input.lower() == 'exit':
            break
        try:
            # Encrypt the message
            iv, encrypted_aes_key, ciphertext = encrypt_message(user_input, 'public_key.pem')
            encrypted_data = {
                'iv': iv,
                'encrypted_aes_key': encrypted_aes_key,
                'ciphertext': ciphertext
            }
            
            # Create the JSON object
            json_obj = {
                "type": "signed_data",
                "data": encrypted_data,
                "counter": counter,
                "signature": sign_message(json.dumps(encrypted_data), 'private_key.pem') + str(counter)
            }
            
            # Send the JSON object to the server
            send_message_to_server(json.dumps(json_obj))
            
            # Increment the counter after sending the message
            counter += 1
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()


# Example JSON input:
# {"type": "signed_data", "data": {"type": "chat", "chat": {"message": "Hello! This is a secret message."}}}