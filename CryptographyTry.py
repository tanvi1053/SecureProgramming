import base64
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# Function to generate RSA public and private keys
def generate_rsa_keys():
    # Generate a new RSA key pair
    rsa_key = RSA.generate(2048)
    # Export the public key in PEM format
    public_key = rsa_key.publickey().export_key(format='PEM', pkcs=8)
    # Export the private key in PEM format
    private_key = rsa_key.export_key(format='PEM', pkcs=8)
    return public_key, private_key

# Function to save the public/private key as a .pem file
def save_to_pem(key, filename):
    with open(filename, 'wb') as file:
        file.write(key)

# Function to encrypt a message using AES and RSA, importing the public key from a .pem file
def encrypt_message(message, public_key_pem_file):
    # Import the public key from the .pem file
    with open(public_key_pem_file, 'rb') as file:
        public_key = RSA.import_key(file.read())
    
    # Generate a random AES key
    aes_key = get_random_bytes(32)
    # Generate a random initialization vector (IV)
    iv = get_random_bytes(16)
    # Create an AES cipher object with the AES key and IV
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    # Encrypt the message and generate the authentication tag
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))

    # Create an RSA cipher object with the public key
    cipher_rsa = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    # Encrypt the AES key with the RSA public key
    print(f"AES Key Length: {len(aes_key)}")
   
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    print(f"Encrypted AES Key Length: {len(encrypted_aes_key)}")
    print(f"Base64 Encoded Encrypted AES Key Length: {len(base64.b64encode(encrypted_aes_key))}")

    # Export the RSA public key
    exported_public_key = public_key.export_key(format='PEM', pkcs=8)

    # Return the IV, ciphertext, encrypted AES key, and exported RSA public key, all base64-encoded
    return base64.b64encode(iv).decode('utf-8'), base64.b64encode(ciphertext).decode('utf-8'), base64.b64encode(encrypted_aes_key).decode('utf-8'), base64.b64encode(exported_public_key).decode('utf-8')

# Function to sign a message using RSA and PSS, importing the private key from a .pem file
def sign_message(message, private_key):
    # Import the private key from the .pem file
    # with open(private_key_pem_file, 'rb') as file:
    #     private_key = RSA.import_key(file.read())

    # Create a SHA-256 hash of the message
    h = SHA256.new(message.encode('utf-8'))
    # Create a PSS signer object with the private key and a specified salt length
    signer = pss.new(private_key, salt_bytes=32)
    # Sign the hash and return the signature, base64-encoded
    signature = signer.sign(h)
    return base64.b64encode(signature).decode('utf-8')

# Function to verify the signature of a message, importing the public key from a .pem file
def verify_signature(message, signature, public_key_pem_file):
    # Import the public key from the .pem file
    with open(public_key_pem_file, 'rb') as file:
        public_key = RSA.import_key(file.read())

    # Create a SHA-256 hash of the message
    h = SHA256.new(message.encode('utf-8'))
    # Create a PSS verifier object with the public key
    verifier = pss.new(public_key)
    try:
        # Verify the signature
        verifier.verify(h, base64.b64decode(signature))
        return True
    except (ValueError, TypeError):
        return False

# Function to decrypt an encrypted message using AES and RSA, importing the private key from a .pem file
def decrypt_message(iv, ciphertext, encrypted_aes_key, private_key_pem_file):
    # Import the private key from the .pem file
    with open(private_key_pem_file, 'rb') as file:
        private_key = RSA.import_key(file.read())

    # Create an RSA cipher object with the private key
    cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    # Decrypt the AES key with the RSA private key
    print(f"Base64 Decoded Encrypted AES Key Length: {len(base64.b64decode(encrypted_aes_key))}")

    aes_key = cipher_rsa.decrypt(base64.b64decode(encrypted_aes_key))

    # Create an AES cipher object with the decrypted AES key and IV
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=base64.b64decode(iv))
    # Decrypt the ciphertext
    decrypted_message = cipher.decrypt(base64.b64decode(ciphertext))

    # Return the decrypted message as a string
    return decrypted_message.decode('utf-8')

# Function to return the encrypted AES key and IV
def get_encrypted_aes_key_and_iv(message, public_key):
    # Generate a random AES key
    aes_key = get_random_bytes(32)
    # Generate a random initialization vector (IV)
    iv = get_random_bytes(16)
    # Create an AES cipher object with the AES key and IV
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    # Encrypt the message and generate the authentication tag
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))

    # Create an RSA cipher object with the public key
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key), hashAlgo=SHA256)
    # Encrypt the AES key with the RSA public key
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    # Return the encrypted AES key and IV, both base64-encoded
    return base64.b64encode(encrypted_aes_key).decode('utf-8'), base64.b64encode(iv).decode('utf-8')

# # Example usage of the functions
# public_key, private_key = generate_rsa_keys()
# message = "This is a secret message."

# # Save the private key as a .pem file
# save_to_pem(private_key, 'private_key.pem')
# print("Private key saved as 'private_key.pem'")

# # Save the public key as a .pem file
# save_to_pem(public_key, 'public_key.pem')
# print("Public key saved as 'public_key.pem'")

# # Get the encrypted AES key and IV + Encrypt the message using the public key from the .pem file
# iv, ciphertext, encrypted_aes_key = encrypt_message(message, 'public_key.pem')
# print("Encrypted AES key:", encrypted_aes_key)
# print("IV:", iv)

# # Sign the message using the private key from the .pem file
# signature = sign_message(message, 'private_key.pem')
# print("Signature:", signature)

# # Verify the signature using the public key from the .pem file
# if verify_signature(message, signature, 'public_key.pem'):
#     print("The signature is valid.")
# else:
#     print("The signature is not valid.")

# # Decrypt the message using the private key from the .pem file
# decrypted_message = decrypt_message(iv, ciphertext, encrypted_aes_key, 'private_key.pem')
# print("Decrypted message:", decrypted_message)