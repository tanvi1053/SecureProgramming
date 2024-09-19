import base64
import json
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# Function to generate RSA public and private keys
def generate_rsa_keys():
    rsa_key = RSA.generate(2048)
    public_key = rsa_key.publickey().export_key(format='PEM', pkcs=8)
    private_key = rsa_key.export_key(format='PEM', pkcs=8)
    return public_key, private_key

# Function to save the public key as a .pem file
def save_key_pem(key, filename):
    with open(filename, 'wb') as file:
        file.write(key)

# Function to encrypt a message using AES and RSA, importing the public key from a .pem file
def encrypt_message(message, public_key_pem_file):
    with open(public_key_pem_file, 'rb') as file:
        public_key = RSA.import_key(file.read())
    
    aes_key = get_random_bytes(32)
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))

    cipher_rsa = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    return base64.b64encode(iv).decode('utf-8'), base64.b64encode(encrypted_aes_key).decode('utf-8'), base64.b64encode(ciphertext).decode('utf-8')

# Function to sign a message using RSA and PSS, importing the private key from a .pem file
def sign_message(message, private_key_pem_file):
    with open(private_key_pem_file, 'rb') as file:
        private_key = RSA.import_key(file.read())

    h = SHA256.new(message.encode('utf-8'))
    signer = pss.new(private_key, salt_bytes=32)
    signature = signer.sign(h)
    
    return base64.b64encode(signature).decode('utf-8')

# Function to verify the signature of a message, importing the public key from a .pem file
def verify_signature(message, signature, public_key_pem_file):
    with open(public_key_pem_file, 'rb') as file:
        public_key = RSA.import_key(file.read())

    h = SHA256.new(message.encode('utf-8'))
    verifier = pss.new(public_key, salt_bytes=32)
    try:
        verifier.verify(h, base64.b64decode(signature))
        
        return True
    except (ValueError, TypeError) as e:
        print(f"Verification error: {e}")
        return False

# Function to decrypt an encrypted message using AES and RSA, importing the private key from a .pem file
def decrypt_message(encrypted_data, private_key_pem_file):
    with open(private_key_pem_file, 'rb') as file:
        private_key = RSA.import_key(file.read())

    cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    aes_key = cipher_rsa.decrypt(base64.b64decode(encrypted_data['encrypted_aes_key']))

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=base64.b64decode(encrypted_data['iv']))
    decrypted_message = cipher.decrypt(base64.b64decode(encrypted_data['ciphertext']))

    return decrypted_message.decode('utf-8')