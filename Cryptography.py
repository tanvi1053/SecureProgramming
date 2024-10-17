from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import base64

def generate_rsa_keys():
    """Generates a new RSA key pair (public and private keys)."""
    rsa_key = RSA.generate(2048)  # Generate a new RSA key
    public_key = rsa_key.publickey().export_key(
        format="PEM", pkcs=8
    )  # Export public key
    private_key = rsa_key.export_key(format="PEM", pkcs=8)  # Export private key
    return public_key, private_key

def save_key_pem(key, filename):
    """Saves a key to a .pem file."""
    with open(filename, "wb") as file:
        file.write(key)

def read_key_pem(key):
    """Reads a key from a .pem file."""
    with open(key, 'rb') as file:
        return RSA.import_key(file.read())

def generate_fingerprint(public_key):
    """Generates a unique fingerprint using public_key.pem file."""
    public_key = public_key.replace("\n", "").replace("\r", "").replace(" ", "")  # Remove whitespace characters
    public_key = "-----BEGIN PUBLIC KEY-----\n" + public_key[26:-24] + "\n-----END PUBLIC KEY-----"  # Add the required spaces and newlines in the BEGIN and END lines of the PEM
    sha256_hash = SHA256.new(public_key.encode('utf-8')).digest()  # Perform SHA-256 hash on the resulting string
    fingerprint = base64.b64encode(sha256_hash).decode('utf-8')  # Encode the resulting binary data into Base64
    
    return fingerprint

def sign_message(message, private_key):
    """Signs a message using the private key."""
    h = SHA256.new(message.encode("utf-8"))  # Create a hash of the message
    signer = pss.new(private_key, salt_bytes=32)  # Create a PSS signer
    signature = signer.sign(h)  # Sign the hash

    return base64.b64encode(signature).decode("utf-8")  # Return signature

def verify_signature(message, signature, public_key):
    """Verifies the signature of a message using the public key."""
    h = SHA256.new(message.encode('utf-8'))
    verifier = pss.new(public_key, salt_bytes=32)

    try:
        verifier.verify(h, base64.b64decode(signature))
        return True
    except (ValueError, TypeError) as e:
        print(f"Verification error: {e}")
        return False

def encrypt_message(message, public_key):
    """Encrypts a message using AES and RSA."""
    public_key = RSA.import_key(public_key)  # Import the public key
    aes_key = get_random_bytes(32)  # Generate a random AES key
    iv = get_random_bytes(16)  # Generate a random initialization vector (IV)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)  # Create an AES cipher
    ciphertext, tag = cipher.encrypt_and_digest(message.encode("utf-8"))  # Encrypt the message
    cipher_rsa = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)  # Create an RSA cipher with the public key
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)  # Encrypt the AES key with the RSA public key

    # Return encrypted components, all base64-encoded
    return (
        base64.b64encode(iv).decode("utf-8"),
        base64.b64encode(encrypted_aes_key).decode("utf-8"),
        base64.b64encode(ciphertext).decode("utf-8"),
    )

def decrypt_message(iv, encrypted_aes_key, ciphertext, private_key_pem_file):
    """Decrypts an encrypted message using AES and RSA."""
    private_key = RSA.import_key(private_key_pem_file)  # Import private key
    cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)  # Create RSA cipher with private key
    aes_key = cipher_rsa.decrypt(base64.b64decode(encrypted_aes_key))  # Decrypt AES key

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=base64.b64decode(iv))  # Create AES cipher with decrypted key and IV
    decrypted_message = cipher.decrypt(base64.b64decode(ciphertext))  # Decrypt the ciphertext

    return decrypted_message.decode("utf-8")  # Return the decrypted message