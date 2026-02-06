import os
import hashlib
import base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256 as CryptoSHA256
from Crypto.Random import get_random_bytes

# --- Password Hashing (SHA-256 + Salt) ---
def hash_password(password: str) -> str:
    """Hashes a password using SHA-256 with a random salt."""
    salt = os.urandom(16)
    hashed_pw = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    # Store salt and hash together as base64
    storage = base64.b64encode(salt + hashed_pw).decode('utf-8')
    return storage

def verify_password(stored_password: str, provided_password: str) -> bool:
    """Verifies a password against the stored salted hash."""
    try:
        decoded = base64.b64decode(stored_password)
        salt = decoded[:16]
        stored_hash = decoded[16:]
        new_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
        return new_hash == stored_hash
    except Exception:
        return False

# --- File Hashing ---
def calculate_file_hash(file_data: bytes) -> str:
    """Calculates SHA-256 hash of file data."""
    sha256 = hashlib.sha256()
    sha256.update(file_data)
    return sha256.hexdigest()

# --- AES Encryption (File Data) ---
def encrypt_data_aes(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    """Encrypts data using AES-256 GCM. Returns (ciphertext, nonce, tag)."""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, cipher.nonce, tag

def decrypt_data_aes(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
    """Decrypts data using AES-256 GCM."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# --- RSA Encryption (Key Protection) ---
def generate_rsa_keypair():
    """Generates a new RSA key pair."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_key_rsa(aes_key: bytes, public_key_pem: bytes) -> bytes:
    """Encrypts an AES key using an RSA public key."""
    recipient_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(aes_key)
    return enc_session_key

def decrypt_key_rsa(enc_aes_key: bytes, private_key_pem: bytes) -> bytes:
    """Decrypts an AES key using an RSA private key."""
    private_key = RSA.import_key(private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(enc_aes_key)
    return aes_key

# --- Digital Signatures ---
def sign_data(data_hash: str, private_key_pem: bytes) -> str:
    """Signs a hash using RSA private key. Returns Base64 signature."""
    key = RSA.import_key(private_key_pem)
    h = CryptoSHA256.new(data_hash.encode('utf-8'))
    signature = pkcs1_15.new(key).sign(h)
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(data_hash: str, signature_b64: str, public_key_pem: bytes) -> bool:
    """Verifies a signature using RSA public key."""
    try:
        key = RSA.import_key(public_key_pem)
        h = CryptoSHA256.new(data_hash.encode('utf-8'))
        signature = base64.b64decode(signature_b64)
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
