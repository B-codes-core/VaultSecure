import secrets
from Crypto.Cipher import AES
from dotenv import load_dotenv, set_key
import os
import base64

class TagMismatchError(Exception):
    """
    A custom exception raised when GCM tag authentication fails during decryption

    Attributes:
        msg (str) : The error message
    """
    def __init__(self, msg="Decryption Failed due to tag mismatch"):
        super().__init__(msg)
        self.msg = msg
    
    def __str__(self):
        return self.msg

def generate_key() -> bytes:
    """
    Generates a cryptographically secure AES-256 key

    Args : None
    Returns : A cryptographically secure AES-256 key 
    """
    return secrets.token_bytes(32)

def store_key():
    """
    Generates and stores an encryption key into a .env file

    Args : None
    Returns : None
    """
    try:
        encryption_key = generate_key()
        set_key(".env", "ENCRYPTION_KEY", base64.b64encode(encryption_key).decode())
    except Exception as exc:
        print(exc)

def encrypt_password(input_password: str, key: bytes) -> tuple:
    """
    Encrypts a password using AES-256 in GCM mode

    Args:
        input_password (string) : The password to be encrypted
        key (bytes) : The AES-256 encryption key

    Returns:
        tuple : nonce, ciphertext and tag in the order meentioned
    """
    nonce = secrets.token_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(input_password.encode('utf-8'))
    return nonce, ciphertext, tag

def decrypt_password(input_ciphertext: bytes, nonce: bytes, tag: bytes, key: bytes) -> str:
    """
    Decrypts a ciphertext using AES-256 GCM mode

    Args:
        input_ciphertext (bytes) : The ciphertext to be decrypted
        nonce (bytes) : The nonce used to encrypt the input password
        tag (bytes) : The authentication tag provided by AES-GCM during encryption
        key (bytes) : The key that was used for encrypting the password

    Returns:
        str : The decrypted password

    Raises:
        TagMismatchhError : If tag authentication fails. This may happen if the ciphertext was tampered or input decryption key is wrong.
    """
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(input_ciphertext, tag)
        return plaintext.decode('utf-8')
    except ValueError as v:
        raise TagMismatchError()
    
if __name__ == "__main__":
    store_key()