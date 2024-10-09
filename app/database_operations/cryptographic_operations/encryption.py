import secrets
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

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

def generate_key(password: str, salt: str, key_length: int = 32, iterations: int = 100000) -> bytes:
    """
    Generates a cryptographically secure AES-256 key using PBKDF2 Key Derivation function

    Args :
        password (str) : The password of the user, using which the key will be derived.
        salt (str) : The salt that is used to generate the key. It is in hex

    Returns : 
        bytes : A cryptographically secure AES-256 key 
    """
    key = PBKDF2(password, bytes.fromhex(salt), dkLen=key_length, count=iterations, hmac_hash_module=SHA256)
    return key

def encrypt_password(input_password: str, key: bytes) -> tuple:
    """
    Encrypts a password using AES-256 in GCM mode

    Args:
        input_password (string) : The password to be encrypted
        key (bytes) : The AES-256 encryption key

    Returns:
        tuple : ciphertext, nonce and tag in the order meentioned
    """
    nonce = secrets.token_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(input_password.encode('utf-8'))
    return ciphertext, nonce, tag

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