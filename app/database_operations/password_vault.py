from cryptographic_operations import encryption
from dotenv import load_dotenv, set_key
import os
import pymongo

load_dotenv(".env")

class Password:
    """
    Represents a password entry for a specific website, which includes the username, website, and an encrypted password.

    Attributes:
        username (str): The username associated with the password.
        website (str): The website for which the password is being stored.
        password (str): The encrypted password in hexadecimal format.
        nonce (str): A cryptographic nonce (Number used once) in hexadecimal format.
        tag (str): Authentication tag for verifying the integrity of the encrypted password in hexadecimal format.
    """
    def __init__(self, username: str, website: str, password: str) -> None:
        """
        Initializes a Password instance by encrypting the provided password using the encryption module and the
        ENCRYPTION_KEY from the environment file.

        Args:
            username (str): The username associated with the password.
            website (str): The website for which the password is stored.
            password (str): The plaintext password to be encrypted.
        """
        self.username = username
        self.website = website
        ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
        encrypted_data = encryption.encrypt_password(password, bytes.fromhex(ENCRYPTION_KEY))
        self.password = encrypted_data[0].hex()
        self.nonce = encrypted_data[1].hex()
        self.tag = encrypted_data[2].hex()

class PasswordVault:
    """
    Represents a password vault that stores and retrieves encrypted passwords for users.

    Attributes:
        collection: password_vault collection object where user passwords are stored.
    """
    def __init__(self, password_vault_collection: pymongo.synchronous.collection.Collection) -> None:
        """
        Initializes a PasswordVault instance.

        Args:
            password_vault_collection: The boject for the database collection that stores password vault data for users.
        """
        self.collection = password_vault_collection

    def add_password(self, username: str, password: Password) -> bool:
        """
        Adds a new encrypted password entry for the given username to the database.

        Args:
            username (str): The username for whom the password is being added.
            password (Password): A Password object containing the encrypted password details.

        Returns:
            bool: True if the password was successfully added, False if an exception occurred.
        """
        new_user_password = {
            "website" : f"{password.website}",
            "username" : f"{password.username}",
            "ciphertext" : f"{password.password}",
            "nonce" : f"{password.nonce}",
            "tag" : f"{password.tag}"
        }
        try:
            self.collection.update_one(
                {"username" : f"{username}"},
                {"$push": {"user_passwords": new_user_password}}
            )
            return True
        except Exception as e:
            print("Exception ocurred while adding new user to DB : ",e)
            return False
        
    def retrieve_all_passwords(self, username: str) -> tuple:
        """
        Retrieves and decrypts all stored passwords for the given username.

        Args:
            username (str): The username for whom the passwords are being retrieved.

        Returns:
            tuple: A list of dictionaries containing the website, username, and decrypted password details.
        """
        try:
            user_passwords = []
            user_details = self.collection.find_one({"username" : f"{username}"})
            for password in user_details["user_passwords"]:
                user_passwords.append(
                    {
                        "website" : f'{password["website"]}',
                        "username" : f'{password["username"]}',
                        "password" : encryption.decrypt_password(
                            bytes.fromhex(password["ciphertext"]),
                            bytes.fromhex(password["nonce"]),
                            bytes.fromhex(password["tag"]),
                            bytes.fromhex(os.getenv("ENCRYPTION_KEY"))
                            )
                    }
                )
            return user_passwords
        except Exception as e:
            print("Exception ocurred while retrieving passwords : ", e)

    def clear_encryption_key(self) -> None:
        """
        Clears the encryption key stored in the .env file when the user logs out.

        This method is useful for security purposes, to ensure the key is removed from the environment after usage.
        """
        set_key(".env", "ENCRYPTION_KEY", "")