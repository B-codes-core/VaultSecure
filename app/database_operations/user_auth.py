from bson import ObjectId
from .cryptographic_operations import hashing, encryption
import os
from dotenv import set_key
import pymongo

class UsernameNotAvailableError(Exception):
    """
    Custom exception raised when the provided username is already taken.
    
    Attributes:
        msg (str): Explanation of the error. Default is "Provided Username is not available".
    """
    def __init__(self, msg="Provided Username is not available"):
        self.msg = msg
        super().__init__(msg)

    def __str__(self):
        return self.msg
    
class UserNotFoundError(Exception):
    """
    Custom exception raised when a user is not found in the database.
    
    Attributes:
        msg (str): Explanation of the error. Default is "User not found in database".
    """
    def __init__(self, msg="User not found in database"):
        self.msg = msg
        super().__init__(msg)

    def __str__(self):
        return self.msg
    
class PasswordVerificationFailedError(Exception):
    """
    Custom exception raised when the user's password verification fails.
    
    Attributes:
        msg (str): Explanation of the error. Default is "Password input by user was wrong".
    """
    def __init__(self, msg="Password input by user was wrong"):
        self.msg = msg
        super().__init__(msg)

    def __str__(self):
        return self.msg

class User:
    """
    Represents a user object with a username, email, and hashed password.
    
    Attributes:
        username (str): The username of the user.
        email (str): The email of the user.
        password (str): The hashed password of the user.
        key_salt (str) : Salt which will be used to generate the encryption key for the user (in hex)
    """
    def __init__(self, username: str, email: str, password: str) -> None:
        self.username = username
        self.email = email
        self.password = hashing.get_hashed_password(password).decode('utf-8')
        self.key_salt = os.urandom(16).hex()

class UserAuth:
    """
    A class used to manage user authentication, including registration, login, 
    and checking username availability in the database.

    This class provides methods to:
    - Check if a username is available for registration.
    - Add a new user to the database.
    - Check if a username exists in the database.
    - Verify user login credentials.
    
    Attributes:
        collection (MongoDB Collection): The database collection where user data is stored.
    """

    def __init__(self, user_auth_collection: pymongo.synchronous.collection.Collection):
        """
        Initializes a pymongo collection object for user_auth collection

        Args:
            user_auth_collection : The collection object for user_auth collection
        """
        self.collection = user_auth_collection

    def check_username_availability(self, username: str) -> None:
        """
        Checks if a username is available in the database.
        
        Args:
            username (str): The username to check.
        
        Raises:
            UsernameNotAvailableError: If the username already exists in the database.
        """
        query = {"username" : f"{username}"}
        result = self.collection.find_one(query)
        if result is not None:
            raise UsernameNotAvailableError()
    
    def add_user(self, user_instance: User) -> bool:
        """
        Adds a new user to the database after checking if the username is available.

        Args:
            user_instance (User): An instance of the User class to be added to the database.

        Returns:
            bool: True if the user was successfully added, False otherwise.
        """
        self.check_username_availability(user_instance.username)

        new_entry = {
            'username' : f'{user_instance.username}',
            'email' : f'{user_instance.email}',
            'password' : f'{user_instance.password}',
            'key_salt' : f'{user_instance.key_salt}',
            'user_passwords' : []
        }
        
        # Change try except ig, let user handle it?
        try:
            self.collection.insert_one(new_entry)
            return True
        except Exception as e:
            print("Exception ocurred while adding new user to DB : ",e)
            return False
        
    def check_username_exists(self, username: str) -> None:
        """
        Checks if the provided username exists in the database.

        Args:
            username (str): The username to be checked.

        Raises:
            UserNotFoundError: If the username does not exist in the database.
        """
        query = {"username" : f"{username}"}
        result = self.collection.find_one(query)
        if result is None:
            raise UserNotFoundError()
        
    def get_user_by_id(self, user_id):
        query_result = self.collection.find_one({'_id': ObjectId(user_id)}, {'_id': 1, 'username': 1})
        if query_result:
            return {'_id': query_result['_id'], 'username': query_result['username']}
        return None

    
    # def verify_user_login(self, username: str, password: str) -> None:
    #     """
    #     Verifies the login credentials (username and password) of the user.

    #     Args:
    #         username (str): The username of the user trying to log in.
    #         password (str): The plain-text password input by the user.

    #     Returns:
    #         bytes : The generated encryption key of the user

    #     Raises:
    #         UserNotFoundError: If the username does not exist in the database.
    #         PasswordVerificationFailedError: If the provided password does not match the stored password.
    #     """
    #     self.check_username_exists(username)
    #     query_result = self.collection.find_one({'username': f"{username}"}, {'_id': 0, 'password': 1, 'key_salt': 1})
    #     stored_password = query_result["password"]
    #     key_salt = query_result["key_salt"]
    #     if not hashing.verify_password(password, stored_password.encode('utf-8')):
    #         raise PasswordVerificationFailedError()
    #     set_key("app/database_operations/.env", "ENCRYPTION_KEY", encryption.generate_key(password, key_salt).hex())



    def verify_user_login(self, username: str, password: str):
        try:
            self.check_username_exists(username)
            query_result = self.collection.find_one({'username': username}, {'_id': 1, 'password': 1, 'key_salt': 1})

            if query_result is None:
                print(f"User '{username}' not found.")
                raise UserNotFoundError("User not found.")

            stored_password = query_result["password"]
            key_salt = query_result["key_salt"]
            user_id = query_result['_id']  # Assuming '_id' is your user ID

            print(f"Stored password: {stored_password}, Key salt: {key_salt}, User ID: {user_id}")  # Debugging output

            if not hashing.verify_password(password, stored_password.encode('utf-8')):
                print("Password verification failed.")
                raise PasswordVerificationFailedError()

            # Successful verification: generate and return the encryption key
            encryption_key = encryption.generate_key(password, key_salt).hex()
            set_key("database_operations/.env", "ENCRYPTION_KEY", encryption_key)

            # Return user information, including user ID
            return {'id': user_id, 'username': username, 'encryption_key': encryption_key}  # Include user ID
        
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            raise


