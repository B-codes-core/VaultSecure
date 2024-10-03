from dotenv import load_dotenv
import pymongo
import os
from cryptographic_operations import hashing

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
    """
    def __init__(self, username: str, email: str, password: str) -> None:
        self.username = username
        self.email = email
        self.password = hashing.get_hashed_password(password).decode('utf-8')

class UserAuth:
    """
    Handles user authentication and database operations using MongoDB.
    
    Class attributes:
        MONGO_HOST (str): The MongoDB host, retrieved from environment variables.
        MONGO_USER (str): The MongoDB user, retrieved from environment variables.
        MONGO_PASSWORD (str): The MongoDB password, retrieved from environment variables.
        MONGO_DB (str): The MongoDB database, retrieved from environment variables.
        MONGO_PORT (int): The MongoDB port, retrieved from environment variables (default: 27017).
    """
    MONGO_HOST = os.getenv('MONGO_HOST', 'localhost')
    MONGO_USER = os.getenv('MONGO_USER')
    MONGO_PASSWORD = os.getenv('MONGO_PASSWORD')
    MONGO_DB = os.getenv('MONGO_DB')
    MONGO_PORT = int(os.getenv('MONGO_PORT', 27017))

    def connect(self) -> bool:
        """
        Establishes a connection to the MongoDB database using credentials from environment variables.
        
        Returns:
            bool: True if connection was successful, False otherwise.
        """
        try:
            connection_string = f"mongodb://{self.MONGO_USER}:{self.MONGO_PASSWORD}@{self.MONGO_HOST}:{self.MONGO_PORT}/{self.MONGO_DB}"
            self.client = pymongo.MongoClient(connection_string)
            self.db = self.client[self.MONGO_DB]
            self.collection = self.db["user_auth"]
            return True

        except Exception as e:
            print("Exception occurred while trying to connect to MongoDB : ",e)
            return False

    # Do Everything like the below 2 functions
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
            'password' : f'{user_instance.password}'
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
    
    def verify_user_login(self, username: str, password: str) -> None:
        """
        Verifies the login credentials (username and password) of the user.

        Args:
            username (str): The username of the user trying to log in.
            password (str): The plain-text password input by the user.

        Raises:
            UserNotFoundError: If the username does not exist in the database.
            PasswordVerificationFailedError: If the provided password does not match the stored password.
        """
        self.check_username_exists(username)
        stored_password = self.collection.find_one({'username': f"{username}"}, {'_id': 0, 'password': 1})['password']
        if not hashing.verify_password(password, stored_password.encode('utf-8')):
            raise PasswordVerificationFailedError()