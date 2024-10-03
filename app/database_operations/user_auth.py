from cryptographic_operations import hashing
from connect import Connection

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

    def __init__(self, user_auth_collection):
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