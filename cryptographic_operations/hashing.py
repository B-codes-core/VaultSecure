import bcrypt

def get_hashed_password(password):
    """
    Generates a bcrypt hash of the given password.

    Args:
        password (string): The input password to be hashed

    Returns:
        bytes: The hash of the input password
    """
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password

def verify_password(provided_password, stored_password):
    """
    Verifies the provided input password against the hash of a stored password.

    Args:
        provided_password (string) : The input password that needs to be verified.
        stored_password (bytes)

    Returns:
        boolean : Whether the verification succeeded or failed
    """
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password)
