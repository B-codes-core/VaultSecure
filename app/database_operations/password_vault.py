from cryptographic_operations import encryption
from dotenv import load_dotenv
import os

load_dotenv("..\\..\\.env")

class Password:
    def __init__(self, website: str, username: str, password: str) -> None:
        self.website = website
        self.username = username
        ENCRYPTION_KEY = os.getenv["ENCRYPTION_KEY"]
        print(ENCRYPTION_KEY)

Password("skbd","asd","password")