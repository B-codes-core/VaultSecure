import pymongo
from dotenv import load_dotenv
import os

load_dotenv("app/database_operations/.env")
MONGO_HOST = os.getenv('MONGO_HOST', 'localhost')
MONGO_USER = os.getenv('MONGO_USER')
MONGO_PASSWORD = os.getenv('MONGO_PASSWORD')
MONGO_DB = os.getenv('MONGO_DB')
MONGO_PORT = os.getenv('MONGO_PORT', 27017)

class Connection:

    def connect(self):
        """
        Establishes a connection to the MongoDB database using credentials from environment variables.
  
        Returns:
            bool: True if connection was successful, False otherwise.
        """
        try:
            connection_string = f"mongodb://{MONGO_USER}:{MONGO_PASSWORD}@{MONGO_HOST}:{MONGO_PORT}/{MONGO_DB}"
            self.client = pymongo.MongoClient(connection_string)
            self.db = self.client[MONGO_DB]
            self.password_vault_collection = self.db["password_vault"]

        except Exception as e:
            print("Exception occurred while trying to connect to MongoDB : ",e)
        
    def get_collection(self) -> pymongo.synchronous.collection.Collection:
        """
        Returns:
            password_vault collection object
        """
        return self.password_vault_collection