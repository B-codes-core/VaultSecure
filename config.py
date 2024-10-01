import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    #SECRET_KEY = os.getenv('SECRET_KEY')
    MONGO_HOST = os.getenv('MONGO_HOST', 'localhost')
    MONGO_USER = os.getenv('MONGO_USER')
    MONGO_PASSWORD = os.getenv('MONGO_PASSWORD')
    MONGO_DB = os.getenv('MONGO_DB')
    MONGO_PORT = int(os.getenv('MONGO_PORT', 27017))