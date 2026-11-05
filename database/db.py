import os
import certifi

from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")

if not MONGO_URI:
    raise ValueError("MONGO_URI is missing from .env")

client = MongoClient(
    MONGO_URI,
    tls=True,
    tlsCAFile=certifi.where(),
    serverSelectionTimeoutMS=15000
)

db = client["loglens"]


def test_connection():
    try:
        client.admin.command("ping")
        print("MongoDB Atlas connected successfully!")
        print("Database: loglens")
        return True

    except Exception as error:
        print("MongoDB connection failed!")
        print(error)
        return False


if __name__ == "__main__":
    test_connection()