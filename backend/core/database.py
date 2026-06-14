# établit la connexion à MongoDB Atlas et expose la base de données "pfe2026" pour les repositories.

from pymongo import MongoClient
from config import MONGO_URI, MONGO_DB

client = MongoClient(MONGO_URI)
db = client[MONGO_DB]

