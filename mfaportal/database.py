import sqlite3
from settings import Settings

settings = Settings()


class DatabaseManager:
    def __init__(self):
        self.db_path = settings.load("SQLITE_DB_PATH")
        print(f"Database path loaded: {self.db_path}")
