##############################
# Auth module for MFA Portal #
##############################
from database import DatabaseManager as DbMgr
from settings import Settings

settings = Settings()


class AuthManager:
    def __init__(self, ):
        self.db_path = settings.load("SQLITE_DB_PATH")
        print(f"AuthManager initialized with DB path: {self.db_path}")
