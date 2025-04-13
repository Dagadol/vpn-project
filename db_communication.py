import os
import sqlite3
import bcrypt


class DatabaseConnection:
    def __init__(self, path):
        # path = "clients.db"  # :memory: meaning db runs on RAM
        self.conn = sqlite3.connect(path)
        self.cursor = self.conn.cursor()

    def initiate_db(self):
        command = ("CREATE TABLE clients (\n"
                   "    user_id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
                   "    email TEXT UNIQUE NOT NULL,\n"
                   "    role TEXT NOT NULL,\n"
                   "    password_hash TEXT NOT NULL,\n"
                   "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ,\n"
                   "    last_login TIMESTAMP DEFAULT  CURRENT_TIMESTAMP,\n"  # same as when it was created
                   "    is_verified BOOLEAN DEFAULT FALSE,\n"
                   "    is_active BOOLEAN DEFAULT TRUE );\n"
                   "        ")

        with self.conn:
            self.cursor.execute(command)


if __name__ != '__main__':
    if not os.path.exists(os.path.abspath("users.db")):
        db = DatabaseConnection("users.db")
        db.initiate_db()
    print("database exist already")


class Client:
    def __init__(self, email, password: str):
        self.email = email
        self.password = password
        self.role = None
        self._user_id = None

        # connect to database
        path = "users.db"
        self.conn = sqlite3.connect(path)
        self.cursor = self.conn.cursor()

    def get_role(self):
        """Assume user is logged"""
        if not self.role:
            self.cursor.execute("SELECT role FROM clients WHERE user_id=:user_id", {"user_id": self._user_id})
            self.role = self.cursor.fetchone()[0]
        return self.role

    def get_user_id(self):
        """Assume user is logged"""
        if not self._user_id:
            self.cursor.execute("SELECT user_id FROM clients WHERE email=:email", {"email": self.email})
            self._user_id = self.cursor.fetchone()[0]
        return self._user_id

    def is_registered(self) -> bool:
        self.cursor.execute("SELECT * From clients WHERE email=:email", {"email": self.email})
        ans = self.cursor.fetchall()
        return bool(ans)

    def valid_login(self) -> bool:
        """Assume email is in system"""

        # get saved password
        self.cursor.execute("SELECT password_hash FROM clients WHERE user_id=:user_id",
                            {"user_id": self._user_id})

        hashed_pass = self.cursor.fetchone()[0]
        if not hashed_pass:
            return False

        return bcrypt.checkpw(self.password.encode(), hashed_pass)

    def insert_client(self):
        """
        insert the new client, with no checking if email already in use, or any other validation
        """
        hashed_pass = bcrypt.hashpw(self.password.encode(), bcrypt.gensalt())
        with self.conn:
            self.cursor.execute("INSERT INTO clients (email, password_hash, role) VALUES (:email, :hash_pass, 'user')",
                                {"email": self.email, "hash_pass": hashed_pass})
        self.role = "user"

    def set_verified(self):
        """Assume user has done the things necessary to be verified"""
        with self.conn:
            self.cursor.execute("UPDATE clients SET is_verified=TRUE WHERE user_id=:user_id",
                                {"user_id": self._user_id})

    def set_active(self):
        with self.conn:
            self.cursor.execute("UPDATE clients SET is_active=TRUE, last_login=CURRENT_TIMESTAMP WHERE user_id=:id",
                                {"id": self._user_id})

    def set_inactive(self):
        """Assume active"""
        with self.conn:
            self.cursor.execute("UPDATE clients SET is_active=FALSE, last_login=CURRENT_TIMESTAMP WHERE user_id=:id",
                                {"id": self._user_id})

    # below are admin commands
    def find_user_by_email(self, email):
        if self.role == "Admin":
            self.cursor.execute("SELECT * FROM clients WHERE email=:email", {"email": email})
            raw = self.cursor.fetchone()[0]
            return raw

    def all_active_users(self):
        if self.role == "Admin":
            self.cursor.execute("SELECT * FROM clients WHERE is_active=TRUE")
            raw = self.cursor.fetchall()
            return raw


if __name__ == '__main__':
    # create the Database
    db = DatabaseConnection("clients.db")
    db.initiate_db()

    # create user
    client = Client("email@noam.com", "123")
    if not client.is_registered():
        client.insert_client()
    print("check if logged in:", client.valid_login())
    print("noam's ID:", client.get_user_id())

    # log into noam
    new_client = Client("email@noam.com", "1234")  # wrong password
    print(f"check if email '{new_client.email}' is already registered: ", new_client.is_registered())

    print("check if is able to log in:", new_client.valid_login())
    print()

    # create new user
    new_client = Client("jonathan@comcom.asd", " ")
    if not new_client.is_registered():
        new_client.insert_client()
    print("new client's ID:", new_client.get_user_id(), end="\t"*5)
    print("None if wasn't created")
    print()

    # check if cursors disrupt each other:
    # new_client.conn = db.conn
    # # new_client.cursor = db.cursor
    # client.conn = db.conn
    # # client.cursor = db.cursor
    # new_client.cursor.execute("SELECT * FROM clients")
    # client.cursor.execute("SELECT email FROM clients")
    # print(new_client.cursor.fetchall())
    # print(client.cursor.fetchall())
    # results show that they do NOT disrupt each other
