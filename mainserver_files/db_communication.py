import os
import sqlite3
import bcrypt
import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

PATH = r"mainserver_files\tables.db"

# Email credentials and settings
smtp_server = "smtp.gmail.com"
smtp_port = 465
email_sender = input("enter the no-reply email: ")
application_password = input("enter the application password/password of your email: ")


class DatabaseConnection:
    def __init__(self, path):
        # path = "clients.db"  # :memory: meaning db runs on RAM
        self.conn = sqlite3.connect(path)
        self.cursor = self.conn.cursor()

    def initiate_db(self):
        command_for_clients = ("CREATE TABLE clients (\n"
                               "    user_id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
                               "    email TEXT UNIQUE DEFAULT NULL,\n"
                               "    username TEXT UNIQUE NOT NULL,\n"
                               "    role TEXT NOT NULL,\n"
                               "    password_hash TEXT NOT NULL,\n"
                               "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ,\n"
                               "    last_login TIMESTAMP DEFAULT  CURRENT_TIMESTAMP,\n"  # same as when it was created
                               "    is_verified BOOLEAN DEFAULT FALSE,\n"
                               "    is_active BOOLEAN DEFAULT TRUE );\n"
                               "        ")

        command_for_servers = ("""
                CREATE TABLE IF NOT EXISTS vpn_servers (
                    ip_address TEXT PRIMARY KEY,
                    country TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    active BOOLEAN DEFAULT FALSE
                )
                """)

        with self.conn:
            self.cursor.execute(command_for_clients)
            self.cursor.execute(command_for_servers)


if __name__ != '__main__':
    if not os.path.exists(os.path.abspath(PATH)):
        db = DatabaseConnection(PATH)
        db.initiate_db()
    print("database exist already")


class Server:
    @staticmethod
    def _get_sql_conn():
        try:
            # connect to database
            conn = sqlite3.connect(PATH)
            cursor = conn.cursor()
            return conn, cursor
        except Exception as e:
            print(f"db exception: {e}")
            return None, None

    @staticmethod
    def add_server(ip_address, country, password):
        conn, cursor = Server._get_sql_conn()
        hashed_pass = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        try:
            cursor.execute("INSERT INTO vpn_servers (ip_address, country, password_hash) VALUES (?, ?, ?)",
                           (ip_address, country, hashed_pass))
            conn.commit()
            print("Server added.")
        except sqlite3.IntegrityError:
            print("Server with this IP already exists.")
        conn.close()

    @staticmethod
    def remove_server(ip_address):
        conn, cursor = Server._get_sql_conn()
        cursor.execute("DELETE FROM vpn_servers WHERE ip_address = ?", (ip_address,))
        conn.commit()
        conn.close()
        print("Server removed if it existed.")

    @staticmethod
    def get_countries():
        conn, cursor = Server._get_sql_conn()
        cursor.execute("""SELECT country 
        FROM vpn_servers 
        WHERE active = TRUE 
        GROUP BY country""")
        result = cursor.fetchall()
        conn.close()

        if isinstance(result, list):
            countries = [country[0] for country in result]
        else:
            countries = result[0]
        return countries

    @staticmethod
    def get_country_by_ip(ip_address):
        conn, cursor = Server._get_sql_conn()
        cursor.execute("SELECT country FROM vpn_servers WHERE ip_address = ?", (ip_address,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None

    @staticmethod
    def check_ip_password(ip_address, password):
        conn, cursor = Server._get_sql_conn()

        # get saved password
        cursor.execute("SELECT password_hash FROM vpn_servers WHERE ip_address=:ip_address",
                       {"ip_address": ip_address})

        hashed_pass = cursor.fetchone()
        if not hashed_pass:
            return None
        conn.close()
        return bcrypt.checkpw(password.encode(), hashed_pass[0])

    @staticmethod
    def set_active(ip_address):
        conn, cursor = Server._get_sql_conn()
        with conn:
            cursor.execute("UPDATE vpn_servers SET active=TRUE WHERE ip_address=:ip",
                           {"ip": ip_address})

    @staticmethod
    def is_active(ip_address):
        conn, cursor = Server._get_sql_conn()
        cursor.execute("SELECT active FROM vpn_servers WHERE ip_address=:ip",
                       {"ip": ip_address})
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None

    @staticmethod
    def get_filtered_countries(exception_ip, country_filter):
        conn, cursor = Server._get_sql_conn()
        cursor.execute("""
        SELECT ip_address
        FROM vpn_servers
        WHERE ip_address != :ip
           AND (
                :country_filter = 'Any'
                OR country = :country_filter
                )
           AND active = TRUE
        """, {"ip": exception_ip, "country_filter": country_filter})
        results = cursor.fetchall()
        conn.close()
        return results


class Client:
    def __init__(self, username, password: str):
        self._verified = None
        self._username = username
        self.email = None
        self._password = password
        self.role = None
        self._user_id = None
        self.code = tuple()  # (code, time, num of try)

        # connect to database
        self.conn = sqlite3.connect(PATH)
        self.cursor = self.conn.cursor()

    @property
    def username(self):
        return self._username

    @property
    def password(self):
        return self._password

    @property
    def is_verified(self):
        if self._verified is None:
            with self.conn:
                self.cursor.execute("SELECT is_verified FROM clients WHERE user_id=:user_id",
                                    {"user_id": self._user_id})
                self._verified = bool(self.cursor.fetchone()[0])
        return self._verified

    def get_role(self):
        """Assume user is logged"""
        if not self.role:
            self.cursor.execute("SELECT role FROM clients WHERE user_id=:user_id", {"user_id": self._user_id})
            self.role = self.cursor.fetchone()[0]
        return self.role

    def get_user_id(self):
        """Assume user is logged"""
        if not self._user_id:
            self.cursor.execute("SELECT user_id FROM clients WHERE username=:username", {"username": self._username})
            self._user_id = self.cursor.fetchone()[0]
        return self._user_id

    def is_registered(self) -> bool:
        self.cursor.execute("SELECT * From clients WHERE username=:username", {"username": self._username})
        ans = self.cursor.fetchall()
        return bool(ans)

    def is_email_registered(self, email) -> bool:
        """"""
        self.cursor.execute("SELECT * From clients WHERE email=:email", {"email": email})
        ans = self.cursor.fetchall()
        return bool(ans)

    def valid_login(self) -> bool:
        """Assume username is in system"""

        # get saved password
        self.cursor.execute("SELECT password_hash FROM clients WHERE user_id=:user_id",
                            {"user_id": self._user_id})

        hashed_pass = self.cursor.fetchone()[0]
        if not hashed_pass:
            return False

        return bcrypt.checkpw(self._password.encode(), hashed_pass)

    def insert_client(self):
        """
        insert the new client, with no checking if username already in use, or any other validation
        """
        hashed_pass = bcrypt.hashpw(self._password.encode(), bcrypt.gensalt())
        with self.conn:
            self.cursor.execute(
                "INSERT INTO clients (username, password_hash, role) VALUES (:username, :hash_pass, 'user')",
                {"username": self._username, "hash_pass": hashed_pass})
        self.role = "user"

    def set_verified(self):
        """Assume user has done the things necessary to be verified"""
        if self.email:
            with self.conn:
                self.cursor.execute("UPDATE clients SET is_verified=TRUE, email=:email WHERE user_id=:user_id",
                                    {"user_id": self._user_id, "email": self.email})
            self._verified = True
            return True
        else:
            return False

    def set_active(self):
        with self.conn:
            self.cursor.execute("UPDATE clients SET is_active=TRUE, last_login=CURRENT_TIMESTAMP WHERE user_id=:id",
                                {"id": self._user_id})

    def set_inactive(self):
        """Assume active"""
        with self.conn:
            self.cursor.execute("UPDATE clients SET is_active=FALSE, last_login=CURRENT_TIMESTAMP WHERE user_id=:id",
                                {"id": self._user_id})

    def send_code(self):
        if self.email:
            with open("mainserver_files/email_content.html", "r") as f:
                html_content = f.read()
                html_content = html_content.replace("-code-", self.code[0])
                html_content = html_content.replace("-name-", self.username)

            # Create the email
            msg = MIMEMultipart("alternative")
            msg["Subject"] = "Verify by Code"
            msg["From"] = email_sender
            msg["To"] = self.email

            mime_html = MIMEText(html_content, "html")
            msg.attach(mime_html)

            # Send the email
            try:
                with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
                    server.login(email_sender, application_password)
                    server.sendmail(email_sender, self.email, msg.as_string())
                print("Email sent successfully.")
            except Exception as e:
                print(f"An error occurred: {e}")

    def query_clients(self, **filters):
        """commands for admins"""
        if not self.is_verified:
            return None
        cols = [
            "user_id",
            "username",
            "email",
            "role",
            "created_at",
            "last_login",
            "is_verified",
            "is_active"
        ]
        base_query = f"SELECT {', '.join(cols)} FROM clients"
        conditions = []
        params = []

        valid_filters = {
            "is_active": "is_active = ?",
            "is_verified": "is_verified = ?",
            "username": "username LIKE ?",
            "email": "email LIKE ?",
            "role": "role = ?",
            "created_after": "created_at >= ?",
            "created_before": "created_at <= ?"
        }
        if "email" not in filters.keys() and "none" not in filters.keys() and "username" not in filters.keys():
            for key, value in filters.items():
                if key in valid_filters and value is not None:
                    conditions.append(valid_filters[key])
                    if key == "email":
                        params.append(f"%{value}%")
                    else:
                        params.append(value)
            if conditions:
                base_query += " WHERE " + " AND ".join(conditions)
        elif "email" in filters.keys():
            base_query += " WHERE " + valid_filters["email"]
            params.append(f"%{filters.get("email")}")
        elif "username" in filters.keys():
            base_query += " WHERE " + valid_filters["username"]
            params.append(f"%{filters.get("username")}")

        print(f"query: '{base_query}', ({params})")
        self.cursor.execute(base_query, params)
        raw = self.cursor.fetchall()
        print(f"raw: {raw}")
        return json.dumps(raw)


if __name__ == '__main__':
    # create the Database
    db = DatabaseConnection("clients.db")
    db.initiate_db()

    # create user
    client = Client("email@noam.com", "123")
    if not client.is_registered():
        client.insert_client()
    print("check if logged in:", client.valid_login())
    print("x's ID:", client.get_user_id())

    # log into noam
    new_client = Client("email@noam.com", "1234")  # wrong password
    print(f"check if email '{new_client.email}' is already registered: ", new_client.is_registered())

    print("check if is able to log in:", new_client.valid_login())
    print()

    # create new user
    new_client = Client("jonathan@comcom.asd", " ")
    if not new_client.is_registered():
        new_client.insert_client()
    print("new client's ID:", new_client.get_user_id(), end="\t" * 5)
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
