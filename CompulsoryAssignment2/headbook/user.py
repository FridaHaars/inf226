import flask_login
from box import Box
from werkzeug.security import generate_password_hash, check_password_hash
from .auth.password_check import *
import json
import secrets
from .utils import debug
import apsw
from flask import g


################################
# Class to store user info
# UserMixin provides us with an `id` field and the necessary methods (`is_authenticated`, `is_active`, `is_anonymous` and `get_id()`).
# Box makes it behave like a dict, but also allows accessing data with `user.key`.
# get user table



class User(flask_login.UserMixin, Box):
    def __init__(self, user_data):
        super().__init__(user_data)

    def save(self):
        """Save this user object to the database"""
        info = json.dumps(
            {k: self[k]
                for k in self if k not in ["username", "password", "id"]}
        )
        if "id" in self:
            pw = generate_password_hash(self.password, method='scrypt', salt_length=8)
            data_pwchange = (self.username, pw, info, self.id)
            data_nopwchange = (self.username, info, self.id)

            if check_password(self.password).get('password_ok'):
                sql = "UPDATE users SET username=?, password=?, info=? WHERE id=?;"
                sql_execute(sql, data_pwchange)

            elif check_password_hash(pw, self.password):
                sql = "UPDATE users SET username=?, info=? WHERE id=?;"
                sql_execute(sql, data_nopwchange)
            
                 
        else:
            pw = generate_password_hash(self.password, method='scrypt', salt_length=8)
            data = (self.username, pw, info)

            if check_password(self.password).get('password_ok'):
                sql = "INSERT INTO users (username, password, info) VALUES (?, ?, ?);"
                sql_execute(sql, data)

            self.id = db.last_insert_rowid()


    def add_token(self, name=""):
        """Add a new access token for a user"""
        token = secrets.token_urlsafe(32)
        data = (self.id, token, name)
        sql = "INSERT INTO tokens (user_id, token, name) VALUES (?, ?, ?);"
        sql_execute(sql, data)

    def delete_token(self, token):
        """Delete an access token"""
        data = (self.id, token)
        sql = "DELETE FROM tokens WHERE user_id = ? AND token = ?;"
        sql_execute(sql, data)

    def get_tokens(self):
        """Retrieve all access tokens belonging to a user"""
        sql = "SELECT token, name FROM tokens WHERE user_id = ?;"
        return sql_execute(sql, self.id).fetchall()

    @staticmethod
    def get_token_user(token):
        """Retrieve the user who owns a particular access token"""
        sql = "SELECT user_id FROM tokens WHERE token = ?"
        user_id = sql_execute(sql, token).get
        if user_id != None:
            return User.get_user(user_id)

    @staticmethod
    def get_user(userid):
        if type(userid) == int or userid.isnumeric():
            sql = "SELECT id, username, password, info FROM users WHERE id = ?;"
        else:
            sql = "SELECT id, username, password, info FROM users WHERE username = ?;"
        row = sql_execute(sql, (userid,)).fetchone()
        if row:
            user = User(json.loads(row[3]))
            user.update({"id": row[0], "username": row[1], "password": row[2]})
            return user





# helper to check whether the current user and the other users are buds
def is_buddies(cuid, uid):
    sql = "SELECT user2_id FROM buddies WHERE user1_id = ?;"
    buds = sql_execute(sql, {cuid}).fetchall()
    if len(buds) > 0:
        return True
    else:
        return False


def get_cursor():
    if "cursor" not in g:
        g.cursor = db.cursor()

    return g.cursor

def sql_execute(stmt, *args, **kwargs):
    debug(stmt, args or "", kwargs or "")
    return get_cursor().execute(stmt, *args, **kwargs)

def sql_init():
    global db

    db = apsw.Connection("./users.db")
    if db.pragma("user_version") == 0:
        sql_users = """CREATE TABLE IF NOT EXISTS users (
            id integer PRIMARY KEY, 
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            info JSON NOT NULL);"""
        sql_tokens = """CREATE TABLE IF NOT EXISTS tokens (
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            token TEXT NOT NULL UNIQUE,
            name TEXT
            );"""
        sql_buddies = """CREATE TABLE IF NOT EXISTS buddies (
            user1_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            user2_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            PRIMARY KEY (user1_id, user2_id)
            );"""
        sql_execute(sql_users)
        sql_execute(sql_tokens)
        sql_execute(sql_buddies)
        add_init_users()

def add_init_users():
        alice = User(
            {
                "username": "alice",
                "password": "pasSword359=",
                "color": "green",
                "picture_url": "https://git.app.uib.no/uploads/-/system/user/avatar/788/avatar.png",
            }
        )
        alice.save()
        alice.add_token("example")
        bob = User(
            {"username": "bob", "password": "Bananas#34", "color": "red"})
        bob.save()
        bob.add_token("test")
        sql = "INSERT INTO buddies (user1_id, user2_id) VALUES (?, ?);"
        # Removed just to test buddies on homepage
        # sql_execute(sql2, data)
        # data = (alice.id, bob.id)
        # sql_execute(sql1, data)
        data = (bob.id, alice.id)
        sql_execute(sql, data)
        sql_execute("PRAGMA user_version = 1;")
