from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3, os, hashlib
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = 'supersecret'

# Charger la clé de chiffrement
with open("secret.key", "rb") as key_file:
    key = key_file.read()
fernet = Fernet(key)

def init_db():
    with sqlite3.connect("data.db") as con:
        cur = con.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)")
        cur.execute("CREATE TABLE IF NOT EXISTS passwords (id INTEGER PRIMARY KEY, user_id INTEGER, site TEXT, login TEXT, password TEXT)")
        con.commit()

def get_user_id(username):
    with sqlite3.connect("data.db") as con:
        cur = con.cursor()
        cur.execute("SELECT id FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        return row[0] if row else None

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        hashed = hashlib.sha256(password.encode()).hexdigest()
        with sqlite3.connect("data.db") as con:
            cur = con.cursor()
            cur.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed))
            if cur.fetchone():
                session["username"] = username
                return redirect("/dashboard")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        hashed = hashlib.sha256(password.encode()).hexdigest()
        try:
            with sqlite3.connect("data.db") as con:
                cur = con.cursor()
                cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
                con.commit()
            return redirect("/")
        except:
            return "Utilisateur déjà existant"
    return render_template("register.html")

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "username" not in session:
        return redirect("/")
    user_id = get_user_id(session["username"])
    if request.method == "POST":
        site = request.form["site"]
        login = request.form["login"]
        password = request.form["password"]
        encrypted = fernet.encrypt(password.encode()).decode()
        with sqlite3.connect("data.db") as con:
            cur = con.cursor()
            cur.execute("INSERT INTO passwords (user_id, site, login, password) VALUES (?, ?, ?, ?)", (user_id, site, login, encrypted))
            con.commit()
    with sqlite3.connect("data.db") as con:
        cur = con.cursor()
        cur.execute("SELECT site, login, password FROM passwords WHERE user_id=?", (user_id,))
        entries = [(site, login, fernet.decrypt(password.encode()).decode()) for site, login, password in cur.fetchall()]
    return render_template("dashboard.html", entries=entries)

@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect("/")

if __name__ == "__main__":
    init_db()

