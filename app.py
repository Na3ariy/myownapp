#!/usr/bin/env python
# coding: utf-8

# In[ ]:


from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Змінити на більш надійний ключ
app.config['WTF_CSRF_SECRET_KEY'] = "secure_csrf_key"  # Додано для CSRF

# Безпека
csrf = CSRFProtect(app)  # CSRF захист
Talisman(app)  # HTTPS
limiter = Limiter(get_remote_address, app=app, default_limits=["100 per minute"])  # Rate Limiting

# Ініціалізація бази даних
def init_db():
    conn = sqlite3.connect("tasks.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        is_done BOOLEAN NOT NULL DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    conn.commit()
    conn.close()

# Реєстрація
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = sqlite3.connect("tasks.db")
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
        except sqlite3.IntegrityError:
            return "Цей логін уже існує!", 400
        finally:
            conn.close()
        return redirect(url_for("login"))
    return render_template("register.html")

# Вхід
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None  # Для зберігання повідомлення про помилку
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = sqlite3.connect("tasks.db")
        cursor = conn.cursor()
        cursor.execute("SELECT id, password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[1]):
            session["user_id"] = user[0]
            return redirect(url_for("index"))
        else:
            error = "Невірний логін або пароль!"  # Повідомлення про помилку
    return render_template("login.html", error=error)

# Головна сторінка (завдання користувача)
@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = sqlite3.connect("tasks.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tasks WHERE user_id = ?", (session["user_id"],))
    tasks = cursor.fetchall()
    conn.close()
    return render_template("index.html", tasks=tasks)

# Додати завдання
@app.route("/add", methods=["POST"])
def add_task():
    if "user_id" not in session:
        return redirect(url_for("login"))

    title = request.form.get("title")
    if len(title) > 255:
        return "Занадто довга назва завдання", 400

    conn = sqlite3.connect("tasks.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO tasks (title, user_id) VALUES (?, ?)", (title, session["user_id"]))
    conn.commit()
    conn.close()
    return redirect(url_for("index"))

# Інші маршрути (видалити, позначити виконаним)
@app.route("/delete/<int:task_id>")
def delete_task(task_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = sqlite3.connect("tasks.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM tasks WHERE id = ? AND user_id = ?", (task_id, session["user_id"]))
    conn.commit()
    conn.close()
    return redirect(url_for("index"))

@app.route("/complete/<int:task_id>")
def complete_task(task_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = sqlite3.connect("tasks.db")
    cursor = conn.cursor()
    cursor.execute("UPDATE tasks SET is_done = 1 WHERE id = ? AND user_id = ?", (task_id, session["user_id"]))
    conn.commit()
    conn.close()
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)

