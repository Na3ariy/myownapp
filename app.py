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
app.secret_key = "supersecretkey"
app.config['WTF_CSRF_SECRET_KEY'] = "secure_csrf_key"

csrf = CSRFProtect(app)
Talisman(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["100 per minute"])


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
        priority TEXT DEFAULT 'Середній',
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    conn.commit()
    conn.close()


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if len(password) < 8 or not any(c.isupper() for c in password) or not any(c.islower() for c in password) or not any(c.isdigit() for c in password):
            error = "Пароль повинен містити щонайменше 8 символів, одну велику літеру, одну маленьку та одну цифру."
            return render_template("register.html", error=error)

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = sqlite3.connect("tasks.db")
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
        except sqlite3.IntegrityError:
            error = "Цей логін уже існує!"
        finally:
            conn.close()

        if error:
            return render_template("register.html", error=error)
        return redirect(url_for("login"))
    return render_template("register.html", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
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
            error = "Невірний логін або пароль!"
    return render_template("login.html", error=error)


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


@app.route("/search", methods=["GET"])
def search_tasks():
    if "user_id" not in session:
        return redirect(url_for("login"))

    query = request.args.get("query", "")
    conn = sqlite3.connect("tasks.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tasks WHERE user_id = ? AND title LIKE ?", (session["user_id"], f"%{query}%"))
    tasks = cursor.fetchall()
    conn.close()
    return render_template("index.html", tasks=tasks, query=query)


@app.route("/add", methods=["POST"])
def add_task():
    if "user_id" not in session:
        return redirect(url_for("login"))

    title = request.form.get("title")
    priority = request.form.get("priority", "Середній")
    if len(title) > 255:
        return "Занадто довга назва завдання", 400

    conn = sqlite3.connect("tasks.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO tasks (title, user_id, priority) VALUES (?, ?, ?)", (title, session["user_id"], priority))
    conn.commit()
    conn.close()
    return redirect(url_for("index"))


@app.route("/edit/<int:task_id>", methods=["GET", "POST"])
def edit_task(task_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = sqlite3.connect("tasks.db")
    cursor = conn.cursor()

    if request.method == "POST":
        new_title = request.form.get("title")
        cursor.execute("UPDATE tasks SET title = ? WHERE id = ? AND user_id = ?", (new_title, task_id, session["user_id"]))
        conn.commit()
        conn.close()
        return redirect(url_for("index"))

    cursor.execute("SELECT * FROM tasks WHERE id = ? AND user_id = ?", (task_id, session["user_id"]))
    task = cursor.fetchone()
    conn.close()
    return render_template("edit.html", task=task)


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

