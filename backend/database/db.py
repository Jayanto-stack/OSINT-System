import sqlite3
import os

# Database path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(BASE_DIR, "users.db")


# Create table function
def create_table():

    conn = sqlite3.connect(db_path)

    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT
    )
    """)

    conn.commit()
    conn.close()


# Insert user function
def insert_user(name, email, phone):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (name, email, phone) VALUES (?, ?, ?)",
            (name, email, phone)
        )
        conn.commit()
        conn.close()
        print("User inserted successfully")
    except Exception as e:
        print("DATABASE ERROR:", e)

# Create table automatically
create_table()