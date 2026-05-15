import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(BASE_DIR, "users.db")

# Connect to SQLite database
conn = sqlite3.connect(db_path, check_same_thread=False)
# sqlite3.connect("database/users.db") Creates database file automatically if not exists.

# Create cursor
cursor = conn.cursor()
# cursor() is used for execute SQL queries, interact with database

# Create users table only once
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT
)
""")

# Save changes
conn.commit()


# Function to insert user data (custom function to save user data)
def insert_user(name, email, phone):

    cursor.execute(
        "INSERT INTO users (name, email, phone) VALUES (?, ?, ?)",
        (name, email, phone)
    )

    conn.commit()