"""
Seed script — V1 & V10 FIX: passwords are now hashed with werkzeug before storage.
Run once to populate the database with initial users.
"""
import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect('database.db')
cursor = conn.cursor()

users = [
    ('admin',    generate_password_hash('admin123'),   'admin'),
    ('doctor1',  generate_password_hash('doctor123'),  'doctor'),
    ('Nick',     generate_password_hash('doctor123'),  'doctor'),
    ('Judy',     generate_password_hash('doctor123'),  'doctor'),
    ('Finnick',  generate_password_hash('doctor123'),  'doctor'),
    ('Gazelle',  generate_password_hash('doctor123'),  'doctor'),
]

cursor.executemany(
    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
    users
)

conn.commit()
conn.close()
print("Users added successfully (passwords hashed)")