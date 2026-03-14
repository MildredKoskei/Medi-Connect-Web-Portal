import sqlite3

print("starting script")

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT,
    role TEXT
)
""")
cursor.execute("ALTER TABLE appointments ADD COLUMN status TEXT DEFAULT 'pending'")
conn.commit()
conn.close()
print("Status column added to appointments table")
print("Database created successfully")