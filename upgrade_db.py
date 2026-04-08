import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

# Messages table
cursor.execute("""
CREATE TABLE IF NOT EXISTS messages(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT,
    receiver TEXT,
    message TEXT
)
""")

# Prescriptions table
cursor.execute("""
CREATE TABLE IF NOT EXISTS prescriptions(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    doctor TEXT,
    patient TEXT,
    medication TEXT,
    notes TEXT
)
""")

conn.commit()
conn.close()

print("New tables created")