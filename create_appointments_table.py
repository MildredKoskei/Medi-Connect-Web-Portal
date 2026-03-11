print("Creating appointments table...")
import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS appointments(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_name TEXT,
    doctor_name TEXT,
    appointment_date TEXT
)
""")

conn.commit()
conn.close()

print("Appointments table created successfully")