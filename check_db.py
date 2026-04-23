import sqlite3

conn = sqlite3.connect("database.db")
cursor = conn.cursor()

cursor.execute("SELECT * FROM users")
print(cursor.fetchall())

# import sqlite3
# from werkzeug.security import generate_password_hash

# conn = sqlite3.connect("database.db")
# cursor = conn.cursor()

# cursor.execute(
# "UPDATE users SET password=? WHERE username='admin'",
# (generate_password_hash("admin123"),)
# )

# cursor.execute(
# "UPDATE users SET password=? WHERE username='doctor1'",
# (generate_password_hash("doctor123"),)
# )

# conn.commit()
# conn.close()

# print("Users updated")

# import sqlite3

# conn = sqlite3.connect("database.db")
# cursor = conn.cursor()

# cursor.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0")
# cursor.execute("ALTER TABLE users ADD COLUMN lock_until TEXT")

# conn.commit()
# conn.close()

# print("User table updated")
# import sqlite3

# conn = sqlite3.connect("database.db")
# cursor = conn.cursor()

# cursor.execute("""
# CREATE TABLE IF NOT EXISTS availability (
#     id INTEGER PRIMARY KEY AUTOINCREMENT,
#     doctor_name TEXT,
#     available_date TEXT,
#     available_time TEXT
# )
# """)

# conn.commit()
# conn.close()

# print("Availability table created")