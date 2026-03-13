import sqlite3
conn = sqlite3.connect('database.db')
cursor = conn.cursor()
cursor.execute(
"INSERT INTO users (username, password, role) VALUES(?,?,?)", 
('admin', 'admin123', 'admin')
)
cursor.execute(
"INSERT INTO users (username,password,role) VALUES (?,?,?)",
("doctor1","doctor123","doctor")
)
cursor.execute(
"INSERT INTO users (username,password,role) VALUES (?,?,?)",
("Nick","doctor123","doctor")
)

cursor.execute(
"INSERT INTO users (username,password,role) VALUES (?,?,?)",
("Judy","doctor123","doctor")
)

cursor.execute(
"INSERT INTO users (username,password,role) VALUES (?,?,?)",
("Finnick","doctor123","doctor")
)

cursor.execute(
"INSERT INTO users (username,password,role) VALUES (?,?,?)",
("Gazelle","doctor123","doctor")
)

conn.commit()
conn.close()
print("Users added successfully")