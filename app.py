from flask import Flask, render_template, request, redirect 
import sqlite3
app = Flask(__name__)

#connection to the db
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

#landing page
@app.route('/')
def login():
    return render_template('login.html')

#signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        conn = get_db_connection()
        conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                     (username, password, role))
        conn.commit()
        conn.close()

        return redirect('/')
    return render_template('signup.html')

#LOGIN PAGE
@app.route('/login', methods=['POST'])
def login_post():
    username = request.form['username']
    password = request.form['password']

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?',
                        (username, password)).fetchone()
    conn.close()

    if user:
        return f"Welcome {user['username']}! You are logged in as {user['role']}."
    else:
        return "Invalid credentials. Please try again."
    
    if __name__ == '__main__':
        app.run(debug=True)