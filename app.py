print("app starting")
from flask import Flask, render_template, request, redirect 
import sqlite3
app = Flask(__name__, template_folder='Components')

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

        conn = get_db_connection()
        #1st vulnerability: no password hashing
        conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                     (username, password, "patient"))
        conn.commit()
  

        return redirect('/')
    return render_template('signup.html')

#LOGIN PAGE
@app.route('/login', methods=['POST'])
def login_post():
    username = request.form['username']
    password = request.form['password']

    conn = get_db_connection()
    #vulnerability 2: weak authentication - brute force attack possible
    user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?',
                        (username, password)
                        ).fetchone()
    if user:
        # vulnerability: 3 - no session management - vulnerability 3: session fixation and hijacking possible
        if user['role'] == 'admin':
            return redirect('/admin')
        if user['role'] == 'doctor':
            return redirect('/doctor')
        if user['role'] == 'patient':
            return redirect('/patient')
        else:
            return ("login failed")
        #patients landing page
@app.route('/patient')
def patient_dashboard():
    #anyon e can access this page without authentication - vulnerability 4: unauthorized access
    return render_template('patient_dashboard.html')
#doctors landing page
@app.route('/doctor')
def doctor_dashboard():
    #anyon e can access this page without authentication - vulnerability 4: unauthorized access
    return render_template('doctor_dashboard.html')

#admin landing page
@app.route('/admin')
def admin_dashboard():
    #anyon e can access this page without authentication - vulnerability 4: unauthorized access
    return render_template('admin_dashboard.html')


if __name__ == '__main__':
        app.run(debug=True)