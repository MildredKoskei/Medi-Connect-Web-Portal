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
#logging in
@app.route('/login', methods=['GET', 'POST'])
def login_post():

    if request.method == 'POST':

        username = request.form.get('username')
        password = request.form.get('password')

        conn = get_db_connection()
#vulnerability 1: no password hashing - passwords stored in plaintext
        user = conn.execute(
            'SELECT * FROM users WHERE username = ? AND password = ?',
            (username, password)
        ).fetchone()
#vulnerability 2: weak authentication - brute force attack possible - no account lockout mechanism
        if user:
            if user['role'] == 'admin':
                return redirect('/admin')
            elif user['role'] == 'doctor':
                return redirect('/doctor')
            elif user['role'] == 'patient':
                return redirect('/patient')

        return "Login failed"

    # If it's a GET request, just show the login page
    return render_template('login.html')

@app.route('/patient')
def patient_dashboard():
    #anyon e can access this page without authentication - vulnerability 4: unauthorized access
    return render_template('patient_dashboard.html')
#doctors landing page
@app.route('/doctor')
def doctor_dashboard():
    #anyon e can access this page without authentication - vulnerability 4: unauthorized access
    conn = get_db_connection()
    appointments = conn.execute('SELECT * FROM appointments').fetchall()
    conn.close()
    return render_template('doctor_dashboard.html', appointments=appointments)

#admin landing page
@app.route('/admin')
def admin_dashboard():
    #anyon e can access this page without authentication - vulnerability 4: unauthorized access
    return render_template('admin_dashboard.html')

#appointments page
@app.route('/appointments')
def view_appointments():
    conn = get_db_connection()
    appointments = conn.execute('SELECT * FROM appointments').fetchall()
    return render_template('appointments.html', appointments=appointments)

@app.route('/create_appointment', methods=['POST'])
def create_appointment():
    patient_name = request.form.get('patient_name')
    doctor_name = request.form.get('doctor_name')
    appointment_date = request.form.get('appointment_date')

    conn = get_db_connection()
#no input validation or sanitization - vulnerability 5: SQL injection possible  
    conn.execute('INSERT INTO appointments (patient_name, doctor_name, appointment_date) VALUES (?, ?, ?)',
                 (patient_name, doctor_name, appointment_date))
    conn.commit()
    conn.close()
    return redirect('/appointments')

    #deleting appointments
@app.route('/delete_appointment/<int:id>')
def delete_appointment(id):
    conn = get_db_connection()
    #vulnerability 5: SQL injection possible
    conn.execute('DELETE FROM appointments WHERE id = ?', (id,))
    conn.commit()

    return redirect('/appointments')
#editting appointments
@app.route('/edit_appointment/<int:id>')
def edit_appointment(id):
    conn = get_db_connection()
    appointment = conn.execute('SELECT * FROM appointments WHERE id = ?', (id,)).fetchone()
    return render_template('edit_appointment.html', appointment=appointment)    

#updating appointments
@app.route('/update_appointment/<int:id>', methods=['POST'])
def update_appointment(id):
    
    patient_name = request.form['patient_name']
    doctor_name = request.form['doctor_name']
    appointment_date = request.form['appointment_date']

    conn = get_db_connection()
    #vulnerability 5: SQL injection possible
    conn.execute('UPDATE appointments SET patient_name = ?, doctor_name = ?, appointment_date = ? WHERE id = ?',
                 (patient_name, doctor_name, appointment_date, id))
    conn.commit()

    return redirect('/appointments')


if __name__ == '__main__':
        app.run(debug=True)