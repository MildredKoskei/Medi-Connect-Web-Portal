print("app starting")
from flask import Flask, render_template, request, redirect, session 
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import html
import sqlite3
from datetime import datetime, timedelta
app = Flask(__name__, template_folder='templates')
app.secret_key = secrets.token_hex(16)
#app.secret_key = 'medi-connect-secret-key'  # Replace with a real secret key

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
        username = request.form.get('username').strip()
        password = request.form.get('password')
        if not username or not password:
            return "Invalid input", 400
        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        #1st vulnerability fixed: added password hashing and closing the connection
        conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                     (username, hashed_password, "patient"))
        conn.commit()
        conn.close()  
        return redirect('/')
    return render_template('signup.html')

#logging in vulnerability fixed
@app.route('/login', methods=['GET', 'POST'])
def login_post():

    if request.method == 'POST':

        username = request.form.get('username')
        password = request.form.get('password')

        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?',
            (username,)
        ).fetchone()
        if not user:
            conn.close()
            return render_template('login.html', error="Invalid credentials")
        if user['lock_until']:
            lock_time = datetime.fromisoformat(user['lock_until'])
            if datetime.now() < lock_time:
                remaining = lock_time - datetime.now()
                minutes = remaining.seconds // 60
                seconds = remaining.seconds % 60
                conn.close()
                return render_template('login.html', 
                error=f"Account is locked. Please try again after {minutes}m {seconds}s")
                #check password
        if check_password_hash(user['password'], password):
            #reset failed attempts
            conn.execute(
                'UPDATE users SET failed_attempts = 0, lock_until = NULL WHERE username = ?', 
                (username,)
            )
            conn.commit()
            conn.close()
            session.clear()
            session['username'] = user['username']
            session['role'] = user['role']
            if user['role'] == 'admin':
                return redirect('/admin')
            elif user['role'] == 'doctor':
                return redirect('/doctor')
            else:
                return redirect('/patient')
        else:
            #increment failed attempts
            attempts = user['failed_attempts'] + 1
#lock the account after 3 failed attempts
            if attempts >= 3:
                if not user['lock_until']:
                    lock_time = datetime.now() + timedelta(minutes=5)

                    conn.execute(
                        "UPDATE users SET failed_attempts = ?, lock_until = ? WHERE username = ?",
                        (attempts,lock_time.isoformat(), username)
                )
                else:
                    conn.execute(
                        "UPDATE users SET failed_attempts = ? WHERE username = ?",
                        (attempts, username)
                    )

                conn.commit()
                conn.close()

                return render_template(
                    'login.html',
                    error="Account locked for 5 minutes due to multiple failed attempts"
                )

            else:
                conn.execute(
                    "UPDATE users SET failed_attempts = ? WHERE username = ?",
                    (attempts, username)
                )
                conn.commit()
                conn.close()

                return render_template(
                    'login.html',
                    error=f"Invalid credentials. Attempt {attempts}/3"
                )
        return render_template('login.html')
        
#vulnerability 2: weak authentication - brute force attack possible - no account lockout mechanism
        if user:
            session['username'] = user['username']
            session['role'] = user['role']

            if user['role'] == 'admin':
                return redirect('/admin')
            elif user['role'] == 'doctor':
                return redirect('/doctor')
            elif user['role'] == 'patient':
                return redirect('/patient')

        return render_template('login.html', error="Login unsuccessful. Please check your credentials.")

    # If it's a GET request, just show the login page
    return render_template('login.html')

@app.route('/patient')
def patient_dashboard():
    if session.get('role') != 'patient':
        return "Unauthorized access", 403  
    #anyone can access this page without authentication - vulnerability 4: unauthorized access
    return render_template('patient_dashboard.html')
#doctors landing page
@app.route('/doctor')
def doctor_dashboard():
    if session.get('role') != 'doctor':
        return "Unauthorized access", 403
    #anyon e can access this page without authentication - vulnerability 4: unauthorized access
    conn = get_db_connection()
    appointments = conn.execute('SELECT * FROM appointments WHERE doctor_name = ?', (session.get('username'),)).fetchall()
    conn.close()
    return render_template('doctor_dashboard.html', appointments=appointments)

#approving appointments
@app.route('/approve/<int:id>', methods=['POST'])
def approve_appointment(id):
    if session.get('role') != 'doctor':
        return "Unauthorized access", 403
    conn = get_db_connection()
    appointment = conn.execute(
        'SELECT * FROM appointments WHERE id = ?',
         (id,)
         ).fetchone()
         #ownership check
    if not appointment or appointment['doctor_name'] != session('username'):
        return "Unauthorized access", 403
    conn.execute('UPDATE appointments SET status = ? WHERE id = ?', 
    ('approved', id)
    )
    conn.commit()
    conn.close()
    return redirect('/doctor')

#rejecting appointments
@app.route('/reject/<int:id>')
def reject_appointment(id):
    if session.get('role') != 'doctor':
        return "Unauthorized access", 403
    conn = get_db_connection()
    appointment = conn.execute(
        'SELECT * FROM appointments WHERE id = ?',
         (id,)
         ).fetchone()
    if not appointment or appointment['doctor_name'] != session('username'):
        return "Unauthorized access", 403
    conn.execute('UPDATE appointments SET status = ? WHERE id = ?', ('rejected', id))
    conn.commit()
    conn.close()
    return redirect('/doctor')
  
#admin landing page
@app.route('/admin')
def admin_dashboard():
    if session.get('role') != 'admin':
        return "Unauthorized access", 403
    #anyon e can access this page without authentication - vulnerability 4: unauthorized access
    return render_template('admin_dashboard.html')

@app.route('/admin/users')
def view_users():
    if session.get('role') != 'admin':
        return "Unauthorized access", 403
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, role FROM users').fetchall()
    conn.close()
    return render_template('view_users.html', users=users)
#deleting users
@app.route('/admin/delete_user/<int:id>')
def delete_user(id):
    if session.get('role') != 'admin':
        return "Unauthorized access", 403
    conn = get_db_connection()
    #vulnerability 5: SQL injection possible
    conn.execute('DELETE FROM users WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    return redirect('/admin/users')
#adding a doctor
@app.route('/admin/add_doctor', methods=['GET', 'POST'])
def add_doctor():
    if session.get('role') != 'admin':
        return "Unauthorized access", 403
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            return "Please fill in all fields", 400

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        conn.execute(
            'INSERT INTO users (username, password, role) VALUES (?, ?, ?)', 
            (username, hashed_password, 'doctor'))
        conn.commit()
        conn.close()
        print("Doctor added successfully")
        return redirect('/admin/users')
    return render_template('add_doctor.html')
#appointments page
@app.route('/appointments')
def view_appointments():
    if not session.get('username'):
        return redirect('/')
    conn = get_db_connection()
    appointments = conn.execute(
        'SELECT * FROM appointments WHERE patient_name = ?', 
        (session.get('username'),)
    ).fetchall()
    #get doctors
    doctors = conn.execute('SELECT username FROM users WHERE role = ?', ('doctor',)
    ).fetchall()

    #get availabiliy
    availability = conn.execute(
        "SELECT * FROM availability"
        ).fetchall()
    conn.close()
    return render_template('appointments.html', 
    appointments=appointments,
    doctors=doctors,
    availability=availability
    )

@app.route('/create_appointment', methods=['POST'])
def create_appointment():
    if session.get('role') != 'patient':
        return "Unauthorized access", 403
    slot = request.form.get('appointment_slot')

    if not slot:
        return "Please select an available slot", 400
    try:
        doctor_name, date_time = slot.split("|")
        appointment_date = date_time.strip()
    except ValueError:
        return "Invalid slot format", 400

    conn = get_db_connection()
    #no duplicate appointment
    existing = conn.execute(
        "SELECT * FROM appointments WHERE doctor_name = ? AND appointment_date = ?",
        (doctor_name, appointment_date)
    ).fetchone()
    
    if existing:
        conn.close()
        return "You already have an appointment with this doctor at this time", 400
    #ensuring slot exists in availability table
    valid_slot = conn.execute(
        "SELECT * FROM availability WHERE doctor_name = ? AND available_date || ' ' || available_time = ?",
        (doctor_name, appointment_date)
    ).fetchone()
    
    if not valid_slot:
        conn.close()
        return "Invalid time slot", 400
    #insert appointment
    conn.execute(
        "INSERT INTO appointments (patient_name, doctor_name, appointment_date) VALUES (?, ?, ?)",
        (session['username'], doctor_name, appointment_date)
    )
    #deleting slot
    conn.execute(
        "DELETE FROM availability WHERE id = ?",
        (valid_slot['id'],)
    )
    conn.commit()
    conn.close()

    return redirect('/appointments')    

    doctor_name = request.form.get('doctor_name')
    appointment_date = request.form.get('appointment_date')

    if not doctor_name or not appointment_date:
        return "Please fill in all fields", 400

    conn = get_db_connection()
    conn.execute('INSERT INTO appointments (patient_name, doctor_name, appointment_date) VALUES (?, ?, ?)',
                 (session['username'],doctor_name, appointment_date)
                 )
    conn.commit()
    conn.close()
    return redirect('/appointments')

    #deleting appointments
@app.route('/delete_appointment/<int:id>', methods=['POST'])
def delete_appointment(id):
    if not session.get('username'):
        return "Unauthorized access", 403
    conn = get_db_connection()
    appointment = conn.execute(
        'SELECT * FROM appointments WHERE id = ?', 
        (id,)
        ).fetchone()
    if not appointment or appointment['patient_name'] != session.get('username'):
        return "Unauthorized access", 403
    conn.execute('DELETE FROM appointments WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    return redirect('/appointments')

#editing appointments
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
@app.route('/doctor/patients')
def view_patients():
    if session.get('role') != 'doctor':
        return "Unauthorized access", 403
    conn = get_db_connection()
    search_query = request.args.get('search', '')
    if search_query:
        patients = conn.execute('SELECT DISTINCT patient_name FROM appointments WHERE doctor_name = ? AND patient_name LIKE ?',
                                (session.get('username'), f'%{search_query}%')).fetchall()
    else:
        patients = conn.execute('SELECT DISTINCT patient_name FROM appointments WHERE doctor_name = ?', (session.get('username'),)).fetchall()
    conn.close()
    return render_template('view_patients.html', patients=patients)

@app.route('/doctor/patient/<username>')
def view_patient_records(username):
    if session.get('role') != 'doctor':
        return "Unauthorized access", 403
    conn = get_db_connection()
    messages = conn.execute('SELECT * FROM messages WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)',
                            (session['username'], username, username, session['username'])
                            ).fetchall()
    
    appointments = conn.execute('SELECT * FROM appointments WHERE patient_name = ? AND doctor_name = ?', 
                                (username, session['username'])).fetchall()
                                
    prescriptions = conn.execute('SELECT * FROM prescriptions WHERE patient = ?', 
                                 (username,)).fetchall()
                                 
    conn.close()
    return render_template('patient_details.html', messages=messages, patient_name=username, appointments=appointments, prescriptions=prescriptions)

@app.route('/send_message', methods=['POST'])
def send_message():
    if not session.get('username'):
        return "Unauthorized access", 403

    sender = session['username']
    receiver = request.form.get('receiver')

    # sanitize input
    message = html.escape(request.form.get('message'))

    if not message:
        return "Empty message", 400
    conn = get_db_connection()
    conn.execute('INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)',
                 (sender, receiver, message))
    conn.commit()
    conn.close()
    return redirect(request.referrer)

@app.route('/add_prescription', methods=['POST'])
def add_prescription():
    if session.get('role') != 'doctor':
        return "Unauthorized access", 403
    doctor = session('username')
    patient = request.form.get('patient')
    medication = html.escape(request.form.get('medication'))
    notes = html.escape(request.form.get('notes'))

    conn = get_db_connection()
    conn.execute(
        'INSERT INTO prescriptions (doctor, patient, medication, notes) VALUES (?, ?, ?, ?)',
                 (doctor, patient, medication, notes))
    conn.commit()
    conn.close()
    return redirect(request.referrer)

@app.route('/patient/records')
def patient_records():
    if session.get('role') != 'patient':
        return "Unauthorized access", 403
    conn = get_db_connection()
    username = session.get('username')
    appointments = conn.execute('SELECT * FROM appointments WHERE patient_name = ?', (username,)).fetchall()
    conn.close()
    return render_template('patient_records.html', appointments=appointments)

@app.route('/patient/prescriptions')
def patient_prescriptions():
    if session.get('role') != 'patient':
        return "Unauthorized access", 403
    conn = get_db_connection()
    username = session.get('username')
    prescriptions = conn.execute('SELECT * FROM prescriptions WHERE patient = ?', (username,)).fetchall()
    conn.close()
    return render_template('patient_prescriptions.html', prescriptions=prescriptions)

@app.route('/patient/messages')
def patient_messages():
    if session.get('role') != 'patient':
        return "Unauthorized access", 403
    conn = get_db_connection()
    username = session.get('username')
    messages = conn.execute('SELECT * FROM messages WHERE sender = ? OR receiver = ?',
                            (username, username)).fetchall()
    doctors = conn.execute('SELECT username FROM users WHERE role = "doctor"').fetchall()
    conn.close()
    return render_template('patient_messages.html', messages=messages, doctors=doctors)
@app.route('/doctor/inbox')
def doctor_inbox():
    if session.get('role') != 'doctor':
        return "Unauthorized access", 403
    conn = get_db_connection()
    username = session.get('username')
    raw_messages = conn.execute('''
        SELECT * FROM messages 
        WHERE sender = ? OR receiver = ?
    ''', (username, username)).fetchall()
    conn.close()
    
    conversations = {}
    for msg in raw_messages:
        other_party = msg['sender'] if msg['receiver'] == username else msg['receiver']
        if other_party not in conversations:
            conversations[other_party] = []
        conversations[other_party].append(msg)
        
    return render_template('doctor_inbox.html', conversations=conversations)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')
@app.route('/doctor/add_availability', methods=['POST'])
def add_availability():

    if session.get('role') != 'doctor':
        return "Unauthorized", 403

    doctor = session.get('username')
    date = request.form.get('date')
    time = request.form.get('time')

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO availability (doctor_name, available_date, available_time) VALUES (?, ?, ?)",
        (doctor, date, time)
    )
    conn.commit()
    conn.close()

    return redirect('/doctor')
@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.get('_csrf_token')
        form_token = request.form.get('_csrf_token')

        if not token or token != form_token:
            return "CSRF attack detected", 403

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token
@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

if __name__ == '__main__':
        app.run(debug=False)