print("app starting")
import os
import datetime
from flask import Flask, render_template, request, redirect, session, url_for, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, template_folder='templates')

# ── V3 FIX: Load secret key from environment variable (never hardcoded) ─────────
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(32))

# ── V11 FIX: Session expires after 30 minutes of inactivity ─────────────────────
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=30)
app.config['SESSION_COOKIE_HTTPONLY'] = True   # prevent JS access to session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF mitigation for session cookie

# ── V4 FIX: Rate-limit login endpoint to prevent brute-force attacks ─────────────
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],          # only apply limits where we decorate
    storage_uri="memory://",
)

# ── V12 FIX: Security headers via Flask-Talisman ─────────────────────────────────
# force_https=False keeps dev working; set to True behind a TLS proxy in production
csp = {
    'default-src': ["'self'"],
    'script-src':  ["'self'", 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com'],
    'style-src':   ["'self'", 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com', 'fonts.googleapis.com', "'unsafe-inline'"],
    'font-src':    ["'self'", 'fonts.gstatic.com'],
    'img-src':     ["'self'", 'data:'],
}
Talisman(
    app,
    force_https=False,
    content_security_policy=csp,
    x_content_type_options=True,
    x_xss_protection=True,
    referrer_policy='strict-origin-when-cross-origin',
)

# ── Helper: connection to the database ──────────────────────────────────────────
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# ── Helper: require a logged-in user (any role) ─────────────────────────────────
def login_required():
    """Returns a redirect response if no user is in session, else None."""
    if not session.get('username'):
        return redirect(url_for('login'))
    return None

# ── Landing / login page ─────────────────────────────────────────────────────────
@app.route('/')
def login():
    return render_template('login.html')

# ── Signup ───────────────────────────────────────────────────────────────────────
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        # ── V6 FIX: Input validation ─────────────────────────────────────────────
        if not username or not password:
            return render_template('signup.html', error="Username and password are required.")
        if len(username) > 80 or len(password) > 128:
            return render_template('signup.html', error="Input too long.")

        # ── V1 FIX: Hash password before storing ────────────────────────────────
        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        existing = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if existing:
            conn.close()
            return render_template('signup.html', error="Username already taken.")
        conn.execute(
            'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
            (username, hashed_password, "patient")
        )
        conn.commit()
        conn.close()
        return redirect(url_for('login'))
    return render_template('signup.html')

# ── Login ────────────────────────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")   # ── V4 FIX: Rate limiting on login
def login_post():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        # ── V6 FIX: Input validation ─────────────────────────────────────────────
        if not username or not password:
            return render_template('login.html', error="Please enter username and password.")

        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?',
            (username,)
        ).fetchone()
        conn.close()

        # ── V1 FIX: Verify hashed password ──────────────────────────────────────
        if user and check_password_hash(user['password'], password):
            session.permanent = True          # ── V11 FIX: start timed session
            session['username'] = user['username']
            session['role'] = user['role']

            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user['role'] == 'doctor':
                return redirect(url_for('doctor_dashboard'))
            elif user['role'] == 'patient':
                return redirect(url_for('patient_dashboard'))

        return render_template('login.html', error="Login unsuccessful. Please check your credentials.")

    return render_template('login.html')

# ── Patient dashboard ─────────────────────────────────────────────────────────────
@app.route('/patient')
def patient_dashboard():
    # ── V7 FIX: Require authenticated patient ────────────────────────────────────
    guard = login_required()
    if guard:
        return guard
    if session.get('role') != 'patient':
        abort(403)
    return render_template('patient_dashboard.html')

# ── Doctor dashboard ──────────────────────────────────────────────────────────────
@app.route('/doctor')
def doctor_dashboard():
    # ── V7 FIX: Require authenticated doctor ─────────────────────────────────────
    guard = login_required()
    if guard:
        return guard
    if session.get('role') != 'doctor':
        abort(403)
    conn = get_db_connection()
    appointments = conn.execute(
        'SELECT * FROM appointments WHERE doctor_name = ?',
        (session.get('username'),)
    ).fetchall()
    conn.close()
    return render_template('doctor_dashboard.html', appointments=appointments)

# ── Approve appointment ───────────────────────────────────────────────────────────
@app.route('/approve/<int:id>')
def approve_appointment(id):
    guard = login_required()
    if guard:
        return guard
    if session.get('role') != 'doctor':
        abort(403)
    conn = get_db_connection()
    # ── V8 FIX: Ownership check — only the assigned doctor can approve ───────────
    conn.execute(
        'UPDATE appointments SET status = ? WHERE id = ? AND doctor_name = ?',
        ('approved', id, session.get('username'))
    )
    conn.commit()
    conn.close()
    return redirect(url_for('doctor_dashboard'))

# ── Reject appointment ────────────────────────────────────────────────────────────
@app.route('/reject/<int:id>')
def reject_appointment(id):
    guard = login_required()
    if guard:
        return guard
    if session.get('role') != 'doctor':
        abort(403)
    conn = get_db_connection()
    # ── V8 FIX: Ownership check ──────────────────────────────────────────────────
    conn.execute(
        'UPDATE appointments SET status = ? WHERE id = ? AND doctor_name = ?',
        ('rejected', id, session.get('username'))
    )
    conn.commit()
    conn.close()
    return redirect(url_for('doctor_dashboard'))

# ── Admin dashboard ───────────────────────────────────────────────────────────────
@app.route('/admin')
def admin_dashboard():
    guard = login_required()
    if guard:
        return guard
    if session.get('role') != 'admin':
        abort(403)
    return render_template('admin_dashboard.html')

# ── View all users (admin) ────────────────────────────────────────────────────────
@app.route('/admin/users')
def view_users():
    guard = login_required()
    if guard:
        return guard
    if session.get('role') != 'admin':
        abort(403)
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, role FROM users').fetchall()
    conn.close()
    return render_template('view_users.html', users=users)

# ── Delete user (admin) ───────────────────────────────────────────────────────────
@app.route('/admin/delete_user/<int:id>')
def delete_user(id):
    guard = login_required()
    if guard:
        return guard
    if session.get('role') != 'admin':
        abort(403)
    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('view_users'))

# ── Add doctor (admin) ────────────────────────────────────────────────────────────
@app.route('/admin/add_doctor', methods=['GET', 'POST'])
def add_doctor():
    guard = login_required()
    if guard:
        return guard
    if session.get('role') != 'admin':
        abort(403)
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        # ── V6 FIX: Input validation ─────────────────────────────────────────────
        if not username or not password:
            return render_template('add_doctor.html', error="Username and password are required.")
        if len(username) > 80 or len(password) > 128:
            return render_template('add_doctor.html', error="Input too long.")

        # ── V1 FIX: Hash password before storing ────────────────────────────────
        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        conn.execute(
            'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
            (username, hashed_password, 'doctor')
        )
        conn.commit()
        conn.close()
        return redirect(url_for('view_users'))
    return render_template('add_doctor.html')

# ── View appointments (patient) ───────────────────────────────────────────────────
@app.route('/appointments')
def view_appointments():
    # ── V7 FIX: Require authenticated user ───────────────────────────────────────
    guard = login_required()
    if guard:
        return guard
    conn = get_db_connection()
    appointments = conn.execute(
        'SELECT * FROM appointments WHERE patient_name = ?',
        (session.get('username'),)
    ).fetchall()
    conn.close()
    return render_template('appointments.html', appointments=appointments)

# ── Create appointment ────────────────────────────────────────────────────────────
@app.route('/create_appointment', methods=['POST'])
def create_appointment():
    # ── V7 FIX: Require authenticated user ───────────────────────────────────────
    guard = login_required()
    if guard:
        return guard

    patient_name = session.get('username')
    doctor_name = request.form.get('doctor_name', '').strip()
    appointment_date = request.form.get('appointment_date', '').strip()

    # ── V6 FIX: Input validation ─────────────────────────────────────────────────
    if not doctor_name or not appointment_date:
        return redirect(url_for('view_appointments'))
    if len(doctor_name) > 80 or len(appointment_date) > 20:
        return redirect(url_for('view_appointments'))

    conn = get_db_connection()
    conn.execute(
        'INSERT INTO appointments (patient_name, doctor_name, appointment_date) VALUES (?, ?, ?)',
        (patient_name, doctor_name, appointment_date)
    )
    conn.commit()
    conn.close()
    return redirect(url_for('view_appointments'))

# ── Delete appointment ────────────────────────────────────────────────────────────
@app.route('/delete_appointment/<int:id>')
def delete_appointment(id):
    # ── V7 FIX: Require authenticated user ───────────────────────────────────────
    guard = login_required()
    if guard:
        return guard
    conn = get_db_connection()
    # ── V8 FIX: Ownership check — patients can only delete their own appointments ─
    conn.execute(
        'DELETE FROM appointments WHERE id = ? AND patient_name = ?',
        (id, session.get('username'))
    )
    conn.commit()
    conn.close()
    return redirect(url_for('view_appointments'))

# ── Edit appointment ──────────────────────────────────────────────────────────────
@app.route('/edit_appointment/<int:id>')
def edit_appointment(id):
    # ── V7 FIX: Require authenticated user ───────────────────────────────────────
    guard = login_required()
    if guard:
        return guard
    conn = get_db_connection()
    # ── V8 FIX: Ownership check ───────────────────────────────────────────────────
    appointment = conn.execute(
        'SELECT * FROM appointments WHERE id = ? AND patient_name = ?',
        (id, session.get('username'))
    ).fetchone()
    conn.close()
    if not appointment:
        abort(403)
    return render_template('edit_appointment.html', appointment=appointment)

# ── Update appointment ────────────────────────────────────────────────────────────
@app.route('/update_appointment/<int:id>', methods=['POST'])
def update_appointment(id):
    # ── V7 FIX: Require authenticated user ───────────────────────────────────────
    guard = login_required()
    if guard:
        return guard

    patient_name = session.get('username')   # ── V8 FIX: always use session username
    doctor_name = request.form.get('doctor_name', '').strip()
    appointment_date = request.form.get('appointment_date', '').strip()

    # ── V6 FIX: Input validation ─────────────────────────────────────────────────
    if not doctor_name or not appointment_date:
        return redirect(url_for('view_appointments'))

    conn = get_db_connection()
    # ── V8 FIX: Ownership check ───────────────────────────────────────────────────
    conn.execute(
        'UPDATE appointments SET patient_name = ?, doctor_name = ?, appointment_date = ? WHERE id = ? AND patient_name = ?',
        (patient_name, doctor_name, appointment_date, id, patient_name)
    )
    conn.commit()
    conn.close()
    return redirect(url_for('view_appointments'))

# ── View patients (doctor) ────────────────────────────────────────────────────────
@app.route('/doctor/patients')
def view_patients():
    guard = login_required()
    if guard:
        return guard
    if session.get('role') != 'doctor':
        abort(403)
    conn = get_db_connection()
    search_query = request.args.get('search', '').strip()
    if search_query:
        patients = conn.execute(
            'SELECT DISTINCT patient_name FROM appointments WHERE doctor_name = ? AND patient_name LIKE ?',
            (session.get('username'), f'%{search_query}%')
        ).fetchall()
    else:
        patients = conn.execute(
            'SELECT DISTINCT patient_name FROM appointments WHERE doctor_name = ?',
            (session.get('username'),)
        ).fetchall()
    conn.close()
    return render_template('view_patients.html', patients=patients)

# ── View patient records (doctor) ─────────────────────────────────────────────────
@app.route('/doctor/patient/<username>')
def view_patient_records(username):
    guard = login_required()
    if guard:
        return guard
    if session.get('role') != 'doctor':
        abort(403)
    conn = get_db_connection()
    messages = conn.execute(
        'SELECT * FROM messages WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)',
        (session['username'], username, username, session['username'])
    ).fetchall()
    appointments = conn.execute(
        'SELECT * FROM appointments WHERE patient_name = ? AND doctor_name = ?',
        (username, session['username'])
    ).fetchall()
    prescriptions = conn.execute(
        'SELECT * FROM prescriptions WHERE patient = ?',
        (username,)
    ).fetchall()
    conn.close()
    return render_template(
        'patient_details.html',
        messages=messages,
        patient_name=username,
        appointments=appointments,
        prescriptions=prescriptions
    )

# ── Send message ──────────────────────────────────────────────────────────────────
@app.route('/send_message', methods=['POST'])
def send_message():
    # ── V7 FIX: Require authenticated user ───────────────────────────────────────
    guard = login_required()
    if guard:
        return guard

    sender = session.get('username')
    receiver = request.form.get('receiver', '').strip()
    message = request.form.get('message', '').strip()

    # ── V6 FIX: Input validation ─────────────────────────────────────────────────
    if not receiver or not message or len(message) > 2000:
        return redirect(url_for('patient_messages'))

    conn = get_db_connection()
    conn.execute(
        'INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)',
        (sender, receiver, message)
    )
    conn.commit()
    conn.close()

    # ── V9 FIX: Replace open redirect with explicit safe redirects ────────────────
    role = session.get('role')
    if role == 'doctor':
        return redirect(url_for('doctor_inbox'))
    return redirect(url_for('patient_messages'))

# ── Add prescription (doctor) ─────────────────────────────────────────────────────
@app.route('/add_prescription', methods=['POST'])
def add_prescription():
    guard = login_required()
    if guard:
        return guard
    if session.get('role') != 'doctor':
        abort(403)

    doctor = session.get('username')
    patient = request.form.get('patient', '').strip()
    medication = request.form.get('medication', '').strip()
    notes = request.form.get('notes', '').strip()

    # ── V6 FIX: Input validation ─────────────────────────────────────────────────
    if not patient or not medication:
        return redirect(url_for('doctor_dashboard'))

    conn = get_db_connection()
    conn.execute(
        'INSERT INTO prescriptions (doctor, patient, medication, notes) VALUES (?, ?, ?, ?)',
        (doctor, patient, medication, notes)
    )
    conn.commit()
    conn.close()

    # ── V9 FIX: Replace open redirect ────────────────────────────────────────────
    return redirect(url_for('view_patient_records', username=patient))

# ── Patient records ───────────────────────────────────────────────────────────────
@app.route('/patient/records')
def patient_records():
    guard = login_required()
    if guard:
        return guard
    if session.get('role') != 'patient':
        abort(403)
    conn = get_db_connection()
    username = session.get('username')
    appointments = conn.execute(
        'SELECT * FROM appointments WHERE patient_name = ?',
        (username,)
    ).fetchall()
    conn.close()
    return render_template('patient_records.html', appointments=appointments)

# ── Patient prescriptions ─────────────────────────────────────────────────────────
@app.route('/patient/prescriptions')
def patient_prescriptions():
    guard = login_required()
    if guard:
        return guard
    if session.get('role') != 'patient':
        abort(403)
    conn = get_db_connection()
    username = session.get('username')
    prescriptions = conn.execute(
        'SELECT * FROM prescriptions WHERE patient = ?',
        (username,)
    ).fetchall()
    conn.close()
    return render_template('patient_prescriptions.html', prescriptions=prescriptions)

# ── Patient messages ──────────────────────────────────────────────────────────────
@app.route('/patient/messages')
def patient_messages():
    guard = login_required()
    if guard:
        return guard
    if session.get('role') != 'patient':
        abort(403)
    conn = get_db_connection()
    username = session.get('username')
    messages = conn.execute(
        'SELECT * FROM messages WHERE sender = ? OR receiver = ?',
        (username, username)
    ).fetchall()
    doctors = conn.execute('SELECT username FROM users WHERE role = "doctor"').fetchall()
    conn.close()
    return render_template('patient_messages.html', messages=messages, doctors=doctors)

# ── Doctor inbox ──────────────────────────────────────────────────────────────────
@app.route('/doctor/inbox')
def doctor_inbox():
    guard = login_required()
    if guard:
        return guard
    if session.get('role') != 'doctor':
        abort(403)
    conn = get_db_connection()
    username = session.get('username')
    raw_messages = conn.execute(
        'SELECT * FROM messages WHERE sender = ? OR receiver = ?',
        (username, username)
    ).fetchall()
    conn.close()

    conversations = {}
    for msg in raw_messages:
        other_party = msg['sender'] if msg['receiver'] == username else msg['receiver']
        if other_party not in conversations:
            conversations[other_party] = []
        conversations[other_party].append(msg)

    return render_template('doctor_inbox.html', conversations=conversations)

# ── Logout ────────────────────────────────────────────────────────────────────────
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    # ── V2 FIX: debug controlled by env variable — defaults to False in production
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode)