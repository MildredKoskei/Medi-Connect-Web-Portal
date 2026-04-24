🔷 MediConnect Web Portal
📌 Overview

MediConnect is a secure healthcare web application built using Flask and SQLite. It supports patient appointment booking, doctor management, and admin control with strong security features.

🚀 Features
User Registration & Login
Appointment Booking System
Doctor Dashboard
Admin User Management

🔐 Security Improvements
Password hashing (PBKDF2-SHA256)
CSRF protection
Role-Based Access Control (RBAC)
Session timeout & secure cookies
Input validation & SQL injection prevention

🏗️ Project Structure
/app.py           → Main application logic  
/db.py            → Database operations  
/templates/       → HTML templates  
/static/          → CSS & assets  

⚙️ Setup Instructions
git clone https://github.com/MildredKoskei/Medi-Connect-Web-Portal
cd Medi-Connect-Web-Portal
pip install -r requirements.txt
python app.py

▶️ Usage
Register as a user
Login
Book appointments (patient)
Manage appointments (doctor/admin)

🧪 Testing
SAST using Bandit
SQL Injection testing
Brute-force attack simulation
RBAC validation

📊 Security Testing Results
SQL Injection: Prevented ✅
Brute Force: Mitigated ✅
Privilege Escalation: Blocked ✅

📌 Contributions
Developed vulnerable baseline
Implemented security controls
Performed testing and validation

📚 References
OWASP Top 10
Flask Documentation
Bandit
