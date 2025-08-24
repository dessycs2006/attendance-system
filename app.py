from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3
from datetime import datetime, timedelta
import hashlib
import secrets
import io
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

app = Flask(__name__)
app.secret_key = 'attendance-system-secret-key-2023'

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Password hashing functions
def hash_password(password):
    """Hash a password with a random salt using SHA-256"""
    salt = secrets.token_hex(16)
    return f"{salt}${hashlib.sha256((salt + password).encode()).hexdigest()}"

def verify_password(stored_password, provided_password):
    """Verify a password against its hash"""
    if not stored_password or '$' not in stored_password:
        return False
    salt, hash_value = stored_password.split('$')
    new_hash = hashlib.sha256((salt + provided_password).encode()).hexdigest()
    return hash_value == new_hash

# Database setup
def init_db():
    """Initialize the database with required tables"""
    conn = sqlite3.connect('attendance.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  email TEXT,
                  role TEXT NOT NULL DEFAULT 'user',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Students table
    c.execute('''CREATE TABLE IF NOT EXISTS students
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  student_id TEXT UNIQUE NOT NULL,
                  name TEXT NOT NULL,
                  email TEXT)''')
    
    # Attendance table
    c.execute('''CREATE TABLE IF NOT EXISTS attendance
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  student_id TEXT NOT NULL,
                  date TEXT NOT NULL,
                  status TEXT NOT NULL,
                  FOREIGN KEY (student_id) REFERENCES students (student_id))''')
    
    # Create default admin user if not exists
    c.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    if c.fetchone()[0] == 0:
        hashed_password = hash_password('admin123')
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                  ('admin', hashed_password, 'admin'))
    
    conn.commit()
    conn.close()

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    """Load user from database for Flask-Login"""
    conn = sqlite3.connect('attendance.db')
    c = conn.cursor()
    c.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    
    if user:
        return User(user[0], user[1], user[2])
    return None

# Database helper function
def get_db_connection():
    """Get a connection to the SQLite database"""
    conn = sqlite3.connect('attendance.db')
    conn.row_factory = sqlite3.Row
    return conn

# Admin required decorator
def admin_required(f):
    """Decorator to require admin role for a route"""
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin':
            flash('Admin access required!', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# Routes
@app.route('/')
@login_required
def index():
    """Home page - show attendance summary and recent records"""
    conn = get_db_connection()
    
    # Get attendance summary
    summary = conn.execute('''
        SELECT s.student_id, s.name, 
               COUNT(a.id) as total,
               SUM(CASE WHEN a.status = 'Present' THEN 1 ELSE 0 END) as present
        FROM students s
        LEFT JOIN attendance a ON s.student_id = a.student_id
        GROUP BY s.student_id, s.name
    ''').fetchall()
    
    # Get recent attendance
    recent_attendance = conn.execute('''
        SELECT a.date, s.student_id, s.name, a.status
        FROM attendance a
        JOIN students s ON a.student_id = s.student_id
        ORDER BY a.date DESC, s.name
        LIMIT 10
    ''').fetchall()
    
    conn.close()
    
    return render_template('index.html', summary=summary, recent_attendance=recent_attendance)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page - authenticate users"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and verify_password(user['password'], password):
            user_obj = User(user['id'], user['username'], user['role'])
            login_user(user_obj)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Logout user"""
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile page - change password"""
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('New passwords do not match!', 'error')
            return redirect(url_for('profile'))
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (current_user.id,)).fetchone()
        
        if user and verify_password(user['password'], current_password):
            hashed_password = hash_password(new_password)
            conn.execute('UPDATE users SET password = ? WHERE id = ?', 
                        (hashed_password, current_user.id))
            conn.commit()
            conn.close()
            flash('Password changed successfully!', 'success')
        else:
            conn.close()
            flash('Current password is incorrect!', 'error')
        
        return redirect(url_for('profile'))
    
    return render_template('profile.html')

@app.route('/record', methods=['GET', 'POST'])
@login_required
def record_attendance():
    """Record attendance page"""
    conn = get_db_connection()
    
    if request.method == 'POST':
        student_id = request.form['student_id']
        name = request.form['name']
        date = request.form['date'] or datetime.now().strftime("%Y-%m-%d")
        status = request.form['status']
        
        # Check if student exists, if not create
        student = conn.execute('SELECT * FROM students WHERE student_id = ?', (student_id,)).fetchone()
        if not student:
            conn.execute('INSERT INTO students (student_id, name) VALUES (?, ?)', (student_id, name))
        
        # Check if attendance already recorded for this date
        existing = conn.execute('SELECT * FROM attendance WHERE student_id = ? AND date = ?', 
                               (student_id, date)).fetchone()
        
        if existing:
            conn.execute('UPDATE attendance SET status = ? WHERE student_id = ? AND date = ?', 
                        (status, student_id, date))
            flash('Attendance updated successfully!', 'success')
        else:
            conn.execute('INSERT INTO attendance (student_id, date, status) VALUES (?, ?, ?)', 
                        (student_id, date, status))
            flash('Attendance recorded successfully!', 'success')
        
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    
    # Get all students for quick selection
    students = conn.execute('SELECT * FROM students ORDER BY name').fetchall()
    conn.close()
    
    return render_template('record.html', students=students)

@app.route('/students')
@login_required
def manage_students():
    """Manage students page"""
    conn = get_db_connection()
    students = conn.execute('SELECT * FROM students ORDER BY name').fetchall()
    conn.close()
    
    return render_template('students.html', students=students)

@app.route('/add_student', methods=['POST'])
@login_required
def add_student():
    """Add a new student"""
    student_id = request.form['student_id']
    name = request.form['name']
    email = request.form.get('email', '')
    
    conn = get_db_connection()
    try:
        conn.execute('INSERT INTO students (student_id, name, email) VALUES (?, ?, ?)', 
                    (student_id, name, email))
        conn.commit()
        flash('Student added successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('Student ID already exists!', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('manage_students'))

@app.route('/users')
@login_required
@admin_required
def manage_users():
    """Manage users page (admin only)"""
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, email, role, created_at FROM users ORDER BY username').fetchall()
    conn.close()
    
    return render_template('users.html', users=users)

@app.route('/add_user', methods=['POST'])
@login_required
@admin_required
def add_user():
    """Add a new user (admin only)"""
    username = request.form['username']
    password = request.form['password']
    email = request.form.get('email', '')
    role = request.form.get('role', 'user')
    
    if not username or not password:
        flash('Username and password are required!', 'error')
        return redirect(url_for('manage_users'))
    
    conn = get_db_connection()
    try:
        hashed_password = hash_password(password)
        conn.execute('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)', 
                    (username, hashed_password, email, role))
        conn.commit()
        flash('User added successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('Username already exists!', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('manage_users'))

@app.route('/delete_user/<int:user_id>')
@login_required
@admin_required
def delete_user(user_id):
    """Delete a user (admin only)"""
    if user_id == current_user.id:
        flash('You cannot delete your own account!', 'error')
        return redirect(url_for('manage_users'))
    
    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    flash('User deleted successfully!', 'success')
    return redirect(url_for('manage_users'))

@app.route('/reports')
@login_required
def reports():
    """Generate attendance reports"""
    student_id = request.args.get('student_id')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date') or datetime.now().strftime("%Y-%m-%d")
    
    if not start_date:
        start_date = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
    
    conn = get_db_connection()
    
    # Get all students for dropdown
    students = conn.execute('SELECT * FROM students ORDER BY name').fetchall()
    
    # Build query based on filters
    query = '''
        SELECT a.date, s.student_id, s.name, a.status
        FROM attendance a
        JOIN students s ON a.student_id = s.student_id
        WHERE a.date BETWEEN ? AND ?
    '''
    params = [start_date, end_date]
    
    if student_id and student_id != 'all':
        query += ' AND s.student_id = ?'
        params.append(student_id)
    
    query += ' ORDER BY a.date DESC, s.name'
    
    records = conn.execute(query, params).fetchall()
    
    # Get summary statistics
    summary_query = '''
        SELECT s.student_id, s.name, 
               COUNT(a.id) as total,
               SUM(CASE WHEN a.status = 'Present' THEN 1 ELSE 0 END) as present,
               ROUND(SUM(CASE WHEN a.status = 'Present' THEN 1 ELSE 0 END) * 100.0 / COUNT(a.id), 2) as percentage
        FROM students s
        LEFT JOIN attendance a ON s.student_id = a.student_id AND a.date BETWEEN ? AND ?
        GROUP BY s.student_id, s.name
    '''
    summary = conn.execute(summary_query, [start_date, end_date]).fetchall()
    
    conn.close()
    
    return render_template('reports.html', records=records, summary=summary, 
                          students=students, student_id=student_id or 'all',
                          start_date=start_date, end_date=end_date)

@app.route('/export/pdf')
@login_required
def export_pdf():
    """Export attendance report as PDF"""
    student_id = request.args.get('student_id', 'all')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date') or datetime.now().strftime("%Y-%m-%d")
    
    if not start_date:
        start_date = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
    
    conn = get_db_connection()
    
    # Build query based on filters
    query = '''
        SELECT a.date, s.student_id, s.name, a.status
        FROM attendance a
        JOIN students s ON a.student_id = s.student_id
        WHERE a.date BETWEEN ? AND ?
    '''
    params = [start_date, end_date]
    
    if student_id != 'all':
        query += ' AND s.student_id = ?'
        params.append(student_id)
    
    query += ' ORDER BY a.date DESC, s.name'
    
    records = conn.execute(query, params).fetchall()
    
    # Get summary statistics
    summary_query = '''
        SELECT s.student_id, s.name, 
               COUNT(a.id) as total,
               SUM(CASE WHEN a.status = 'Present' THEN 1 ELSE 0 END) as present,
               ROUND(SUM(CASE WHEN a.status = 'Present' THEN 1 ELSE 0 END) * 100.0 / COUNT(a.id), 2) as percentage
        FROM students s
        LEFT JOIN attendance a ON s.student_id = a.student_id AND a.date BETWEEN ? AND ?
        GROUP BY s.student_id, s.name
    '''
    summary = conn.execute(summary_query, [start_date, end_date]).fetchall()
    
    conn.close()
    
    # Create PDF
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    
    styles = getSampleStyleSheet()
    title = Paragraph("Attendance Report", styles['Title'])
    elements.append(title)
    
    # Add date range
    date_range = Paragraph(f"Date Range: {start_date} to {end_date}", styles['Normal'])
    elements.append(date_range)
    
    if student_id != 'all':
        student_info = Paragraph(f"Student: {student_id}", styles['Normal'])
        elements.append(student_info)
    
    # Add summary table
    summary_data = [['Student ID', 'Name', 'Present', 'Total', 'Percentage']]
    for row in summary:
        summary_data.append([row['student_id'], row['name'], str(row['present']), 
                           str(row['total']), f"{row['percentage']}%"])
    
    summary_table = Table(summary_data)
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('FONTSIZE', (0, 1), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(summary_table)
    
    # Add detailed records
    if records:
        details_title = Paragraph("<br/><br/>Detailed Records:", styles['Heading2'])
        elements.append(details_title)
        
        details_data = [['Date', 'Student ID', 'Name', 'Status']]
        for record in records:
            details_data.append([record['date'], record['student_id'], 
                              record['name'], record['status']])
        
        details_table = Table(details_data)
        details_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(details_table)
    
    doc.build(elements)
    buffer.seek(0)
    
    return send_file(buffer, as_attachment=True, download_name='attendance_report.pdf', mimetype='application/pdf')

@app.route('/export/csv')
@login_required
def export_csv():
    """Export attendance report as CSV"""
    import csv
    
    student_id = request.args.get('student_id', 'all')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date') or datetime.now().strftime("%Y-%m-%d")
    
    if not start_date:
        start_date = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
    
    conn = get_db_connection()
    
    # Build query based on filters
    query = '''
        SELECT a.date, s.student_id, s.name, a.status
        FROM attendance a
        JOIN students s ON a.student_id = s.student_id
        WHERE a.date BETWEEN ? AND ?
    '''
    params = [start_date, end_date]
    
    if student_id != 'all':
        query += ' AND s.student_id = ?'
        params.append(student_id)
    
    query += ' ORDER BY a.date DESC, s.name'
    
    records = conn.execute(query, params).fetchall()
    conn.close()
    
    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Date', 'Student ID', 'Name', 'Status'])
    
    for record in records:
        writer.writerow([record['date'], record['student_id'], record['name'], record['status']])
    
    output.seek(0)
    
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        as_attachment=True,
        download_name='attendance_report.csv',
        mimetype='text/csv'
    )

# Initialize the database when the app starts
with app.app_context():
    init_db()

if __name__ == '__main__':
    app.run(debug=True)