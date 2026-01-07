"""
PowerSchool API Gateway - OAuth Platform for Developers
Provides secure OAuth 2.0 access to PowerSchool student data for third-party applications.
"""

from flask import Flask, request, jsonify, redirect, render_template, session, url_for
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
from functools import wraps
import requests
from bs4 import BeautifulSoup
import re
import json
import uuid
import hashlib
import secrets
import time
import os
import base64
from datetime import datetime, timedelta
from urllib.parse import urlencode, parse_qs, urlparse

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Encryption key for credentials - MUST be set in production
# Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    # For development only - in production this should fail
    ENCRYPTION_KEY = base64.urlsafe_b64encode(hashlib.sha256(app.secret_key.encode()).digest())
else:
    ENCRYPTION_KEY = ENCRYPTION_KEY.encode()
cipher = Fernet(ENCRYPTION_KEY)

def encrypt_credential(plaintext):
    """Encrypt a credential using Fernet symmetric encryption"""
    return cipher.encrypt(plaintext.encode()).decode()

def decrypt_credential(ciphertext):
    """Decrypt a credential"""
    return cipher.decrypt(ciphertext.encode()).decode()

# Database configuration
database_url = os.environ.get('DATABASE_URL')
# Fix postgres:// to postgresql:// for SQLAlchemy compatibility
if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
# Fallback to SQLite if no DATABASE_URL is set
if not database_url:
    database_url = 'sqlite:///api_manager.db'
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}
db = SQLAlchemy(app)

# ============================================================================
# DATABASE MODELS
# ============================================================================

class Developer(db.Model):
    __tablename__ = 'developers'
    id = db.Column(db.String(64), primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(64), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    is_super_admin = db.Column(db.Boolean, default=False)
    applications = db.relationship('Application', backref='developer', lazy=True)

class InviteCode(db.Model):
    __tablename__ = 'invite_codes'
    code = db.Column(db.String(32), primary_key=True)
    created_by = db.Column(db.String(64), db.ForeignKey('developers.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used_by = db.Column(db.String(64), db.ForeignKey('developers.id'), nullable=True)
    used_at = db.Column(db.DateTime, nullable=True)
    max_uses = db.Column(db.Integer, default=1)
    use_count = db.Column(db.Integer, default=0)

class Application(db.Model):
    __tablename__ = 'applications'
    id = db.Column(db.String(64), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    client_secret = db.Column(db.String(64), nullable=False)
    redirect_uris = db.Column(db.JSON, nullable=False)
    scopes = db.Column(db.JSON, nullable=False)
    developer_id = db.Column(db.String(64), db.ForeignKey('developers.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    app_type = db.Column(db.String(20), default='student')  # 'student' or 'teacher'
    verified = db.Column(db.Boolean, default=False)  # Show verified badge on OAuth screen
    hide_permissions = db.Column(db.Boolean, default=False)  # Hide permissions list on OAuth screen

class StudentSession(db.Model):
    __tablename__ = 'student_sessions'
    token = db.Column(db.String(64), primary_key=True)
    cookies = db.Column(db.JSON, nullable=False)
    district_url = db.Column(db.String(512), nullable=False)
    student_info = db.Column(db.JSON, nullable=False)
    home_html = db.Column(db.Text)
    expires_at = db.Column(db.Float, nullable=False)
    # Encrypted credentials for auto-refresh
    encrypted_username = db.Column(db.Text)
    encrypted_password = db.Column(db.Text)

class AuthCode(db.Model):
    __tablename__ = 'auth_codes'
    code = db.Column(db.String(64), primary_key=True)
    app_id = db.Column(db.String(64), nullable=False)
    session_token = db.Column(db.String(64), nullable=False)
    scopes = db.Column(db.JSON, nullable=False)
    redirect_uri = db.Column(db.String(512), nullable=False)
    expires_at = db.Column(db.Float, nullable=False)

class AccessToken(db.Model):
    __tablename__ = 'access_tokens'
    token = db.Column(db.String(64), primary_key=True)
    app_id = db.Column(db.String(64), nullable=False)
    session_token = db.Column(db.String(64), nullable=False)
    scopes = db.Column(db.JSON, nullable=False)
    expires_at = db.Column(db.Float, nullable=False)

class RefreshToken(db.Model):
    __tablename__ = 'refresh_tokens'
    token = db.Column(db.String(64), primary_key=True)
    app_id = db.Column(db.String(64), nullable=False)
    session_token = db.Column(db.String(64), nullable=False)
    scopes = db.Column(db.JSON, nullable=False)

class TeacherSession(db.Model):
    __tablename__ = 'teacher_sessions'
    token = db.Column(db.String(64), primary_key=True)
    cookies = db.Column(db.JSON, nullable=False)
    district_url = db.Column(db.String(512), nullable=False)
    teacher_info = db.Column(db.JSON, nullable=False)
    sections = db.Column(db.JSON)  # Teacher's sections/classes
    categories = db.Column(db.JSON)  # Assignment categories
    expires_at = db.Column(db.Float, nullable=False)
    encrypted_username = db.Column(db.Text)
    encrypted_password = db.Column(db.Text)

class TeacherAccessToken(db.Model):
    __tablename__ = 'teacher_access_tokens'
    token = db.Column(db.String(64), primary_key=True)
    app_id = db.Column(db.String(64), nullable=False)
    session_token = db.Column(db.String(64), nullable=False)
    scopes = db.Column(db.JSON, nullable=False)
    expires_at = db.Column(db.Float, nullable=False)

class TeacherRefreshToken(db.Model):
    __tablename__ = 'teacher_refresh_tokens'
    token = db.Column(db.String(64), primary_key=True)
    app_id = db.Column(db.String(64), nullable=False)
    session_token = db.Column(db.String(64), nullable=False)
    scopes = db.Column(db.JSON, nullable=False)

class TeacherAuthCode(db.Model):
    __tablename__ = 'teacher_auth_codes'
    code = db.Column(db.String(64), primary_key=True)
    app_id = db.Column(db.String(64), nullable=False)
    session_token = db.Column(db.String(64), nullable=False)
    scopes = db.Column(db.JSON, nullable=False)
    redirect_uri = db.Column(db.String(512), nullable=False)
    expires_at = db.Column(db.Float, nullable=False)

# Create tables and run migrations
with app.app_context():
    db.create_all()
    # Migration: Add encrypted credential columns if they don't exist
    from sqlalchemy import inspect, text
    inspector = inspect(db.engine)
    columns = [col['name'] for col in inspector.get_columns('student_sessions')]
    if 'encrypted_username' not in columns:
        db.session.execute(text('ALTER TABLE student_sessions ADD COLUMN encrypted_username TEXT'))
        db.session.execute(text('ALTER TABLE student_sessions ADD COLUMN encrypted_password TEXT'))
        db.session.commit()
    
    # Migration: Add verified and hide_permissions columns to applications
    app_columns = [col['name'] for col in inspector.get_columns('applications')]
    if 'verified' not in app_columns:
        db.session.execute(text('ALTER TABLE applications ADD COLUMN verified BOOLEAN DEFAULT FALSE'))
        db.session.execute(text('ALTER TABLE applications ADD COLUMN hide_permissions BOOLEAN DEFAULT FALSE'))
        db.session.commit()
    
    # Migration: Add admin columns to developers
    dev_columns = [col['name'] for col in inspector.get_columns('developers')]
    if 'is_admin' not in dev_columns:
        db.session.execute(text('ALTER TABLE developers ADD COLUMN is_admin BOOLEAN DEFAULT FALSE'))
        db.session.execute(text('ALTER TABLE developers ADD COLUMN is_super_admin BOOLEAN DEFAULT FALSE'))
        db.session.commit()
    
    # Create super admin if configured via environment variable or use default
    super_admin_email = os.environ.get('SUPER_ADMIN_EMAIL', 'ethan@hackclub.com')
    if super_admin_email:
        super_admin = Developer.query.filter_by(email=super_admin_email).first()
        if super_admin:
            super_admin.is_admin = True
            super_admin.is_super_admin = True
            db.session.commit()

# ============================================================================
# CONSTANTS
# ============================================================================

VALID_SCOPES = {
    'profile': 'Basic student profile (name, ID, school)',
    'grades': 'Current grades and GPA',
    'grades.assignments': 'Individual assignment scores',
    'schedule': 'Class schedule and periods',
    'attendance': 'Attendance records and history',
}

TEACHER_SCOPES = {
    'teacher.profile': 'Teacher profile information',
    'teacher.classes': 'List of classes/sections taught',
    'teacher.students': 'Student rosters for classes',
    'teacher.assignments': 'View assignments',
    'teacher.assignments.write': 'Create and manage assignments',
    'teacher.grades': 'View and manage student grades',
}

USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_token(prefix=''):
    return f"{prefix}{secrets.token_urlsafe(32)}"

def cleanup_expired():
    """Remove expired tokens and sessions from database"""
    now = time.time()
    # Only delete sessions that are expired AND don't have stored credentials for auto-refresh
    StudentSession.query.filter(
        StudentSession.expires_at < now,
        StudentSession.encrypted_username.is_(None)
    ).delete()
    TeacherSession.query.filter(
        TeacherSession.expires_at < now,
        TeacherSession.encrypted_username.is_(None)
    ).delete()
    AuthCode.query.filter(AuthCode.expires_at < now).delete()
    # Only delete access tokens whose sessions are gone or don't have credentials
    # Keep tokens if their session can be auto-refreshed
    for token in AccessToken.query.filter(AccessToken.expires_at < now).all():
        session = StudentSession.query.get(token.session_token)
        if not session or not session.encrypted_username:
            db.session.delete(token)
    for token in TeacherAccessToken.query.filter(TeacherAccessToken.expires_at < now).all():
        session = TeacherSession.query.get(token.session_token)
        if not session or not session.encrypted_username:
            db.session.delete(token)
    db.session.commit()

# ============================================================================
# POWERSCHOOL INTEGRATION
# ============================================================================

def powerschool_login(district_url, username, password):
    """Authenticate with PowerSchool and return session cookies"""
    district_url = district_url.rstrip('/')
    if not district_url.startswith('http'):
        district_url = 'https://' + district_url
    
    s = requests.Session()
    s.headers.update({'User-Agent': USER_AGENT})
    
    login_data = {
        'dbpw': password,
        'account': username,
        'pw': password,
        'credentialType': 'User Id and Password Credential',
    }
    
    try:
        response = s.post(f"{district_url}/guardian/home.html", data=login_data, allow_redirects=True, timeout=30)
        
        if response.status_code != 200:
            return None, "Couldn't connect to PowerSchool. Please check the district URL."
        
        if 'Your username or password is incorrect' in response.text:
            return None, "Incorrect username or password. Please try again."
        
        if 'Grades and Attendance' not in response.text and 'quickLookup' not in response.text:
            return None, "Couldn't sign in. Please verify your district URL and credentials."
        
        # Parse student info
        student_info = parse_student_info(response.text)
        
        return {
            'cookies': dict(s.cookies),
            'district_url': district_url,
            'student_info': student_info,
            'home_html': response.text
        }, None
        
    except requests.exceptions.Timeout:
        return None, "Connection timed out. Please try again."
    except requests.exceptions.RequestException as e:
        return None, "Couldn't connect to PowerSchool. Please check your internet connection."

def parse_student_info(html):
    """Extract student information from PowerSchool home page"""
    soup = BeautifulSoup(html, 'html.parser')
    
    info = {
        'name': 'Unknown',
        'student_id': '',
        'school': '',
        'district': '',
        'grade_level': '',
    }
    
    # Student name
    name_elem = soup.find('span', id='firstlast')
    if name_elem:
        info['name'] = name_elem.get_text().strip()
    
    # Student ID from various locations
    id_elem = soup.find('span', id='student-number')
    if id_elem:
        info['student_id'] = id_elem.get_text().strip()
    else:
        # Try to find in the page
        id_match = re.search(r'Student\s*(?:ID|Number)[:\s]*(\d+)', html, re.I)
        if id_match:
            info['student_id'] = id_match.group(1)
    
    # Grade level - try multiple patterns
    grade_elem = soup.find('span', id='grade')
    if grade_elem:
        info['grade_level'] = grade_elem.get_text().strip()
    else:
        # Look for grade in various formats
        grade_match = re.search(r'Grade[:\s]*(\d+)', html, re.I)
        if grade_match:
            info['grade_level'] = grade_match.group(1)
        else:
            # Try to infer from course names (e.g., "English 1" suggests 9th grade)
            course_match = re.search(r'(?:English|Math|History)\s*(\d)', html, re.I)
            if course_match:
                course_num = int(course_match.group(1))
                info['grade_level'] = str(8 + course_num)  # English 1 = 9th grade
    
    # School/District
    school_elem = soup.find('div', id='print-school')
    if school_elem:
        text = school_elem.get_text(separator='\n').strip()
        parts = [p.strip() for p in text.split('\n') if p.strip()]
        if len(parts) >= 2:
            info['district'] = parts[0]
            info['school'] = parts[1]
        elif len(parts) == 1:
            info['school'] = parts[0]
    
    return info

def fetch_grades(session_data):
    """Fetch grades from PowerSchool"""
    s = requests.Session()
    s.cookies.update(session_data['cookies'])
    s.headers.update({'User-Agent': USER_AGENT})
    
    # Use cached home_html if available
    html = session_data.get('home_html')
    if not html:
        response = s.get(f"{session_data['district_url']}/guardian/home.html", timeout=30)
        html = response.text
    
    soup = BeautifulSoup(html, 'html.parser')
    grades = []
    
    table = soup.find('table', class_='linkDescList')
    if table:
        rows = table.find_all('tr', class_='center')
        for row in rows:
            if not row.get('id', '').startswith('ccid_'):
                continue
            
            cells = row.find_all('td')
            if len(cells) < 4:
                continue
            
            course_cell = None
            for cell in cells:
                if 'table-element-text-align-start' in cell.get('class', []):
                    course_cell = cell
                    break
            
            if not course_cell:
                continue
            
            # Course name
            course_name = course_cell.get_text(separator=' ').strip()
            course_name = re.sub(r'\s+', ' ', course_name)
            course_name = re.sub(r'\s*Email\s*', ' ', course_name).strip()
            course_name = re.sub(r'\s*-?\s*Rm:?\s*\w*\s*$', '', course_name).strip()
            
            # Teacher
            teacher_match = re.search(r'((?:De\s+|O\')?[A-Z][a-z\']+,\s*[A-Z][a-z]+)\s*$', course_name)
            teacher = teacher_match.group(1) if teacher_match else ''
            if teacher:
                course_name = course_name[:course_name.rfind(teacher)].strip()
            
            period = cells[0].get_text().strip() if cells else ""
            
            # Extract grades and score links
            grade_data = {
                'id': row.get('id', '').replace('ccid_', ''),
                'course': course_name, 
                'period': period, 
                'teacher': teacher, 
                'grades': {},
                'score_links': {}
            }
            
            links = row.find_all('a', href=re.compile(r'scores\.html'))
            for link in links:
                href = link.get('href', '')
                # Grade text may be duplicated with <br/> (e.g., "91<br/>91"), take first part
                text_parts = list(link.stripped_strings)
                text = text_parts[0] if text_parts else ''
                
                if not text or text == '[ i ]':
                    continue
                
                # Extract term from fg parameter or infer from begdate
                fg_match = re.search(r'fg=(\w+)', href)
                if fg_match:
                    term = fg_match.group(1)
                elif 'begdate=' in href:
                    # Q2 uses begdate format - check if it's Q2 based on date range
                    # The second link with begdate is typically Q2
                    begdate_match = re.search(r'begdate=(\d+)/(\d+)/(\d+)', href)
                    if begdate_match:
                        month = int(begdate_match.group(1))
                        # Nov-Jan is Q2, Sept-Oct is Q1
                        if month >= 11 or month <= 1:
                            term = 'Q2'
                        elif month >= 9:
                            term = 'Q1'
                        elif month >= 3:
                            term = 'Q3' if month < 6 else 'Q4'
                        else:
                            continue
                    else:
                        continue
                else:
                    continue
                
                try:
                    grade_data['grades'][term] = int(text)
                except ValueError:
                    pass
                grade_data['score_links'][term] = href
            
            if grade_data['course'] and not any(skip in grade_data['course'].lower() for skip in ['lunch', 'homeroom']):
                grades.append(grade_data)
    
    # Calculate GPA
    total_points = 0
    count = 0
    for course in grades:
        grade = course['grades'].get('Q2') or course['grades'].get('S1') or course['grades'].get('Q1')
        if isinstance(grade, int):
            if grade >= 93: points = 4.0
            elif grade >= 90: points = 3.7
            elif grade >= 87: points = 3.3
            elif grade >= 83: points = 3.0
            elif grade >= 80: points = 2.7
            elif grade >= 77: points = 2.3
            elif grade >= 73: points = 2.0
            elif grade >= 70: points = 1.7
            elif grade >= 67: points = 1.3
            elif grade >= 65: points = 1.0
            else: points = 0.0
            total_points += points
            count += 1
    
    gpa = round(total_points / count, 2) if count > 0 else 0.0
    
    # Store grade data for assignment lookups
    session_data['grades_data'] = grades
    
    return {'courses': grades, 'gpa': gpa}

def fetch_assignments(session_data, section_id, student_dcid, store_code):
    """Fetch assignments for a specific class/term"""
    s = requests.Session()
    s.cookies.update(session_data['cookies'])
    
    url = f"{session_data['district_url']}/ws/xte/assignment/lookup"
    headers = {
        'User-Agent': USER_AGENT,
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json;charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': session_data['district_url'],
        'Referer': f"{session_data['district_url']}/guardian/home.html",
    }
    
    payload = {
        'section_ids': [int(section_id)],
        'student_ids': [int(student_dcid)],
        'store_codes': [store_code]
    }
    
    try:
        response = s.post(url, json=payload, headers=headers, timeout=30)
        if response.status_code != 200:
            return []
        
        data = response.json()
        assignments = []
        
        for item in data:
            for section in item.get('_assignmentsections', []):
                name = section.get('name', 'Unknown')
                due_date = section.get('duedate', '')
                total_points = section.get('totalpointvalue', 0)
                
                category = ''
                for cat_assoc in section.get('_assignmentcategoryassociations', []):
                    category = cat_assoc.get('_teachercategory', {}).get('name', '')
                    break
                
                score = None
                percent = None
                flags = []
                for score_data in section.get('_assignmentscores', []):
                    score_val = score_data.get('scorepoints')
                    if score_val is not None:
                        score = int(score_val) if isinstance(score_val, float) and score_val == int(score_val) else score_val
                    percent_val = score_data.get('scorepercent')
                    if percent_val is not None:
                        percent = int(percent_val) if isinstance(percent_val, float) and percent_val == int(percent_val) else percent_val
                    if score_data.get('ismissing'): flags.append('missing')
                    if score_data.get('islate'): flags.append('late')
                    if score_data.get('isexempt'): flags.append('exempt')
                
                if due_date and '-' in due_date:
                    parts = due_date.split('-')
                    if len(parts) == 3:
                        due_date = f"{parts[1]}/{parts[2]}/{parts[0]}"
                
                assignments.append({
                    'name': name,
                    'due_date': due_date,
                    'category': category,
                    'score': score,
                    'points_possible': int(total_points) if total_points else None,
                    'percent': percent,
                    'flags': flags
                })
        
        return assignments
    except:
        return []

def fetch_attendance(session_data):
    """Fetch attendance summary"""
    html = session_data.get('home_html', '')
    soup = BeautifulSoup(html, 'html.parser')
    
    attendance = {'absences': 0, 'tardies': 0}
    
    abs_elem = soup.find('td', id='termAbsTotal')
    if abs_elem:
        link = abs_elem.find('a')
        if link:
            try:
                attendance['absences'] = int(link.get_text().strip())
            except:
                pass
    
    tar_elem = soup.find('td', id='termTarTotal')
    if tar_elem:
        link = tar_elem.find('a')
        if link:
            try:
                attendance['tardies'] = int(link.get_text().strip())
            except:
                pass
    
    return attendance

# ============================================================================
# TEACHER POWERSCHOOL INTEGRATION
# ============================================================================

def powerteacher_login(district_url, username, password):
    """Authenticate with PowerTeacher and return session cookies"""
    district_url = district_url.rstrip('/')
    if not district_url.startswith('http'):
        district_url = 'https://' + district_url
    
    s = requests.Session()
    s.headers.update({'User-Agent': USER_AGENT})
    
    # Teacher login uses username/password fields (different from student login)
    login_data = {
        'username': username,
        'password': password,
        'translator_username': '',
        'translator_password': '',
        'translator_ldappassword': '',
    }
    
    try:
        # Post to teacher home page
        response = s.post(f"{district_url}/teachers/home.html", data=login_data, allow_redirects=True, timeout=30)
        
        if response.status_code != 200:
            return None, "Couldn't connect to PowerSchool. Please check the district URL."
        
        # Check if login failed
        if 'Your username or password is incorrect' in response.text or 'Invalid username' in response.text:
            return None, "Incorrect username or password. Please try again."
        
        # Try to access the teacher API to verify login
        session_response = s.get(f"{district_url}/ws/xte/user/teacher/me/session", timeout=30)
        
        if session_response.status_code != 200:
            return None, "Couldn't sign in. Make sure you're using a teacher account."
        
        try:
            teacher_session = session_response.json()
        except:
            return None, "Couldn't sign in. Please try again."
        
        # Get default resources for sections and categories
        resources_response = s.get(f"{district_url}/ws/xte/batch/default_resources", timeout=30)
        resources = {}
        sections = []
        categories = []
        
        if resources_response.status_code == 200:
            try:
                resources = resources_response.json()
                categories = resources.get('teacherCategories', [])
                
                # Extract sections from years data - structure is years[].terms[].schedule._sections
                years = resources.get('years', [])
                for year in years:
                    if year.get('defaultyear'):
                        terms = year.get('terms', [])
                        if terms:
                            # First term usually has the schedule with sections
                            for term in terms:
                                schedule = term.get('schedule', {})
                                term_sections = schedule.get('_sections', [])
                                if term_sections:
                                    sections = term_sections
                                    break
                        break
            except:
                pass
        
        teacher_info = {
            'username': teacher_session.get('username', username),
            'first_name': teacher_session.get('firstName', ''),
            'last_name': teacher_session.get('lastName', ''),
            'name': f"{teacher_session.get('firstName', '')} {teacher_session.get('lastName', '')}".strip(),
            'session_key': teacher_session.get('session_key', ''),
        }
        
        return {
            'cookies': dict(s.cookies),
            'district_url': district_url,
            'teacher_info': teacher_info,
            'sections': sections,
            'categories': categories,
        }, None
        
    except requests.exceptions.Timeout:
        return None, "Connection timed out. Please try again."
    except requests.exceptions.RequestException as e:
        return None, "Couldn't connect to PowerSchool. Please check your internet connection."

def teacher_make_request(session_data, method, endpoint, **kwargs):
    """Make a request to PowerTeacher API with automatic session refresh on failure"""
    s = requests.Session()
    s.cookies.update(session_data['cookies'])
    s.headers.update({
        'User-Agent': USER_AGENT,
        'Accept': 'application/json, text/plain, */*',
        'X-Requested-With': 'XMLHttpRequest',
    })
    
    url = f"{session_data['district_url']}{endpoint}"
    
    try:
        if method.upper() == 'GET':
            response = s.get(url, timeout=30, **kwargs)
        elif method.upper() == 'POST':
            response = s.post(url, timeout=30, **kwargs)
        elif method.upper() == 'DELETE':
            response = s.delete(url, timeout=30, **kwargs)
        else:
            response = s.request(method, url, timeout=30, **kwargs)
        
        # If we get a 401 or redirect to login, try to refresh the session
        if response.status_code in [401, 403] or 'pw.html' in response.url:
            # Try to refresh session using stored credentials
            refreshed_data = teacher_refresh_session(session_data)
            if refreshed_data:
                # Update session_data in place
                session_data['cookies'] = refreshed_data['cookies']
                session_data['sections'] = refreshed_data.get('sections', [])
                session_data['categories'] = refreshed_data.get('categories', [])
                
                # Update the database record if we have access to it
                if session_data.get('_session_record'):
                    try:
                        session_record = session_data['_session_record']
                        session_record.cookies = refreshed_data['cookies']
                        session_record.sections = refreshed_data.get('sections', [])
                        session_record.categories = refreshed_data.get('categories', [])
                        session_record.expires_at = time.time() + 1800
                        db.session.commit()
                    except:
                        pass
                
                # Retry the request with new cookies
                s = requests.Session()
                s.cookies.update(refreshed_data['cookies'])
                s.headers.update({
                    'User-Agent': USER_AGENT,
                    'Accept': 'application/json, text/plain, */*',
                    'X-Requested-With': 'XMLHttpRequest',
                })
                
                if method.upper() == 'GET':
                    response = s.get(url, timeout=30, **kwargs)
                elif method.upper() == 'POST':
                    response = s.post(url, timeout=30, **kwargs)
                elif method.upper() == 'DELETE':
                    response = s.delete(url, timeout=30, **kwargs)
                else:
                    response = s.request(method, url, timeout=30, **kwargs)
        
        return response
    except Exception as e:
        return None

def teacher_refresh_session(session_data):
    """Attempt to refresh teacher session using stored credentials"""
    # Check if we have credentials stored
    if not session_data.get('_username') or not session_data.get('_password'):
        return None
    
    try:
        result, error = powerteacher_login(
            session_data['district_url'],
            session_data['_username'],
            session_data['_password']
        )
        if not error:
            return result
    except:
        pass
    return None
    """Fetch teacher's sections/classes"""
    s = requests.Session()
    s.cookies.update(session_data['cookies'])
    s.headers.update({'User-Agent': USER_AGENT})
    
    try:
        response = s.get(f"{session_data['district_url']}/ws/xte/batch/default_resources", timeout=30)
        if response.status_code != 200:
            return session_data.get('sections', [])
        
        data = response.json()
        years = data.get('years', [])
        for year in years:
            if year.get('defaultyear'):
                terms = year.get('terms', [])
                for term in terms:
                    schedule = term.get('schedule', {})
                    sections = schedule.get('_sections', [])
                    if sections:
                        return sections
        return []
    except:
        return session_data.get('sections', [])

def teacher_fetch_students(session_data, section_ids, status='A,P'):
    """Fetch students for specific sections"""
    section_ids_str = ','.join(str(sid) for sid in section_ids) if isinstance(section_ids, list) else str(section_ids)
    
    response = teacher_make_request(
        session_data, 'GET', '/ws/xte/student',
        params={'section_ids': section_ids_str, 'status': status}
    )
    
    if response and response.status_code == 200:
        try:
            return response.json()
        except:
            pass
    return []

def teacher_fetch_assignments(session_data, section_ids, store_code='Q2'):
    """Fetch assignments for teacher's sections"""
    section_ids_list = section_ids if isinstance(section_ids, list) else [section_ids]
    
    payload = json.dumps({
        'section_ids': [str(sid) for sid in section_ids_list],
        'store_codes': [store_code]
    })
    
    response = teacher_make_request(
        session_data, 'POST', '/ws/xte/assignment',
        data=payload,
        headers={
            'Content-Type': 'application/json;charset=UTF-8',
            'Origin': session_data['district_url'],
            'Referer': f"{session_data['district_url']}/teachers/index.html",
        }
    )
    
    if response and response.status_code == 200:
        try:
            return response.json()
        except:
            pass
    return []

def teacher_create_assignment(session_data, section_id, assignment_data):
    """Create a new assignment"""
    # Build assignment payload
    due_date = assignment_data.get('due_date', datetime.utcnow().strftime('%Y-%m-%d'))
    
    payload = {
        'standardcalcdirection': 'NONE',
        'standardscoringmethod': 'GradeScale',
        'yearid': assignment_data.get('year_id', 35),
        '_assignmentsections': [{
            'description': assignment_data.get('description', ''),
            'extracreditpoints': assignment_data.get('extra_credit', 0),
            'relatedgradescaleitemdcid': None,
            'iscountedinfinalgrade': assignment_data.get('count_in_grade', True),
            'isscoringneeded': True,
            'name': assignment_data.get('name', 'New Assignment'),
            'pointspossible': assignment_data.get('points', 100),
            'scoreentrypoints': assignment_data.get('points', 100),
            'selectedScoreType': {'label': 'Percent', 'value': 'PERCENT'},
            'totalpointvalue': assignment_data.get('points', 100),
            'weight': assignment_data.get('weight', 1),
            'isscorespublish': assignment_data.get('publish_scores', True),
            'publishoption': assignment_data.get('publish_option', 'Immediately'),
            'publishdaysbeforedue': 0,
            'selectedPublishOption': {'label': 'Immediately', 'value': 'Immediately'},
            'maxretakeallowed': 0,
            'sectionsdcid': int(section_id),
            'yearid': assignment_data.get('year_id', 35),
            '_assignmentcategoryassociations': [{
                'teachercategoryid': assignment_data.get('category_id', 2511),
                'isprimary': True
            }],
            'scoretype': 'PERCENT',
            'duedate': due_date,
            'publishonspecificdate': due_date,
        }],
        '_assignmentstandardassociations': []
    }
    
    response = teacher_make_request(
        session_data, 'POST', '/ws/xte/section/assignment',
        data=json.dumps(payload),
        headers={
            'Content-Type': 'application/json;charset=UTF-8',
            'Origin': session_data['district_url'],
            'Referer': f"{session_data['district_url']}/teachers/index.html",
        }
    )
    
    if response and response.status_code in [200, 201]:
        try:
            return response.json(), None
        except:
            return {'success': True}, None
    return None, f"Failed to create assignment: {response.status_code if response else 'No response'}"

def teacher_delete_assignment(session_data, assignment_id):
    """Delete an assignment"""
    response = teacher_make_request(
        session_data, 'DELETE', f'/ws/xte/section/assignment/{assignment_id}',
        headers={
            'Origin': session_data['district_url'],
            'Referer': f"{session_data['district_url']}/teachers/index.html",
        }
    )
    
    if response:
        # 204 No Content is success for DELETE
        return response.status_code in [200, 204], response.status_code
    return False, 'No response'

def teacher_fetch_final_grades(session_data, section_ids, student_ids, store_code='Q2'):
    """Fetch final grades for students in sections"""
    section_ids_list = section_ids if isinstance(section_ids, list) else [section_ids]
    student_ids_list = student_ids if isinstance(student_ids, list) else [student_ids]
    
    payload = json.dumps({
        'section_ids': section_ids_list,
        'student_ids': student_ids_list,
        'store_codes': [store_code]
    })
    
    response = teacher_make_request(
        session_data, 'POST', '/ws/xte/final_grade',
        data=payload,
        headers={
            'Content-Type': 'application/json;charset=UTF-8',
            'Origin': session_data['district_url'],
            'Referer': f"{session_data['district_url']}/teachers/index.html",
        }
    )
    
    if response and response.status_code == 200:
        try:
            return response.json()
        except:
            pass
    return []

def teacher_update_score(session_data, score_data):
    """Update assignment score for a student"""
    payload = json.dumps({
        'assignment_scores': [score_data]
    })
    
    response = teacher_make_request(
        session_data, 'PUT', '/ws/xte/score?status=A,I,P',
        data=payload,
        headers={
            'Content-Type': 'application/json;charset=UTF-8',
            'Origin': session_data['district_url'],
            'Referer': f"{session_data['district_url']}/teachers/index.html",
        }
    )
    
    if response and response.status_code == 200:
        try:
            return response.json(), None
        except:
            return {'success': True}, None
    
    # Try to get error details from response
    error_detail = ''
    if response:
        try:
            error_detail = response.text[:200]
        except:
            pass
    return None, f"Failed to update score: {response.status_code if response else 'No response'} {error_detail}"

def teacher_fetch_student_scores(session_data, section_ids, student_ids, store_code='Q2'):
    """Fetch assignment scores for specific students in sections"""
    section_ids_list = section_ids if isinstance(section_ids, list) else [section_ids]
    student_ids_list = student_ids if isinstance(student_ids, list) else [student_ids]
    
    payload = json.dumps({
        'section_ids': [int(sid) for sid in section_ids_list],
        'student_ids': [int(sid) for sid in student_ids_list],
        'store_codes': [store_code]
    })
    
    response = teacher_make_request(
        session_data, 'POST', '/ws/xte/assignment/lookup',
        data=payload,
        headers={
            'Content-Type': 'application/json;charset=UTF-8',
            'Origin': session_data['district_url'],
            'Referer': f"{session_data['district_url']}/teachers/index.html",
        }
    )
    
    if response and response.status_code == 200:
        try:
            return response.json()
        except:
            pass
    return []

def teacher_fetch_student_all_classes(session_data, student_id):
    """Find all classes where this student is enrolled (taught by this teacher)"""
    sections = session_data.get('sections', [])
    student_classes = []
    
    for section in sections:
        section_id = section.get('sectionsdcid')
        if section_id:
            students = teacher_fetch_students(session_data, [section_id])
            for student in students:
                if str(student.get('dcid')) == str(student_id) or str(student.get('_id')) == str(student_id):
                    student_classes.append({
                        'section_id': section_id,
                        'class_name': section.get('sectionnickname', section.get('coursename', '')),
                        'course_name': section.get('coursename', ''),
                        'period': section.get('expression', ''),
                        'term': section.get('termabbreviation', ''),
                        'termbins': section.get('termbins', [])
                    })
                    break
    return student_classes

def teacher_fetch_student_full_schedule(session_data, student_dcid):
    """Fetch the full schedule for a student (all classes, not just teacher's)
    
    Uses the /teachers/studentpages/schedule.html endpoint with frn parameter.
    FRN format is 001{student_dcid} (student table record number)
    """
    # Build FRN - format is 001 followed by student dcid
    frn = f"001{student_dcid}"
    
    response = teacher_make_request(
        session_data, 'GET', f'/teachers/studentpages/schedule.html?frn={frn}',
        headers={
            'Referer': f"{session_data['district_url']}/teachers/index.html",
        }
    )
    
    if not response or response.status_code != 200:
        return []
    
    html = response.text
    soup = BeautifulSoup(html, 'html.parser')
    
    schedule = []
    # Find the schedule table
    table = soup.find('table', {'border': '0', 'cellspacing': '0', 'cellpadding': '4'})
    if not table:
        return []
    
    rows = table.find_all('tr')
    for row in rows[1:]:  # Skip header row
        cells = row.find_all('td')
        if len(cells) >= 6:
            # Extract period (with section ID from comment)
            period_cell = cells[0].get_text(strip=True)
            
            # Extract section ID from HTML comment (e.g., <!-- 364820010 3500 -->)
            period_html = str(cells[0])
            section_id_match = re.search(r'<!--.*?(\d{4,6})\s*-->', period_html)
            
            # Extract course section ID from course cell comment
            course_cell_html = str(cells[2])
            course_section_match = re.search(r'<!--\s*(\d+)\s*-->', course_cell_html)
            section_id = course_section_match.group(1) if course_section_match else ''
            
            schedule.append({
                'period': period_cell,
                'term': cells[1].get_text(strip=True),
                'course_code': cells[2].get_text(strip=True),
                'course_name': cells[3].get_text(strip=True),
                'teacher': cells[4].get_text(strip=True),
                'room': cells[5].get_text(strip=True),
                'section_id': section_id,
                'enroll_date': cells[6].get_text(strip=True) if len(cells) > 6 else '',
                'leave_date': cells[7].get_text(strip=True) if len(cells) > 7 else '',
            })
    
    return schedule

def teacher_fetch_student_grades_all_classes(session_data, student_dcid, store_code='Q2'):
    """Fetch grades for a student across ALL their classes (not just teacher's classes)
    
    Uses /ws/xte/assignment/lookup to get assignments and calculates grade from scores.
    """
    # Get the full schedule
    full_schedule = teacher_fetch_student_full_schedule(session_data, student_dcid)
    
    if not full_schedule:
        return []
    
    grades = []
    for cls in full_schedule:
        section_id = cls.get('section_id')
        if not section_id:
            grades.append({
                'period': cls['period'],
                'course_name': cls['course_name'],
                'course_code': cls['course_code'],
                'teacher': cls['teacher'],
                'room': cls['room'],
                'term': cls['term'],
                'section_id': section_id,
                'grade': None,
                'percent': None,
                'grade_available': False
            })
            continue
        
        # Fetch assignments for this section and calculate grade
        try:
            payload = json.dumps({
                'section_ids': [int(section_id)],
                'student_ids': [int(student_dcid)],
                'store_codes': [store_code]
            })
            
            response = teacher_make_request(
                session_data, 'POST', '/ws/xte/assignment/lookup',
                data=payload,
                headers={
                    'Content-Type': 'application/json;charset=UTF-8',
                    'Origin': session_data['district_url'],
                    'Referer': f"{session_data['district_url']}/teachers/index.html",
                }
            )
            
            if response and response.status_code == 200:
                assignments_data = response.json()
                
                # Calculate grade from assignments
                total_points_earned = 0
                total_points_possible = 0
                
                for assignment in assignments_data:
                    for section in assignment.get('_assignmentsections', []):
                        if not section.get('iscountedinfinalgrade', True):
                            continue
                        
                        points_possible = section.get('totalpointvalue', 0) or 0
                        
                        for score in section.get('_assignmentscores', []):
                            if str(score.get('studentsdcid')) == str(student_dcid):
                                if score.get('isexempt'):
                                    continue
                                score_points = score.get('scorepoints')
                                if score_points is not None:
                                    total_points_earned += float(score_points)
                                    total_points_possible += float(points_possible)
                                break
                
                # Calculate percent
                percent = None
                if total_points_possible > 0:
                    percent = round((total_points_earned / total_points_possible) * 100, 1)
                
                # Convert percent to letter grade (simple scale)
                grade = None
                if percent is not None:
                    if percent >= 93: grade = 'A'
                    elif percent >= 90: grade = 'A-'
                    elif percent >= 87: grade = 'B+'
                    elif percent >= 83: grade = 'B'
                    elif percent >= 80: grade = 'B-'
                    elif percent >= 77: grade = 'C+'
                    elif percent >= 73: grade = 'C'
                    elif percent >= 70: grade = 'C-'
                    elif percent >= 67: grade = 'D+'
                    elif percent >= 63: grade = 'D'
                    elif percent >= 60: grade = 'D-'
                    else: grade = 'F'
                
                grades.append({
                    'period': cls['period'],
                    'course_name': cls['course_name'],
                    'course_code': cls['course_code'],
                    'teacher': cls['teacher'],
                    'room': cls['room'],
                    'term': cls['term'],
                    'section_id': section_id,
                    'grade': grade,
                    'percent': percent,
                    'points_earned': total_points_earned,
                    'points_possible': total_points_possible,
                    'grade_available': percent is not None
                })
            else:
                grades.append({
                    'period': cls['period'],
                    'course_name': cls['course_name'],
                    'course_code': cls['course_code'],
                    'teacher': cls['teacher'],
                    'room': cls['room'],
                    'term': cls['term'],
                    'section_id': section_id,
                    'grade': None,
                    'percent': None,
                    'grade_available': False
                })
        except Exception as e:
            grades.append({
                'period': cls['period'],
                'course_name': cls['course_name'],
                'course_code': cls['course_code'],
                'teacher': cls['teacher'],
                'room': cls['room'],
                'term': cls['term'],
                'section_id': section_id,
                'grade': None,
                'percent': None,
                'grade_available': False,
                'error': str(e)
            })
    
    return grades

# ============================================================================
# DECORATORS
# ============================================================================

def require_developer_auth(f):
    """Require developer to be logged in"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'developer_id' not in session:
            return redirect(url_for('developer_login'))
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    """Require admin privileges"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'developer_id' not in session:
            return redirect(url_for('developer_login'))
        dev = Developer.query.get(session['developer_id'])
        if not dev or not dev.is_admin:
            return redirect(url_for('developer_dashboard'))
        return f(*args, **kwargs)
    return decorated

def require_super_admin(f):
    """Require super admin privileges"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'developer_id' not in session:
            return redirect(url_for('developer_login'))
        dev = Developer.query.get(session['developer_id'])
        if not dev or not dev.is_super_admin:
            return redirect(url_for('developer_dashboard'))
        return f(*args, **kwargs)
    return decorated

def require_access_token(f):
    """Require valid OAuth access token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        cleanup_expired()
        
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'missing_token', 'message': 'Authorization header required'}), 401
        
        token = auth_header[7:]
        token_record = AccessToken.query.get(token)
        
        if not token_record:
            return jsonify({'error': 'invalid_token', 'message': 'Invalid or expired access token'}), 401
        
        session_record = StudentSession.query.get(token_record.session_token)
        if not session_record:
            db.session.delete(token_record)
            db.session.commit()
            return jsonify({'error': 'session_expired', 'message': 'Student session has expired, re-authorization required'}), 401
        
        # If access token is expired, only reject if session can't be refreshed
        if token_record.expires_at < time.time():
            if not session_record.encrypted_username or not session_record.encrypted_password:
                db.session.delete(token_record)
                db.session.commit()
                return jsonify({'error': 'token_expired', 'message': 'Access token has expired'}), 401
            # Token expired but session can be refreshed - extend the token
            token_record.expires_at = time.time() + 3600
            db.session.commit()
        
        # Check if PowerSchool session is expired (or close to expiring) and auto-refresh if we have credentials
        # Proactively refresh if within 5 minutes of expiring
        needs_refresh = session_record.expires_at < time.time() + 300  # 5 minute buffer
        
        if needs_refresh and session_record.encrypted_username and session_record.encrypted_password:
            # Try to re-authenticate
            try:
                username = decrypt_credential(session_record.encrypted_username)
                password = decrypt_credential(session_record.encrypted_password)
                result, error = powerschool_login(session_record.district_url, username, password)
                
                if not error:
                    # Update session with new cookies
                    session_record.cookies = result['cookies']
                    session_record.home_html = result['home_html']
                    session_record.student_info = result['student_info']
                    session_record.expires_at = time.time() + 1800  # 30 minutes
                    db.session.commit()
                else:
                    # Only fail if session is actually expired, not just close to expiring
                    if session_record.expires_at < time.time():
                        session_record.encrypted_username = None
                        session_record.encrypted_password = None
                        db.session.commit()
                        return jsonify({'error': 'session_expired', 'message': 'PowerSchool session expired and auto-refresh failed'}), 401
            except Exception:
                if session_record.expires_at < time.time():
                    return jsonify({'error': 'session_expired', 'message': 'Student session has expired, re-authorization required'}), 401
        elif session_record.expires_at < time.time():
            return jsonify({'error': 'session_expired', 'message': 'Student session has expired, re-authorization required'}), 401
        
        # Convert to dict format for compatibility
        request.token_data = {
            'app_id': token_record.app_id,
            'session_token': token_record.session_token,
            'scopes': token_record.scopes,
            'expires_at': token_record.expires_at
        }
        request.session_data = {
            'cookies': session_record.cookies,
            'district_url': session_record.district_url,
            'student_info': session_record.student_info,
            'home_html': session_record.home_html
        }
        return f(*args, **kwargs)
    return decorated

def require_scope(scope):
    """Require specific OAuth scope"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if scope not in request.token_data.get('scopes', []):
                return jsonify({
                    'error': 'insufficient_scope',
                    'message': f'This endpoint requires the "{scope}" scope'
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

def require_teacher_token(f):
    """Require valid teacher OAuth access token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        cleanup_expired()
        
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'missing_token', 'message': 'Authorization header required'}), 401
        
        token = auth_header[7:]
        token_record = TeacherAccessToken.query.get(token)
        
        if not token_record:
            return jsonify({'error': 'invalid_token', 'message': 'Invalid or expired access token'}), 401
        
        session_record = TeacherSession.query.get(token_record.session_token)
        if not session_record:
            db.session.delete(token_record)
            db.session.commit()
            return jsonify({'error': 'session_expired', 'message': 'Teacher session has expired, re-authorization required'}), 401
        
        # If access token is expired, only reject if session can't be refreshed
        if token_record.expires_at < time.time():
            if not session_record.encrypted_username or not session_record.encrypted_password:
                db.session.delete(token_record)
                db.session.commit()
                return jsonify({'error': 'token_expired', 'message': 'Access token has expired'}), 401
            # Token expired but session can be refreshed - extend the token
            token_record.expires_at = time.time() + 3600
            db.session.commit()
        
        # Check if PowerSchool session is expired and auto-refresh if we have credentials
        # Also proactively refresh if session is close to expiring (within 5 minutes)
        needs_refresh = session_record.expires_at < time.time() + 300  # 5 minute buffer
        
        if needs_refresh and session_record.encrypted_username and session_record.encrypted_password:
            try:
                username = decrypt_credential(session_record.encrypted_username)
                password = decrypt_credential(session_record.encrypted_password)
                result, error = powerteacher_login(session_record.district_url, username, password)
                
                if not error:
                    session_record.cookies = result['cookies']
                    session_record.teacher_info = result['teacher_info']
                    session_record.sections = result['sections']
                    session_record.categories = result['categories']
                    session_record.expires_at = time.time() + 1800
                    db.session.commit()
                else:
                    # Only fail if session is actually expired, not just close to expiring
                    if session_record.expires_at < time.time():
                        session_record.encrypted_username = None
                        session_record.encrypted_password = None
                        db.session.commit()
                        return jsonify({'error': 'session_expired', 'message': 'PowerSchool session expired and auto-refresh failed'}), 401
            except Exception:
                if session_record.expires_at < time.time():
                    return jsonify({'error': 'session_expired', 'message': 'Teacher session has expired, re-authorization required'}), 401
        elif session_record.expires_at < time.time():
            return jsonify({'error': 'session_expired', 'message': 'Teacher session has expired, re-authorization required'}), 401
        
        # Decrypt credentials for on-demand refresh in API calls
        decrypted_username = None
        decrypted_password = None
        if session_record.encrypted_username and session_record.encrypted_password:
            try:
                decrypted_username = decrypt_credential(session_record.encrypted_username)
                decrypted_password = decrypt_credential(session_record.encrypted_password)
            except:
                pass
        
        request.token_data = {
            'app_id': token_record.app_id,
            'session_token': token_record.session_token,
            'scopes': token_record.scopes,
            'expires_at': token_record.expires_at
        }
        request.session_data = {
            'cookies': session_record.cookies,
            'district_url': session_record.district_url,
            'teacher_info': session_record.teacher_info,
            'sections': session_record.sections or [],
            'categories': session_record.categories or [],
            '_username': decrypted_username,
            '_password': decrypted_password,
            '_session_record': session_record,  # For updating after refresh
        }
        return f(*args, **kwargs)
    return decorated

def require_teacher_scope(scope):
    """Require specific teacher OAuth scope"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if scope not in request.token_data.get('scopes', []):
                return jsonify({
                    'error': 'insufficient_scope',
                    'message': f'This endpoint requires the "{scope}" scope'
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# ============================================================================
# DEVELOPER PORTAL ROUTES
# ============================================================================

@app.route('/')
def index():
    if 'developer_id' in session:
        return redirect(url_for('developer_dashboard'))
    return redirect(url_for('developer_login'))

@app.route('/docs')
def docs():
    return render_template('docs.html', scopes=VALID_SCOPES)

@app.route('/developer/register', methods=['GET', 'POST'])
def developer_register():
    if request.method == 'POST':
        invite_code = request.form.get('invite_code', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        name = request.form.get('name', '').strip()
        
        if not invite_code or not email or not password or not name:
            return render_template('developer_register.html', error='All fields are required')
        
        # Validate invite code
        code = InviteCode.query.get(invite_code)
        if not code:
            return render_template('developer_register.html', error='Invalid invite code')
        if code.max_uses > 0 and code.use_count >= code.max_uses:
            return render_template('developer_register.html', error='This invite code has been used')
        
        # Check if email exists
        if Developer.query.filter_by(email=email).first():
            return render_template('developer_register.html', error='Email already registered')
        
        # Create developer
        dev_id = generate_token('dev_')
        new_dev = Developer(
            id=dev_id,
            email=email,
            password_hash=hash_password(password),
            name=name
        )
        db.session.add(new_dev)
        
        # Mark invite code as used
        code.use_count += 1
        if code.max_uses == 1:
            code.used_by = dev_id
            code.used_at = datetime.utcnow()
        
        db.session.commit()
        
        session['developer_id'] = dev_id
        return redirect(url_for('developer_dashboard'))
    
    return render_template('developer_register.html')

@app.route('/developer/login', methods=['GET', 'POST'])
def developer_login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        dev = Developer.query.filter_by(email=email, password_hash=hash_password(password)).first()
        if dev:
            session['developer_id'] = dev.id
            return redirect(url_for('developer_dashboard'))
        
        return render_template('developer_login.html', error='Invalid credentials')
    
    return render_template('developer_login.html')

@app.route('/developer/logout')
def developer_logout():
    session.pop('developer_id', None)
    return redirect(url_for('index'))

@app.route('/developer/dashboard')
@require_developer_auth
def developer_dashboard():
    dev_apps = Application.query.filter_by(developer_id=session['developer_id']).all()
    apps_dict = {app.id: {
        'name': app.name,
        'client_secret': app.client_secret,
        'redirect_uris': app.redirect_uris,
        'scopes': app.scopes,
        'created_at': app.created_at.isoformat(),
        'app_type': getattr(app, 'app_type', 'student') or 'student',
        'verified': getattr(app, 'verified', False) or False,
        'hide_permissions': getattr(app, 'hide_permissions', False) or False
    } for app in dev_apps}
    developer = Developer.query.get(session['developer_id'])
    dev_dict = {
        'email': developer.email, 
        'name': developer.name, 
        'created_at': developer.created_at.isoformat(),
        'is_admin': developer.is_admin or False,
        'is_super_admin': developer.is_super_admin or False
    }
    return render_template('developer_dashboard.html', 
        apps=apps_dict, 
        developer=dev_dict,
        impersonating=session.get('impersonating', False))

@app.route('/developer/apps/create', methods=['GET', 'POST'])
@require_developer_auth
def create_app():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        redirect_uris = request.form.get('redirect_uris', '').strip().split('\n')
        redirect_uris = [uri.strip() for uri in redirect_uris if uri.strip()]
        scopes = request.form.getlist('scopes')
        app_type = request.form.get('app_type', 'student')
        verified = request.form.get('verified') == 'on'
        hide_permissions = request.form.get('hide_permissions') == 'on'
        
        if not name or not redirect_uris:
            return render_template('create_app.html', scopes=VALID_SCOPES, teacher_scopes=TEACHER_SCOPES, error='Name and redirect URI required')
        
        app_id = generate_token('app_')
        client_secret = generate_token('secret_')
        
        new_app = Application(
            id=app_id,
            name=name,
            client_secret=client_secret,
            redirect_uris=redirect_uris,
            scopes=scopes,
            developer_id=session['developer_id'],
            app_type=app_type,
            verified=verified,
            hide_permissions=hide_permissions
        )
        db.session.add(new_app)
        db.session.commit()
        
        return render_template('app_created.html', app_id=app_id, client_secret=client_secret, name=name, app_type=app_type)
    
    return render_template('create_app.html', scopes=VALID_SCOPES, teacher_scopes=TEACHER_SCOPES)

@app.route('/developer/apps/<app_id>/edit', methods=['GET', 'POST'])
@require_developer_auth
def edit_app(app_id):
    app_record = Application.query.get(app_id)
    if not app_record or app_record.developer_id != session['developer_id']:
        return redirect(url_for('developer_dashboard'))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        redirect_uris = request.form.get('redirect_uris', '').strip().split('\n')
        redirect_uris = [uri.strip() for uri in redirect_uris if uri.strip()]
        scopes = request.form.getlist('scopes')
        verified = request.form.get('verified') == 'on'
        hide_permissions = request.form.get('hide_permissions') == 'on'
        
        if not name or not redirect_uris:
            return render_template('edit_app.html', app=app_record, app_id=app_id, scopes=VALID_SCOPES, teacher_scopes=TEACHER_SCOPES, error='Name and redirect URI required')
        
        app_record.name = name
        app_record.redirect_uris = redirect_uris
        app_record.scopes = scopes
        app_record.verified = verified
        app_record.hide_permissions = hide_permissions
        db.session.commit()
        
        return redirect(url_for('developer_dashboard'))
    
    return render_template('edit_app.html', app=app_record, app_id=app_id, scopes=VALID_SCOPES, teacher_scopes=TEACHER_SCOPES)

@app.route('/developer/apps/<app_id>/delete', methods=['POST'])
@require_developer_auth
def delete_app(app_id):
    app_record = Application.query.get(app_id)
    if not app_record or app_record.developer_id != session['developer_id']:
        return redirect(url_for('developer_dashboard'))
    
    # Delete associated tokens and auth codes
    AccessToken.query.filter_by(app_id=app_id).delete()
    RefreshToken.query.filter_by(app_id=app_id).delete()
    AuthCode.query.filter_by(app_id=app_id).delete()
    TeacherAccessToken.query.filter_by(app_id=app_id).delete()
    TeacherRefreshToken.query.filter_by(app_id=app_id).delete()
    TeacherAuthCode.query.filter_by(app_id=app_id).delete()
    
    db.session.delete(app_record)
    db.session.commit()
    
    return redirect(url_for('developer_dashboard'))

@app.route('/developer/apps/<app_id>/regenerate-secret', methods=['POST'])
@require_developer_auth
def regenerate_secret(app_id):
    app_record = Application.query.get(app_id)
    if not app_record or app_record.developer_id != session['developer_id']:
        return redirect(url_for('developer_dashboard'))
    
    app_record.client_secret = generate_token('secret_')
    db.session.commit()
    
    return redirect(url_for('edit_app', app_id=app_id))

@app.route('/oauth-playground')
@require_developer_auth
def oauth_playground():
    """OAuth 2.0 Playground - Interactive demo of the OAuth flow"""
    return render_template('oauth_playground.html')

@app.route('/oauth-playground/callback')
def oauth_playground_callback():
    """Callback URL for OAuth playground testing"""
    code = request.args.get('code', '')
    state = request.args.get('state', '')
    error = request.args.get('error', '')
    return render_template('oauth_playground.html', callback_code=code, callback_state=state, callback_error=error)

# ============================================================================
# ADMIN PANEL ROUTES
# ============================================================================

@app.route('/admin')
@require_admin
def admin_panel():
    """Admin dashboard"""
    developer = Developer.query.get(session['developer_id'])
    developers = Developer.query.order_by(Developer.created_at.desc()).all()
    invite_codes = InviteCode.query.order_by(InviteCode.created_at.desc()).limit(50).all()
    
    stats = {
        'total_developers': Developer.query.count(),
        'total_apps': Application.query.count(),
        'active_sessions': StudentSession.query.filter(StudentSession.expires_at > time.time()).count(),
        'total_invite_codes': InviteCode.query.count(),
        'unused_codes': InviteCode.query.filter(InviteCode.use_count == 0).count()
    }
    
    return render_template('admin.html', 
        developer=developer, 
        developers=developers, 
        invite_codes=invite_codes,
        stats=stats)

@app.route('/admin/invite-codes', methods=['POST'])
@require_admin
def admin_create_invite():
    """Generate new invite code"""
    max_uses = int(request.form.get('max_uses', 1))
    code = secrets.token_urlsafe(12)
    
    invite = InviteCode(
        code=code,
        created_by=session['developer_id'],
        max_uses=max_uses
    )
    db.session.add(invite)
    db.session.commit()
    
    return redirect(url_for('admin_panel'))

@app.route('/admin/invite-codes/<code>/delete', methods=['POST'])
@require_admin
def admin_delete_invite(code):
    """Delete invite code"""
    invite = InviteCode.query.get(code)
    if invite:
        db.session.delete(invite)
        db.session.commit()
    return redirect(url_for('admin_panel'))

@app.route('/admin/users/<user_id>/toggle-admin', methods=['POST'])
@require_super_admin
def admin_toggle_admin(user_id):
    """Toggle admin status for a user"""
    user = Developer.query.get(user_id)
    if user and user.id != session['developer_id']:
        user.is_admin = not user.is_admin
        db.session.commit()
    return redirect(url_for('admin_panel'))

@app.route('/admin/users/<user_id>/delete', methods=['POST'])
@require_super_admin
def admin_delete_user(user_id):
    """Delete a user account"""
    user = Developer.query.get(user_id)
    if user and user.id != session['developer_id'] and not user.is_super_admin:
        # Delete user's apps first
        for app in user.applications:
            AccessToken.query.filter_by(app_id=app.id).delete()
            RefreshToken.query.filter_by(app_id=app.id).delete()
            AuthCode.query.filter_by(app_id=app.id).delete()
            TeacherAccessToken.query.filter_by(app_id=app.id).delete()
            TeacherRefreshToken.query.filter_by(app_id=app.id).delete()
            TeacherAuthCode.query.filter_by(app_id=app.id).delete()
            db.session.delete(app)
        db.session.delete(user)
        db.session.commit()
    return redirect(url_for('admin_panel'))

@app.route('/admin/users/<user_id>/reset-password', methods=['POST'])
@require_admin
def admin_reset_password(user_id):
    """Reset user password"""
    user = Developer.query.get(user_id)
    current_admin = Developer.query.get(session['developer_id'])
    
    # Only super admin can reset other admin passwords
    if user and (not user.is_admin or current_admin.is_super_admin):
        new_password = request.form.get('new_password', '')
        if new_password and len(new_password) >= 6:
            user.password_hash = hash_password(new_password)
            db.session.commit()
    return redirect(url_for('admin_panel'))

@app.route('/admin/users/<user_id>/impersonate', methods=['POST'])
@require_super_admin
def admin_impersonate(user_id):
    """Login as another user"""
    user = Developer.query.get(user_id)
    if user:
        session['developer_id'] = user.id
        session['impersonating'] = True
    return redirect(url_for('developer_dashboard'))

@app.route('/admin/stop-impersonate')
@require_developer_auth
def admin_stop_impersonate():
    """Stop impersonating and return to admin"""
    # Find super admin to return to
    super_admin = Developer.query.filter_by(is_super_admin=True).first()
    if super_admin and session.get('impersonating'):
        session['developer_id'] = super_admin.id
        session.pop('impersonating', None)
    return redirect(url_for('admin_panel'))

# ============================================================================
# OAUTH 2.0 ROUTES
# ============================================================================

@app.route('/oauth/authorize', methods=['GET', 'POST'])
def oauth_authorize():
    """OAuth 2.0 Authorization Endpoint"""
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    scope = request.args.get('scope', '')
    state = request.args.get('state', '')
    response_type = request.args.get('response_type', 'code')
    
    # Validate client
    app_record = Application.query.get(client_id)
    if not app_record:
        return render_template('oauth_error.html', error='Invalid client_id')
    
    app_data = {
        'name': app_record.name,
        'redirect_uris': app_record.redirect_uris,
        'scopes': app_record.scopes,
        'verified': app_record.verified,
        'hide_permissions': app_record.hide_permissions
    }
    
    if redirect_uri not in app_record.redirect_uris:
        return render_template('oauth_error.html', error='Invalid redirect_uri')
    
    requested_scopes = scope.split() if scope else []
    invalid_scopes = [s for s in requested_scopes if s not in VALID_SCOPES]
    if invalid_scopes:
        return redirect(f"{redirect_uri}?error=invalid_scope&state={state}")
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'deny':
            return redirect(f"{redirect_uri}?error=access_denied&state={state}")
        
        # User approved - authenticate with PowerSchool
        district_url = request.form.get('district_url', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not district_url or not username or not password:
            return render_template('oauth_authorize.html',
                app=app_data, scopes=requested_scopes, scope_descriptions=VALID_SCOPES,
                client_id=client_id, redirect_uri=redirect_uri, scope=scope, state=state,
                error='Please fill in all fields')
        
        # Authenticate with PowerSchool
        result, error = powerschool_login(district_url, username, password)
        
        if error:
            return render_template('oauth_authorize.html',
                app=app_data, scopes=requested_scopes, scope_descriptions=VALID_SCOPES,
                client_id=client_id, redirect_uri=redirect_uri, scope=scope, state=state,
                error=error)
        
        # Create student session with encrypted credentials for auto-refresh
        session_token = generate_token('sess_')
        student_session = StudentSession(
            token=session_token,
            cookies=result['cookies'],
            district_url=result['district_url'],
            student_info=result['student_info'],
            home_html=result['home_html'],
            expires_at=time.time() + 1800,  # 30 minutes - PowerSchool sessions expire quickly
            encrypted_username=encrypt_credential(username),
            encrypted_password=encrypt_credential(password)
        )
        db.session.add(student_session)
        
        # Create authorization code
        auth_code = generate_token('code_')
        auth_code_record = AuthCode(
            code=auth_code,
            app_id=client_id,
            session_token=session_token,
            scopes=requested_scopes,
            redirect_uri=redirect_uri,
            expires_at=time.time() + 600  # 10 minute expiry
        )
        db.session.add(auth_code_record)
        db.session.commit()
        
        return redirect(f"{redirect_uri}?code={auth_code}&state={state}")
    
    return render_template('oauth_authorize.html',
        app=app_data, scopes=requested_scopes, scope_descriptions=VALID_SCOPES,
        client_id=client_id, redirect_uri=redirect_uri, scope=scope, state=state)

@app.route('/oauth/token', methods=['POST'])
def oauth_token():
    """OAuth 2.0 Token Endpoint"""
    grant_type = request.form.get('grant_type')
    
    if grant_type == 'authorization_code':
        code = request.form.get('code', '').strip()
        client_id = request.form.get('client_id', '').strip()
        client_secret = request.form.get('client_secret', '').strip()
        redirect_uri = request.form.get('redirect_uri', '').strip()
        
        # Debug: log what we received
        print(f"Token request - client_id: '{client_id}' (len={len(client_id)})")
        
        # Validate client
        app_record = db.session.get(Application, client_id)
        if not app_record:
            # Try to find by querying
            app_record = Application.query.filter_by(id=client_id).first()
            if not app_record:
                print(f"App not found for client_id: '{client_id}'")
                # List all app IDs for debugging
                all_apps = Application.query.all()
                print(f"Available app IDs: {[a.id for a in all_apps]}")
                return jsonify({'error': 'invalid_client', 'message': 'Client ID not found'}), 401
        
        if app_record.client_secret != client_secret:
            return jsonify({'error': 'invalid_client', 'message': 'Invalid client secret'}), 401
        
        # Validate code
        code_record = db.session.get(AuthCode, code)
        if not code_record:
            return jsonify({'error': 'invalid_grant', 'message': 'Invalid or expired authorization code'}), 400
        
        if code_record.app_id != client_id:
            return jsonify({'error': 'invalid_grant'}), 400
        
        if code_record.redirect_uri != redirect_uri:
            return jsonify({'error': 'invalid_grant'}), 400
        
        if code_record.expires_at < time.time():
            db.session.delete(code_record)
            db.session.commit()
            return jsonify({'error': 'invalid_grant', 'message': 'Authorization code expired'}), 400
        
        # Generate tokens
        access_token = generate_token('at_')
        refresh_token_val = generate_token('rt_')
        
        access_token_record = AccessToken(
            token=access_token,
            app_id=client_id,
            session_token=code_record.session_token,
            scopes=code_record.scopes,
            expires_at=time.time() + 3600  # 1 hour
        )
        db.session.add(access_token_record)
        
        refresh_token_record = RefreshToken(
            token=refresh_token_val,
            app_id=client_id,
            session_token=code_record.session_token,
            scopes=code_record.scopes
        )
        db.session.add(refresh_token_record)
        
        # Delete used auth code
        scopes = code_record.scopes
        db.session.delete(code_record)
        db.session.commit()
        
        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': 3600,
            'refresh_token': refresh_token_val,
            'scope': ' '.join(scopes)
        })
    
    elif grant_type == 'refresh_token':
        refresh_token_val = request.form.get('refresh_token')
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
        
        app_record = Application.query.get(client_id)
        if not app_record or app_record.client_secret != client_secret:
            return jsonify({'error': 'invalid_client'}), 401
        
        rt_record = RefreshToken.query.get(refresh_token_val)
        if not rt_record or rt_record.app_id != client_id:
            return jsonify({'error': 'invalid_grant'}), 400
        
        # Check if session still valid
        if not StudentSession.query.get(rt_record.session_token):
            db.session.delete(rt_record)
            db.session.commit()
            return jsonify({'error': 'invalid_grant', 'message': 'Session expired, re-authorization required'}), 400
        
        # Generate new access token
        access_token = generate_token('at_')
        access_token_record = AccessToken(
            token=access_token,
            app_id=client_id,
            session_token=rt_record.session_token,
            scopes=rt_record.scopes,
            expires_at=time.time() + 3600
        )
        db.session.add(access_token_record)
        db.session.commit()
        
        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': 3600,
            'scope': ' '.join(rt_record.scopes)
        })
    
    return jsonify({'error': 'unsupported_grant_type'}), 400

# ============================================================================
# TEACHER OAUTH 2.0 ROUTES
# ============================================================================

@app.route('/oauth/teacher/authorize', methods=['GET', 'POST'])
def teacher_oauth_authorize():
    """Teacher OAuth 2.0 Authorization Endpoint"""
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    scope = request.args.get('scope', '')
    state = request.args.get('state', '')
    response_type = request.args.get('response_type', 'code')
    
    # Validate client
    app_record = Application.query.get(client_id)
    if not app_record:
        return render_template('oauth_error.html', error='Invalid client_id')
    
    # Check app type is teacher
    if getattr(app_record, 'app_type', 'student') != 'teacher':
        return render_template('oauth_error.html', error='This app is not configured for teacher OAuth')
    
    app_data = {
        'name': app_record.name,
        'redirect_uris': app_record.redirect_uris,
        'scopes': app_record.scopes,
        'verified': app_record.verified,
        'hide_permissions': app_record.hide_permissions
    }
    
    if redirect_uri not in app_record.redirect_uris:
        return render_template('oauth_error.html', error='Invalid redirect_uri')
    
    requested_scopes = scope.split() if scope else []
    invalid_scopes = [s for s in requested_scopes if s not in TEACHER_SCOPES]
    if invalid_scopes:
        return redirect(f"{redirect_uri}?error=invalid_scope&state={state}")
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'deny':
            return redirect(f"{redirect_uri}?error=access_denied&state={state}")
        
        # Teacher approved - authenticate with PowerTeacher
        district_url = request.form.get('district_url', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not district_url or not username or not password:
            return render_template('oauth_authorize.html',
                app=app_data, scopes=requested_scopes, scope_descriptions=TEACHER_SCOPES,
                client_id=client_id, redirect_uri=redirect_uri, scope=scope, state=state,
                error='Please fill in all fields', is_teacher=True)
        
        # Authenticate with PowerTeacher
        result, error = powerteacher_login(district_url, username, password)
        
        if error:
            return render_template('oauth_authorize.html',
                app=app_data, scopes=requested_scopes, scope_descriptions=TEACHER_SCOPES,
                client_id=client_id, redirect_uri=redirect_uri, scope=scope, state=state,
                error=error, is_teacher=True)
        
        # Create teacher session
        session_token = generate_token('tsess_')
        teacher_session = TeacherSession(
            token=session_token,
            cookies=result['cookies'],
            district_url=result['district_url'],
            teacher_info=result['teacher_info'],
            sections=result.get('sections', []),
            expires_at=time.time() + 1800,
            encrypted_username=encrypt_credential(username),
            encrypted_password=encrypt_credential(password)
        )
        db.session.add(teacher_session)
        
        # Create teacher authorization code
        auth_code = generate_token('tcode_')
        auth_code_record = TeacherAuthCode(
            code=auth_code,
            app_id=client_id,
            session_token=session_token,
            scopes=requested_scopes,
            redirect_uri=redirect_uri,
            expires_at=time.time() + 600
        )
        db.session.add(auth_code_record)
        db.session.commit()
        
        return redirect(f"{redirect_uri}?code={auth_code}&state={state}")
    
    return render_template('oauth_authorize.html',
        app=app_data, scopes=requested_scopes, scope_descriptions=TEACHER_SCOPES,
        client_id=client_id, redirect_uri=redirect_uri, scope=scope, state=state,
        is_teacher=True)

@app.route('/oauth/teacher/token', methods=['POST'])
def teacher_oauth_token():
    """Teacher OAuth 2.0 Token Endpoint"""
    grant_type = request.form.get('grant_type')
    
    if grant_type == 'authorization_code':
        code = request.form.get('code', '').strip()
        client_id = request.form.get('client_id', '').strip()
        client_secret = request.form.get('client_secret', '').strip()
        redirect_uri = request.form.get('redirect_uri', '').strip()
        
        # Validate client
        app_record = Application.query.get(client_id)
        if not app_record:
            return jsonify({'error': 'invalid_client', 'message': 'Client ID not found'}), 401
        
        if app_record.client_secret != client_secret:
            return jsonify({'error': 'invalid_client', 'message': 'Invalid client secret'}), 401
        
        # Validate code
        code_record = TeacherAuthCode.query.get(code)
        if not code_record:
            return jsonify({'error': 'invalid_grant', 'message': 'Invalid or expired authorization code'}), 400
        
        if code_record.app_id != client_id:
            return jsonify({'error': 'invalid_grant'}), 400
        
        if code_record.redirect_uri != redirect_uri:
            return jsonify({'error': 'invalid_grant'}), 400
        
        if code_record.expires_at < time.time():
            db.session.delete(code_record)
            db.session.commit()
            return jsonify({'error': 'invalid_grant', 'message': 'Authorization code expired'}), 400
        
        # Generate tokens
        access_token = generate_token('tat_')
        refresh_token_val = generate_token('trt_')
        
        access_token_record = TeacherAccessToken(
            token=access_token,
            app_id=client_id,
            session_token=code_record.session_token,
            scopes=code_record.scopes,
            expires_at=time.time() + 3600
        )
        db.session.add(access_token_record)
        
        refresh_token_record = TeacherRefreshToken(
            token=refresh_token_val,
            app_id=client_id,
            session_token=code_record.session_token,
            scopes=code_record.scopes
        )
        db.session.add(refresh_token_record)
        
        # Delete used auth code
        scopes = code_record.scopes
        db.session.delete(code_record)
        db.session.commit()
        
        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': 3600,
            'refresh_token': refresh_token_val,
            'scope': ' '.join(scopes)
        })
    
    elif grant_type == 'refresh_token':
        refresh_token_val = request.form.get('refresh_token')
        client_id = request.form.get('client_id')
        client_secret = request.form.get('client_secret')
        
        app_record = Application.query.get(client_id)
        if not app_record or app_record.client_secret != client_secret:
            return jsonify({'error': 'invalid_client'}), 401
        
        rt_record = TeacherRefreshToken.query.get(refresh_token_val)
        if not rt_record or rt_record.app_id != client_id:
            return jsonify({'error': 'invalid_grant'}), 400
        
        # Check if session still valid
        if not TeacherSession.query.get(rt_record.session_token):
            db.session.delete(rt_record)
            db.session.commit()
            return jsonify({'error': 'invalid_grant', 'message': 'Session expired, re-authorization required'}), 400
        
        # Generate new access token
        access_token = generate_token('tat_')
        access_token_record = TeacherAccessToken(
            token=access_token,
            app_id=client_id,
            session_token=rt_record.session_token,
            scopes=rt_record.scopes,
            expires_at=time.time() + 3600
        )
        db.session.add(access_token_record)
        db.session.commit()
        
        return jsonify({
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': 3600,
            'scope': ' '.join(rt_record.scopes)
        })
    
    return jsonify({'error': 'unsupported_grant_type'}), 400

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route('/api/v1/me')
@require_access_token
@require_scope('profile')
def api_me():
    """Get current student's profile"""
    info = request.session_data['student_info'].copy()
    
    # Re-parse student info if grade_level is missing (for sessions created before the update)
    if not info.get('grade_level') and request.session_data.get('home_html'):
        fresh_info = parse_student_info(request.session_data['home_html'])
        info.update({k: v for k, v in fresh_info.items() if v and not info.get(k)})
    
    # If student_id is still not available, try to extract from psaid cookie or FRN
    if not info.get('student_id'):
        cookies = request.session_data.get('cookies', {})
        psaid = cookies.get('psaid', '')
        # psaid format: <-V2->usersdcid/studentdcid/token<-V2->
        parts = psaid.replace('<-V2->', '').split('/')
        if len(parts) >= 2:
            info['student_id'] = parts[1]  # Student DCID
    
    # Also get attendance if available
    attendance = fetch_attendance(request.session_data)
    
    # Get current term grades summary
    grades_data = fetch_grades(request.session_data)
    current_gpa = grades_data.get('gpa', 0)
    course_count = len(grades_data.get('courses', []))
    
    return jsonify({
        'name': info['name'],
        'student_id': info.get('student_id', ''),
        'grade_level': info.get('grade_level', ''),
        'school': info.get('school', ''),
        'district': info.get('district', ''),
        'current_gpa': current_gpa,
        'enrolled_courses': course_count,
        'attendance': {
            'absences': attendance.get('absences', 0),
            'tardies': attendance.get('tardies', 0)
        }
    })

@app.route('/api/v1/grades')
@require_access_token
@require_scope('grades')
def api_grades():
    """Get current grades"""
    grades_data = fetch_grades(request.session_data)
    # Remove internal data from response
    courses = []
    for c in grades_data['courses']:
        courses.append({
            'id': c.get('id', ''),
            'course': c['course'],
            'period': c['period'],
            'teacher': c['teacher'],
            'grades': c['grades']
        })
    return jsonify({'courses': courses, 'gpa': grades_data['gpa']})

@app.route('/api/v1/grades/summary')
@require_access_token
@require_scope('grades')
def api_grades_summary():
    """Get a simplified grades summary"""
    grades_data = fetch_grades(request.session_data)
    summary = []
    for c in grades_data['courses']:
        current_grade = c['grades'].get('Q2') or c['grades'].get('S1') or c['grades'].get('Q1')
        summary.append({
            'course': c['course'],
            'current_grade': current_grade,
            'teacher': c['teacher']
        })
    return jsonify({
        'gpa': grades_data['gpa'],
        'courses': summary
    })

@app.route('/api/v1/courses')
@require_access_token
@require_scope('schedule')
def api_courses():
    """Get list of enrolled courses"""
    grades_data = fetch_grades(request.session_data)
    courses = []
    for c in grades_data['courses']:
        courses.append({
            'id': c.get('id', ''),
            'name': c['course'],
            'period': c['period'],
            'teacher': c['teacher']
        })
    return jsonify({'courses': courses, 'count': len(courses)})

@app.route('/api/v1/courses/<course_id>')
@require_access_token
@require_scope('schedule')
def api_course_detail(course_id):
    """Get details for a specific course"""
    grades_data = fetch_grades(request.session_data)
    for c in grades_data['courses']:
        if c.get('id') == course_id:
            return jsonify({
                'id': c.get('id', ''),
                'name': c['course'],
                'period': c['period'],
                'teacher': c['teacher'],
                'grades': c['grades']
            })
    return jsonify({'error': 'Course not found'}), 404

@app.route('/api/v1/courses/<course_id>/assignments')
@require_access_token
@require_scope('grades.assignments')
def api_course_assignments(course_id):
    """Get assignments for a specific course"""
    term = request.args.get('term', 'Q2')
    
    # First fetch grades to get the score link
    grades_data = fetch_grades(request.session_data)
    course = None
    for c in grades_data['courses']:
        if c.get('id') == course_id:
            course = c
            break
    
    if not course:
        return jsonify({'error': 'Course not found'}), 404
    
    score_link = course.get('score_links', {}).get(term)
    if not score_link:
        return jsonify({'error': f'No data for term {term}', 'available_terms': list(course.get('score_links', {}).keys())}), 404
    
    # Fetch scores page to get section_id and student_dcid
    s = requests.Session()
    s.cookies.update(request.session_data['cookies'])
    
    if score_link.startswith('/'):
        url = f"{request.session_data['district_url']}{score_link}"
    else:
        url = f"{request.session_data['district_url']}/guardian/{score_link}"
    
    # Add Referer header for the scores page request
    headers = {
        'User-Agent': USER_AGENT,
        'Referer': f"{request.session_data['district_url']}/guardian/home.html",
    }
    response = s.get(url, headers=headers, timeout=30)
    if response.status_code != 200:
        return jsonify({'error': 'Failed to fetch course data'}), 500
    
    scores_html = response.text
    
    # Check if we got redirected to login page
    if 'Student and Parent Sign In' in scores_html or 'pslogin' in scores_html[:1000]:
        return jsonify({
            'error': 'session_expired',
            'message': 'PowerSchool session expired - please re-link your account',
            'course': course['course'],
            'term': term,
            'current_grade': course['grades'].get(term)
        }), 401
    
    section_match = re.search(r'data-sectionid="(\d+)"', scores_html)
    student_frn_match = re.search(r"studentFRN\s*=\s*'(\d+)'", scores_html)
    store_code_match = re.search(r"storecode\s*=\s*'([^']+)'", scores_html)
    
    if not section_match or not student_frn_match:
        return jsonify({'error': 'Could not parse course data'}), 500
    
    section_id = section_match.group(1)
    student_frn = student_frn_match.group(1)
    store_code = store_code_match.group(1) if store_code_match else term
    
    # Convert FRN to dcid using PowerSchool's pattern: /001([0-9]+)/
    dcid_match = re.match(r'001(\d+)', student_frn)
    if dcid_match:
        student_dcid = dcid_match.group(1)
    else:
        # Fallback: strip leading zeros
        student_dcid = student_frn.lstrip('0')
    
    # Fetch assignments
    assignments = fetch_assignments(request.session_data, section_id, student_dcid, store_code)
    
    return jsonify({
        'course': course['course'],
        'term': store_code,
        'assignments': assignments,
        'count': len(assignments)
    })

@app.route('/api/v1/assignments')
@require_access_token
@require_scope('grades.assignments')
def api_all_assignments():
    """Get recent assignments across all courses"""
    term = request.args.get('term', 'Q2')
    limit = min(int(request.args.get('limit', 50)), 100)
    
    grades_data = fetch_grades(request.session_data)
    all_assignments = []
    assignment_error = None
    
    for course in grades_data['courses'][:5]:  # Limit to first 5 courses for performance
        score_link = course.get('score_links', {}).get(term)
        if not score_link:
            continue
        
        s = requests.Session()
        s.cookies.update(request.session_data['cookies'])
        s.headers.update({'User-Agent': USER_AGENT})
        
        if score_link.startswith('/'):
            url = f"{request.session_data['district_url']}{score_link}"
        else:
            url = f"{request.session_data['district_url']}/guardian/{score_link}"
        
        try:
            # Add Referer header for the scores page request
            headers = {
                'User-Agent': USER_AGENT,
                'Referer': f"{request.session_data['district_url']}/guardian/home.html",
            }
            response = s.get(url, headers=headers, timeout=15)
            if response.status_code != 200:
                continue
            
            scores_html = response.text
            
            # Check if redirected to login
            if 'Student and Parent Sign In' in scores_html or 'pslogin' in scores_html[:1000]:
                assignment_error = 'PowerSchool session expired - please re-link your account'
                break
            
            section_match = re.search(r'data-sectionid="(\d+)"', scores_html)
            student_frn_match = re.search(r"studentFRN\s*=\s*'(\d+)'", scores_html)
            store_code_match = re.search(r"storecode\s*=\s*'([^']+)'", scores_html)
            
            if not section_match or not student_frn_match:
                # Page loaded but couldn't find expected data - might be a different page format
                continue
            
            section_id = section_match.group(1)
            student_frn = student_frn_match.group(1)
            store_code = store_code_match.group(1) if store_code_match else term
            
            # Convert FRN to dcid using PowerSchool's pattern: /001([0-9]+)/
            dcid_match = re.match(r'001(\d+)', student_frn)
            if dcid_match:
                student_dcid = dcid_match.group(1)
            else:
                student_dcid = student_frn.lstrip('0')
            
            assignments = fetch_assignments(request.session_data, section_id, student_dcid, store_code)
            
            for a in assignments:
                a['course'] = course['course']
                all_assignments.append(a)
        except:
            continue
    
    # If we got an error and no assignments, return error
    if assignment_error and not all_assignments:
        return jsonify({
            'error': 'assignments_unavailable',
            'message': assignment_error,
            'term': term,
            'grades_summary': [{'course': c['course'], 'grade': c['grades'].get(term)} for c in grades_data['courses']]
        }), 503
    
    # Sort by due date (most recent first)
    all_assignments.sort(key=lambda x: x.get('due_date', ''), reverse=True)
    
    return jsonify({
        'term': term,
        'assignments': all_assignments[:limit],
        'count': len(all_assignments[:limit])
    })

@app.route('/api/v1/attendance')
@require_access_token
@require_scope('attendance')
def api_attendance():
    """Get attendance summary"""
    attendance = fetch_attendance(request.session_data)
    return jsonify(attendance)

@app.route('/api/v1/schedule')
@require_access_token
@require_scope('schedule')
def api_schedule():
    """Get class schedule organized by period"""
    grades_data = fetch_grades(request.session_data)
    schedule = []
    for c in grades_data['courses']:
        schedule.append({
            'period': c['period'],
            'course': c['course'],
            'teacher': c['teacher']
        })
    # Sort by period
    schedule.sort(key=lambda x: x['period'])
    return jsonify({'schedule': schedule})

# ============================================================================
# TEACHER API ENDPOINTS
# ============================================================================

@app.route('/api/v1/teacher/me')
@require_teacher_token
@require_teacher_scope('teacher.profile')
def api_teacher_me():
    """Get current teacher's profile"""
    info = request.session_data['teacher_info']
    sections = request.session_data.get('sections', [])
    
    return jsonify({
        'username': info.get('username', ''),
        'name': info.get('name', ''),
        'first_name': info.get('first_name', ''),
        'last_name': info.get('last_name', ''),
        'class_count': len(sections)
    })

@app.route('/api/v1/teacher/classes')
@require_teacher_token
@require_teacher_scope('teacher.classes')
def api_teacher_classes():
    """Get list of classes the teacher teaches"""
    sections = request.session_data.get('sections', [])
    
    # If sections are empty, try to refresh from API
    if not sections:
        sections = teacher_fetch_sections(request.session_data)
    
    classes = []
    for section in sections:
        classes.append({
            'id': section.get('sectionsdcid', section.get('sectionlegacyid', '')),
            'name': section.get('sectionnickname', section.get('coursename', '')),
            'course_name': section.get('coursename', ''),
            'section_number': section.get('sectionnumber', ''),
            'period': section.get('expression', ''),
            'term': section.get('termabbreviation', ''),
            'school': section.get('schoolabbreviation', ''),
            'termbins': section.get('termbins', []),
        })
    
    return jsonify({'classes': classes, 'count': len(classes)})

@app.route('/api/v1/teacher/classes/<int:section_id>')
@require_teacher_token
@require_teacher_scope('teacher.classes')
def api_teacher_class_detail(section_id):
    """Get details for a specific class"""
    sections = request.session_data.get('sections', [])
    
    for section in sections:
        if section.get('sectionsdcid') == section_id or section.get('sectionlegacyid') == section_id:
            return jsonify({
                'id': section.get('sectionsdcid', section.get('sectionlegacyid', '')),
                'name': section.get('sectionnickname', section.get('coursename', '')),
                'course_name': section.get('coursename', ''),
                'course_number': section.get('coursenumber', ''),
                'section_number': section.get('sectionnumber', ''),
                'period': section.get('expression', ''),
                'term': section.get('termabbreviation', ''),
                'term_start': section.get('termstartdate', ''),
                'term_end': section.get('termenddate', ''),
                'school': section.get('schoolabbreviation', ''),
                'termbins': section.get('termbins', []),
                'gradebook_type': section.get('gradebooktype', 0),
            })
    
    return jsonify({'error': 'Class not found'}), 404

@app.route('/api/v1/teacher/classes/<int:section_id>/students')
@require_teacher_token
@require_teacher_scope('teacher.students')
def api_teacher_class_students(section_id):
    """Get students in a specific class"""
    status = request.args.get('status', 'A,P')
    
    students = teacher_fetch_students(request.session_data, [section_id], status)
    
    result = []
    for student in students:
        result.append({
            'id': student.get('dcid', student.get('_id', '')),
            'student_number': student.get('studentnumber', ''),
            'first_name': student.get('firstname', ''),
            'last_name': student.get('lastname', ''),
            'name': student.get('lastfirst', ''),
            'grade_level': student.get('gradelevel', ''),
            'gender': student.get('gender', ''),
            'has_photo': student.get('photoflag', False),
            'enrollment_status': student.get('_enrollments', [{}])[0].get('statuscode', 'A') if student.get('_enrollments') else 'A',
        })
    
    return jsonify({'students': result, 'count': len(result)})

@app.route('/api/v1/teacher/classes/<int:section_id>/assignments')
@require_teacher_token
@require_teacher_scope('teacher.assignments')
def api_teacher_class_assignments(section_id):
    """Get assignments for a specific class"""
    store_code = request.args.get('term', 'Q2')
    
    assignments_data = teacher_fetch_assignments(request.session_data, [section_id], store_code)
    
    result = []
    for assignment in assignments_data:
        for section in assignment.get('_assignmentsections', []):
            result.append({
                'id': assignment.get('assignmentid', assignment.get('_id', '')),
                'assignment_section_id': section.get('assignmentsectionid', section.get('_id', '')),
                'name': section.get('name', ''),
                'description': assignment.get('description', ''),
                'due_date': section.get('duedate', ''),
                'points_possible': section.get('totalpointvalue', 0),
                'score_type': section.get('scoretype', 'PERCENT'),
                'category_id': None,
                'is_published': section.get('isscorespublish', False),
                'count_in_grade': section.get('iscountedinfinalgrade', True),
                'publish_option': section.get('publishoption', ''),
            })
            # Get category if available
            for cat in section.get('_assignmentcategoryassociations', []):
                result[-1]['category_id'] = cat.get('teachercategoryid')
                result[-1]['category_name'] = cat.get('_teachercategory', {}).get('name', '')
                break
    
    return jsonify({'assignments': result, 'count': len(result), 'term': store_code})

@app.route('/api/v1/teacher/classes/<int:section_id>/assignments', methods=['POST'])
@require_teacher_token
@require_teacher_scope('teacher.assignments.write')
def api_teacher_create_assignment(section_id):
    """Create a new assignment for a class"""
    data = request.json
    
    if not data.get('name'):
        return jsonify({'error': 'Assignment name is required'}), 400
    
    assignment_data = {
        'name': data.get('name'),
        'description': data.get('description', ''),
        'due_date': data.get('due_date', datetime.utcnow().strftime('%Y-%m-%d')),
        'points': data.get('points', 100),
        'category_id': data.get('category_id', 2511),
        'count_in_grade': data.get('count_in_grade', True),
        'publish_scores': data.get('publish_scores', True),
        'extra_credit': data.get('extra_credit', 0),
        'weight': data.get('weight', 1),
        'year_id': data.get('year_id', 35),
    }
    
    result, error = teacher_create_assignment(request.session_data, section_id, assignment_data)
    
    if error:
        return jsonify({'error': error}), 500
    
    return jsonify({'success': True, 'assignment': result})

@app.route('/api/v1/teacher/assignments/<int:assignment_id>', methods=['DELETE'])
@require_teacher_token
@require_teacher_scope('teacher.assignments.write')
def api_teacher_delete_assignment(assignment_id):
    """Delete an assignment"""
    success, status = teacher_delete_assignment(request.session_data, assignment_id)
    
    if success:
        return jsonify({'success': True, 'message': 'Assignment deleted'})
    return jsonify({'error': f'Failed to delete assignment: {status}'}), 500

@app.route('/api/v1/teacher/classes/<int:section_id>/grades')
@require_teacher_token
@require_teacher_scope('teacher.grades')
def api_teacher_class_grades(section_id):
    """Get grades for all students in a class"""
    store_code = request.args.get('term', 'Q2')
    
    # First get students
    students = teacher_fetch_students(request.session_data, [section_id])
    student_ids = [s.get('dcid', s.get('_id')) for s in students]
    
    if not student_ids:
        return jsonify({'grades': [], 'count': 0})
    
    # Get final grades
    grades = teacher_fetch_final_grades(request.session_data, [section_id], student_ids, store_code)
    
    result = []
    for grade in grades:
        student = next((s for s in students if s.get('dcid') == grade.get('studentdcid')), {})
        result.append({
            'student_id': grade.get('studentdcid', ''),
            'student_name': student.get('lastfirst', ''),
            'grade': grade.get('grade', ''),
            'percent': grade.get('percent', 0),
            'calculated_grade': grade.get('calculatedgrade', ''),
            'calculated_percent': grade.get('calculatedpercent', 0),
            'is_locked': grade.get('islocked', False),
            'is_exempt': grade.get('isexempt', False),
            'last_update': grade.get('lastgradeupdate', ''),
        })
    
    return jsonify({'grades': result, 'count': len(result), 'term': store_code})

@app.route('/api/v1/teacher/categories')
@require_teacher_token
@require_teacher_scope('teacher.assignments')
def api_teacher_categories():
    """Get assignment categories"""
    categories = request.session_data.get('categories', [])
    
    result = []
    for cat in categories:
        if cat.get('isactive', True):
            result.append({
                'id': cat.get('teachercategoryid', cat.get('_id', '')),
                'name': cat.get('name', ''),
                'color': cat.get('color', ''),
                'default_points': cat.get('defaultscoreentrypoints', 100),
                'in_final_grade': cat.get('isinfinalgrades', True),
                'category_type': cat.get('categorytype', ''),
            })
    
    return jsonify({'categories': result, 'count': len(result)})

@app.route('/api/v1/teacher/classes/<int:section_id>/students/<int:student_id>')
@require_teacher_token
@require_teacher_scope('teacher.students')
def api_teacher_student_detail(section_id, student_id):
    """Get detailed information about a specific student in a class"""
    students = teacher_fetch_students(request.session_data, [section_id])
    
    for student in students:
        if student.get('dcid') == student_id or student.get('id') == student_id:
            # Build photo URL if student has photo
            photo_url = None
            if student.get('photoflag'):
                photo_url = f"{request.session_data['district_url']}/teachers/uspthumb/{student_id}ph.jpeg"
            
            return jsonify({
                'id': student.get('dcid', student.get('_id', '')),
                'student_number': student.get('studentnumber', ''),
                'first_name': student.get('firstname', ''),
                'last_name': student.get('lastname', ''),
                'name': student.get('lastfirst', ''),
                'grade_level': student.get('gradelevel', ''),
                'gender': student.get('gender', ''),
                'school_id': student.get('schoolid', ''),
                'person_id': student.get('personid', ''),
                'has_photo': student.get('photoflag', False),
                'photo_url': photo_url,
                'alerts': [
                    {
                        'type': alert.get('type', ''),
                        'message': alert.get('message', ''),
                        'expires': alert.get('expires', '')
                    }
                    for alert in student.get('_alerts', [])
                ],
                'enrollment': {
                    'status': student.get('_enrollments', [{}])[0].get('statuscode', 'A') if student.get('_enrollments') else 'A',
                    'enrolled_date': student.get('_enrollments', [{}])[0].get('enrolleddate', '') if student.get('_enrollments') else '',
                    'enrolled_late': student.get('_enrollments', [{}])[0].get('enrolledlate', False) if student.get('_enrollments') else False,
                }
            })
    
    return jsonify({'error': 'Student not found in this class'}), 404

@app.route('/api/v1/teacher/students/<int:student_id>/photo')
@require_teacher_token
@require_teacher_scope('teacher.students')
def api_teacher_student_photo(student_id):
    """Get student photo URL"""
    photo_url = f"{request.session_data['district_url']}/teachers/uspthumb/{student_id}ph.jpeg"
    thumbnail_url = f"{request.session_data['district_url']}/teachers/stpthumb/{student_id}ph_thumb.jpeg"
    
    return jsonify({
        'student_id': student_id,
        'photo_url': photo_url,
        'thumbnail_url': thumbnail_url
    })

@app.route('/api/v1/teacher/classes/<int:section_id>/students/alerts')
@require_teacher_token
@require_teacher_scope('teacher.students')
def api_teacher_class_alerts(section_id):
    """Get all student alerts for a class"""
    students = teacher_fetch_students(request.session_data, [section_id])
    
    alerts = []
    for student in students:
        student_alerts = student.get('_alerts', [])
        if student_alerts:
            for alert in student_alerts:
                alerts.append({
                    'student_id': student.get('dcid', student.get('_id', '')),
                    'student_name': student.get('lastfirst', ''),
                    'alert_type': alert.get('type', ''),
                    'message': alert.get('message', ''),
                    'expires': alert.get('expires', '')
                })
    
    return jsonify({'alerts': alerts, 'count': len(alerts)})

@app.route('/api/v1/teacher/classes/<int:section_id>/roster')
@require_teacher_token
@require_teacher_scope('teacher.students')
def api_teacher_class_roster(section_id):
    """Get a printable roster for a class with photos and basic info"""
    students = teacher_fetch_students(request.session_data, [section_id])
    
    # Get class info
    sections = request.session_data.get('sections', [])
    class_info = None
    for section in sections:
        if section.get('sectionsdcid') == section_id:
            class_info = {
                'name': section.get('sectionnickname', section.get('coursename', '')),
                'period': section.get('expression', ''),
                'term': section.get('termabbreviation', '')
            }
            break
    
    roster = []
    for student in students:
        photo_url = None
        if student.get('photoflag'):
            photo_url = f"{request.session_data['district_url']}/teachers/uspthumb/{student.get('dcid')}ph.jpeg"
        
        roster.append({
            'id': student.get('dcid', student.get('_id', '')),
            'student_number': student.get('studentnumber', ''),
            'name': student.get('lastfirst', ''),
            'first_name': student.get('firstname', ''),
            'last_name': student.get('lastname', ''),
            'grade_level': student.get('gradelevel', ''),
            'gender': student.get('gender', ''),
            'photo_url': photo_url,
            'has_alerts': len(student.get('_alerts', [])) > 0,
            'enrollment_status': student.get('_enrollments', [{}])[0].get('statuscode', 'A') if student.get('_enrollments') else 'A',
        })
    
    # Sort by last name
    roster.sort(key=lambda x: x.get('last_name', ''))
    
    return jsonify({
        'class': class_info,
        'students': roster,
        'count': len(roster)
    })

@app.route('/api/v1/teacher/classes/<int:section_id>/scoring')
@require_teacher_token
@require_teacher_scope('teacher.grades')
def api_teacher_scoring_metadata(section_id):
    """Get scoring metadata for a class (grade scale, etc)"""
    s = requests.Session()
    s.cookies.update(request.session_data['cookies'])
    s.headers.update({
        'User-Agent': USER_AGENT,
        'Accept': 'application/json, text/plain, */*',
        'X-Requested-With': 'XMLHttpRequest',
    })
    
    store_code = request.args.get('term', 'Q2')
    
    try:
        response = s.get(
            f"{request.session_data['district_url']}/ws/xte/section/assignment/scoring_metadata",
            params={'section_ids': str(section_id), 'status': 'A,P', 'store_code': store_code},
            timeout=30
        )
        if response.status_code == 200:
            data = response.json()
            return jsonify({'scoring_metadata': data, 'term': store_code})
        return jsonify({'error': 'Failed to fetch scoring metadata'}), response.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/teacher/classes/all/students')
@require_teacher_token
@require_teacher_scope('teacher.students')
def api_teacher_all_students():
    """Get all students across all classes taught by the teacher"""
    sections = request.session_data.get('sections', [])
    
    all_students = {}
    for section in sections:
        section_id = section.get('sectionsdcid')
        if section_id:
            students = teacher_fetch_students(request.session_data, [section_id])
            for student in students:
                student_id = student.get('dcid', student.get('_id'))
                if student_id not in all_students:
                    all_students[student_id] = {
                        'id': student_id,
                        'student_number': student.get('studentnumber', ''),
                        'name': student.get('lastfirst', ''),
                        'first_name': student.get('firstname', ''),
                        'last_name': student.get('lastname', ''),
                        'grade_level': student.get('gradelevel', ''),
                        'gender': student.get('gender', ''),
                        'has_photo': student.get('photoflag', False),
                        'classes': []
                    }
                all_students[student_id]['classes'].append({
                    'section_id': section_id,
                    'class_name': section.get('sectionnickname', section.get('coursename', '')),
                    'period': section.get('expression', '')
                })
    
    result = list(all_students.values())
    result.sort(key=lambda x: x.get('last_name', ''))
    
    return jsonify({'students': result, 'count': len(result)})

@app.route('/api/v1/teacher/search/students')
@require_teacher_token
@require_teacher_scope('teacher.students')
def api_teacher_search_students():
    """Search for students by name or student number across teacher's classes"""
    query = request.args.get('q', '').lower().strip()
    
    if not query or len(query) < 2:
        return jsonify({'error': 'Search query must be at least 2 characters'}), 400
    
    sections = request.session_data.get('sections', [])
    
    matches = []
    seen_ids = set()
    
    for section in sections:
        section_id = section.get('sectionsdcid')
        if section_id:
            students = teacher_fetch_students(request.session_data, [section_id])
            for student in students:
                student_id = student.get('dcid', student.get('_id'))
                
                # Check if already added
                if student_id in seen_ids:
                    continue
                
                # Search in name and student number
                name = student.get('lastfirst', '').lower()
                student_num = str(student.get('studentnumber', '')).lower()
                first_name = student.get('firstname', '').lower()
                last_name = student.get('lastname', '').lower()
                
                if query in name or query in student_num or query in first_name or query in last_name:
                    seen_ids.add(student_id)
                    matches.append({
                        'id': student_id,
                        'student_number': student.get('studentnumber', ''),
                        'name': student.get('lastfirst', ''),
                        'first_name': student.get('firstname', ''),
                        'last_name': student.get('lastname', ''),
                        'grade_level': student.get('gradelevel', ''),
                        'class_name': section.get('sectionnickname', section.get('coursename', '')),
                        'section_id': section_id
                    })
    
    return jsonify({'results': matches, 'count': len(matches), 'query': query})

# ============================================================================
# TEACHER STUDENT DATA ENDPOINTS
# ============================================================================

@app.route('/api/v1/teacher/students/<int:student_id>/full-schedule')
@require_teacher_token
@require_teacher_scope('teacher.students')
def api_teacher_student_full_schedule(student_id):
    """Get the FULL schedule for a student - all classes in their schedule, not just yours"""
    full_schedule = teacher_fetch_student_full_schedule(request.session_data, student_id)
    
    if not full_schedule:
        return jsonify({'error': 'Could not fetch student schedule'}), 404
    
    # Get basic student info from one of teacher's classes (if available)
    student_info = None
    student_classes = teacher_fetch_student_all_classes(request.session_data, student_id)
    if student_classes:
        for cls in student_classes:
            students = teacher_fetch_students(request.session_data, [cls['section_id']])
            for s in students:
                if str(s.get('dcid')) == str(student_id):
                    student_info = {
                        'id': s.get('dcid', ''),
                        'name': s.get('lastfirst', ''),
                        'student_number': s.get('studentnumber', ''),
                        'grade_level': s.get('gradelevel', '')
                    }
                    break
            if student_info:
                break
    
    return jsonify({
        'student': student_info,
        'schedule': full_schedule,
        'count': len(full_schedule)
    })

@app.route('/api/v1/teacher/students/<int:student_id>/all-grades')
@require_teacher_token
@require_teacher_scope('teacher.grades')
def api_teacher_student_all_grades(student_id):
    """Get grades for ALL classes in a student's schedule (not just your classes)"""
    store_code = request.args.get('term', 'Q2')
    
    grades = teacher_fetch_student_grades_all_classes(request.session_data, student_id, store_code)
    
    if not grades:
        return jsonify({'error': 'Could not fetch student grades'}), 404
    
    # Get basic student info
    student_info = None
    student_classes = teacher_fetch_student_all_classes(request.session_data, student_id)
    if student_classes:
        for cls in student_classes:
            students = teacher_fetch_students(request.session_data, [cls['section_id']])
            for s in students:
                if str(s.get('dcid')) == str(student_id):
                    photo_url = None
                    if s.get('photoflag'):
                        photo_url = f"{request.session_data['district_url']}/teachers/uspthumb/{student_id}ph.jpeg"
                    student_info = {
                        'id': s.get('dcid', ''),
                        'name': s.get('lastfirst', ''),
                        'student_number': s.get('studentnumber', ''),
                        'grade_level': s.get('gradelevel', ''),
                        'photo_url': photo_url
                    }
                    break
            if student_info:
                break
    
    # Calculate summary stats
    graded_classes = [g for g in grades if g.get('percent') is not None]
    avg_percent = sum(g['percent'] for g in graded_classes) / len(graded_classes) if graded_classes else None
    
    return jsonify({
        'student': student_info,
        'term': store_code,
        'grades': grades,
        'class_count': len(grades),
        'graded_count': len(graded_classes),
        'average_percent': round(avg_percent, 1) if avg_percent else None
    })

# ============================================================================
# TEACHER GRADING ENDPOINTS
# ============================================================================

@app.route('/api/v1/teacher/scores', methods=['POST'])
@require_teacher_token
@require_teacher_scope('teacher.grades')
def api_teacher_update_score():
    """Update/add a score for a student on an assignment
    
    Requires: student_id, assignment_id, section_id, score
    """
    data = request.json
    
    if not data:
        return jsonify({'error': 'Request body required'}), 400
    
    student_id = data.get('student_id')
    assignment_id = data.get('assignment_id')
    section_id = data.get('section_id')
    score = data.get('score')
    
    if not all([student_id, assignment_id, section_id]):
        return jsonify({'error': 'Missing required fields: student_id, assignment_id, section_id'}), 400
    
    # Fetch assignment to get assignment_section_id
    assignments = teacher_fetch_assignments(request.session_data, [section_id])
    assignment_section_id = None
    for a in assignments:
        if a.get('assignmentid') == int(assignment_id):
            for section in a.get('_assignmentsections', []):
                assignment_section_id = section.get('assignmentsectionid')
                break
            break
    
    if not assignment_section_id:
        return jsonify({'error': 'Assignment not found in this section'}), 404
    
    # Check if score already exists for this student
    existing_scores = teacher_fetch_student_scores(request.session_data, [section_id], [student_id])
    score_id = None
    for item in existing_scores:
        if item.get('assignmentid') == int(assignment_id):
            for section in item.get('_assignmentsections', []):
                for s in section.get('_assignmentscores', []):
                    if str(s.get('studentsdcid')) == str(student_id):
                        score_id = s.get('_id')
                        break
    
    # Build score object
    score_data = {
        'studentsdcid': int(student_id),
        'islate': data.get('is_late', False),
        'isexempt': data.get('is_exempt', False),
        'ismissing': data.get('is_missing', False),
        'actualscorekind': 'REAL_SCORE',
        'scorepercent': None,
        '_assignmentsection': {
            'assignmentsectionid': int(assignment_section_id),
            'sectionsdcid': int(section_id),
            '_assignment': {
                'assignmentid': int(assignment_id)
            }
        }
    }
    
    if score is not None:
        score_data['actualscoreentered'] = str(score)
    
    if score_id:
        score_data['_id'] = int(score_id)
    
    if data.get('comment'):
        score_data['_assignmentscorecomment'] = {
            'comment': data['comment']
        }
    
    result, error = teacher_update_score(request.session_data, score_data)
    
    if error:
        return jsonify({'error': error}), 400
    
    if result and result.get('assignment_scores'):
        updated_score = result['assignment_scores'][0]
        return jsonify({
            'success': True,
            'score': {
                'id': updated_score.get('_id') or updated_score.get('id'),
                'student_id': updated_score.get('studentsdcid'),
                'score_points': updated_score.get('scorepoints'),
                'score_percent': updated_score.get('scorepercent'),
                'letter_grade': updated_score.get('scorelettergrade'),
                'is_late': updated_score.get('islate', False),
                'is_missing': updated_score.get('ismissing', False),
                'is_exempt': updated_score.get('isexempt', False),
            }
        })
    
    return jsonify({'success': True, 'result': result})

@app.route('/api/v1/teacher/scores/batch', methods=['POST'])
@require_teacher_token
@require_teacher_scope('teacher.grades')
def api_teacher_update_scores_batch():
    """Update multiple scores at once (batch grading)
    
    Requires: section_id, assignment_id, and scores array with student_id and score
    """
    data = request.json
    
    if not data or not data.get('scores'):
        return jsonify({'error': 'Request body with scores array required'}), 400
    
    section_id = data.get('section_id')
    assignment_id = data.get('assignment_id')
    
    if not section_id or not assignment_id:
        return jsonify({'error': 'Missing required fields: section_id, assignment_id'}), 400
    
    scores_list = data['scores']
    if not isinstance(scores_list, list) or len(scores_list) == 0:
        return jsonify({'error': 'scores must be a non-empty array'}), 400
    
    # Get assignment_section_id
    assignments = teacher_fetch_assignments(request.session_data, [section_id])
    assignment_section_id = None
    for a in assignments:
        if a.get('assignmentid') == int(assignment_id):
            for section in a.get('_assignmentsections', []):
                assignment_section_id = section.get('assignmentsectionid')
                break
            break
    
    if not assignment_section_id:
        return jsonify({'error': 'Assignment not found in this section'}), 404
    
    # Get existing scores to find score_ids
    student_ids = [s['student_id'] for s in scores_list if s.get('student_id')]
    existing_scores = teacher_fetch_student_scores(request.session_data, [section_id], student_ids)
    
    # Build map of student_id -> score_id
    score_id_map = {}
    for item in existing_scores:
        if item.get('assignmentid') == int(assignment_id):
            for section in item.get('_assignmentsections', []):
                for score in section.get('_assignmentscores', []):
                    score_id_map[str(score.get('studentsdcid'))] = score.get('_id')
    
    # Build score objects
    score_objects = []
    for s in scores_list:
        student_id = s.get('student_id')
        if not student_id:
            continue
            
        score_obj = {
            'studentsdcid': int(student_id),
            'islate': s.get('is_late', False),
            'isexempt': s.get('is_exempt', False),
            'ismissing': s.get('is_missing', False),
            'actualscorekind': 'REAL_SCORE',
            'scorepercent': None,
            '_assignmentsection': {
                'assignmentsectionid': int(assignment_section_id),
                'sectionsdcid': int(section_id),
                '_assignment': {
                    'assignmentid': int(assignment_id)
                }
            }
        }
        
        if s.get('score') is not None:
            score_obj['actualscoreentered'] = str(s['score'])
        
        # Add existing score_id if we have one
        if str(student_id) in score_id_map:
            score_obj['_id'] = int(score_id_map[str(student_id)])
        
        score_objects.append(score_obj)
    
    # Make the request
    payload = {'assignment_scores': score_objects}
    
    response = teacher_make_request(
        request.session_data, 'PUT', '/ws/xte/score?status=A,I,P',
        data=json.dumps(payload),
        headers={
            'Content-Type': 'application/json;charset=UTF-8',
            'Origin': request.session_data['district_url'],
            'Referer': f"{request.session_data['district_url']}/teachers/index.html",
        }
    )
    
    if response and response.status_code == 200:
        result = response.json()
        updated_scores = []
        for score in result.get('assignment_scores', []):
            updated_scores.append({
                'id': score.get('_id') or score.get('id'),
                'student_id': score.get('studentsdcid'),
                'score_points': score.get('scorepoints'),
                'score_percent': score.get('scorepercent'),
                'letter_grade': score.get('scorelettergrade'),
            })
        return jsonify({
            'success': True,
            'updated_count': len(updated_scores),
            'scores': updated_scores
        })
    
    error_detail = ''
    if response:
        try:
            error_detail = response.text[:200]
        except:
            pass
    return jsonify({'error': f'Failed to update scores: {response.status_code if response else "No response"} {error_detail}'}), 400

@app.route('/api/v1/teacher/scores/delete', methods=['POST'])
@require_teacher_token
@require_teacher_scope('teacher.grades')
def api_teacher_delete_score():
    """Delete/clear a score for a student
    
    Requires: student_id, assignment_id, section_id
    Note: This sets the score to null/missing rather than truly deleting.
    """
    data = request.json or {}
    
    student_id = data.get('student_id')
    assignment_id = data.get('assignment_id')
    section_id = data.get('section_id')
    
    if not all([student_id, assignment_id, section_id]):
        return jsonify({'error': 'Missing required fields: student_id, assignment_id, section_id'}), 400
    
    # Get assignment_section_id
    assignments = teacher_fetch_assignments(request.session_data, [section_id])
    assignment_section_id = None
    for a in assignments:
        if a.get('assignmentid') == int(assignment_id):
            for section in a.get('_assignmentsections', []):
                assignment_section_id = section.get('assignmentsectionid')
                break
            break
    
    if not assignment_section_id:
        return jsonify({'error': 'Assignment not found in this section'}), 404
    
    # Find existing score_id
    existing_scores = teacher_fetch_student_scores(request.session_data, [section_id], [student_id])
    score_id = None
    for item in existing_scores:
        if item.get('assignmentid') == int(assignment_id):
            for section in item.get('_assignmentsections', []):
                for s in section.get('_assignmentscores', []):
                    if str(s.get('studentsdcid')) == str(student_id):
                        score_id = s.get('_id')
                        break
    
    if not score_id:
        return jsonify({'error': 'No score found for this student on this assignment'}), 404
    
    # To "delete" a score, we update it to have no value and optionally mark as missing
    score_data = {
        '_id': int(score_id),
        'studentsdcid': int(student_id),
        'islate': False,
        'isexempt': False,
        'ismissing': data.get('mark_missing', False),
        'actualscoreentered': '',
        'actualscorekind': 'REAL_SCORE',
        'scorepercent': None,
        '_assignmentsection': {
            'assignmentsectionid': int(assignment_section_id),
            'sectionsdcid': int(section_id),
            '_assignment': {
                'assignmentid': int(assignment_id)
            }
        }
    }
    
    result, error = teacher_update_score(request.session_data, score_data)
    
    if error:
        return jsonify({'error': error}), 400
    
    return jsonify({
        'success': True,
        'message': 'Score cleared successfully'
    })

@app.route('/api/v1/teacher/assignments/<int:assignment_id>/scores', methods=['GET'])
@require_teacher_token
@require_teacher_scope('teacher.grades')
def api_teacher_get_assignment_scores(assignment_id):
    """Get all scores for a specific assignment"""
    section_id = request.args.get('section_id')
    
    if not section_id:
        return jsonify({'error': 'section_id query parameter required'}), 400
    
    # Fetch assignment scores using POST /ws/xte/assignment_score
    payload = json.dumps({
        'assignment_ids': [str(assignment_id)],
        'section_ids': [str(section_id)]
    })
    
    response = teacher_make_request(
        request.session_data, 'POST', '/ws/xte/assignment_score',
        data=payload,
        headers={
            'Content-Type': 'application/json;charset=UTF-8',
            'Origin': request.session_data['district_url'],
            'Referer': f"{request.session_data['district_url']}/teachers/index.html",
        }
    )
    
    if response and response.status_code == 200:
        result = response.json()
        scores = []
        for score in result:
            scores.append({
                'student_id': score.get('studentsdcid'),
                'score_points': score.get('scorepoints'),
                'score_percent': score.get('scorepercent'),
                'letter_grade': score.get('scorelettergrade'),
                'is_late': score.get('islate', False),
                'is_missing': score.get('ismissing', False),
                'is_exempt': score.get('isexempt', False),
            })
        
        return jsonify({
            'assignment_id': assignment_id,
            'section_id': section_id,
            'scores': scores,
            'count': len(scores)
        })
    
    return jsonify({'error': 'Failed to fetch scores'}), 400

@app.route('/api/v1/teacher/students/<int:student_id>/scores', methods=['GET'])
@require_teacher_token
@require_teacher_scope('teacher.grades')
def api_teacher_get_student_scores(student_id):
    """Get all scores for a specific student in a class"""
    section_id = request.args.get('section_id')
    store_code = request.args.get('term', 'Q2')
    
    if not section_id:
        return jsonify({'error': 'section_id query parameter required'}), 400
    
    # Fetch scores using assignment lookup
    scores_data = teacher_fetch_student_scores(request.session_data, [int(section_id)], [student_id], store_code)
    
    assignments = []
    for item in scores_data:
        for section in item.get('_assignmentsections', []):
            assignment = {
                'assignment_id': item.get('assignmentid', ''),
                'name': section.get('name', ''),
                'due_date': section.get('duedate', ''),
                'points_possible': section.get('totalpointvalue', 0),
                'score': None,
            }
            
            for score_data in section.get('_assignmentscores', []):
                if str(score_data.get('studentsdcid')) == str(student_id):
                    assignment['score'] = score_data.get('scorepoints')
                    assignment['score_percent'] = score_data.get('scorepercent')
                    assignment['letter_grade'] = score_data.get('scorelettergrade')
                    assignment['is_late'] = score_data.get('islate', False)
                    assignment['is_missing'] = score_data.get('ismissing', False)
                    assignment['is_exempt'] = score_data.get('isexempt', False)
                    break
            
            assignments.append(assignment)
    
    return jsonify({
        'student_id': student_id,
        'section_id': section_id,
        'term': store_code,
        'assignments': assignments,
        'count': len(assignments)
    })

# ============================================================================
# API PLAYGROUND
# ============================================================================

@app.route('/playground')
@require_developer_auth
def playground():
    """Interactive API playground"""
    developer = Developer.query.get(session['developer_id'])
    return render_template('playground.html', scopes=VALID_SCOPES, developer=developer)

@app.route('/playground/quick-auth', methods=['POST'])
@require_developer_auth
def playground_quick_auth():
    """Quick authentication for playground testing"""
    data = request.json
    district_url = data.get('district_url', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not district_url or not username or not password:
        return jsonify({'error': 'Missing required fields'})
    
    # Authenticate with PowerSchool
    result, error = powerschool_login(district_url, username, password)
    
    if error:
        return jsonify({'error': error})
    
    # Create session with encrypted credentials
    session_token = generate_token('sess_')
    student_session = StudentSession(
        token=session_token,
        cookies=result['cookies'],
        district_url=result['district_url'],
        student_info=result['student_info'],
        home_html=result['home_html'],
        expires_at=time.time() + 1800,  # 30 minutes - PowerSchool sessions expire quickly
        encrypted_username=encrypt_credential(username),
        encrypted_password=encrypt_credential(password)
    )
    db.session.add(student_session)
    
    # Create access token with all scopes for testing
    access_token = generate_token('at_')
    access_token_record = AccessToken(
        token=access_token,
        app_id='playground',
        session_token=session_token,
        scopes=list(VALID_SCOPES.keys()),
        expires_at=time.time() + 3600
    )
    db.session.add(access_token_record)
    db.session.commit()
    
    return jsonify({
        'access_token': access_token,
        'token_type': 'Bearer',
        'expires_in': 3600,
        'student_name': result['student_info']['name']
    })

@app.route('/playground/test', methods=['POST'])
@require_developer_auth
def playground_test():
    """Test API endpoint from playground"""
    data = request.json
    endpoint = data.get('endpoint', '')
    token = data.get('token', '')
    
    if not endpoint or not token:
        return jsonify({'error': 'Missing endpoint or token'})
    
    # Make request to our own API
    headers = {'Authorization': f'Bearer {token}'}
    
    try:
        with app.test_client() as client:
            response = client.get(endpoint, headers=headers)
            return jsonify({
                'status': response.status_code,
                'data': response.get_json()
            })
    except Exception as e:
        return jsonify({'error': str(e)})

# ============================================================================
# TEACHER PLAYGROUND
# ============================================================================

@app.route('/playground/teachers')
@require_developer_auth
def teacher_playground():
    """Interactive teacher API playground"""
    developer = Developer.query.get(session['developer_id'])
    return render_template('teacher_playground.html', scopes=TEACHER_SCOPES, developer=developer)

@app.route('/playground/teachers/quick-auth', methods=['POST'])
@require_developer_auth
def teacher_playground_quick_auth():
    """Quick authentication for teacher playground testing"""
    data = request.json
    district_url = data.get('district_url', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not district_url or not username or not password:
        return jsonify({'error': 'Missing required fields'})
    
    # Authenticate with PowerTeacher
    result, error = powerteacher_login(district_url, username, password)
    
    if error:
        return jsonify({'error': error})
    
    # Create session with encrypted credentials
    session_token = generate_token('tsess_')
    teacher_session = TeacherSession(
        token=session_token,
        cookies=result['cookies'],
        district_url=result['district_url'],
        teacher_info=result['teacher_info'],
        sections=result['sections'],
        categories=result['categories'],
        expires_at=time.time() + 1800,
        encrypted_username=encrypt_credential(username),
        encrypted_password=encrypt_credential(password)
    )
    db.session.add(teacher_session)
    
    # Create access token with all teacher scopes for testing
    access_token = generate_token('tat_')
    access_token_record = TeacherAccessToken(
        token=access_token,
        app_id='teacher_playground',
        session_token=session_token,
        scopes=list(TEACHER_SCOPES.keys()),
        expires_at=time.time() + 3600
    )
    db.session.add(access_token_record)
    db.session.commit()
    
    return jsonify({
        'access_token': access_token,
        'token_type': 'Bearer',
        'expires_in': 3600,
        'teacher_name': result['teacher_info']['name'],
        'class_count': len(result['sections'])
    })

# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
