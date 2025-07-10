from flask import Flask, render_template, request, session, jsonify
import sqlite3
import hashlib
import os
import logging
import re
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)

DATABASE = os.environ.get('DATABASE', 'users.db')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    try:
        os.makedirs(os.path.dirname(DATABASE) if os.path.dirname(DATABASE) else '.', exist_ok=True)
        conn = get_db_connection()
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                phone TEXT,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
        logger.info(f"Database initialized successfully at {DATABASE}")
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        raise

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_username(username):
    pattern = r'^[a-zA-Z0-9_]{3,20}$'
    return re.match(pattern, username) is not None

def validate_phone(phone):
    if not phone:
        return True
    pattern = r'^\+?[0-9\s\-]{10,15}$'
    return re.match(pattern, phone) is not None

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Za-z]', password):
        return False, "Password must contain at least one letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    return True, "Valid password"

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def api_response(success=True, message="", data=None, status_code=200):
    response = {
        'success': success,
        'message': message,
        'timestamp': datetime.now().isoformat()
    }
    if data is not None:
        response['data'] = data
    return jsonify(response), status_code

# Frontend Routes (serve HTML pages)
@app.route('/')
def index():
    if 'user_id' in session:
        return render_template('profile.html')
    return render_template('login.html')

@app.route('/login')
def login_page():
    if 'user_id' in session:
        return render_template('profile.html')
    return render_template('login.html')

@app.route('/signup')
def signup_page():
    if 'user_id' in session:
        return render_template('profile.html')
    return render_template('signup.html')

@app.route('/profile')
def profile_page():
    if 'user_id' not in session:
        return render_template('login.html')
    return render_template('profile.html')

# API Routes
@app.route('/api/auth/signup', methods=['POST'])
def api_signup():
    try:
        data = request.get_json()
        
        if not data:
            return api_response(False, "No data provided", status_code=400)
        
        full_name = data.get('full_name', '').strip()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        phone = data.get('phone', '').strip()
        password = data.get('password', '')
        
        logger.info(f"API signup attempt for username: {username}, email: {email}")
        
        # Validate required fields
        if not full_name or not username or not email or not password:
            return api_response(False, "Full name, username, email, and password are required", status_code=400)
        
        # Validate full name
        if len(full_name) < 2 or len(full_name) > 100:
            return api_response(False, "Full name must be between 2 and 100 characters", status_code=400)
        
        # Validate username
        if not validate_username(username):
            return api_response(False, "Username must be 3-20 characters and contain only letters, numbers, and underscores", status_code=400)
        
        # Validate email
        if not validate_email(email):
            return api_response(False, "Please enter a valid email address", status_code=400)
        
        # Validate phone (optional)
        if phone and not validate_phone(phone):
            return api_response(False, "Please enter a valid phone number", status_code=400)
        
        # Validate password
        is_valid_password, password_message = validate_password(password)
        if not is_valid_password:
            return api_response(False, password_message, status_code=400)
        
        conn = get_db_connection()
        
        # Check for existing username
        existing_username = conn.execute(
            'SELECT id FROM users WHERE username = ?', (username,)
        ).fetchone()
        
        # Check for existing email
        existing_email = conn.execute(
            'SELECT id FROM users WHERE email = ?', (email,)
        ).fetchone()
        
        if existing_username and existing_email:
            conn.close()
            logger.warning(f"API signup failed - both username {username} and email {email} exist")
            return api_response(False, "Both username and email already exist", status_code=409)
        elif existing_username:
            conn.close()
            logger.warning(f"API signup failed - username {username} already exists")
            return api_response(False, "Username already exists", status_code=409)
        elif existing_email:
            conn.close()
            logger.warning(f"API signup failed - email {email} already exists")
            return api_response(False, "Email already exists", status_code=409)
        
        # Create the user
        cursor = conn.execute(
            'INSERT INTO users (full_name, username, email, phone, password) VALUES (?, ?, ?, ?, ?)',
            (full_name, username, email, phone, hash_password(password))
        )
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        logger.info(f"API user created successfully: {username} ({email}) with ID: {user_id}")
        return api_response(True, "Account created successfully", {"user_id": user_id})
        
    except sqlite3.Error as e:
        logger.error(f"Database error during API signup: {str(e)}")
        return api_response(False, "Database error occurred", status_code=500)
    except Exception as e:
        logger.error(f"Unexpected error during API signup: {str(e)}")
        return api_response(False, "An unexpected error occurred", status_code=500)

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json()
        
        if not data:
            return api_response(False, "No data provided", status_code=400)
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        logger.info(f"API login attempt for username: {username}")
        
        # Basic validation
        if not username or not password:
            logger.warning(f"API login failed - missing credentials for username: {username}")
            return api_response(False, "Username and password are required", status_code=400)
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        conn.close()
        
        if user and user['password'] == hash_password(password):
            session['user_id'] = user['id']
            session['full_name'] = user['full_name']
            session['username'] = user['username']
            session['email'] = user['email']
            session['phone'] = user['phone']
            
            logger.info(f"API successful login for user: {username} (ID: {user['id']})")
            
            return api_response(True, f"Welcome back, {user['full_name']}!", {
                'user': {
                    'id': user['id'],
                    'full_name': user['full_name'],
                    'username': user['username'],
                    'email': user['email'],
                    'phone': user['phone']
                }
            })
        else:
            logger.warning(f"API failed login attempt for username: {username}")
            return api_response(False, "Invalid username or password", status_code=401)
            
    except Exception as e:
        logger.error(f"API error during login: {str(e)}")
        return api_response(False, "An error occurred during login", status_code=500)

@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def api_logout():
    username = session.get('username', 'Unknown')
    logger.info(f"API user logged out: {username}")
    session.clear()
    return api_response(True, "Logged out successfully")

@app.route('/api/user/profile', methods=['GET'])
@require_auth
def api_get_profile():
    try:
        logger.info(f"API profile accessed by user: {session.get('username')} (ID: {session.get('user_id')})")
        
        user_data = {
            'id': session.get('user_id'),
            'full_name': session.get('full_name'),
            'username': session.get('username'),
            'email': session.get('email'),
            'phone': session.get('phone')
        }
        
        return api_response(True, "Profile retrieved successfully", {'user': user_data})
        
    except Exception as e:
        logger.error(f"API error retrieving profile: {str(e)}")
        return api_response(False, "Error retrieving profile", status_code=500)

@app.route('/api/auth/status', methods=['GET'])
def api_auth_status():
    if 'user_id' in session:
        return api_response(True, "User is authenticated", {
            'authenticated': True,
            'user': {
                'id': session.get('user_id'),
                'username': session.get('username'),
                'full_name': session.get('full_name')
            }
        })
    else:
        return api_response(True, "User is not authenticated", {'authenticated': False})

@app.route('/health')
def health():
    try:
        conn = get_db_connection()
        conn.execute('SELECT 1').fetchone()
        conn.close()
        logger.debug("Health check passed")
        return api_response(True, "Service is healthy", {'database': 'connected'})
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return api_response(False, "Service is unhealthy", {'error': str(e)}, 503)

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return api_response(False, "Endpoint not found", status_code=404)

@app.errorhandler(405)
def method_not_allowed(error):
    return api_response(False, "Method not allowed", status_code=405)

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    return api_response(False, "Internal server error", status_code=500)

init_db()

if __name__ == '__main__':
    app.run()