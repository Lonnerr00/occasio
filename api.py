from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from pymongo import MongoClient, server_api
import os
import random
import json
from smtplib import SMTP
import jwt
import bleach
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
# from redis import Redis

# Load environment variables
load_dotenv()
EMAIL_USER = os.getenv('EMAIL_USER')
EMAIL_PASS = os.getenv('EMAIL_PASS')
mongo_pass = os.getenv('mongo_pass')
mongo_user = os.getenv('mongo_user')
SECRET_KEY = os.getenv('SECRET_KEY')

# MongoDB URI
MONGO_URI = f'mongodb+srv://{mongo_user}:{mongo_pass}@cluster0.vqfml.mongodb.net/'

# Initialize Flask app
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Rate Limiter setup with Redis
# redis_client = Redis(host='localhost', port=6379)
limiter = Limiter(
    key_func=get_remote_address,
    # storage_uri="redis://localhost:6379",
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

limiter.init_app(app)

# Function to sanitize inputs
def sanitize_input(data):
    if not isinstance(data, str):
        return data
    return bleach.clean(data)

# Authentication decorator
def authenticate_request(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Missing token'}), 401
        try:
            token = token.split("Bearer ")[1]
            jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        return func(*args, **kwargs)
    return wrapper

# MongoDB client setup
client = MongoClient(MONGO_URI, server_api=server_api.ServerApi('1'))
try:
    client.admin.command('ping')
    print("Connected to MongoDB!")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")

db = client['Occasio_EventReminder']
user_collection = db['UsersList']

# Email credentials
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587

# JSON file to store local data
DATA_FILE = 'data.json'

# Utility Functions
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as file:
            return json.load(file)
    return {}

def save_data(data):
    with open(DATA_FILE, 'w') as file:
        json.dump(data, file, indent=4)

def sync_with_mongo():
    """Synchronize local JSON with MongoDB."""
    users = list(user_collection.find({}, {"_id": 0}))
    save_data({user['email']: user for user in users})

def generate_otp():
    return str(random.randint(100000, 999999))

# Generate JWT token
def generate_token(email):
    payload = {
        'email': email,
        'exp': datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

# Home route
@app.route('/')
def home():
    return 'Welcome to the Flask API!'

# Send OTP API
@app.route('/send-otp', methods=['POST'])
def send_otp():
    if not request.is_json:
        return jsonify({'message': 'Request must be JSON'}), 400

    data = request.json
    email = sanitize_input(data.get('email'))
    otp = generate_otp()

    try:
        # Send OTP via email
        with SMTP(EMAIL_HOST, EMAIL_PORT) as smtp:
            smtp.starttls()
            smtp.login(EMAIL_USER, EMAIL_PASS)
            smtp.sendmail(EMAIL_USER, email, f"Subject: Signup OTP\n\nYour OTP is {otp}")

        # Store OTP temporarily
        user_collection.update_one({'email': email}, {'$set': {'otp': otp}}, upsert=True)
        return jsonify({'message': 'OTP sent successfully!'}), 200
    except Exception as e:
        app.logger.error(f'Failed to send OTP: {e}')
        return jsonify({'message': 'Failed to send OTP.', 'error': str(e)}), 500

# Login API
@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({'message': 'Request must be JSON'}), 400

    print(request);
    data = request.json
    email = sanitize_input(data.get('email'))
    password = sanitize_input(data.get('password'))

    try:
        user = user_collection.find_one({'email': email})
        if not user or user['password'] != password:
            return jsonify({'message': 'Invalid email or password.'}), 401

        token = generate_token(user['email'])
        return jsonify({
            'message': 'Login successful.',
            'token': token,
            'name': user['name'],
            'email': user['email'],
            'password': user['password'],
            'mobile': user.get('mobile', '')
        }), 200
    except Exception as e:
        app.logger.error(f'Login failed: {e}')
        return jsonify({'message': 'Login failed.', 'error': str(e)}), 500

# Resend OTP API
@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    if not request.is_json:
        return jsonify({'message': 'Request must be JSON'}), 400

    data = request.json
    email = sanitize_input(data.get('email'))
    otp = generate_otp()

    try:
        user = user_collection.find_one({'email': email})
        if not user:
            return jsonify({'message': 'Email not found.'}), 404

        # Send OTP via email
        with SMTP(EMAIL_HOST, EMAIL_PORT) as smtp:
            smtp.starttls()
            smtp.login(EMAIL_USER, EMAIL_PASS)
            smtp.sendmail(EMAIL_USER, email, f"Subject: Resend OTP\n\nYour OTP is {otp}")

        user_collection.update_one({'email': email}, {'$set': {'otp': otp}})
        sync_with_mongo()
        return jsonify({'message': 'OTP resent successfully.'}), 200
    except Exception as e:
        app.logger.error(f'Failed to resend OTP: {e}')
        return jsonify({'message': 'Failed to resend OTP.', 'error': str(e)}), 500

# Verify OTP API
@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    if not request.is_json:
        return jsonify({'message': 'Request must be JSON'}), 400

    data = request.json
    email = sanitize_input(data.get('email'))
    otp = data.get('otp')
    name = sanitize_input(data.get('name'))
    password = sanitize_input(data.get('password'))
    mobile = sanitize_input(data.get('mobile'))
    events = data.get('events', [])
    settings = data.get('settings', {})
    signupDate = data.get('signupDate')

    try:
        user = user_collection.find_one({'email': email})
        if not user:
            return jsonify({'message': 'Email not found.'}), 404
        if user['otp'] == otp:
            # Add user data to the database
            user_data = {
                'email': email,
                'name': name,
                'password': password,
                'events': events,
                'mobile': mobile,
                'settings': settings,
                'signupDate': signupDate,
                'loggedIn': True
            }
            user_collection.replace_one({'email': email}, user_data, upsert=True)
            sync_with_mongo()
            token = generate_token(email)
            return jsonify({'message': 'OTP verified successfully.', 'token': token, 'userData': user_data}), 200
        return jsonify({'message': 'Invalid OTP.'}), 400
    except Exception as e:
        return jsonify({'message': 'Failed to verify OTP.', 'error': str(e)}), 500

# Get Users API
@app.route('/get-users', methods=['GET'])
def get_users():
    try:
        users = list(user_collection.find({}, {"_id": 0}))
        return jsonify({'users': users}), 200
    except Exception as e:
        app.logger.error(f'Error retrieving users: {e}')
        return jsonify({'message': 'Failed to retrieve users.', 'error': str(e)}), 500

# Get Events API
@app.route('/events', methods=['GET'])
@authenticate_request
def get_events():
    email = request.headers.get('email')
    if not email:  # Check if email is provided in the headers
        return jsonify({'message': 'Missing email in request headers.'}), 400
    try:
        user = user_collection.find_one({'email': email})
        if not user:
            return jsonify({'message': 'User not found.'}), 404
        events = user.get('events', [])
        return jsonify({'events': events}), 200
    except Exception as e:
        app.logger.error(f'Error retrieving events: {e}')
        return jsonify({'message': 'Failed to retrieve events.', 'error': str(e)}), 500

# Update Events API
@app.route('/update-events', methods=['POST'])
@authenticate_request
def update_events():
    data = request.json
    email = sanitize_input(data.get('email'))
    events = data.get('events')

    try:
        user = user_collection.find_one({'email': email})
        if not user:
            return jsonify({'message': 'User not found.'}), 404

        user_collection.update_one({'email': email}, {'$set': {'events': events}})
        sync_with_mongo()
        return jsonify({'message': 'Events updated successfully.'}), 200
    except Exception as e:
        app.logger.error(f'Error updating events: {e}')
        return jsonify({'message': 'Failed to update events.', 'error': str(e)}), 500

# Update User API
@app.route('/update-user', methods=['POST'])
@authenticate_request
def update_user():
    if not request.is_json:
        return jsonify({'message': 'Request must be JSON'}), 400

    data = request.json
    email = sanitize_input(data.get('email'))

    try:
        user = user_collection.find_one({'email': email})
        if not user:
            return jsonify({'message': 'User not found.'}), 404

        user_collection.update_one({'email': email}, {'$set': data})
        sync_with_mongo()
        return jsonify({'message': 'User updated successfully.'}), 200
    except Exception as e:
        app.logger.error(f'Error updating user: {e}')
        return jsonify({'message': 'Failed to update user.', 'error': str(e)}), 500

# Refresh Token API
@app.route('/refresh-token', methods=['POST'])
@authenticate_request
def refresh_token():
    token = request.headers.get('Authorization').split("Bearer ")[1]
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        email = decoded['email']
        new_token = generate_token(email)
        return jsonify({'token': new_token}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

# Logger setup
handler = RotatingFileHandler('api.log', maxBytes=10000, backupCount=1)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

if __name__ == '__main__':
    sync_with_mongo()
    app.run(host='0.0.0.0', port=5000)
