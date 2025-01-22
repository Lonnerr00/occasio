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
    if users:
        users = list(user_collection.find({}, {"_id": 0}))
        save_data({user['email']: user for user in users})

# Function to generate OTP with expiry
def generate_otp():
    otp = str(random.randint(100000, 999999))
    expiry_time = datetime.utcnow() + timedelta(minutes=5)  # OTP expires in 5 minutes
    return otp, expiry_time

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
    otp, expiry_time = generate_otp()
    token = generate_token(email)

    try:
        # Send OTP via email
        with SMTP(EMAIL_HOST, EMAIL_PORT) as smtp:
            smtp.starttls()
            smtp.login(EMAIL_USER, EMAIL_PASS)
            smtp.sendmail(EMAIL_USER, email, f"Subject: Signup OTP\n\nYour OTP is {otp}")

        return jsonify({'message': 'OTP sent successfully!', 'otp': otp, 'token': token}), 200
    except Exception as e:
        app.logger.error(f'Failed to send OTP: {e}')
        return jsonify({'message': 'Failed to send OTP.', 'error': str(e)}), 500

# Login API
@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({'message': 'Request must be JSON'}), 400

    data = request.json
    email = sanitize_input(data.get('email'))
    password = sanitize_input(data.get('password'))

    try:
        user = user_collection.find_one({'email': email})
        if not user or user['password'] != password:
            return jsonify({'message': 'Invalid email or password.'}), 401

        token = generate_token(user['email'])
        user['_id'] = str(user['_id'])
        return jsonify({
            'message': 'Login successful.',
            'token': token,
            'userData': {
                'email': user['email'],
                'name': user['name'],
                'events': user['events'],
                'mobile': user['mobile'],
                'settings': user.get('settings', {}),
                'signupDate': user['signupDate'],
                'password': user['password'],
                'signupDate': user['signupDate']
            }
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

        # No longer storing OTP in the database
        return jsonify({'message': 'OTP resent successfully.', 'otp': otp}), 200
    except Exception as e:
        app.logger.error(f'Failed to resend OTP: {e}')
        return jsonify({'message': 'Failed to resend OTP.', 'error': str(e)}), 500

# Signup API
@app.route('/signup', methods=['POST'])
def signup():
    if not request.is_json:
        return jsonify({'message': 'Request must be JSON'}), 400

    data = request.json
    email = sanitize_input(data.get('email'))
    name = sanitize_input(data.get('name'))
    password = sanitize_input(data.get('password'))
    settings = sanitize_input(data.get('settings', {}))

    try:
        if user_collection.find_one({'email': email}):
            return jsonify({'message': 'Email already exists.'}), 400
        
        user_data = {
            'email': email,
            'name': name,
            'password': password,
            'events': [],
            'mobile': '',
            'settings': settings,
            'signupDate': datetime.utcnow(),
            'loggedIn': True
        }
        user_collection.insert_one(user_data)

        return jsonify({'message': 'Signup successful!'}), 200
    except Exception as e:
        app.logger.error(f'Signup failed: {e}')
        return jsonify({'message': 'Signup failed.', 'error': str(e)}), 500



# Get Users API
@app.route('/get-users', methods=['GET'])
def get_users():
    try:
        users = list(user_collection.find({}, {"_id": 0}))
        return jsonify({'users': users}), 200
    except Exception as e:
        app.logger.error(f'Error retrieving users: {e}')
        return jsonify({'message': 'Failed to retrieve users.', 'error': str(e)}), 500

# Update User API
@app.route('/update-user', methods=['POST'])
@authenticate_request
def update_user():
    if not request.is_json:
        return jsonify({'message': 'Request must be JSON'}), 400

    data = request.json
    email = sanitize_input(data.get('email'))
    updated_user_data = {
        'email': data.get('email'),
        'name': data.get('name'),
        'events': data.get('events'),
        'mobile': data.get('mobile'),
        'settings': data.get('settings', {}),
        'signupDate': data.get('signupDate'),
        'password': data.get('password')
    }

    try:
        user = user_collection.find_one({'email': email})
        if not user:
            user_collection.insert_one(updated_user_data)
            return jsonify({'message': 'User not found, So added as new user!'}), 200
        else:
            user_collection.update_one({'email': email}, {'$set': updated_user_data})
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
    

# Notifications Changes

def get_todays_events():
    """Retrieve events happening today for all users."""
    today = datetime.now().strftime('%Y-%m-%d')
    events_today = []

    users = user_collection.find()
    for user in users:
        if not user.get('settings', {}).get('notifications', False):
            continue  # Skip if notifications are disabled for the user
        
        # Iterate over events
        for event in user.get('events', []):
            if event['date'][:10] == today:  # Check if the event is today
                events_today.append({
                    'email': user['email'],
                    'name': event['name'],
                    'type': event['type']
                })
    return events_today

def get_upcoming_events():
    """Retrieve upcoming events based on user settings."""
    now = datetime.now()
    upcoming_events = []

    users = user_collection.find()
    for user in users:
        settings = user.get('settings', {})
        reminder_settings = settings.get('reminder', {})
        frequency = reminder_settings.get('frequency', 'Monthly')  # Default to Monthly
        range_type = reminder_settings.get('range', 'Month')  # Default to Month

        days_range = {
            'Week': 7,
            'Month': 30,
            'Year': 365
        }.get(range_type, 30)  # Default range to 30 days

        if not settings.get('notifications', False):
            continue  # Skip if notifications are disabled for the user

        for event in user.get('events', []):
            event_date = datetime.strptime(event['date'], '%Y-%m-%dT%H:%M:%S.%fZ')
            if (event_date - now).days <= days_range:  # Check if within range
                upcoming_events.append({
                    'email': user['email'],
                    'name': event['name'],
                    'date': event['date'],
                    'type': event['type']
                })
    return upcoming_events

@app.before_first_request
def daily_event_check():
    """Scheduled task to check for today's and upcoming events."""
    today_events = get_todays_events()
    upcoming_events = get_upcoming_events()

    send_push_notifications(today_events, 'Today')
    send_push_notifications(upcoming_events, 'Upcoming')

def send_push_notifications(events, notification_type):
    """Send notifications to users about events."""
    for event in events:
        print(f"Sending {notification_type} notification to {event['email']} for {event['name']}.")

# Get Events API
@app.route('/get-events', methods=['GET'])
def get_events():
    email = request.args.get('email')
    if not email:
        return jsonify({'message': 'Email is required'}), 400

    try:
        user = user_collection.find_one({'email': email}, {'_id': 0, 'events': 1})
        if not user:
            return jsonify({'message': 'User not found'}), 404

        return jsonify({'events': user.get('events', [])}), 200
    except Exception as e:
        app.logger.error(f'Error retrieving events: {e}')
        return jsonify({'message': 'Failed to retrieve events.', 'error': str(e)}), 500

# Reset Password API
@app.route('/reset-password', methods=['POST'])
def reset_password():
    if not request.is_json:
        return jsonify({'message': 'Request must be JSON'}), 400

    data = request.json
    email = sanitize_input(data.get('email'))
    new_password = sanitize_input(data.get('newPassword'))

    try:
        user = user_collection.find_one({'email': email})
        if not user:
            return jsonify({'message': 'Email not found.'}), 404

        user_collection.update_one({'email': email}, {'$set': {'password': new_password}})
        sync_with_mongo()
        return jsonify({'message': 'Password reset successful.'}), 200
    except Exception as e:
        app.logger.error(f'Failed to reset password: {e}')
        return jsonify({'message': 'Failed to reset password.', 'error': str(e)}), 500

# Logger setup
handler = RotatingFileHandler('api.log', maxBytes=10000, backupCount=1)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

if __name__ == '__main__':
    sync_with_mongo()
    app.run(host='0.0.0.0', port=5000)
