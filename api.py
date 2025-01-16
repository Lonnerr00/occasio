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
#from redis import Redis

# Load environment variables
load_dotenv()
EMAIL_USER = os.getenv('EMAIL_USER')
EMAIL_PASS = os.getenv('EMAIL_PASS')
mongo_pass = os.getenv('mongo_pass')
mongo_user = os.getenv('mongo_user')
SECRET_KEY = os.getenv('SECRET_KEY')

# Check for missing environment variables
# required_env_vars = ['EMAIL_USER', 'EMAIL_PASS', 'mongo_pass', 'mongo_user', 'SECRET_KEY']
# missing_vars = [var for var in required_env_vars if not locals().get(var)]
# if missing_vars:
#     raise EnvironmentError(f"Missing required environment variables: {', '.join(missing_vars)}")

MONGO_URI = f'mongodb+srv://{mongo_user}:{mongo_pass}@cluster0.vqfml.mongodb.net/'

# Initialize Flask app
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Rate Limiter setup with Redis
#redis_client = Redis(host='localhost', port=6379)
limiter = Limiter(
    key_func=get_remote_address,
    #storage_uri="redis://localhost:6379",
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

@app.route('/')
def home():
    return 'Welcome to the Flask API!'

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    email = sanitize_input(data.get('email'))
    name = sanitize_input(data.get('name'))
    password = sanitize_input(data.get('password'))
    otp = generate_otp()

    try:
        # Send OTP via email
        with SMTP(EMAIL_HOST, EMAIL_PORT) as smtp:
            smtp.starttls()
            smtp.login(EMAIL_USER, EMAIL_PASS)
            smtp.sendmail(EMAIL_USER, email, f"Subject: Signup OTP\n\nYour OTP is {otp}")
        # Store user details and OTP in MongoDB
        user = {'email': email, 'name': name, 'password': password, 'otp': otp}
        user_collection.replace_one({'email': email}, user, upsert=True)

        # Sync with local JSON
        sync_with_mongo()

        return jsonify({'message': 'Signup successful. OTP sent!'}), 201
    except Exception as e:
        app.logger.error(f'Signup failed: {e}')
        return jsonify({'message': 'Signup failed.', 'error': str(e)}), 500

@app.route('/resend-otp', methods=['POST'])
def resend_otp():
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

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json
    email = sanitize_input(data.get('email'))
    otp = data.get('otp')

    try:
        user = user_collection.find_one({'email': email})
        if not user:
            return jsonify({'message': 'Email not found.'}), 404
        if user['otp'] == otp:
            return jsonify({'message': 'OTP verified successfully.'}), 200
        return jsonify({'message': 'Invalid OTP.'}), 400
    except Exception as e:
        return jsonify({'message': 'Failed to verify OTP.', 'error': str(e)}), 500

@app.route('/get-users', methods=['GET'])
def get_users():
    try:
        users = list(user_collection.find({}, {"_id": 0}))
        return jsonify({'users': users}), 200
    except Exception as e:
        app.logger.error(f'Error retrieving users: {e}')
        return jsonify({'message': 'Failed to retrieve users.', 'error': str(e)}), 500

# Logger setup
handler = RotatingFileHandler('api.log', maxBytes=10000, backupCount=1)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

if __name__ == '__main__':
    sync_with_mongo()
    app.run(host='0.0.0.0', port=5000)
